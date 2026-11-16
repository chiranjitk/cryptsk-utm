/**
 * Email Security OS service — resolves console EmailGateway/EmailPolicy/
 * EmailRoutingRule rows into the Postfix+Rspamd render and executes/reads live
 * state for the /email-security/os routes. Pure mapping lives in os.ts;
 * everything touching db/exec/fs is here (server-only imports).
 *
 * Target appliance: Debian 13 — postfix (installed, INACTIVE), rspamd 3.12.1
 * (installed, INACTIVE), clamav-daemon (freshclam may still be downloading),
 * rsyslog already logging postfix.
 */

import fs from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import { db } from "@/lib/db";
import { getDataPlaneMode } from "@/lib/engine";
import { hasTool, readServiceStates, runTool } from "@/lib/host/tools";
import { getOrCreatePolicy } from "@/app/api/v1/email-security/service";
import {
  buildEmailApplyPlan,
  computeEmailDrift,
  EMAIL_BACKUP_RE,
  EMAIL_MANAGED_PATHS,
  EMAIL_SS_PROBE,
  EMAIL_STATE_DIR,
  EMAIL_STATE_FILE,
  emailConfHash,
  emailHash,
  emailStepGuarded,
  isEmailBackupDir,
  parseSsPorts,
  POSTFIX_TRANSPORT,
  RSPAMD_MILTER_PORT,
  RSPAMD_WEBUI_PORT,
  SMTP_PORT,
  renderEmailFiles,
  type DmarcPolicyOs,
  type EmailApplyPlan,
  type EmailDriftInput,
  type EmailGatewayOsShape,
  type EmailPolicyOsShape,
  type EmailRuleOsShape,
  type GatewayModeOs,
  type RoutingActionOs,
  type TlsModeOs,
} from "./os";

// ── shapes (db rows → pure renderer input, defensive enum fallbacks) ────────

function parseJsonArray(json: string): string[] {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string");
  } catch {
    return [];
  }
}

export async function buildGatewayShapes(tenantId: number): Promise<EmailGatewayOsShape[]> {
  const rows = await db.emailGateway.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    mode: (r.mode === "relay" ? "relay" : "proxy") as GatewayModeOs,
    listenPort: r.listenPort,
    relayDomains: parseJsonArray(r.relayDomains),
    upstreamHost: r.upstreamHost,
    tlsMode: (["none", "starttls", "wrapper"].includes(r.tlsMode) ? r.tlsMode : "starttls") as TlsModeOs,
    enabled: r.enabled,
  }));
}

export async function buildRuleShapes(tenantId: number): Promise<EmailRuleOsShape[]> {
  const rows = await db.emailRoutingRule.findMany({
    where: { tenantId },
    orderBy: [{ priority: "asc" }, { id: "asc" }],
  });
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    matchDomain: r.matchDomain,
    action: (["deliver", "relay", "reject", "quarantine"].includes(r.action) ? r.action : "relay") as RoutingActionOs,
    targetHost: r.targetHost,
    priority: r.priority,
    enabled: r.enabled,
  }));
}

async function buildPolicyShape(tenantId: number): Promise<EmailPolicyOsShape> {
  // GET auto-creates the singleton defaults — the module's documented contract
  const p = await getOrCreatePolicy(tenantId);
  return {
    spamThreshold: p.spamThreshold,
    blockPhishing: p.blockPhishing,
    blockMalware: p.blockMalware,
    scanArchives: p.scanArchives,
    maxMessageSizeMb: p.maxMessageSizeMb,
    blockedExtensions: p.blockedExtensions,
    spfVerify: p.spfVerify,
    dkimVerify: p.dkimVerify,
    dmarcPolicy: p.dmarcPolicy as DmarcPolicyOs,
    quarantineRetentionDays: p.quarantineRetentionDays,
    enabled: p.enabled,
  };
}

export async function buildEmailShapes(tenantId: number): Promise<{
  gateways: EmailGatewayOsShape[];
  rules: EmailRuleOsShape[];
  policy: EmailPolicyOsShape;
}> {
  const [gateways, rules, policy] = await Promise.all([
    buildGatewayShapes(tenantId),
    buildRuleShapes(tenantId),
    buildPolicyShape(tenantId),
  ]);
  return { gateways, rules, policy };
}

// ── state.json ──────────────────────────────────────────────────────────────

export interface EmailStateFile {
  confHash: string | null;
  fileHashes?: Record<string, string>;
  gatewayIds: number[];
  appliedAt: string | null;
  /** teardown marker: last apply stopped the stack (no gateways enabled) */
  stopped?: boolean;
}

export async function readEmailState(): Promise<EmailStateFile | null> {
  try {
    const raw = await fs.readFile(EMAIL_STATE_FILE, "utf8");
    const parsed = JSON.parse(raw) as EmailStateFile;
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.gatewayIds)) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeEmailState(content: string): Promise<void> {
  await fs.mkdir(EMAIL_STATE_DIR, { recursive: true });
  await fs.writeFile(EMAIL_STATE_FILE, content, "utf8");
}

// ── live OS reads ───────────────────────────────────────────────────────────

export interface EmailManagedFileFact {
  path: string;
  present: boolean;
  bytes: number;
  hash: string | null;
}

/** Managed files currently on disk (facts + contents for the on-disk hash). */
export async function readOnDiskFiles(): Promise<{
  facts: EmailManagedFileFact[];
  contents: Array<{ path: string; content: string }>;
}> {
  const facts: EmailManagedFileFact[] = [];
  const contents: Array<{ path: string; content: string }> = [];
  for (const p of EMAIL_MANAGED_PATHS) {
    try {
      const content = await fs.readFile(p, "utf8");
      facts.push({ path: p, present: true, bytes: Buffer.byteLength(content), hash: emailHash(content) });
      contents.push({ path: p, content });
    } catch {
      facts.push({ path: p, present: false, bytes: 0, hash: null });
    }
  }
  return { facts, contents };
}

export async function readEmailUnits(): Promise<{ postfix: string | null; rspamd: string | null }> {
  const states = await readServiceStates(["postfix", "rspamd"]);
  return { postfix: states?.postfix ?? null, rspamd: states?.rspamd ?? null };
}

/**
 * Availability probe for clamd (clamdscan --ping 1). Availability ONLY — never
 * a blocking apply step; freshclam may still be downloading on a fresh box.
 */
export async function probeClamd(): Promise<boolean | null> {
  if (!(await hasTool("clamdscan"))) return null;
  const r = await runTool("clamdscan --ping 1", 4000);
  return r.ok;
}

/** Listener probe — informational: smtp 25, rspamd milter 11332, webui 11334. */
export async function probeEmailPorts(): Promise<Record<number, boolean> | null> {
  if (!(await hasTool("ss"))) return null;
  const r = await runTool(EMAIL_SS_PROBE, 5000);
  if (!r.ok) return null;
  return parseSsPorts(r.stdout, [SMTP_PORT, RSPAMD_MILTER_PORT, RSPAMD_WEBUI_PORT]);
}

/** Tools + data plane decide whether OS enforcement is real or preview-only. */
export async function readEmailAvailability(): Promise<boolean> {
  const [postfix, rspamadm, ss] = await Promise.all([hasTool("postfix"), hasTool("rspamadm"), hasTool("ss")]);
  return postfix && rspamadm && ss && getDataPlaneMode() === "host";
}

// ── status assembly (GET /email-security/os) ────────────────────────────────

export interface EmailOsGatewayStatus {
  id: number;
  name: string;
  mode: GatewayModeOs;
  listenPort: number;
  relayDomains: string[];
  upstreamHost: string | null;
  tlsMode: TlsModeOs;
  enabled: boolean;
  renderHash: string;
  transportLines: string[];
}

export interface EmailOsStatus {
  available: boolean;
  dataPlaneMode: string;
  gate: "on" | "off";
  note: string;
  postfixState: string | null;
  rspamdState: string | null;
  clamdReachable: boolean | null;
  portsBound: { p25: boolean | null; p11332: boolean | null; p11334: boolean | null };
  managedFiles: EmailManagedFileFact[];
  confHash: string | null;
  inSync: boolean | null;
  managedByConsole: boolean;
  driftReasons: string[];
  state: EmailStateFile | null;
  gateways: EmailOsGatewayStatus[];
  policy: EmailPolicyOsShape;
  rules: EmailRuleOsShape[];
  plan: { confHash: string | null; gatewayIds: number[]; files: Array<{ path: string; bytes: number; kind: string }> };
  warnings: string[];
}

export async function getEmailOsStatus(tenantId: number): Promise<EmailOsStatus> {
  const [{ gateways, rules, policy }, available] = await Promise.all([buildEmailShapes(tenantId), readEmailAvailability()]);
  const gate: "on" | "off" = process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off";
  const rendered = renderEmailFiles({ gateways, policy, rules });

  const warnings = [...rendered.warnings];
  let postfixState: string | null = null;
  let rspamdState: string | null = null;
  let postfixActive: boolean | null = null;
  let rspamdActive: boolean | null = null;
  let clamdReachable: boolean | null = null;
  let portsBound: EmailOsStatus["portsBound"] = { p25: null, p11332: null, p11334: null };
  let onDiskHash: string | null = null;
  let managedFiles: EmailManagedFileFact[] = [];
  let state: EmailStateFile | null = null;
  let inSync: boolean | null = null;
  let managedByConsole = false;
  let driftReasons: string[] = [];

  if (available) {
    const units = await readEmailUnits();
    postfixState = units.postfix;
    rspamdState = units.rspamd;
    postfixActive = postfixState === "active" ? true : postfixState ? false : null;
    rspamdActive = rspamdState === "active" ? true : rspamdState ? false : null;

    const onDisk = await readOnDiskFiles();
    managedFiles = onDisk.facts;
    onDiskHash = onDisk.contents.length > 0 ? emailConfHash(onDisk.contents) : null;
    state = await readEmailState();
    clamdReachable = await probeClamd();
    const ports = await probeEmailPorts();
    portsBound = {
      p25: ports ? ports[SMTP_PORT] : null,
      p11332: ports ? ports[RSPAMD_MILTER_PORT] : null,
      p11334: ports ? ports[RSPAMD_WEBUI_PORT] : null,
    };

    const driftInput: EmailDriftInput = {
      enabledGatewayCount: gateways.filter((g) => g.enabled).length,
      renderedHash: rendered.confHash,
      onDiskHash,
      stateHash: state?.confHash ?? null,
      postfixActive,
      rspamdActive,
    };
    const drift = computeEmailDrift(driftInput);
    inSync = drift.inSync;
    managedByConsole = drift.managedByConsole;
    driftReasons = drift.driftReasons;
  } else {
    driftReasons = ["postfix/rspamadm/ss unavailable or data plane not in host mode — OS enforcement is preview-only"];
  }

  if (policy.blockMalware && clamdReachable === false) {
    warnings.push("clamav daemon not running — malware scan inactive (clamd 127.0.0.1:3310 unreachable)");
  }
  if (gate === "off") {
    warnings.push("CONSOLE_OS_APPLY is off — Apply returns the exact command plan as a preview");
  }

  return {
    available,
    dataPlaneMode: getDataPlaneMode(),
    gate,
    note: available
      ? "postfix + rspamadm present — Apply converges /etc/postfix/main.cf, /etc/postfix/utm-transport and /etc/rspamd/local.d/*.conf on the appliance"
      : "postfix/rspamadm unavailable or data plane in simulated mode — OS enforcement is preview-only",
    postfixState,
    rspamdState,
    clamdReachable,
    portsBound,
    managedFiles,
    confHash: onDiskHash,
    inSync,
    managedByConsole,
    driftReasons,
    state,
    gateways: rendered.gateways.map((g) => ({
      id: g.id,
      name: g.name,
      mode: g.mode,
      listenPort: g.listenPort,
      relayDomains: g.relayDomains,
      upstreamHost: g.upstreamHost,
      tlsMode: g.tlsMode,
      enabled: g.enabled,
      renderHash: g.renderHash,
      transportLines: g.transportLines,
    })),
    policy,
    rules,
    plan: {
      confHash: rendered.confHash,
      gatewayIds: rendered.gateways.filter((g) => g.enabled).map((g) => g.id),
      files: rendered.files.map((f) => ({ path: f.path, bytes: Buffer.byteLength(f.content), kind: f.kind })),
    },
    warnings,
  };
}

// ── apply executor (mirrors the logs/waf route pattern) ─────────────────────

export interface EmailStepResult {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface EmailApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  refused?: string;
  reason: string;
  /** zero-churn: live hashes + units already matched — nothing touched */
  skipped?: boolean;
  rolledBack: boolean;
  confHash?: string | null;
  backupDir?: string;
  plan: {
    steps: Array<{ step: string; cmd: string; kind: string; optional?: boolean }>;
    files: Array<{ path: string; bytes: number; kind: string }>;
    gatewayIds: number[];
    warnings: string[];
  };
  results: EmailStepResult[];
}

function planPreview(plan: EmailApplyPlan): EmailApplyOutcome["plan"] {
  return {
    steps: plan.steps.map((s) => ({ step: s.step, cmd: s.cmd, kind: s.kind, optional: s.optional })),
    files: plan.files.map((f) => ({ path: f.path, bytes: Buffer.byteLength(f.content), kind: f.kind })),
    gatewayIds: plan.gatewayIds,
    warnings: plan.warnings,
  };
}

/** Forensic record of the pre-apply postfix/rspamd tree (best-effort). */
async function writeBackupListing(backupDir: string): Promise<void> {
  try {
    await fs.mkdir(backupDir, { recursive: true });
    const listing: string[] = [];
    for (const dir of ["/etc/postfix", "/etc/rspamd/local.d", "/etc/rspamd"]) {
      try {
        const entries = await fs.readdir(dir);
        for (const e of entries.sort()) listing.push(`${dir}/${e}`);
      } catch {
        /* dir not deployed */
      }
    }
    await fs.writeFile(`${backupDir}/pre-apply-listing.txt`, listing.join("\n") + "\n", "utf8");
  } catch {
    /* best-effort */
  }
}

/** Restore pre-apply files from the backup dir (fs; missing backup → unlink). */
async function restoreFromBackup(backupDir: string, paths: readonly string[]): Promise<number> {
  let restored = 0;
  for (const p of paths) {
    try {
      const prev = await fs.readFile(path.join(backupDir, p), "utf8");
      await fs.mkdir(path.dirname(p), { recursive: true });
      await fs.writeFile(p, prev, "utf8");
      restored += 1;
    } catch {
      // no pre-apply file existed → remove the console-installed one
      await fs.unlink(p).catch(() => {});
      if (p === POSTFIX_TRANSPORT) await fs.unlink(`${POSTFIX_TRANSPORT}.db`).catch(() => {});
    }
  }
  return restored;
}

/**
 * Execute the convergence plan on the appliance (gate checked here):
 *   snapshot-first → stage → install → postmap → rspamadm configtest →
 *   postfix check → services → verify → state.json LAST.
 * Any failure AFTER the first install auto-restores the backup dir and re-runs
 * postmap + service restarts. The state file is only written on full success.
 */
export async function applyEmailToOs(tenantId: number): Promise<EmailApplyOutcome> {
  const gateOn = process.env.CONSOLE_OS_APPLY === "1" && getDataPlaneMode() === "host";
  const gate: "on" | "off" = gateOn ? "on" : "off";
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  const [{ gateways, rules, policy }, units, onDisk] = await Promise.all([
    buildEmailShapes(tenantId),
    readEmailUnits(),
    readOnDiskFiles(),
  ]);

  const plan = buildEmailApplyPlan({
    gateways,
    policy,
    rules,
    onDiskPaths: onDisk.facts.filter((f) => f.present).map((f) => f.path),
    postfixState: units.postfix,
    rspamdState: units.rspamd,
    mode: gateOn ? "exec" : "plan",
    ts,
  });
  const preview = planPreview(plan);

  if (plan.refused) {
    return { gate, applied: false, refused: plan.refused, reason: plan.refused, rolledBack: false, plan: preview, results: [] };
  }
  if (!gateOn) {
    return {
      gate: "off",
      applied: false,
      reason:
        "CONSOLE_OS_APPLY is off or the data plane is not in host mode — plan preview only (postfix/rspamd command sequence attached)",
      rolledBack: false,
      plan: preview,
      results: [],
    };
  }
  const [postfixBin, rspamadmBin] = await Promise.all([hasTool("postfix"), hasTool("rspamadm")]);
  if (!postfixBin || !rspamadmBin) {
    return {
      gate,
      applied: false,
      reason: `postfix/rspamadm binaries not found on the host (${postfixBin ? "postfix ok" : "postfix missing"}, ${rspamadmBin ? "rspamadm ok" : "rspamadm missing"}) — cannot validate or converge`,
      rolledBack: false,
      plan: preview,
      results: [],
    };
  }
  const unguarded = plan.steps.find((s) => s.cmd !== "" && !emailStepGuarded(s.cmd));
  if (unguarded) {
    return {
      gate,
      applied: false,
      reason: `refused: step failed the email command whitelist — "${unguarded.cmd}" (systemctl postfix/rspamd, postmap, postfix check, rspamadm configtest, ss, install/cp/rm inside console email paths only)`,
      rolledBack: false,
      plan: preview,
      results: [],
    };
  }

  // ── zero-churn: files already match the render AND both units are active ──
  const state = await readEmailState();
  const onDiskHash = onDisk.contents.length > 0 ? emailConfHash(onDisk.contents) : null;
  const bothActive = units.postfix === "active" && units.rspamd === "active";
  if (!plan.empty && plan.confHash != null && onDiskHash === plan.confHash && state?.confHash === plan.confHash && bothActive) {
    return {
      gate,
      applied: true,
      skipped: true,
      reason: `managed files already match the render (hash ${plan.confHash}) and postfix+rspamd are active — no restart`,
      rolledBack: false,
      confHash: plan.confHash,
      plan: preview,
      results: [],
    };
  }

  const results: EmailStepResult[] = [];
  let failed = false;
  let failDetail = "";
  /** set once an install step succeeded → restore is required on failure */
  let mutated = false;
  await fs.mkdir(plan.backupDir, { recursive: true }).catch(() => {});

  for (const s of plan.steps) {
    if (s.kind === "dir") {
      const ok = await fs
        .mkdir(EMAIL_STATE_DIR, { recursive: true })
        .then(() => true)
        .catch(() => false);
      results.push({ step: s.step, ok, detail: ok ? EMAIL_STATE_DIR : "mkdir failed" });
      if (!ok) {
        failed = true;
        failDetail = "state dir could not be created";
        break;
      }
      continue;
    }

    if (s.kind === "backup") {
      // skip sources that vanished since planning (cp would fail)
      const src = s.cmd.split(/\s+/)[1];
      if (src && !existsSync(src)) continue;
      const r = await runTool(s.cmd, 10000);
      results.push({ step: s.step, ok: r.ok, detail: r.ok ? src : (r.stderr || r.error || "cp failed").slice(0, 200) });
      if (!r.ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: ${(r.stderr || r.error || "cp failed").trim().slice(0, 300)}`;
        break;
      }
      continue;
    }

    if (s.kind === "stage") {
      const f = plan.files.find((x) => `stage ${x.path.split("/").pop()}` === s.step);
      try {
        if (!f) throw new Error("stage file not found in plan");
        await fs.writeFile(f.stage, f.content, "utf8");
        results.push({ step: s.step, ok: true, detail: `${Buffer.byteLength(f.content)} bytes → ${f.stage}` });
      } catch (err) {
        failed = true;
        failDetail = `stage failed: ${(err as Error).message.slice(0, 200)}`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      continue;
    }

    if (s.kind === "verify" && s.cmd === "") {
      // verify managed file hashes (fs read — the only verify without a command)
      const onDiskNow = await readOnDiskFiles();
      const hashNow = onDiskNow.contents.length > 0 ? emailConfHash(onDiskNow.contents) : null;
      const ok = hashNow != null && hashNow === plan.confHash;
      results.push({ step: s.step, ok, detail: ok ? hashNow : `live ${hashNow ?? "missing"} — expected ${plan.confHash}` });
      if (!ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: live hash ${hashNow ?? "missing"} — expected ${plan.confHash}`;
      }
      continue;
    }

    if (s.kind === "writefile") {
      await writeEmailState(plan.stateContent);
      results.push({ step: s.step, ok: true, detail: EMAIL_STATE_FILE });
      continue;
    }

    if (!emailStepGuarded(s.cmd)) {
      failed = true;
      failDetail = `step '${s.step}' failed the email command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    const r = await runTool(s.cmd, s.kind === "service" ? 30000 : 20000);

    if (s.kind === "install") mutated = true;

    if (!r.ok && !s.optional) {
      failed = true;
      failDetail = `step '${s.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    if (s.kind === "verify" && s.cmd.startsWith("systemctl is-active") && r.stdout.trim() !== "active") {
      failed = true;
      failDetail = `step '${s.step}' failed: unit state '${r.stdout.trim() || "unknown"}' — expected 'active'`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    if (s.kind === "probe") {
      const ports = parseSsPorts(r.stdout, [SMTP_PORT, RSPAMD_MILTER_PORT, RSPAMD_WEBUI_PORT]);
      results.push({
        step: s.step,
        ok: true,
        detail: `:25=${ports[SMTP_PORT] ? "up" : "down"} :11332=${ports[RSPAMD_MILTER_PORT] ? "up" : "down"} :11334=${ports[RSPAMD_WEBUI_PORT] ? "up" : "down"}`,
      });
      continue;
    }

    results.push({ step: s.step, ok: true, detail: r.stdout.trim().slice(0, 200) || undefined });
  }

  // ── auto-restore: pre-apply files back + postmap + service restarts ──
  let rolledBack = false;
  if (failed && mutated) {
    await writeBackupListing(plan.backupDir).catch(() => {});
    const restored = await restoreFromBackup(plan.backupDir, EMAIL_MANAGED_PATHS);
    const postmapOk = existsSync(POSTFIX_TRANSPORT) ? (await runTool(`postmap ${POSTFIX_TRANSPORT}`, 10000)).ok : true;
    const rspamdRestart = await runTool("systemctl restart rspamd", 30000);
    const postfixRestart = await runTool("systemctl restart postfix", 30000);
    rolledBack = postmapOk && rspamdRestart.ok && postfixRestart.ok;
    results.push({
      step: "auto-restore",
      ok: rolledBack,
      detail: rolledBack
        ? `pre-apply files restored from ${plan.backupDir} (${restored} file(s)), postmap + rspamd/postfix restarted`
        : "restore incomplete — inspect /etc/postfix/main.cf and /etc/rspamd/local.d/ manually",
    });
  }

  if (!failed) {
    await writeEmailState(plan.stateContent);
  }

  return {
    gate,
    applied: !failed,
    reason: failed
      ? failDetail
      : plan.empty
        ? "no enabled gateways — postfix and rspamd stopped (teardown)"
        : `postfix + rspamd converged (hash ${plan.confHash})`,
    rolledBack,
    confHash: plan.confHash,
    backupDir: plan.backupDir,
    plan: preview,
    results,
  };
}

// ── rollback action ─────────────────────────────────────────────────────────

export interface EmailRollbackResult {
  rolledBack: boolean;
  backupDir: string | null;
  restored: number;
  postmapped: boolean;
  restarted: boolean;
  detail: string;
}

/** Restore the NEWEST backup-<ts>/ under EMAIL_STATE_DIR + postmap + restarts. */
export async function rollbackEmailOs(): Promise<EmailRollbackResult> {
  let newest: string | null = null;
  try {
    const entries = (await fs.readdir(EMAIL_STATE_DIR)).filter((n) => EMAIL_BACKUP_RE.test(n)).sort();
    newest = entries.length > 0 ? path.join(EMAIL_STATE_DIR, entries[entries.length - 1]) : null;
  } catch {
    newest = null;
  }
  if (!newest || !isEmailBackupDir(newest)) {
    return { rolledBack: false, backupDir: null, restored: 0, postmapped: false, restarted: false, detail: "no console backup found — nothing to roll back" };
  }

  const restored = await restoreFromBackup(newest, EMAIL_MANAGED_PATHS);
  if (restored === 0) {
    return { rolledBack: false, backupDir: newest, restored: 0, postmapped: false, restarted: false, detail: `backup ${path.basename(newest)} holds no restorable files` };
  }

  const postmapped = existsSync(POSTFIX_TRANSPORT) ? (await runTool(`postmap ${POSTFIX_TRANSPORT}`, 10000)).ok : true;
  const rspamdRestart = await runTool("systemctl restart rspamd", 30000);
  const postfixRestart = await runTool("systemctl restart postfix", 30000);
  const restarted = rspamdRestart.ok && postfixRestart.ok;

  await writeEmailState(
    JSON.stringify(
      {
        confHash: null,
        gatewayIds: [],
        appliedAt: new Date().toISOString(),
        rolledBackFrom: path.basename(newest),
      },
      null,
      2,
    ),
  ).catch(() => {});

  return {
    rolledBack: true,
    backupDir: newest,
    restored,
    postmapped,
    restarted,
    detail: `${restored} file(s) restored from ${path.basename(newest)}${postmapped ? ", transport re-postmap'd" : ""}${restarted ? ", rspamd + postfix restarted" : " (service restart failed — check unit states)"}`,
  };
}

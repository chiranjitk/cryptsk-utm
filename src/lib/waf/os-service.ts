/**
 * WAF OS service (M17 §2.4) — the db/exec glue for lib/waf/os.ts (mirrors the
 * dns/os.ts + ips apply executor architecture):
 *
 *   collectWafInputs   DB rows → pure WafInputs (geo JSON parsed, certs staged)
 *   readWafOsFacts     nginx/modsec availability, unit state, on-disk hashes,
 *                      CRS root detection, listener probe, state.json
 *   buildWafApplyPlan  facts + inputs → guarded step list (pure core)
 *   execWafApplyPlan   gate (CONSOLE_OS_APPLY=1 + host mode) → run the plan:
 *                      fs stage → `nginx -t` → start|reload → verify;
 *                      any validate/activate failure → restore backups + revalidate
 *   rollbackWafOs      restore the newest backup-<ts>/ + revalidate + reload
 *
 * File writes go through node fs with the managed paths pinned by wafStepGuarded;
 * runTool only executes whitelisted commands (nginx -t, systemctl, ss, cp, rm).
 */

import fs from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import { hasTool, readServiceStates, runTool } from "@/lib/host/tools";
import { getDataPlaneMode } from "@/lib/engine";
import {
  buildWafApplyPlan,
  computeWafDrift,
  interpretNginxTest,
  isWafBackupDir,
  MANAGED_FOOTER,
  MANAGED_HEADER,
  MODSEC_MODULE_CONF,
  renderWafManaged,
  wafStepGuarded,
  WAF_BACKUP_RE,
  WAF_MANAGED_FILE,
  WAF_RULES_DIR,
  WAF_SSL_DIR,
  WAF_STATE_DIR,
  CRS_BASE_DIR,
  CRS_FALLBACK_DIRS,
  INSTALLED_CRS_VERSION,
  wafConfHash,
  wafHash,
  type WafCertInput,
  type WafExclusionInput,
  type WafInputs,
  type WafOsFacts,
  type WafManagedFileFact,
  type WafPolicyInput,
  type WafVhostInput,
} from "./os";

// ── shapes ──────────────────────────────────────────────────────────────────

export interface WafApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  refused?: string;
  reason: string;
  rolledBack: boolean;
  confHash?: string;
  backupDir?: string;
  plan: {
    steps: Array<{ step: string; cmd: string; kind: string; optional?: boolean }>;
    files: Array<{ path: string; bytes: number; kind: string }>;
    managedVhostIds: number[];
    warnings: string[];
  };
  results: Array<{ step: string; ok: boolean; detail?: string }>;
}

export interface WafApplyState {
  confHash: string | null;
  vhostIds: number[];
  appliedAt: string | null;
  lastApply?: { at: string; backupDir: string | null; applied: boolean; reason: string };
  steps?: number;
  results?: unknown;
}

// ── DB collectors ───────────────────────────────────────────────────────────

/** Active, unexpired PKI material for the given cert ids (server-only). */
async function collectCertMaterials(tenantId: number, certIds: number[]): Promise<Map<number, WafCertInput>> {
  const out = new Map<number, WafCertInput>();
  const unique = [...new Set(certIds.filter((id): id is number => id != null))];
  if (unique.length === 0) return out;
  const rows = await db.certificate.findMany({
    where: { tenantId, id: { in: unique } },
    select: { id: true, certPem: true, keyPem: true, status: true, notAfter: true, issuedFor: true },
  });
  for (const c of rows) {
    const notExpired = !c.notAfter || c.notAfter.getTime() > Date.now();
    const usable = c.status === "active" && notExpired && (c.issuedFor === "waf" || c.issuedFor === "general");
    if (usable && c.certPem && c.keyPem) {
      out.set(c.id, { certId: c.id, certPem: c.certPem, keyPem: c.keyPem });
    }
  }
  return out;
}

/** DB desired state → pure WafInputs (geo JSON parsed defensively). */
export async function collectWafInputs(tenantId: number): Promise<WafInputs> {
  const [vhostRows, policyRows, exclusionRows] = await Promise.all([
    db.wafVhost.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.wafPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.wafExclusion.findMany({ where: { tenantId, enabled: true }, orderBy: { id: "asc" } }),
  ]);
  const certs = await collectCertMaterials(
    tenantId,
    vhostRows.map((v) => v.certId).filter((id): id is number => id != null),
  );

  const vhosts: WafVhostInput[] = vhostRows.map((v) => ({
    id: v.id,
    name: v.name,
    hostname: v.hostname,
    backendHost: v.backendHost,
    backendPort: v.backendPort,
    listenPort: v.listenPort,
    tls: v.tls,
    certId: v.certId,
    mode: v.mode,
    enabled: v.enabled,
  }));
  const policies: WafPolicyInput[] = policyRows.map((p) => ({
    id: p.id,
    name: p.name,
    vhostId: p.vhostId,
    owaspCrsEnabled: p.owaspCrsEnabled,
    crsVersion: p.crsVersion,
    paranoiaLevel: p.paranoiaLevel,
    anomalyInThreshold: p.anomalyInThreshold,
    anomalyOutThreshold: p.anomalyOutThreshold,
    learningMode: p.learningMode,
    geoBlockCountries: parseJson<string[]>(p.geoBlockCountries, []),
    rateLimitRpm: p.rateLimitRpm,
    rateLimitBurst: p.rateLimitBurst,
    apiProtection: p.apiProtection,
    enabled: p.enabled,
  }));
  const exclusions: WafExclusionInput[] = exclusionRows.map((x) => ({
    id: x.id,
    policyId: x.policyId,
    scope: x.scope,
    matchValue: x.matchValue,
    ruleId: x.ruleId,
    enabled: x.enabled,
  }));
  return { vhosts, policies, exclusions, certs: [...certs.values()] };
}

// ── CRS root detection (constant + detect) ──────────────────────────────────

/** First CRS root that actually exists on the host (constant primary). */
export function detectCrsDir(): string | null {
  for (const dir of [CRS_BASE_DIR, ...CRS_FALLBACK_DIRS]) {
    if (existsSync(dir)) return dir;
  }
  return null;
}

// ── state.json ──────────────────────────────────────────────────────────────

async function readState(): Promise<WafApplyState> {
  try {
    const raw = await fs.readFile(path.join(WAF_STATE_DIR, "state.json"), "utf8");
    return parseJson<WafApplyState>(raw, { confHash: null, vhostIds: [], appliedAt: null });
  } catch {
    return { confHash: null, vhostIds: [], appliedAt: null };
  }
}

async function persistState(patch: Partial<WafApplyState>): Promise<void> {
  try {
    await fs.mkdir(WAF_STATE_DIR, { recursive: true });
    const cur = await readState();
    await fs.writeFile(
      path.join(WAF_STATE_DIR, "state.json"),
      JSON.stringify({ ...cur, ...patch }, null, 2),
      "utf8",
    );
  } catch {
    /* best-effort */
  }
}

// ── OS facts (real reads) ───────────────────────────────────────────────────

/** sha256[:16] over the managed files CURRENTLY on disk (sorted by path). */
function hashOnDisk(contents: Array<{ path: string; content: string }>): string | null {
  return contents.length > 0 ? wafConfHash(contents) : null;
}

export async function readWafOsFacts(): Promise<WafOsFacts> {
  const [nginx, systemctl] = await Promise.all([hasTool("nginx"), hasTool("systemctl")]);
  const unitStates = systemctl ? await readServiceStates(["nginx"]) : null;
  const modsecModule = existsSync(MODSEC_MODULE_CONF);
  const crsDir = detectCrsDir();

  // managed files currently deployed
  const managedFiles: WafManagedFileFact[] = [];
  const onDisk: Array<{ path: string; content: string }> = [];
  try {
    const content = await fs.readFile(WAF_MANAGED_FILE, "utf8");
    // only console-managed content counts (an operator's own conf.d file with
    // the same name would break the managed marker — reported honestly)
    const managed = content.includes(MANAGED_HEADER) && content.includes(MANAGED_FOOTER);
    managedFiles.push({ path: WAF_MANAGED_FILE, present: true, bytes: content.length, hash: wafHash(content) });
    if (managed) onDisk.push({ path: WAF_MANAGED_FILE, content });
  } catch {
    managedFiles.push({ path: WAF_MANAGED_FILE, present: false, bytes: 0, hash: null });
  }
  try {
    const entries = await fs.readdir(WAF_RULES_DIR);
    for (const name of entries.sort()) {
      const p = path.join(WAF_RULES_DIR, name);
      try {
        const st = await fs.stat(p);
        if (!st.isFile()) continue;
        const content = await fs.readFile(p, "utf8");
        managedFiles.push({ path: p, present: true, bytes: st.size, hash: wafHash(content) });
        onDisk.push({ path: p, content });
      } catch {
        /* unreadable file — skip */
      }
    }
  } catch {
    /* rules dir not deployed yet */
  }

  // listener probe (informational)
  let portBound: boolean | null = null;
  if (nginx) {
    const ss = await runTool("ss -ltn '( sport = :443 or sport = :80 )'", 5000);
    if (ss.ok) {
      portBound = /:(443|80)\s/.test(ss.stdout);
    }
  }

  const state = await readState();
  return {
    available: nginx && modsecModule,
    unitState: unitStates?.nginx ?? null,
    managedFiles,
    confHash: hashOnDisk(onDisk),
    stateHash: state.confHash ?? null,
    portBound,
    crsDir,
  };
}

// ── status assembly (GET /waf/os) ───────────────────────────────────────────

export interface WafOsVhostStatus {
  id: number;
  hostname: string;
  mode: string;
  renderHash: string;
  policy: {
    id: number;
    crs: boolean;
    crsVersion: string;
    pl: number;
    thresholds: { in: number; out: number };
    learning: boolean;
    rateLimit: { rpm: number; burst: number } | null;
  } | null;
  exclusions: Array<{ id: number; scope: string; matchValue: string; ruleId: number | null }>;
  warnings: string[];
}

export interface WafOsStatus {
  available: boolean;
  dataPlaneMode: string;
  gate: "on" | "off";
  unitState: string | null;
  managedFiles: WafManagedFileFact[];
  portBound: boolean | null;
  inSync: boolean;
  managedByConsole: boolean;
  driftReasons: string[];
  confHash: string | null;
  crs: { dir: string | null; installed: boolean; version: string };
  lastApply: WafApplyState;
  vhosts: WafOsVhostStatus[];
  warnings: string[];
}

export async function getWafOsStatus(tenantId: number): Promise<WafOsStatus> {
  const [inputs, facts] = await Promise.all([collectWafInputs(tenantId), readWafOsFacts()]);
  const rendered = renderWafManaged(inputs);
  const drift = computeWafDrift(facts, rendered.confHash, rendered.managedVhostIds.length);
  const state = await readState();

  const policyByVhost = new Map(inputs.policies.map((p) => [p.vhostId, p]));

  const warnings = [...rendered.warnings];
  if (!facts.crsDir) {
    warnings.push(`OWASP CRS bundle not found (${CRS_BASE_DIR}) — policies render engine-only until it is installed`);
  }
  if (!existsSync(MODSEC_MODULE_CONF)) {
    warnings.push(`ModSecurity nginx module conf not present (${MODSEC_MODULE_CONF}) — nginx would start without the WAF engine`);
  }

  const vhostStatus: WafOsVhostStatus[] = rendered.vhosts.map((v) => {
    const policy = policyByVhost.get(v.id) ?? null;
    return {
      id: v.id,
      hostname: v.hostname,
      mode: v.mode,
      renderHash: v.renderHash,
      policy:
        v.policySummary && policy
          ? {
              id: policy.id,
              crs: v.policySummary.crs,
              crsVersion: v.policySummary.crsVersion,
              pl: v.policySummary.pl,
              thresholds: v.policySummary.thresholds,
              learning: v.policySummary.learning,
              rateLimit: v.policySummary.rateLimit,
            }
          : null,
      exclusions: policy
        ? inputs.exclusions
            .filter((x) => x.policyId === policy.id)
            .map((x) => ({ id: x.id, scope: x.scope, matchValue: x.matchValue, ruleId: x.ruleId }))
        : [],
      warnings: v.warnings,
    };
  });

  return {
    available: facts.available,
    dataPlaneMode: getDataPlaneMode(),
    gate: isWafGateOn() ? "on" : "off",
    unitState: facts.unitState,
    managedFiles: facts.managedFiles,
    portBound: facts.portBound,
    inSync: drift.inSync,
    managedByConsole: drift.managedByConsole,
    driftReasons: drift.reasons,
    confHash: facts.confHash,
    crs: { dir: facts.crsDir, installed: facts.crsDir != null, version: INSTALLED_CRS_VERSION },
    lastApply: state,
    vhosts: vhostStatus,
    warnings,
  };
}

// ── gate ────────────────────────────────────────────────────────────────────

export function isWafGateOn(): boolean {
  return process.env.CONSOLE_OS_APPLY === "1" && getDataPlaneMode() === "host";
}

// ── plan (service wrapper) ──────────────────────────────────────────────────

export async function buildWafPlan(
  tenantId: number,
  mode: "exec" | "plan",
  ts: string,
): Promise<ReturnType<typeof buildWafApplyPlan>> {
  const [inputs, facts] = await Promise.all([collectWafInputs(tenantId), readWafOsFacts()]);
  const crsDir = facts.crsDir ?? undefined;
  return buildWafApplyPlan(inputs, facts, mode, ts, { crsDir });
}

// ── executor ────────────────────────────────────────────────────────────────

function fileBytes(plan: ReturnType<typeof buildWafApplyPlan>): Array<{ path: string; bytes: number; kind: string }> {
  return plan.files.map((f) => ({ path: f.path, bytes: Buffer.byteLength(f.content), kind: f.kind }));
}

/** fs backup of every plan file that currently exists (source of truth for restore). */
async function backupPlanFiles(plan: ReturnType<typeof buildWafApplyPlan>): Promise<string | null> {
  try {
    let backedUp = 0;
    for (const f of plan.files) {
      try {
        const cur = await fs.readFile(f.path, "utf8");
        await fs.mkdir(path.dirname(path.join(plan.backupDir, f.path)), { recursive: true });
        await fs.writeFile(path.join(plan.backupDir, f.path), cur, "utf8");
        backedUp += 1;
      } catch {
        /* file not on disk yet */
      }
    }
    await fs.mkdir(WAF_STATE_DIR, { recursive: true });
    if (backedUp === 0) await fs.mkdir(plan.backupDir, { recursive: true });
    return plan.backupDir;
  } catch {
    return null;
  }
}

/** Restore from a console backup dir (layout: backupDir + absolute path). */
async function restoreBackupDir(dir: string, files: Array<{ path: string }>): Promise<void> {
  for (const f of files) {
    try {
      const prev = await fs.readFile(path.join(dir, f.path), "utf8");
      await fs.mkdir(path.dirname(f.path), { recursive: true });
      await fs.writeFile(f.path, prev, "utf8");
    } catch {
      await fs.unlink(f.path).catch(() => {});
    }
  }
}

async function stageFile(f: { path: string; content: string; kind: string }): Promise<void> {
  await fs.mkdir(path.dirname(f.path), { recursive: true });
  await fs.writeFile(f.path, f.content, "utf8");
  // private key material stays 0600; nginx confs are world-readable by design
  await fs.chmod(f.path, f.kind === "pki" && f.path.endsWith(".key") ? 0o600 : 0o644);
}

export async function execWafApplyPlan(
  plan: ReturnType<typeof buildWafApplyPlan>,
): Promise<WafApplyOutcome> {
  const outcomeBase = {
    plan: {
      steps: plan.steps.map((s) => ({ step: s.step, cmd: s.cmd, kind: s.kind, optional: s.optional })),
      files: fileBytes(plan),
      managedVhostIds: plan.managedVhostIds,
      warnings: plan.warnings,
    },
    // early returns (gate off / refused / missing tool) carry no executed steps;
    // later returns override this with the real results array
    results: [] as WafApplyOutcome["results"],
  };

  if (!isWafGateOn()) {
    return {
      gate: "off",
      applied: false,
      reason:
        "OS enforcement disabled (CONSOLE_OS_APPLY off or non-host data plane) — plan is a preview only; rendered files attached",
      rolledBack: false,
      ...outcomeBase,
    };
  }
  if (plan.refused) {
    return { gate: "on", applied: false, refused: plan.refused, reason: plan.refused, rolledBack: false, ...outcomeBase };
  }
  if (!(await hasTool("nginx"))) {
    return {
      gate: "on",
      applied: false,
      reason: "'nginx' binary not found on the host — cannot validate or reload",
      rolledBack: false,
      ...outcomeBase,
    };
  }
  const unguarded = plan.steps.find((s) => s.kind !== "write" && !wafStepGuarded(s.cmd));
  if (unguarded) {
    return {
      gate: "on",
      applied: false,
      reason: `refused: step failed the WAF guard — "${unguarded.cmd}" (nginx -t, systemctl nginx, ss, cp/rm inside /etc/nginx utm-waf paths only)`,
      rolledBack: false,
      ...outcomeBase,
    };
  }

  const results: Array<{ step: string; ok: boolean; detail?: string }> = [];
  const backupDir = await backupPlanFiles(plan);

  // stage every managed file via fs (no shell writes)
  let staged = false;
  try {
    for (const f of plan.files) {
      await stageFile(f);
      results.push({ step: `write ${path.basename(f.path)}`, ok: true, detail: `${Buffer.byteLength(f.content)} bytes` });
    }
    staged = true;
  } catch (err) {
    const detail = err instanceof Error ? err.message : "write failed";
    if (backupDir) await restoreBackupDir(backupDir, plan.files);
    return {
      gate: "on",
      applied: false,
      reason: `file staging failed: ${detail} — backups restored`,
      rolledBack: true,
      backupDir: backupDir ?? undefined,
      ...outcomeBase,
      results,
    };
  }

  // run the guarded steps (skip write steps — done via fs above; skip backup
  // steps whose source vanished since planning)
  let activated = false;
  let failed = false;
  let failDetail = "";
  for (const step of plan.steps) {
    if (step.kind === "write") continue;
    const src = step.kind === "backup" ? step.cmd.split(/\s+/)[1] : null;
    if (src && !existsSync(src)) continue;
    const r = await runTool(step.cmd, step.kind === "reload" ? 20000 : 15000);

    if (step.kind === "validate" || (step.kind === "verify" && step.cmd === "nginx -t")) {
      const verdict = interpretNginxTest(`${r.stderr}${r.stdout}`, r.ok);
      results.push({ step: step.step, ok: verdict.ok, detail: verdict.detail });
      if (!verdict.ok) {
        failed = true;
        failDetail = `step '${step.step}' failed: ${verdict.detail}`;
        break;
      }
      continue;
    }
    if (!r.ok && !step.optional) {
      failed = true;
      failDetail = `step '${step.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: step.step, ok: false, detail: failDetail });
      break;
    }
    if (step.kind === "reload" || step.kind === "verify") activated = true;
    const detail = r.stdout.trim().slice(0, 200);
    results.push({ step: step.step, ok: true, ...(detail ? { detail } : {}) });
  }

  // ── auto-rollback: restore backups + revalidate (nginx -t) on any failure ──
  let rolledBack = false;
  if (failed && backupDir && isWafBackupDir(backupDir)) {
    await restoreBackupDir(backupDir, plan.files);
    rolledBack = true;
    const revalidate = await runTool("nginx -t", 15000);
    const verdict = interpretNginxTest(`${revalidate.stderr}${revalidate.stdout}`, revalidate.ok);
    results.push({
      step: "auto-rollback",
      ok: verdict.ok,
      detail: verdict.ok
        ? "previous managed files restored — nginx -t passed again"
        : `restored, but nginx -t still fails: ${verdict.detail}`,
    });
    if (activated) await runTool("systemctl reload nginx", 20000);
  }

  const applied = staged && !failed;
  const reason = applied
    ? plan.empty
      ? "empty managed conf written (no enabled vhosts) — nginx unit left untouched"
      : `nginx converged (hash ${plan.confHash})${activated ? "" : " — unit was not activated (validate-only path)"}`
    : failed
      ? failDetail
      : "apply did not complete";

  if (applied) {
    await persistState({
      confHash: plan.confHash,
      vhostIds: plan.managedVhostIds,
      appliedAt: new Date().toISOString(),
      lastApply: { at: new Date().toISOString(), backupDir, applied, reason },
      steps: results.length,
      results,
    });
  } else {
    await persistState({
      lastApply: { at: new Date().toISOString(), backupDir, applied: false, reason },
    });
  }

  return {
    gate: "on",
    applied,
    reason,
    rolledBack,
    confHash: plan.confHash,
    backupDir: backupDir ?? undefined,
    ...outcomeBase,
    results,
  };
}

/** Full converge pass (inputs → facts → plan → exec). Never throws. */
export async function applyWafOs(tenantId: number): Promise<WafApplyOutcome> {
  try {
    const gateOn = isWafGateOn();
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const plan = await buildWafPlan(tenantId, gateOn ? "exec" : "plan", ts);
    return await execWafApplyPlan(plan);
  } catch (err) {
    return {
      gate: isWafGateOn() ? "on" : "off",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      rolledBack: false,
      plan: { steps: [], files: [], managedVhostIds: [], warnings: [] },
      results: [],
    };
  }
}

// ── rollback action ─────────────────────────────────────────────────────────

export interface WafRollbackResult {
  rolledBack: boolean;
  backupDir: string | null;
  revalidated: boolean;
  reloaded: boolean;
  detail: string;
}

/** Restore the NEWEST backup-<ts>/ under WAF_STATE_DIR, revalidate, reload. */
export async function rollbackWafOs(): Promise<WafRollbackResult> {
  let newest: string | null = null;
  try {
    const entries = (await fs.readdir(WAF_STATE_DIR)).filter((n) => WAF_BACKUP_RE.test(n)).sort();
    newest = entries.length > 0 ? path.join(WAF_STATE_DIR, entries[entries.length - 1]) : null;
  } catch {
    newest = null;
  }
  if (!newest || !isWafBackupDir(newest)) {
    return { rolledBack: false, backupDir: null, revalidated: false, reloaded: false, detail: "no console backup found — nothing to roll back" };
  }

  // restore every file captured in the backup (paths encoded under the dir)
  const restored: string[] = [];
  try {
    const stack = [newest];
    for (;;) {
      const cur = stack.pop();
      if (!cur) break;
      const entries = await fs.readdir(cur, { withFileTypes: true });
      for (const e of entries) {
        const full = path.join(cur, e.name);
        if (e.isDirectory()) {
          stack.push(full);
          continue;
        }
        const rel = full.slice(newest.length); // absolute original path
        const prev = await fs.readFile(full, "utf8");
        await fs.mkdir(path.dirname(rel), { recursive: true });
        await fs.writeFile(rel, prev, "utf8");
        restored.push(rel);
      }
    }
  } catch (err) {
    return {
      rolledBack: false,
      backupDir: newest,
      revalidated: false,
      reloaded: false,
      detail: `restore failed: ${err instanceof Error ? err.message : "unknown"}`,
    };
  }

  const test = await runTool("nginx -t", 15000);
  const verdict = interpretNginxTest(`${test.stderr}${test.stdout}`, test.ok);
  let reloaded = false;
  if (verdict.ok) {
    const active = await readServiceStates(["nginx"]);
    const cmd = active?.nginx === "active" ? "systemctl reload nginx" : null;
    if (cmd) {
      const r = await runTool(cmd, 20000);
      reloaded = r.ok;
    }
  }

  await persistState({
    lastApply: {
      at: new Date().toISOString(),
      backupDir: newest,
      applied: false,
      reason: `rolled back to ${path.basename(newest)} (${restored.length} file(s))`,
    },
  });

  return {
    rolledBack: true,
    backupDir: newest,
    revalidated: verdict.ok,
    reloaded,
    detail: verdict.ok
      ? `${restored.length} file(s) restored from ${path.basename(newest)} — nginx -t ${reloaded ? "passed, nginx reloaded" : "passed (unit state unchanged)"}`
      : `restored, but nginx -t still fails: ${verdict.detail}`,
  };
}

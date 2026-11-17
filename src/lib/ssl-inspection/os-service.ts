/**
 * SSL Inspection OS service — db/exec glue for the PURE renderer in os.ts
 * (mirrors url-filter/os-service.ts + waf/os-service.ts layering):
 *
 *   collectSslInputs    tenant policies + bypass rules + effective CA info
 *   readSslOsFacts      REAL host reads (squid binary, `squid -v` capability
 *                       parse, ssl_crtd fallback probe, unit state, live
 *                       fragment hash, :3129, sslcrtd cache dir)
 *   getSslOsStatus      GUI↔OS honesty view + plan preview + drift
 *   buildSslPlan        inputs + facts → guarded plan (exec | plan mode)
 *   execSslApplyPlan    gated executor: backup → stage → init sslcrtd cache →
 *                       `squid -k parse` → reload/start → verify, with
 *                       auto-restore from backup-<ts>/ on failure
 *   rollbackSslOs       restore the newest backup-<ts>/ + revalidate + reload
 *
 * HARD RED LINES: /etc/squid/squid.conf is never touched (URL-Filter module
 * owns it full-file — this module writes ONLY its own conf.d fragment),
 * nftables is never flushed, and apply REFUSES when the host squid lacks
 * ssl-crtd (honest degradation, spec §6) instead of shipping a bump flow the
 * binary cannot run.
 *
 * Server-only (fs/exec/db imports). The exec gate is CONSOLE_OS_APPLY=1 AND
 * data plane in host mode — otherwise every path returns a plan preview.
 */

import { existsSync } from "fs";
import { chmod, mkdir, readFile, readdir, rm, writeFile } from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { getDataPlaneMode } from "@/lib/engine";
import { hasTool, readServiceStates, runTool } from "@/lib/host/tools";
import { parseJson } from "@/lib/json";
import {
  buildSslApplyPlan,
  computeSslDrift,
  interpretSquidParse,
  isSslBackupDir,
  MANAGED_FOOTER,
  MANAGED_HEADER,
  renderSslFragment,
  sha256_16,
  sslCrtdFromVersionOutput,
  sslStepGuarded,
  SSL_BUMP_PORT,
  SSL_CRTD_DB_DIR,
  SSL_CRTD_LEGACY_BINARY,
  SSL_CRTD_PROGRAM,
  SSL_MANAGED_FILE,
  SSL_STATE_DIR,
  SSL_STATE_FILE,
  type SslApplyPlan,
  type SslBypassRuleInput,
  type SslOsFacts,
  type SslPlanStep,
  type SslPolicyInput,
  type SslRenderInput,
} from "./os";

// ── db collectors ───────────────────────────────────────────────────────────

export interface SslCaInfo {
  id: number;
  name: string;
  status: string;
  notAfter: string | null;
  hasKey: boolean;
}

export interface SslInputs extends SslRenderInput {
  /** CA of the effective (first enabled MITM) policy — null when none */
  ca: SslCaInfo | null;
  enabledPolicyId: number | null;
}

/**
 * DB desired state → pure SslRenderInput. CA name/status resolved for the
 * effective policy (first enabled by id asc, same rule the simulated engine
 * uses) so the renderer can warn about missing/inactive generated CAs.
 */
export async function collectSslInputs(tenantId: number): Promise<SslInputs> {
  const [policyRows, ruleRows] = await Promise.all([
    db.sslInspectionPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.sslBypassRule.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
  ]);

  const enabledMitm = policyRows
    .filter((p) => p.enabled && (p.mode === "selective" || p.mode === "full"))
    .sort((a, b) => a.id - b.id)[0];

  let ca: SslCaInfo | null = null;
  if (enabledMitm?.signingCaId != null) {
    const row = await db.certificateAuthority.findFirst({
      where: { id: enabledMitm.signingCaId, tenantId },
      select: { id: true, name: true, status: true, notAfter: true, keyPem: true },
    });
    if (row) {
      ca = {
        id: row.id,
        name: row.name,
        status: row.status,
        notAfter: row.notAfter ? row.notAfter.toISOString() : null,
        hasKey: row.keyPem.length > 0,
      };
    }
  }

  const policies: SslPolicyInput[] = policyRows.map((p) => ({
    id: p.id,
    name: p.name,
    mode: p.mode,
    signingCaId: p.signingCaId,
    signingCaName: ca && p.id === enabledMitm?.id ? ca.name : null,
    signingCaStatus: ca && p.id === enabledMitm?.id ? ca.status : null,
    hstsHandling: p.hstsHandling,
    certPinningAction: p.certPinningAction,
    invalidCertAction: p.invalidCertAction,
    minTlsVersion: p.minTlsVersion,
    enabled: p.enabled,
  }));
  const bypassRules: SslBypassRuleInput[] = ruleRows.map((r) => ({
    id: r.id,
    policyId: r.policyId,
    matchType: r.matchType,
    matchValue: r.matchValue,
    reason: r.reason,
    enabled: r.enabled,
  }));
  return { policies, bypassRules, ca, enabledPolicyId: enabledMitm?.id ?? null };
}

// ── OS facts (real reads) ───────────────────────────────────────────────────

function isRunning(state: string | undefined | null): boolean {
  return state === "running" || state === "active";
}

/**
 * ssl-crtd capability detection:
 *   primary — `squid -v` configure line contains --enable-ssl-crtd;
 *   fallback — `ls /usr/lib/squid/ssl_crtd` (legacy helper) or the modern
 *   security_file_certgen binary present on disk.
 */
export async function detectSslCrtd(squidAvailable: boolean): Promise<{
  supported: boolean;
  method: SslOsFacts["sslCrtdMethod"];
}> {
  if (squidAvailable) {
    const v = await runTool("squid -v", 6000);
    if (v.ok && sslCrtdFromVersionOutput(`${v.stdout}\n${v.stderr}`)) {
      return { supported: true, method: "configure-flag" };
    }
    const ls = await runTool(`ls ${SSL_CRTD_LEGACY_BINARY}`, 4000);
    if (ls.ok && ls.stdout.trim().length > 0) {
      return { supported: true, method: "binary-present" };
    }
  }
  // no squid binary (or the -v probe failed) — helper binaries on disk are
  // still honest evidence (package files can exist before the unit is set up)
  if (existsSync(SSL_CRTD_PROGRAM) || existsSync(SSL_CRTD_LEGACY_BINARY)) {
    return { supported: true, method: "binary-present" };
  }
  return { supported: false, method: null };
}

export async function readSslOsFacts(): Promise<SslOsFacts> {
  const squidTool = await hasTool("squid");
  const [svcStates, capability] = await Promise.all([readServiceStates(["squid"]), detectSslCrtd(squidTool)]);
  const facts: SslOsFacts = {
    available: squidTool,
    unitState: svcStates?.["squid"] ?? null,
    running: isRunning(svcStates?.["squid"]),
    sslCrtdSupported: capability.supported,
    sslCrtdMethod: capability.method,
    version: null,
    managedFilePresent: false,
    managedByConsole: false,
    liveHash: null,
    port3129Bound: null,
    sslDbPresent: existsSync(SSL_CRTD_DB_DIR)
      ? true
      : existsSync(path.dirname(SSL_CRTD_DB_DIR))
        ? false
        : null,
  };

  const [ssRes, verRes] = await Promise.all([
    squidTool
      ? runTool(`ss -ltn '( sport = :${SSL_BUMP_PORT} )'`, 5000)
      : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no tool" }),
    squidTool
      ? runTool("squid -v 2>/dev/null", 6000)
      : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no tool" }),
  ]);
  if (ssRes.ok) facts.port3129Bound = new RegExp(`:${SSL_BUMP_PORT}\\s`).test(ssRes.stdout);
  if (verRes.ok) facts.version = /Version\s+(\S+)/i.exec(verRes.stdout)?.[1] ?? null;

  try {
    const cur = await readFile(SSL_MANAGED_FILE, "utf8");
    facts.managedFilePresent = true;
    facts.managedByConsole = cur.includes(MANAGED_HEADER) && cur.includes(MANAGED_FOOTER);
    facts.liveHash = sha256_16(cur);
  } catch {
    /* fragment not deployed yet */
  }
  return facts;
}

// ── state.json (confHash / appliedAt, mirrors url-filter layout) ────────────

interface SslStateFile {
  confHash?: string | null;
  appliedAt?: string | null;
  lastApply?: { at: string; action: string; applied: boolean; reason: string; backupDir: string | null; confHash: string | null };
  results?: unknown;
}

export async function readSslState(): Promise<SslStateFile | null> {
  try {
    return parseJson<SslStateFile>(await readFile(SSL_STATE_FILE, "utf8"), {});
  } catch {
    return null;
  }
}

async function persistState(patch: Record<string, unknown>): Promise<void> {
  try {
    await mkdir(SSL_STATE_DIR, { recursive: true });
    let cur: Record<string, unknown> = {};
    try {
      cur = parseJson<Record<string, unknown>>(await readFile(SSL_STATE_FILE, "utf8"), {});
    } catch {
      /* first write */
    }
    await writeFile(SSL_STATE_FILE, JSON.stringify({ ...cur, ...patch }, null, 2), "utf8");
  } catch {
    /* best-effort */
  }
}

// ── gate ────────────────────────────────────────────────────────────────────

export function isSslGateOn(): boolean {
  return process.env.CONSOLE_OS_APPLY === "1" && getDataPlaneMode() === "host";
}

// ── status (GUI ↔ OS honesty view) ──────────────────────────────────────────

export interface SslOsStatus {
  available: boolean;
  dataPlaneMode: string;
  gate: "on" | "off";
  note: string;
  unitState: string | null;
  running: boolean;
  version: string | null;
  /** ssl-crtd capability of the host squid (false → apply refuses with guidance) */
  sslCrtdSupported: boolean;
  sslCrtdMethod: SslOsFacts["sslCrtdMethod"];
  managedFile: string;
  fragmentPresent: boolean;
  fragmentByConsole: boolean;
  liveHash: string | null;
  port3129Bound: boolean | null;
  /** null when squid is unavailable (honest "unknown" instead of fake sync) */
  inSync: boolean | null;
  driftReasons: string[];
  state: { confHash: string; appliedAt: string; backupDir: string | null; applied: boolean } | null;
  policy: { id: number; name: string; mode: string; enabled: boolean; bypassRuleCount: number; signingCaId: number | null } | null;
  ca: SslCaInfo | null;
  plan: {
    steps: Array<{ step: string; cmd: string; kind: string; optional?: boolean }>;
    warnings: string[];
    skipped: Array<{ name: string; reason: string }>;
    confText: string;
    confHash: string;
    guarded: boolean;
    refused: string | null;
    empty: boolean;
  };
  warnings: string[];
}

export async function getSslOsStatus(tenantId: number): Promise<SslOsStatus> {
  const [inputs, facts, state] = await Promise.all([collectSslInputs(tenantId), readSslOsFacts(), readSslState()]);
  const render = renderSslFragment(inputs);
  const drift = computeSslDrift({ ...facts, stateHash: state?.confHash ?? null }, render.confHash, render.needsSslBump);
  const gate = isSslGateOn();

  const plan = buildSslApplyPlan(inputs, facts, gate ? "exec" : "plan", "preview", render);
  const enabledPolicy = inputs.policies.find((p) => p.id === inputs.enabledPolicyId) ?? null;

  const warnings = [...render.warnings];
  if (facts.available && !facts.sslCrtdSupported && render.needsSslBump) {
    warnings.push(
      "capability: host squid lacks ssl-crtd — Apply refuses until squid is installed/compiled with ssl-crtd or the policy is set to mode none",
    );
  }

  return {
    available: facts.available,
    dataPlaneMode: getDataPlaneMode(),
    gate: gate ? "on" : "off",
    note: !facts.available
      ? "squid not installed on this host — OS enforcement is preview-only"
      : !facts.sslCrtdSupported && render.needsSslBump
        ? "host squid lacks ssl-crtd — apply is refused (install/compile squid with ssl-crtd or use mode none)"
        : gate
          ? "squid present — Apply stages /etc/squid/conf.d/utm-ssl.conf, validates with squid -k parse and reloads"
          : "CONSOLE_OS_APPLY is off or the data plane is not in host mode — plan preview only",
    unitState: facts.unitState,
    running: facts.running,
    version: facts.version,
    sslCrtdSupported: facts.sslCrtdSupported,
    sslCrtdMethod: facts.sslCrtdMethod,
    managedFile: SSL_MANAGED_FILE,
    fragmentPresent: facts.managedFilePresent,
    fragmentByConsole: facts.managedByConsole,
    liveHash: facts.liveHash,
    port3129Bound: facts.port3129Bound,
    inSync: facts.available ? drift.inSync : null,
    driftReasons: drift.reasons,
    state: state?.lastApply
      ? {
          confHash: state.lastApply.confHash ?? "",
          appliedAt: state.lastApply.at,
          backupDir: state.lastApply.backupDir,
          applied: state.lastApply.applied,
        }
      : null,
    policy: enabledPolicy
      ? {
          id: enabledPolicy.id,
          name: enabledPolicy.name,
          mode: enabledPolicy.mode,
          enabled: enabledPolicy.enabled,
          bypassRuleCount: inputs.bypassRules.filter((r) => r.policyId === enabledPolicy.id && r.enabled).length,
          signingCaId: enabledPolicy.signingCaId,
        }
      : null,
    ca: inputs.ca,
    plan: {
      steps: plan.steps.map(({ step, cmd, kind, optional }) => (optional ? { step, cmd, kind, optional } : { step, cmd, kind })),
      warnings: plan.warnings,
      skipped: plan.skipped,
      confText: plan.confText,
      confHash: plan.confHash,
      guarded: plan.guarded,
      refused: plan.refused,
      empty: plan.empty,
    },
    warnings,
  };
}

// ── plan (service wrapper) ──────────────────────────────────────────────────

export async function buildSslPlan(tenantId: number, mode: "exec" | "plan", ts: string): Promise<SslApplyPlan> {
  const [inputs, facts] = await Promise.all([collectSslInputs(tenantId), readSslOsFacts()]);
  return buildSslApplyPlan(inputs, facts, mode, ts);
}

// ── apply / rollback outcomes ───────────────────────────────────────────────

export interface SslStepResult {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface SslApplyOutcome {
  action: "apply" | "rollback";
  applied: boolean;
  refused?: string;
  reason: string;
  gate: "on" | "off";
  rolledBack: boolean;
  confHash?: string;
  backupDir?: string | null;
  plan: {
    steps: Array<{ step: string; cmd: string; kind: string; optional?: boolean }>;
    warnings: string[];
    skipped: Array<{ name: string; reason: string }>;
    confText: string;
    guarded: boolean;
    empty: boolean;
    policyId: number | null;
  };
  results: SslStepResult[];
}

function planView(plan: SslApplyPlan): SslApplyOutcome["plan"] {
  return {
    steps: plan.steps.map(({ step, cmd, kind, optional }) => (optional ? { step, cmd, kind, optional } : { step, cmd, kind })),
    warnings: plan.warnings,
    skipped: plan.skipped,
    confText: plan.confText,
    guarded: plan.guarded,
    empty: plan.empty,
    policyId: plan.policyId,
  };
}

/** fs backup of the current fragment (source of truth for auto-restore). */
async function backupPlanFiles(plan: SslApplyPlan): Promise<string | null> {
  try {
    let backedUp = 0;
    for (const f of plan.files) {
      try {
        const cur = await readFile(f.path, "utf8");
        await mkdir(path.dirname(path.join(plan.backupDir, f.path)), { recursive: true });
        await writeFile(path.join(plan.backupDir, f.path), cur, "utf8");
        backedUp += 1;
      } catch {
        /* fragment not on disk yet (fresh install) */
      }
    }
    await mkdir(SSL_STATE_DIR, { recursive: true });
    if (backedUp === 0) await mkdir(plan.backupDir, { recursive: true });
    return plan.backupDir;
  } catch {
    return null;
  }
}

/**
 * Restore a plan file from the backup dir (layout: backupDir + absolute path).
 * No backup of this file → it did not exist pre-apply → staged file removed.
 */
async function restoreFile(backupDir: string, filePath: string): Promise<boolean> {
  try {
    const prev = await readFile(path.join(backupDir, filePath), "utf8");
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, prev, "utf8");
    await chmod(filePath, 0o644);
    return true;
  } catch {
    await rm(filePath, { force: true });
    return false;
  }
}

/** Automatic rollback path (restore → revalidate → reload when it was running). */
async function runRestoreSteps(results: SslStepResult[], backupDir: string, wasRunning: boolean): Promise<boolean> {
  const restored = await restoreFile(backupDir, SSL_MANAGED_FILE);
  results.push({
    step: "restore backup",
    ok: true,
    detail: restored
      ? `${backupDir}${SSL_MANAGED_FILE}`
      : "no previous fragment — staged file removed (fresh install)",
  });
  const r = await runTool("squid -k parse", 20000);
  const verdict = interpretSquidParse(`${r.stderr}${r.stdout}`, r.ok);
  results.push({
    step: "revalidate restored conf",
    ok: verdict.ok,
    detail: verdict.ok ? "squid -k parse passed again" : `still failing: ${verdict.detail}`,
  });
  if (!verdict.ok) return false;
  if (wasRunning) {
    const rl = await runTool("systemctl reload squid", 20000);
    results.push({
      step: "reload squid on restored conf",
      ok: rl.ok,
      detail: rl.ok ? undefined : (rl.stderr || rl.error || "exec error").slice(0, 200),
    });
    return rl.ok;
  }
  return true;
}

async function runSteps(steps: SslPlanStep[], results: SslStepResult[]): Promise<{ failed: boolean; detail: string }> {
  for (const s of steps) {
    if (!sslStepGuarded(s.cmd)) {
      const detail = `step '${s.step}' failed the ssl-inspection command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail });
      return { failed: true, detail };
    }
    // init is skipped when the sslcrtd cache exists (source-of-truth check,
    // same shape as the waf backup steps whose source vanished)
    if (s.kind === "init" && existsSync(SSL_CRTD_DB_DIR)) {
      results.push({ step: s.step, ok: true, detail: "sslcrtd cache already present — skipped" });
      continue;
    }
    const r = await runTool(s.cmd, 30000);
    if (s.kind === "validate") {
      const verdict = interpretSquidParse(`${r.stderr}${r.stdout}`, r.ok);
      results.push({ step: s.step, ok: verdict.ok, detail: verdict.detail });
      if (!verdict.ok) return { failed: true, detail: `step '${s.step}' failed: ${verdict.detail}` };
      continue;
    }
    if (!r.ok && !s.optional) {
      const detail = `step '${s.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: s.step, ok: false, detail });
      return { failed: true, detail };
    }
    const detail = r.stdout.trim().slice(0, 200) || undefined;
    results.push({ step: s.step, ok: true, ...(detail ? { detail } : {}) });
  }
  return { failed: false, detail: "" };
}

/**
 * Build + (gate-permitting) execute the ssl-bump convergence plan.
 * REFUSAL FIRST: a MITM plan on a squid without ssl-crtd never stages a file,
 * never parses, never reloads — the actionable refusal string is returned with
 * the full plan attached so the operator sees exactly what WOULD have run.
 */
export async function execSslApplyPlan(plan: SslApplyPlan): Promise<SslApplyOutcome> {
  const outcomeBase = {
    plan: planView(plan),
    results: [] as SslStepResult[],
  };

  if (plan.mode !== "exec" || !isSslGateOn()) {
    return {
      action: "apply",
      applied: false,
      refused: plan.refused ?? undefined,
      reason:
        plan.refused ??
        (isSslGateOn()
          ? "data plane is not in host mode — OS enforcement is preview-only"
          : "CONSOLE_OS_APPLY is off — plan preview only (fragment render + command sequence attached)"),
      gate: "off",
      rolledBack: false,
      confHash: plan.confHash,
      backupDir: null,
      ...outcomeBase,
    };
  }
  if (plan.refused) {
    return {
      action: "apply",
      applied: false,
      refused: plan.refused,
      reason: plan.refused,
      gate: "on",
      rolledBack: false,
      confHash: plan.confHash,
      backupDir: null,
      ...outcomeBase,
    };
  }
  if (!(await hasTool("squid"))) {
    return {
      action: "apply",
      applied: false,
      reason: "'squid' binary not found on the host — cannot validate or reload",
      gate: "on",
      rolledBack: false,
      confHash: plan.confHash,
      backupDir: null,
      ...outcomeBase,
    };
  }
  const unguarded = plan.steps.find((s) => s.kind !== "write" && !sslStepGuarded(s.cmd));
  if (unguarded) {
    return {
      action: "apply",
      applied: false,
      reason: `refused: step failed the ssl-inspection guard — "${unguarded.cmd}" (squid -k parse, systemctl squid, ss :3129, cp/rm inside the managed fragment paths only)`,
      gate: "on",
      rolledBack: false,
      confHash: plan.confHash,
      backupDir: null,
      ...outcomeBase,
    };
  }

  const wasRunning = (await readServiceStates(["squid"]))?.["squid"] === "active";
  const results: SslStepResult[] = [];
  const backupDir = await backupPlanFiles(plan);

  // stage the fragment via fs (no shell writes)
  let staged = false;
  try {
    for (const f of plan.files) {
      await mkdir(path.dirname(f.path), { recursive: true });
      await writeFile(f.path, f.content, "utf8");
      await chmod(f.path, 0o644);
      results.push({ step: `write ${path.basename(f.path)}`, ok: true, detail: `${Buffer.byteLength(f.content)} bytes` });
    }
    staged = true;
  } catch (err) {
    const detail = err instanceof Error ? err.message : "write failed";
    if (backupDir && isSslBackupDir(backupDir)) await restoreFile(backupDir, SSL_MANAGED_FILE);
    return {
      action: "apply",
      applied: false,
      reason: `file staging failed: ${detail} — ${backupDir ? "previous fragment restored" : "no backup existed"}`,
      gate: "on",
      rolledBack: Boolean(backupDir),
      backupDir,
      confHash: plan.confHash,
      ...outcomeBase,
      results,
    };
  }

  // backup steps stay in the plan for preview honesty, but the EXECUTOR's
  // fs backup (backupPlanFiles above) is the source of truth — a shell `cp`
  // here would run AFTER staging and clobber the backup with the new bytes.
  const execSteps = plan.steps.filter((s) => s.kind !== "write" && s.kind !== "backup");
  const { failed, detail } = await runSteps(execSteps, results);
  let rolledBack = false;
  if (failed && backupDir && isSslBackupDir(backupDir)) {
    rolledBack = await runRestoreSteps(results, backupDir, wasRunning);
  }

  const okSteps = results.every((r) => r.ok);
  const applied = staged && !failed && okSteps;
  const reason = !failed
    ? plan.empty
      ? "empty fragment written (no enabled selective/full policy) — squid unit untouched"
      : `utm-ssl.conf applied (backup → stage → ${plan.steps.some((s) => s.kind === "init") ? "sslcrtd init → " : ""}squid -k parse → ${wasRunning ? "reload" : "start"} → verify), hash ${plan.confHash}`
    : rolledBack
      ? `apply failed at: ${detail} — automatic rollback restored the previous fragment`
      : `apply failed at: ${detail} — rollback NOT clean — inspect squid state`;

  await persistState({
    ...(applied ? { confHash: plan.confHash, appliedAt: new Date().toISOString() } : {}),
    lastApply: {
      at: new Date().toISOString(),
      action: "apply",
      applied,
      reason,
      backupDir,
      confHash: applied ? plan.confHash : null,
    },
    steps: execSteps.length,
    results,
  });

  return {
    action: "apply",
    applied,
    reason,
    gate: "on",
    rolledBack,
    confHash: plan.confHash,
    backupDir,
    ...outcomeBase,
    results,
  };
}

/** Full converge pass (inputs → facts → plan → exec). Never throws. */
export async function applySslOs(tenantId: number): Promise<SslApplyOutcome> {
  try {
    const gateOn = isSslGateOn();
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const plan = await buildSslPlan(tenantId, gateOn ? "exec" : "plan", ts);
    return await execSslApplyPlan(plan);
  } catch (err) {
    return {
      action: "apply",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      gate: isSslGateOn() ? "on" : "off",
      rolledBack: false,
      plan: { steps: [], warnings: [], skipped: [], confText: "", guarded: false, empty: true, policyId: null },
      results: [],
    };
  }
}

// ── rollback action ─────────────────────────────────────────────────────────

export interface SslRollbackResult {
  action: "rollback";
  rolledBack: boolean;
  backupDir: string | null;
  revalidated: boolean;
  reloaded: boolean;
  detail: string;
  gate: "on" | "off";
}

async function newestBackupDir(): Promise<string | null> {
  try {
    const entries = (await readdir(SSL_STATE_DIR)).filter((n) => /^backup-[\w.-]+$/.test(n)).sort();
    return entries.length > 0 ? path.join(SSL_STATE_DIR, entries[entries.length - 1]) : null;
  } catch {
    return null;
  }
}

/**
 * Restore the NEWEST backup-<ts>/ under SSL_STATE_DIR, revalidate, reload.
 * Gate off → READ-ONLY preview (no fs writes, no exec) with the candidate
 * backup dir reported honestly.
 */
export async function rollbackSslOs(gateOn = true): Promise<SslRollbackResult> {
  const base = (over: Partial<SslRollbackResult>): SslRollbackResult => ({
    action: "rollback",
    rolledBack: false,
    backupDir: null,
    revalidated: false,
    reloaded: false,
    detail: "",
    gate: gateOn ? "on" : "off",
    ...over,
  });

  const newest = await newestBackupDir();
  if (!gateOn) {
    return base({
      backupDir: newest,
      detail: newest
        ? `CONSOLE_OS_APPLY is off — rollback is preview-only (candidate backup ${newest})`
        : "CONSOLE_OS_APPLY is off — rollback is preview-only (no recorded backup exists)",
    });
  }
  if (!newest || !isSslBackupDir(newest)) {
    return base({ detail: "no recorded backup — nothing to roll back to (apply first)" });
  }

  // restore every file captured in the backup (paths encoded under the dir)
  const restored: string[] = [];
  try {
    const stack = [newest];
    for (;;) {
      const cur = stack.pop();
      if (!cur) break;
      const entries = await readdir(cur, { withFileTypes: true });
      for (const e of entries) {
        const full = path.join(cur, e.name);
        if (e.isDirectory()) {
          stack.push(full);
          continue;
        }
        const rel = full.slice(newest.length); // absolute original path
        const prev = await readFile(full, "utf8");
        await mkdir(path.dirname(rel), { recursive: true });
        await writeFile(rel, prev, "utf8");
        restored.push(rel);
      }
    }
  } catch (err) {
    return base({
      backupDir: newest,
      detail: `restore failed: ${err instanceof Error ? err.message : "unknown"}`,
    });
  }

  const test = await runTool("squid -k parse", 20000);
  const verdict = interpretSquidParse(`${test.stderr}${test.stdout}`, test.ok);
  let reloaded = false;
  if (verdict.ok) {
    const states = await readServiceStates(["squid"]);
    const cmd = states?.squid === "active" ? "systemctl reload squid" : null;
    if (cmd) {
      const r = await runTool(cmd, 20000);
      reloaded = r.ok;
    }
  }

  await persistState({
    lastApply: {
      at: new Date().toISOString(),
      action: "rollback",
      applied: false,
      reason: `rolled back to ${path.basename(newest)} (${restored.length} file(s))`,
      backupDir: newest,
      confHash: null,
    },
  });

  return base({
    rolledBack: true,
    backupDir: newest,
    revalidated: verdict.ok,
    reloaded,
    detail: verdict.ok
      ? `${restored.length} file(s) restored from ${path.basename(newest)} — squid -k parse ${reloaded ? "passed, squid reloaded" : "passed (unit state unchanged)"}`
      : `restored, but squid -k parse still fails: ${verdict.detail}`,
  });
}

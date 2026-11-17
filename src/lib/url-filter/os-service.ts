/**
 * URL-Filter OS service — db/exec glue for the PURE renderer in os.ts
 * (mirrors dns/os.ts + qos/os-service.ts layering):
 *
 *   • collectUrlFilterInputs   tenant policies + category rules + custom lists
 *   • readUrlFilterOsFacts     REAL host reads (squid binary, unit state, :3128,
 *                              live /etc/squid/squid.conf hash, version)
 *   • getUrlFilterOsStatus     GUI↔OS honesty view + per-policy drift hints
 *   • execUrlFilterApplyPlan   gated executor: stage → validate → install →
 *                              reload → verify, auto-rollback from backup-<ts>/
 *   • rollbackUrlFilterOs      manual rollback to the last recorded backup
 *
 * Server-only (fs/exec/db imports). The exec gate is CONSOLE_OS_APPLY=1 AND
 * data plane in host mode — otherwise every path returns a plan preview.
 */

import { mkdir, readFile, writeFile, chmod, rm, stat } from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { getDataPlaneMode } from "@/lib/engine";
import { hasTool, readServiceStates, runTool } from "@/lib/host/tools";
import { parseJson } from "@/lib/json";
import {
  SQUID_CONF,
  UF_STATE_DIR,
  UF_STATE_FILE,
  buildSquidApplyPlan,
  computeSquidDrift,
  renderSquidConf,
  sha256_16,
  squidStepGuarded,
  type UfApplyPlan,
  type UfCategoryRuleInput,
  type UfCustomListInput,
  type UfPlanStep,
  type UfPolicyInput,
  type UfRenderInput,
} from "./os";

// ── db collectors ───────────────────────────────────────────────────────────

/** Defensive parse of the fileTypesBlocked JSON column — bad payload → []. */
function parseFileTypes(json: string): string[] {
  const parsed = parseJson<string[]>(json, []);
  return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : [];
}

export interface UrlFilterInputs extends UfRenderInput {
  /** parseFileTypes already applied — renderer takes the string[] as-is */
  policies: UfPolicyInput[];
  categoryRules: UfCategoryRuleInput[];
  customLists: UfCustomListInput[];
}

export async function collectUrlFilterInputs(tenantId: number): Promise<UrlFilterInputs> {
  const [policyRows, ruleRows, listRows] = await Promise.all([
    db.urlFilterPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.urlCategoryRule.findMany({ where: { tenantId }, orderBy: [{ policyId: "asc" }, { id: "asc" }] }),
    db.urlCustomList.findMany({ where: { tenantId }, orderBy: [{ policyId: "asc" }, { value: "asc" }] }),
  ]);
  return {
    policies: policyRows.map((p) => ({
      id: p.id,
      name: p.name,
      defaultAction: p.defaultAction,
      safeSearchEnforce: p.safeSearchEnforce,
      fileTypesBlocked: parseFileTypes(p.fileTypesBlocked),
      httpsInspection: p.httpsInspection,
      transparentProxy: p.transparentProxy,
      enabled: p.enabled,
    })),
    categoryRules: ruleRows.map((r) => ({
      policyId: r.policyId,
      category: r.category,
      action: r.action,
      listSource: r.listSource,
      enabled: r.enabled,
    })),
    customLists: listRows.map((l) => ({
      policyId: l.policyId,
      listType: l.listType,
      matchType: l.matchType,
      value: l.value,
    })),
  };
}

// ── OS facts (real reads) ───────────────────────────────────────────────────

export interface UfOsFacts {
  available: boolean;
  squidTool: boolean;
  unitState: string | null;
  running: boolean;
  port3128Bound: boolean;
  managedFilePresent: boolean;
  liveHash: string | null;
  version: string | null;
}

function isRunning(state: string | undefined | null): boolean {
  return state === "running" || state === "active";
}

export async function readUrlFilterOsFacts(): Promise<UfOsFacts> {
  const [squidTool, svcStates] = await Promise.all([hasTool("squid"), readServiceStates(["squid"])]);
  const facts: UfOsFacts = {
    available: squidTool,
    squidTool,
    unitState: svcStates?.["squid"] ?? null,
    running: isRunning(svcStates?.["squid"]),
    port3128Bound: false,
    managedFilePresent: false,
    liveHash: null,
    version: null,
  };

  const [ssRes, verRes] = await Promise.all([
    runTool("ss -ltn '( sport = :3128 )' 2>/dev/null", 5000),
    squidTool ? runTool("squid -v 2>/dev/null", 6000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no tool" }),
  ]);
  facts.port3128Bound = ssRes.ok && /:3128\s/.test(ssRes.stdout);
  if (verRes.ok) {
    facts.version = /Version\s+(\S+)/i.exec(verRes.stdout)?.[1] ?? null;
  }

  try {
    const cur = await readFile(SQUID_CONF, "utf8");
    facts.managedFilePresent = true;
    facts.liveHash = sha256_16(cur);
  } catch {
    /* stock conf absent — squid not installed / not applied yet */
  }
  return facts;
}

// ── status (GUI ↔ OS honesty view) ──────────────────────────────────────────

export interface UrlOsPolicyStatus {
  id: number;
  name: string;
  enabled: boolean;
  renderHash: string | null;
  categoryRules: Array<{ category: string; action: string; listSource: string; enabled: boolean; configured: boolean }>;
  customListCounts: { block: number; allow: number };
  warnings: string[];
}

export interface UrlOsStatus {
  available: boolean;
  dataPlaneMode: string;
  gate: "on" | "off";
  note: string;
  unitState: string | null;
  managedFile: string;
  port3128Bound: boolean;
  version: string | null;
  /** null when squid is unavailable (honest "unknown" instead of fake sync) */
  inSync: boolean | null;
  driftReasons: string[];
  state: { confHash: string; appliedAt: string; backupDir: string | null; applied: boolean } | null;
  policies: UrlOsPolicyStatus[];
  warnings: string[];
}

interface UfStateFile {
  lastApply?: { at: string; action: string; applied: boolean; reason: string; backupDir: string | null; confHash: string | null };
}

export async function readUrlFilterState(): Promise<UfStateFile | null> {
  try {
    return parseJson<UfStateFile>(await readFile(UF_STATE_FILE, "utf8"), {});
  } catch {
    return null;
  }
}

export async function getUrlFilterOsStatus(tenantId: number): Promise<UrlOsStatus> {
  const [inputs, facts, stateFile] = await Promise.all([
    collectUrlFilterInputs(tenantId),
    readUrlFilterOsFacts(),
    readUrlFilterState(),
  ]);
  const render = renderSquidConf(inputs);
  const drift = computeSquidDrift(facts, render.confHash);
  const gate: "on" | "off" = process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off";
  const mode = getDataPlaneMode();

  const policies: UrlOsPolicyStatus[] = inputs.policies.map((p) => ({
    id: p.id,
    name: p.name,
    enabled: p.enabled,
    renderHash: p.enabled ? render.policyHashes[p.id] ?? null : null,
    categoryRules: (inputs.categoryRules.filter((r) => r.policyId === p.id)).map((r) => ({
      category: r.category,
      action: r.action,
      listSource: r.listSource,
      enabled: r.enabled,
      configured: true,
    })),
    customListCounts: {
      block: inputs.customLists.filter((l) => l.policyId === p.id && l.listType === "block").length,
      allow: inputs.customLists.filter((l) => l.policyId === p.id && l.listType === "allow").length,
    },
    warnings: render.warnings.filter((w) => w.includes(`'#${p.id} `)),
  }));

  return {
    available: facts.available,
    dataPlaneMode: mode,
    gate,
    note: !facts.available
      ? "squid not installed on this host — OS enforcement is preview-only"
      : gate === "off" || mode !== "host"
        ? "CONSOLE_OS_APPLY is off or the data plane is not in host mode — plan preview only"
        : "squid present — Apply renders the full /etc/squid/squid.conf, validates the stage, installs and reloads",
    unitState: facts.unitState,
    managedFile: SQUID_CONF,
    port3128Bound: facts.port3128Bound,
    version: facts.version,
    inSync: facts.available ? drift.inSync : null,
    driftReasons: drift.driftReasons,
    state: stateFile?.lastApply
      ? {
          confHash: stateFile.lastApply.confHash ?? "",
          appliedAt: stateFile.lastApply.at,
          backupDir: stateFile.lastApply.backupDir,
          applied: stateFile.lastApply.applied,
        }
      : null,
    policies,
    warnings: render.warnings,
  };
}

// ── apply / rollback outcomes ───────────────────────────────────────────────

export interface UfStepResult {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface UfApplyOutcome {
  action: "apply" | "rollback";
  applied: boolean;
  refused?: string;
  reason: string;
  gate: "on" | "off";
  rolledBack: boolean;
  confHash?: string;
  backupDir?: string | null;
  plan: {
    steps: Array<{ step: string; cmd: string; kind: string }>;
    rollbackSteps: Array<{ step: string; cmd: string; kind: string }>;
    warnings: string[];
    skipped: Array<{ name: string; reason: string }>;
    confText: string;
    guarded: boolean;
  };
  results: UfStepResult[];
}

async function writePlanFiles(plan: UfApplyPlan): Promise<UfStepResult[]> {
  const results: UfStepResult[] = [];
  await mkdir(UF_STATE_DIR, { recursive: true });
  await mkdir(plan.backupDir, { recursive: true });
  for (const f of plan.files) {
    try {
      await mkdir(path.dirname(f.path), { recursive: true });
      await writeFile(f.path, f.content, "utf8");
      await chmod(f.path, f.mode);
      results.push({ step: `stage ${path.basename(f.path)}`, ok: true, detail: `${f.content.length} bytes` });
    } catch (err) {
      results.push({ step: `stage ${path.basename(f.path)}`, ok: false, detail: err instanceof Error ? err.message : "write failed" });
    }
  }
  return results;
}

/** Restore the pre-apply conf from a backup dir via pinned fs paths (no exec). */
async function restoreConfFile(backupPath: string, livePath: string): Promise<boolean> {
  try {
    const prev = await readFile(backupPath, "utf8");
    await writeFile(livePath, prev, "utf8");
    await chmod(livePath, 0o644);
    return true;
  } catch {
    return false;
  }
}

async function persistState(patch: Record<string, unknown>): Promise<void> {
  try {
    await mkdir(UF_STATE_DIR, { recursive: true });
    let cur: Record<string, unknown> = {};
    try {
      cur = parseJson<Record<string, unknown>>(await readFile(UF_STATE_FILE, "utf8"), {});
    } catch {
      /* first write */
    }
    await writeFile(UF_STATE_FILE, JSON.stringify({ ...cur, ...patch }, null, 2), "utf8");
  } catch {
    /* best-effort */
  }
}

async function runSteps(steps: UfPlanStep[], results: UfStepResult[]): Promise<{ failed: boolean; detail: string }> {
  for (const s of steps) {
    if (!squidStepGuarded(s.cmd)) {
      const detail = `step '${s.step}' failed the squid command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail });
      return { failed: true, detail };
    }
    const r = await runTool(s.cmd, 30000);
    if (!r.ok) {
      const detail = `step '${s.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: s.step, ok: false, detail });
      return { failed: true, detail };
    }
    results.push({ step: s.step, ok: true, detail: r.stdout.trim().slice(0, 200) || undefined });
  }
  return { failed: false, detail: "" };
}

/** Automatic rollback path (backup restore → revalidate → restart). */
async function runRollbackSteps(plan: UfApplyPlan, results: UfStepResult[]): Promise<boolean> {
  const backupFile = `${plan.backupDir}/squid.conf`;
  let hadBackup = false;
  try {
    hadBackup = (await stat(backupFile)).size > 0;
  } catch {
    /* no backup (fresh install) */
  }
  if (!hadBackup) {
    results.push({ step: "restore backup", ok: true, detail: "no previous squid.conf to restore (fresh install)" });
    return true;
  }
  const restored = await restoreConfFile(backupFile, SQUID_CONF);
  results.push({ step: "restore backup", ok: restored, detail: restored ? backupFile : `restore from ${backupFile} failed` });
  if (!restored) return false;
  for (const s of plan.rollbackSteps.filter((x) => x.kind !== "restore")) {
    if (!squidStepGuarded(s.cmd)) {
      results.push({ step: s.step, ok: false, detail: "step failed the squid command whitelist" });
      return false;
    }
    const r = await runTool(s.cmd, 30000);
    results.push({ step: s.step, ok: r.ok, detail: r.ok ? (r.stdout.trim().slice(0, 160) || undefined) : (r.stderr || r.error || "exec error").slice(0, 200) });
    if (!r.ok) return false;
  }
  return true;
}

/**
 * Build + (gate-permitting) execute the squid convergence plan.
 * Zero-churn: when the live file hash already equals the rendered hash and the
 * unit is active, the backup/validate/install/reload steps are skipped and
 * only the verify steps run.
 */
export async function execUrlFilterApplyPlan(tenantId: number, gateOn: boolean): Promise<UfApplyOutcome> {
  const inputs = await collectUrlFilterInputs(tenantId);
  const facts = await readUrlFilterOsFacts();
  const mode: "exec" | "plan" = gateOn && getDataPlaneMode() === "host" ? "exec" : "plan";
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const render = renderSquidConf(inputs);
  const plan = buildSquidApplyPlan(inputs, facts, { mode, ts }, render);
  const planView = () => ({
    steps: plan.steps.map(({ step, cmd, kind }) => ({ step, cmd, kind })),
    rollbackSteps: plan.rollbackSteps.map(({ step, cmd, kind }) => ({ step, cmd, kind })),
    warnings: plan.warnings,
    skipped: plan.skipped,
    confText: plan.confText,
    guarded: plan.guarded,
  });

  const preview = (reason: string, refused?: string): UfApplyOutcome => ({
    action: "apply",
    applied: false,
    refused,
    reason,
    gate: gateOn ? "on" : "off",
    rolledBack: false,
    confHash: plan.confHash,
    backupDir: null,
    plan: planView(),
    results: [],
  });

  if (!facts.available) {
    return preview("'squid' binary not found on the host — cannot validate or install the managed conf", "squid not installed");
  }
  if (mode !== "exec") {
    return preview(
      gateOn
        ? "data plane is not in host mode — OS enforcement is preview-only"
        : "CONSOLE_OS_APPLY is off — plan preview only (squid.conf render + command sequence attached)",
    );
  }
  if (!plan.guarded) {
    return { ...preview("plan failed the command whitelist — refusing to execute", "whitelist refusal"), gate: "on" };
  }

  const results: UfStepResult[] = await writePlanFiles(plan);
  if (results.some((r) => !r.ok)) {
    await Promise.all(plan.files.map((f) => rm(f.path, { force: true }).catch(() => {})));
    return {
      action: "apply",
      applied: false,
      refused: "staging the managed files failed — nothing was installed",
      reason: "stage write failed",
      gate: "on",
      rolledBack: false,
      confHash: plan.confHash,
      backupDir: null,
      plan: planView(),
      results,
    };
  }

  // zero-churn: live conf identical and unit up → verify only (conf untouched)
  const zeroChurn = facts.managedFilePresent && facts.liveHash === plan.confHash && facts.running;
  const execSteps = zeroChurn ? plan.steps.filter((s) => s.kind === "verify" || s.kind === "cleanup") : plan.steps;

  const { failed, detail } = await runSteps(execSteps, results);
  let rolledBack = false;
  if (failed && !zeroChurn) {
    rolledBack = await runRollbackSteps(plan, results);
  }

  const okSteps = results.every((r) => r.ok);
  const applied = !failed && okSteps;
  const reason = zeroChurn && !failed
    ? "in sync — managed squid.conf unchanged (zero-churn verify)"
    : failed
      ? zeroChurn
        ? `verify failed after zero-churn check: ${detail} — conf untouched, no rollback needed`
        : `apply failed at: ${detail} — ${rolledBack ? "automatic rollback restored the previous conf" : "rollback NOT clean — inspect squid state"}`
      : `squid.conf applied (validate → install → ${plan.wasRunning ? "reconfigure" : "restart"} → verify), hash ${plan.confHash}`;

  await persistState({
    lastApply: { at: new Date().toISOString(), action: "apply", applied, reason, backupDir: plan.backupDir, confHash: plan.confHash },
    steps: execSteps.length,
    results,
  });

  // stage files are forensic records — kept alongside backup-<ts>/
  return {
    action: "apply",
    applied,
    reason,
    gate: "on",
    rolledBack: rolledBack,
    confHash: plan.confHash,
    backupDir: plan.backupDir,
    plan: planView(),
    results,
  };
}

/**
 * Manual rollback to the last recorded backup (POST {action:"rollback"}).
 * Restores backup-<ts>/squid.conf via fs, then revalidate + restart squid.
 */
export async function rollbackUrlFilterOs(tenantId: number, gateOn: boolean): Promise<UfApplyOutcome> {
  const state = await readUrlFilterState();
  const backupDir = state?.lastApply?.backupDir ?? null;
  const facts = await readUrlFilterOsFacts();
  const mode: "exec" | "plan" = gateOn && getDataPlaneMode() === "host" ? "exec" : "plan";
  const planView = (steps: UfPlanStep[]) => ({
    steps: steps.map(({ step, cmd, kind }) => ({ step, cmd, kind })),
    rollbackSteps: [],
    warnings: [] as string[],
    skipped: [] as Array<{ name: string; reason: string }>,
    confText: "",
    guarded: true,
  });

  if (!backupDir) {
    return {
      action: "rollback",
      applied: false,
      refused: "no recorded backup — nothing to roll back to (apply first)",
      reason: "rollback refused",
      gate: gateOn ? "on" : "off",
      rolledBack: false,
      plan: planView([]),
      results: [],
    };
  }

  const steps: UfPlanStep[] = [
    { step: "restore backup", cmd: `fs:restore ${backupDir}/squid.conf -> ${SQUID_CONF}`, kind: "restore" },
    { step: "revalidate restored conf", cmd: `squid -k parse -f ${SQUID_CONF}`, kind: "validate" },
    { step: "restart squid on restored conf", cmd: "systemctl restart squid", kind: "reload" },
    { step: "verify unit", cmd: "systemctl is-active squid", kind: "verify" },
  ];

  if (mode !== "exec") {
    return {
      action: "rollback",
      applied: false,
      reason: gateOn
        ? "data plane is not in host mode — rollback is preview-only"
        : "CONSOLE_OS_APPLY is off — rollback is preview-only",
      gate: gateOn ? "on" : "off",
      rolledBack: false,
      backupDir,
      plan: planView(steps),
      results: [],
    };
  }

  const results: UfStepResult[] = [];
  const backupFile = `${backupDir}/squid.conf`;
  const restored = await restoreConfFile(backupFile, SQUID_CONF);
  results.push({ step: "restore backup", ok: restored, detail: restored ? backupFile : `restore from ${backupFile} failed` });
  let failed = !restored;
  if (!failed) {
    const r = await runSteps(steps.filter((s) => s.kind !== "restore"), results);
    failed = r.failed;
  }

  const applied = !failed;
  const reason = applied
    ? `squid.conf restored from ${backupDir} (revalidate + restart)`
    : "rollback failed — inspect squid state manually";
  await persistState({
    lastApply: { at: new Date().toISOString(), action: "rollback", applied, reason, backupDir, confHash: null },
    results,
  });
  return {
    action: "rollback",
    applied,
    reason,
    gate: "on",
    rolledBack: false,
    backupDir,
    plan: planView(steps),
    results,
  };
}

/**
 * app-control/os-service — real nftables convergence for App Control.
 *
 * THE missing leg for M18: GUI app rules previously terminated at the DB
 * (simulated engine only); this module plans (os.ts generateAppctlRuleset),
 * verifies (`nft -c`), applies (`nft -f`) and ROLLS BACK (commit-confirm) the
 * dedicated `inet utm_appctl` table. Pure rendering/parsing lives in os.ts;
 * everything touching db/fs/exec is here. Server-only module.
 *
 * Safety architecture (mirror of firewall-os.ts):
 *   • gate          CONSOLE_OS_APPLY=1 AND data-plane host mode required
 *                   (off → plan preview only)
 *   • pre-check     `nft -c -f` syntax/commit check BEFORE any mutation
 *   • backup        full live ruleset dumped to <dir>/backup-<ts>.nft with a
 *                   `flush ruleset` prologue — a faithful restore point; the
 *                   apply is REFUSED when no backup can be captured
 *   • commit-confirm a detached rollback timer (nohup sh) restores the backup
 *                   after CONSOLE_NFT_CONFIRM_SEC unless the confirm flag file
 *                   appears; WAN health is probed before/after and a measured
 *                   regression auto-restores immediately
 *   • isolation     only `inet utm_appctl` is touched (atomic destroy +
 *                   recreate; no `flush ruleset` in generated files) —
 *                   console-firewall, fail2ban and foreign tables survive
 *   • persistence   /etc/console-nft/appctl.nft + an `include` line appended
 *                   to /etc/nftables.conf (backup first; failures are
 *                   warnings — runtime state stands)
 *   • whitelist     every exec'd command passes appctlStepGuarded; a failing
 *                   guard aborts the pipeline before the shell runs
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { hasTool, runTool, readNftRuleset } from "@/lib/host/tools";
import { probeWanHealth, pbrHealthRegressed, type PbrWanHealth } from "@/lib/network/pbr-os";
import {
  APPCTL_TABLE_NAME,
  appctlStepGuarded,
  appctlTableBlocksInSync,
  buildAppctlApplySteps,
  buildAppctlRollbackScript,
  composeBackupFile,
  generateAppctlRuleset,
  isRestoreFileContent,
  parseAppctlRuleCounters,
  type AppCtlPolicyShape,
  type AppCtlRuleShape,
  type AppctlCounter,
  type AppctlGenResult,
  type AppctlPlanStep,
} from "./os";

export const APPCTL_DIR = process.env.CONSOLE_APPCTL_DIR || "/var/lib/console/appctl";
export const APPCTL_STATE_FILE = path.join(APPCTL_DIR, "state.json");
export const APPCTL_ETC_DIR = "/etc/console-nft";
export const APPCTL_ETC_FILE = `${APPCTL_ETC_DIR}/appctl.nft`;
export const APPCTL_INCLUDE_LINE = `include "${APPCTL_ETC_FILE}"`;
export const APPCTL_ETC_CONF = "/etc/nftables.conf";
const CONFIRM_SEC = Math.max(15, Number(process.env.CONSOLE_NFT_CONFIRM_SEC || 60));

// ── DB → generator input ────────────────────────────────────────────────────

function parseUserGroupIds(json: string): number[] {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is number => typeof v === "number" && Number.isInteger(v));
  } catch {
    return [];
  }
}

type RuleAction = "allow" | "block" | "limit";
type Direction = "both" | "upload" | "download";
type PolicyAction = "allow" | "block";
type UnknownAppAction = "allow" | "block" | "log";

const asRuleAction = (v: string): RuleAction => (v === "allow" || v === "limit" ? v : "block");
const asDirection = (v: string): Direction => (v === "upload" || v === "download" ? v : "both");
const asPolicyAction = (v: string): PolicyAction => (v === "block" ? "block" : "allow");
const asUnknownAction = (v: string): UnknownAppAction => (v === "allow" || v === "block" ? v : "log");

/** All tenant policies + rules → deterministic shapes for the pure generator. */
export async function loadAppctlShapes(tenantId: number): Promise<AppCtlPolicyShape[]> {
  const [policies, rules] = await Promise.all([
    db.appControlPolicy.findMany({ where: { tenantId } }),
    db.appControlRule.findMany({ where: { tenantId } }),
  ]);

  const byPolicy = new Map<number, AppCtlRuleShape[]>();
  for (const r of [...rules].sort((a, b) => a.id - b.id)) {
    const list = byPolicy.get(r.policyId) ?? [];
    list.push({
      id: r.id,
      appName: r.appName,
      action: asRuleAction(r.action),
      bandwidthLimitMbps: r.bandwidthLimitMbps,
      direction: asDirection(r.direction),
      userGroupIds: parseUserGroupIds(r.userGroupIds),
      enabled: r.enabled,
    });
    byPolicy.set(r.policyId, list);
  }

  return [...policies]
    .sort((a, b) => a.id - b.id)
    .map((p) => ({
      id: p.id,
      name: p.name,
      defaultAction: asPolicyAction(p.defaultAction),
      unknownAppAction: asUnknownAction(p.unknownAppAction),
      enabled: p.enabled,
      rules: byPolicy.get(p.id) ?? [],
    }));
}

// ── OS facts ────────────────────────────────────────────────────────────────

export interface AppctlOsFacts {
  nftAvailable: boolean;
  nftVersion: string | null;
  /** utm_appctl table present in the live kernel ruleset */
  tablePresent: boolean;
  /** engine data-plane mode ("host" required for exec) */
  mode: string;
}

async function dataPlaneMode(): Promise<string> {
  const { getDataPlaneMode } = await import("@/lib/engine");
  return getDataPlaneMode();
}

export async function readAppctlOsFacts(liveRuleset?: string): Promise<AppctlOsFacts> {
  const nftOk = await hasTool("nft");
  const [versionRes, dump, mode] = await Promise.all([
    nftOk ? runTool("nft --version", 3000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no nft" }),
    liveRuleset !== undefined ? Promise.resolve(liveRuleset) : readNftRuleset().then((r) => r.ruleset),
    dataPlaneMode(),
  ]);
  return {
    nftAvailable: nftOk,
    nftVersion: versionRes.ok ? versionRes.stdout.trim() || null : null,
    tablePresent: new RegExp(`table inet ${APPCTL_TABLE_NAME}\\b`).test(dump),
    mode,
  };
}

// ── plan ────────────────────────────────────────────────────────────────────

export interface AppctlDrift {
  /** utm_appctl table exists in the live kernel */
  applied: boolean;
  /** live table matches the generated policy (normalized compare) */
  inSync: boolean;
  /** honest reasons when applied/inSync are false */
  reasons: string[];
}

export interface AppctlPlan {
  gen: AppctlGenResult;
  facts: AppctlOsFacts;
  drift: AppctlDrift;
  /** generated file — surfaced for the preview dialog */
  file: string;
}

function buildDriftReasons(facts: AppctlOsFacts, applied: boolean, inSync: boolean): string[] {
  const reasons: string[] = [];
  if (!facts.nftAvailable) reasons.push("nftables binary unavailable — kernel state unreadable");
  if (!applied) {
    reasons.push(`table inet ${APPCTL_TABLE_NAME} is not present in the live ruleset — apply once to install it`);
  } else if (!inSync) {
    reasons.push(
      "live utm_appctl table differs from the generated policy (normalized compare) — re-apply to converge",
    );
  }
  return reasons;
}

export async function buildAppctlPlan(tenantId: number): Promise<AppctlPlan> {
  const [shapes, live] = await Promise.all([loadAppctlShapes(tenantId), readNftRuleset()]);
  const facts = await readAppctlOsFacts(live.ruleset);
  const gen = generateAppctlRuleset({ policies: shapes });
  const applied = facts.tablePresent;
  const inSync = applied ? appctlTableBlocksInSync(gen.file, live.ruleset) : false;
  return {
    gen,
    facts,
    drift: { applied, inSync, reasons: buildDriftReasons(facts, applied, inSync) },
    file: gen.file,
  };
}

// ── apply state (commit-confirm window) ─────────────────────────────────────

interface ApplyState {
  ts: string;
  armedAt: string;
  deadlineAt: string;
  mode: "manual" | "auto";
  backupFile: string;
  confirmFile: string;
}

async function writeState(state: ApplyState | null): Promise<void> {
  await fs.mkdir(APPCTL_DIR, { recursive: true });
  await fs.writeFile(APPCTL_STATE_FILE, JSON.stringify(state, null, 2), "utf8");
}

export async function readApplyState(): Promise<ApplyState | null> {
  try {
    const raw = await fs.readFile(APPCTL_STATE_FILE, "utf8");
    const s = JSON.parse(raw) as ApplyState;
    const confirmed = await fs
      .access(s.confirmFile)
      .then(() => true)
      .catch(() => false);
    if (confirmed) return null; // commit confirmed → no pending window
    return s;
  } catch {
    return null;
  }
}

function assertOwnPath(p: string, prefix: RegExp): string {
  const resolved = path.resolve(p);
  if (!resolved.startsWith(path.resolve(APPCTL_DIR)) || resolved.includes("..")) {
    throw new Error(`refusing path outside the console appctl directory: ${p}`);
  }
  if (!prefix.test(path.basename(resolved))) {
    throw new Error(`refusing unexpected file name: ${p}`);
  }
  return resolved;
}

/** Remove superseded/stale artefacts: armed scripts >60min, files >24h, backups >7d. */
async function housekeepArtefacts(): Promise<void> {
  const now = Date.now();
  const files = await fs.readdir(APPCTL_DIR).catch(() => [] as string[]);
  for (const f of files) {
    const full = path.join(APPCTL_DIR, f);
    try {
      const st = await fs.stat(full);
      const ageMin = (now - st.mtimeMs) / 60_000;
      const stale =
        (/^rollback-[\w.-]+\.sh$/.test(f) && ageMin > 60) ||
        (/^(appctl|confirm)-[\w.-]+(\.nft)?$/.test(f) && ageMin > 24 * 60) ||
        (/^backup-[\w.-]+\.nft$/.test(f) && ageMin > 7 * 24 * 60);
      if (stale) await fs.unlink(full).catch(() => {});
    } catch {
      // vanished already
    }
  }
}

/** Guarded exec — runs the command ONLY when it passes the module whitelist. */
async function guardedRun(cmd: string, timeoutMs: number): Promise<{ ok: boolean; stderr?: string }> {
  if (!appctlStepGuarded(cmd)) {
    return { ok: false, stderr: `command rejected by the appctl whitelist: ${cmd.slice(0, 120)}` };
  }
  const r = await runTool(cmd, timeoutMs);
  return r.ok ? { ok: true } : { ok: false, stderr: r.stderr || r.error || "exec failed" };
}

// ── apply pipeline ──────────────────────────────────────────────────────────

export interface AppctlApplyResults {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface AppctlApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  rolledBack: boolean;
  rollbackReason: string | null;
  confirmSec: number;
  confirmDeadlineAt: string | null;
  ts: string;
  warnings: AppctlGenResult["warnings"];
  counts: AppctlGenResult["counts"] | null;
  /** the generated nft file — surfaced even for gate-off preview */
  file: string;
  plan: { steps: AppctlPlanStep[] };
  health: {
    baseline: PbrWanHealth | null;
    after: PbrWanHealth | null;
    postRollback: PbrWanHealth | null;
  };
  results: AppctlApplyResults[];
  persistence: AppctlApplyResults[];
}

export interface AppctlApplyOptions {
  mode?: "manual" | "auto";
  confirmSec?: number;
}

/**
 * Full apply pipeline. Never throws — every failure surfaces as an honest
 * outcome so the API layer can report it.
 */
export async function applyAppctlToOs(tenantId: number, opts: AppctlApplyOptions = {}): Promise<AppctlApplyOutcome> {
  const mode = opts.mode ?? "manual";
  const confirmSec = Math.max(15, Number(opts.confirmSec ?? CONFIRM_SEC));
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const results: AppctlApplyResults[] = [];
  const persistence: AppctlApplyResults[] = [];
  const gateOn = process.env.CONSOLE_OS_APPLY === "1";

  const plan = await buildAppctlPlan(tenantId);
  const steps = buildAppctlApplySteps({
    file: path.join(APPCTL_DIR, `appctl-${ts}.nft`),
    backupFile: path.join(APPCTL_DIR, `backup-${ts}.nft`),
    rollbackScript: path.join(APPCTL_DIR, `rollback-${ts}.sh`),
  });
  const outcome: AppctlApplyOutcome = {
    gate: gateOn ? "on" : "off",
    applied: false,
    rolledBack: false,
    rollbackReason: null,
    confirmSec,
    confirmDeadlineAt: null,
    ts,
    warnings: plan.gen.warnings,
    counts: plan.gen.counts,
    file: plan.file,
    plan: { steps },
    health: { baseline: null, after: null, postRollback: null },
    results,
    persistence,
  };

  if (!gateOn) {
    results.push({ step: "gate", ok: false, detail: "OS convergence disabled by platform policy — plan is a preview only" });
    return outcome;
  }
  if ((await dataPlaneMode()) !== "host") {
    results.push({ step: "mode", ok: false, detail: "data plane is not in host mode — OS enforcement is preview-only" });
    return outcome;
  }
  if (!(await hasTool("nft"))) {
    results.push({ step: "tool", ok: false, detail: "nft binary not found on host" });
    return outcome;
  }

  // 1. write + syntax/commit pre-check — never touch the kernel on a broken plan
  const file = path.join(APPCTL_DIR, `appctl-${ts}.nft`);
  await fs.mkdir(APPCTL_DIR, { recursive: true });
  void housekeepArtefacts();
  await fs.writeFile(file, plan.file, "utf8");
  const check = await guardedRun(`nft -c -f ${JSON.stringify(file)}`, 10000);
  results.push({ step: "nft -c check", ok: check.ok, detail: check.ok ? undefined : check.stderr });
  if (!check.ok) {
    await writeState(null);
    return outcome;
  }

  // 2. backup — full live ruleset + flush prologue = faithful restore point
  const live = await readNftRuleset();
  if (!live.available) {
    results.push({ step: "backup", ok: false, detail: "cannot read the live ruleset — refusing to apply without a restore point" });
    return outcome;
  }
  const backupFile = path.join(APPCTL_DIR, `backup-${ts}.nft`);
  const backupContent = composeBackupFile(live.ruleset);
  if (!isRestoreFileContent(backupContent)) {
    results.push({ step: "backup", ok: false, detail: "backup composed without the flush prologue — refusing (would merge instead of restore)" });
    return outcome;
  }
  await fs.writeFile(backupFile, backupContent, "utf8");
  results.push({ step: "backup", ok: true, detail: backupFile });

  // 3. arm the detached rollback timer (survives console restarts)
  const confirmFile = path.join(APPCTL_DIR, `confirm-${ts}`);
  const rollbackScript = path.join(APPCTL_DIR, `rollback-${ts}.sh`);
  await fs.writeFile(
    rollbackScript,
    buildAppctlRollbackScript({ ts, confirmSec, confirmFile, backupFile, scriptFile: rollbackScript, stateFile: APPCTL_STATE_FILE }),
    "utf8",
  );
  const arm = await guardedRun(`nohup /bin/sh ${JSON.stringify(rollbackScript)} >/dev/null 2>&1 &`, 4000);
  results.push({ step: "rollback timer", ok: arm.ok, detail: arm.ok ? `auto-restore in ${confirmSec}s unless confirmed` : arm.stderr });

  const deadlineAt = new Date(Date.now() + confirmSec * 1000).toISOString();
  // a new apply SUPERSEDES any still-pending window: confirm the previous
  // timer so it cannot fire mid-flight and revert the newer policy
  const prior = await readApplyState();
  if (prior) await fs.writeFile(prior.confirmFile, "superseded", "utf8").catch(() => {});
  await writeState({ ts, armedAt: new Date().toISOString(), deadlineAt, mode, backupFile, confirmFile });
  outcome.confirmDeadlineAt = deadlineAt;

  // 4. WAN health baseline (the 2026-11-14 outage class guard)
  const baseline = await probeWanHealth();
  outcome.health.baseline = baseline;

  // 5. apply — atomic destroy+recreate of the utm_appctl table only
  const applyRes = await guardedRun(`nft -f ${JSON.stringify(file)}`, 10000);
  results.push({ step: "apply", ok: applyRes.ok, detail: applyRes.ok ? undefined : applyRes.stderr });
  if (!applyRes.ok) {
    // failed mid-file? `nft -f` is transactional, but restore defensively
    await guardedRun(`nft -f ${JSON.stringify(backupFile)}`, 10000);
    outcome.rolledBack = true;
    outcome.rollbackReason = "apply failed — backup restored";
    await writeState(null);
    return outcome;
  }
  outcome.applied = true;

  // 6. post-apply health — immediate auto-restore on measured regression
  const after = await probeWanHealth();
  outcome.health.after = after;
  if (pbrHealthRegressed(baseline, after)) {
    const restore = await guardedRun(`nft -f ${JSON.stringify(backupFile)}`, 10000);
    const post = await probeWanHealth();
    outcome.rolledBack = true;
    outcome.rollbackReason = `WAN health regressed after apply (gateway ${after.gatewayOk === false ? "unreachable" : "?"} / public probe ${after.internetOk === false ? "unreachable" : "?"}) — backup restored automatically`;
    outcome.health.postRollback = post;
    results.push({ step: "auto-rollback", ok: restore.ok, detail: restore.ok ? "backup restored" : restore.stderr });
    await writeState(null);
    return outcome;
  }

  // 7. persistence (best-effort — failures are warnings, runtime state stands)
  try {
    await fs.mkdir(APPCTL_ETC_DIR, { recursive: true });
    await fs.writeFile(APPCTL_ETC_FILE, plan.file, "utf8");
    persistence.push({ step: `write ${APPCTL_ETC_FILE}`, ok: true });
    const conf = await fs.readFile(APPCTL_ETC_CONF, "utf8").catch(() => null);
    if (conf !== null && !conf.includes(APPCTL_INCLUDE_LINE)) {
      await fs.writeFile(`${APPCTL_ETC_CONF}.console-backup-${ts}`, conf, "utf8");
      await fs.writeFile(
        APPCTL_ETC_CONF,
        `${conf.replace(/\s*$/, "")}\n\n# console-managed app-control policy (GUI: App Control → Apply to Host)\n${APPCTL_INCLUDE_LINE}\n`,
        "utf8",
      );
      persistence.push({ step: `include added to ${APPCTL_ETC_CONF} (backup saved)`, ok: true });
    } else if (conf === null) {
      persistence.push({ step: `${APPCTL_ETC_CONF} absent — persistence skipped`, ok: false });
    } else {
      persistence.push({ step: `${APPCTL_ETC_CONF} include already present`, ok: true });
    }
    const en = await guardedRun("systemctl enable nftables >/dev/null 2>&1", 10000);
    persistence.push({ step: "systemctl enable nftables", ok: en.ok, detail: en.ok ? undefined : en.stderr });
  } catch (err) {
    persistence.push({ step: "persistence", ok: false, detail: err instanceof Error ? err.message : "unknown" });
  }

  // 8. auto mode self-confirms on healthy apply; manual mode leaves the
  //    commit-confirm window open for the operator
  if (mode === "auto") {
    await fs.writeFile(confirmFile, new Date().toISOString(), "utf8").catch(() => {});
    await writeState(null);
    await fs.rm(rollbackScript, { force: true }).catch(() => {});
    outcome.confirmDeadlineAt = null;
    persistence.push({ step: "auto-confirm", ok: true, detail: "auto mode — commit confirmed immediately (health verified)" });
  }
  return outcome;
}

// ── confirm / rollback / counters ───────────────────────────────────────────

export async function confirmAppctlApply(ts: string): Promise<{ confirmed: boolean; ts: string }> {
  const state = await readApplyState();
  const target = state?.ts === ts ? state : null;
  if (!target) return { confirmed: false, ts };
  await fs.writeFile(target.confirmFile, new Date().toISOString(), "utf8");
  await writeState(null);
  await fs.rm(path.join(APPCTL_DIR, `rollback-${ts}.sh`), { force: true }).catch(() => {});
  return { confirmed: true, ts };
}

export async function rollbackAppctl(ts?: string): Promise<{ rolledBack: boolean; file: string | null; health: PbrWanHealth | null; detail: string }> {
  const state = await readApplyState();
  let backupFile: string | null = state?.backupFile ?? null;
  if (!backupFile && ts) {
    backupFile = assertOwnPath(path.join(APPCTL_DIR, `backup-${ts}.nft`), /^backup-[\w.-]+\.nft$/);
  }
  if (!backupFile) {
    // fall back to the newest backup file on disk
    const files = (await fs.readdir(APPCTL_DIR).catch(() => [] as string[]))
      .filter((f) => /^backup-[\w.-]+\.nft$/.test(f))
      .sort();
    backupFile = files.length > 0 ? path.join(APPCTL_DIR, files[files.length - 1]) : null;
  }
  if (!backupFile) return { rolledBack: false, file: null, health: null, detail: "no backup available" };
  const res = await guardedRun(`nft -f ${JSON.stringify(backupFile)}`, 10000);
  if (state) {
    await fs.writeFile(state.confirmFile, "rollback", "utf8").catch(() => {});
    await writeState(null);
    await fs.rm(path.join(APPCTL_DIR, `rollback-${state.ts}.sh`), { force: true }).catch(() => {});
  }
  const health = await probeWanHealth();
  return {
    rolledBack: res.ok,
    file: backupFile,
    health,
    detail: res.ok ? "backup restored" : res.stderr || "restore failed",
  };
}

/** Live dump of only the appctl table (for status UI/counters). */
export async function readAppctlTableDump(): Promise<string | null> {
  const cmd = `nft list table inet ${APPCTL_TABLE_NAME} 2>/dev/null`;
  if (!appctlStepGuarded(cmd)) return null;
  const res = await runTool(cmd, 6000);
  return res.ok && res.stdout.trim() ? res.stdout : null;
}

/** Optional: push kernel counters into AppControlRule.hitCount (real hits). */
export async function syncAppctlHitsFromKernel(tenantId: number): Promise<{ updated: number }> {
  const dump = (await readNftRuleset()).ruleset;
  if (!new RegExp(`table inet ${APPCTL_TABLE_NAME}\\b`).test(dump)) return { updated: 0 };
  const counters: AppctlCounter[] = parseAppctlRuleCounters(dump);
  let updated = 0;
  for (const c of counters) {
    const row = await db.appControlRule.findFirst({ where: { id: c.ruleId, tenantId } }).catch(() => null);
    if (!row) continue;
    await db.appControlRule.update({ where: { id: c.ruleId }, data: { hitCount: c.packets } }).catch(() => null);
    updated += 1;
  }
  return { updated };
}

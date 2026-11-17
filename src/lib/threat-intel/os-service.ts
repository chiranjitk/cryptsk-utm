/**
 * threat-intel/os-service — REAL nftables convergence for Threat Intel
 * auto-block (spec §2.11 "Auto-block malicious IPs (feed → firewall)").
 *
 * GUI auto-block rules previously terminated at the DB (simulated hit
 * stats only); this module plans (os.ts generateTiBlockRuleset), verifies
 * (`nft -c`), applies (`nft -f`) and ROLLS BACK (commit-confirm) the
 * dedicated `inet utm_ti_block` table. Pure rendering/parsing lives in
 * os.ts; everything touching db/fs/exec is here. Server-only module.
 *
 * Safety architecture (mirror of app-control/os-service.ts):
 *   • gate          CONSOLE_OS_APPLY=1 AND data-plane host mode required
 *                   (off → plan preview only; sandbox degrades to
 *                   available:false without touching anything)
 *   • pre-check     `nft -c -f` syntax/commit check BEFORE any mutation
 *   • backup        snapshot-first: full live ruleset dumped to
 *                   <dir>/backup-<ts>/ruleset.nft with a `flush ruleset`
 *                   prologue — a faithful restore point; the apply is
 *                   REFUSED when no backup can be captured
 *   • commit-confirm a detached rollback timer (nohup sh) restores the
 *                   backup after CONSOLE_NFT_CONFIRM_SEC unless the confirm
 *                   flag file appears; WAN health is probed before/after and
 *                   a measured regression auto-restores immediately
 *   • isolation     only `inet utm_ti_block` is touched (atomic destroy +
 *                   recreate; no `flush ruleset` in generated files) —
 *                   console-firewall, utm_appctl, fail2ban and foreign
 *                   tables survive every apply
 *   • whitelist     every exec'd command passes tiStepGuarded; a failing
 *                   guard aborts the pipeline before the shell runs
 *   • state         state.json carries confHash + appliedAt of the LAST
 *                   successful apply (drift compare) plus the current
 *                   commit-confirm window (pending = confirm file absent)
 *   • hit sync      parseTiElements reads per-element counters back into
 *                   AutoBlockRule.hitCount; the chain drop counters are the
 *                   aggregate reference (returned alongside)
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { hasTool, runTool, readNftRuleset } from "@/lib/host/tools";
import { probeWanHealth, pbrHealthRegressed, type PbrWanHealth } from "@/lib/network/pbr-os";
import {
  TI_DIR_NAME_BACKUP_RE,
  TI_TABLE_NAME,
  composeBackupFile,
  buildTiApplySteps,
  buildTiRollbackScript,
  generateTiBlockRuleset,
  isRestoreFileContent,
  parseTiDropCounters,
  parseTiElements,
  tiStepGuarded,
  tiTableBlocksInSync,
  type TiBlockRuleShape,
  type TiDropCounters,
  type TiElement,
  type TiGenResult,
  type TiPlanStep,
} from "./os";

// re-exported for the API layer/tests — the pure renderer lives in ./os
export { generateTiBlockRuleset };

export const TI_DIR = process.env.CONSOLE_TI_DIR || "/var/lib/console/threat-intel";
export const TI_STATE_FILE = path.join(TI_DIR, "state.json");
const CONFIRM_SEC = Math.max(15, Number(process.env.CONSOLE_NFT_CONFIRM_SEC || 60));

// ── DB → generator input ────────────────────────────────────────────────────

/** All tenant auto-block rules → deterministic shapes for the pure generator. */
export async function loadTiBlockShapes(tenantId: number): Promise<TiBlockRuleShape[]> {
  const rows = await db.autoBlockRule.findMany({ where: { tenantId } });
  return rows
    .sort((a, b) => a.id - b.id)
    .map((r) => ({
      id: r.id,
      name: r.name,
      matchType: r.matchType,
      matchValue: r.matchValue,
      action: r.action,
      direction: r.direction,
      enabled: r.enabled,
    }));
}

// ── OS facts ────────────────────────────────────────────────────────────────

export interface TiOsFacts {
  nftAvailable: boolean;
  nftVersion: string | null;
  /** utm_ti_block table present in the live kernel ruleset */
  tablePresent: boolean;
  /** engine data-plane mode ("host" required for exec) */
  mode: string;
}

async function dataPlaneMode(): Promise<string> {
  const { getDataPlaneMode } = await import("@/lib/engine");
  return getDataPlaneMode();
}

export async function readTiOsFacts(liveRuleset?: string): Promise<TiOsFacts> {
  const nftOk = await hasTool("nft");
  const [versionRes, dump, mode] = await Promise.all([
    nftOk ? runTool("nft --version", 3000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no nft" }),
    liveRuleset !== undefined ? Promise.resolve(liveRuleset) : readNftRuleset().then((r) => r.ruleset),
    dataPlaneMode(),
  ]);
  return {
    nftAvailable: nftOk,
    nftVersion: versionRes.ok ? versionRes.stdout.trim() || null : null,
    tablePresent: new RegExp(`table inet ${TI_TABLE_NAME}\\b`).test(dump),
    mode,
  };
}

// ── plan ────────────────────────────────────────────────────────────────────

export interface TiDrift {
  /** utm_ti_block table exists in the live kernel */
  applied: boolean;
  /** live table skeleton matches the generated policy (normalized compare) */
  inSync: boolean;
  /** honest reasons when applied/inSync are false */
  reasons: string[];
}

/** Per-rule kernel presence: is this rule's element live in ti_block_v4? */
export interface TiRulePresence {
  ruleId: number;
  name: string;
  matchValue: string;
  enabled: boolean;
  /** enabled action=block rules with a renderable value become expected */
  expected: boolean;
  /** element with comment ti:<ruleId> present in the live set */
  present: boolean;
}

export interface TiPlan {
  gen: TiGenResult;
  facts: TiOsFacts;
  drift: TiDrift;
  /** per-rule element presence in the live blocklist */
  perRule: TiRulePresence[];
  /** live chain drop counters (null when the table is absent) */
  dropCounters: TiDropCounters | null;
  /** live per-rule element counters (when the kernel attached them) */
  elementCounters: TiElement[];
  /** last-apply state.json snapshot (confHash + appliedAt) */
  state: TiStateFile | null;
  /** generated file — surfaced for the preview dialog */
  file: string;
}

function buildDriftReasons(facts: TiOsFacts, applied: boolean, inSync: boolean, hashDrift: boolean): string[] {
  const reasons: string[] = [];
  if (!facts.nftAvailable) reasons.push("nftables binary unavailable — kernel state unreadable");
  if (!applied) {
    reasons.push(`table inet ${TI_TABLE_NAME} is not present in the live ruleset — apply once to install it`);
  } else if (!inSync) {
    reasons.push(
      "live utm_ti_block table differs from the generated policy (normalized skeleton compare) — re-apply to converge",
    );
  } else if (hashDrift) {
    reasons.push("console auto-block policy changed since the last apply (state.json confHash mismatch) — re-apply to converge");
  }
  return reasons;
}

export async function buildTiPlan(tenantId: number): Promise<TiPlan> {
  const [shapes, live] = await Promise.all([loadTiBlockShapes(tenantId), readNftRuleset()]);
  const facts = await readTiOsFacts(live.ruleset);
  const gen = generateTiBlockRuleset({ rules: shapes });
  const applied = facts.tablePresent;
  const skeletonInSync = applied ? tiTableBlocksInSync(gen.file, live.ruleset) : false;

  const state = await readTiState();
  const hashDrift = Boolean(state.state?.confHash && state.state.confHash !== gen.confHash);
  const inSync = skeletonInSync && !hashDrift;

  // rules the kernel SHOULD carry = the rendered element comments
  const expectedIds = new Set(parseTiElements(gen.file).map((e) => e.ruleId));
  const liveElements = parseTiElements(live.ruleset);
  const liveRuleIds = new Set(liveElements.map((e) => e.ruleId));
  const perRule: TiRulePresence[] = shapes.map((r) => ({
    ruleId: r.id,
    name: r.name,
    matchValue: r.matchValue,
    enabled: r.enabled,
    expected: r.enabled && expectedIds.has(r.id),
    present: liveRuleIds.has(r.id),
  }));

  const dropCounters = applied ? parseTiDropCounters(live.ruleset) : null;
  return {
    gen,
    facts,
    drift: { applied, inSync, reasons: buildDriftReasons(facts, applied, skeletonInSync && !hashDrift, hashDrift) },
    perRule,
    dropCounters,
    elementCounters: liveElements,
    state: state.state,
    file: gen.file,
  };
}

// ── apply state (confHash + appliedAt + commit-confirm window) ──────────────

export interface TiStateFile {
  /** sha256 of the LAST successfully applied fragment (null until applied) */
  confHash: string | null;
  /** ISO timestamp of the LAST successful apply (null until applied) */
  appliedAt: string | null;
  ts: string;
  mode: "manual" | "auto";
  armedAt: string;
  deadlineAt: string;
  /** <dir>/backup-<ts>/ruleset.nft — the faithful restore point */
  backupFile: string;
  confirmFile: string;
}

export interface TiPendingWindow {
  ts: string;
  deadlineAt: string;
  mode: string;
  backupFile: string;
}

export interface TiStateSnapshot {
  state: TiStateFile | null;
  /** non-null while a commit-confirm window is open (confirm file absent) */
  pending: TiPendingWindow | null;
}

async function writeState(state: TiStateFile | null): Promise<void> {
  await fs.mkdir(TI_DIR, { recursive: true });
  await fs.writeFile(TI_STATE_FILE, JSON.stringify(state, null, 2), "utf8");
}

export async function readTiState(): Promise<TiStateSnapshot> {
  try {
    const raw = await fs.readFile(TI_STATE_FILE, "utf8");
    const s = JSON.parse(raw) as TiStateFile;
    if (!s || typeof s !== "object") return { state: null, pending: null };
    const confirmed = await fs
      .access(s.confirmFile)
      .then(() => true)
      .catch(() => false);
    // confHash persists for drift compare even after the window closes
    return { state: s, pending: confirmed ? null : { ts: s.ts, deadlineAt: s.deadlineAt, mode: s.mode, backupFile: s.backupFile } };
  } catch {
    return { state: null, pending: null };
  }
}

function assertOwnPath(p: string, prefix: RegExp): string {
  // raw traversal check FIRST — path.resolve would silently collapse `..`
  // and turn an escape attempt into an innocent-looking in-dir path
  if (p.includes("..")) {
    throw new Error(`refusing path outside the console threat-intel directory: ${p}`);
  }
  const resolved = path.resolve(p);
  if (!resolved.startsWith(path.resolve(TI_DIR)) || resolved.includes("..")) {
    throw new Error(`refusing path outside the console threat-intel directory: ${p}`);
  }
  if (!prefix.test(path.basename(resolved))) {
    throw new Error(`refusing unexpected file name: ${p}`);
  }
  return resolved;
}

/** Remove superseded/stale artefacts: armed scripts >60min, files >24h, backups >7d. */
async function housekeepArtefacts(): Promise<void> {
  const now = Date.now();
  const entries = await fs.readdir(TI_DIR, { withFileTypes: true }).catch(() => [] as Array<{ name: string; isDirectory: () => boolean }>);
  for (const e of entries) {
    const full = path.join(TI_DIR, e.name);
    try {
      const st = await fs.stat(full);
      const ageMin = (now - st.mtimeMs) / 60_000;
      const stale =
        (/^rollback-[\w.-]+\.sh$/.test(e.name) && ageMin > 60) ||
        (/^(ti-block|confirm)-[\w.-]+$/.test(e.name) && ageMin > 24 * 60) ||
        (TI_DIR_NAME_BACKUP_RE.test(e.name) && e.isDirectory() && ageMin > 7 * 24 * 60);
      if (stale) await fs.rm(full, { recursive: true, force: true }).catch(() => {});
    } catch {
      // vanished already
    }
  }
}

/** Guarded exec — runs the command ONLY when it passes the module whitelist. */
async function guardedRun(cmd: string, timeoutMs: number): Promise<{ ok: boolean; stderr?: string }> {
  if (!tiStepGuarded(cmd)) {
    return { ok: false, stderr: `command rejected by the threat-intel whitelist: ${cmd.slice(0, 120)}` };
  }
  const r = await runTool(cmd, timeoutMs);
  return r.ok ? { ok: true } : { ok: false, stderr: r.stderr || r.error || "exec failed" };
}

// ── apply pipeline ──────────────────────────────────────────────────────────

export interface TiApplyResults {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface TiApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  rolledBack: boolean;
  rollbackReason: string | null;
  confirmSec: number;
  confirmDeadlineAt: string | null;
  ts: string;
  warnings: TiGenResult["warnings"];
  counts: TiGenResult["counts"] | null;
  confHash: string;
  /** the generated nft file — surfaced even for gate-off preview */
  file: string;
  plan: { steps: TiPlanStep[] };
  health: {
    baseline: PbrWanHealth | null;
    after: PbrWanHealth | null;
    postRollback: PbrWanHealth | null;
  };
  results: TiApplyResults[];
  persistence: TiApplyResults[];
}

export interface TiApplyOptions {
  mode?: "manual" | "auto";
  confirmSec?: number;
}

/**
 * Full apply pipeline. Never throws — every failure surfaces as an honest
 * outcome so the API layer can report it.
 */
export async function applyTiToOs(tenantId: number, opts: TiApplyOptions = {}): Promise<TiApplyOutcome> {
  const mode = opts.mode ?? "manual";
  const confirmSec = Math.max(15, Number(opts.confirmSec ?? CONFIRM_SEC));
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const results: TiApplyResults[] = [];
  const persistence: TiApplyResults[] = [];
  const gateOn = process.env.CONSOLE_OS_APPLY === "1";

  const plan = await buildTiPlan(tenantId);
  const file = path.join(TI_DIR, `ti-block-${ts}.nft`);
  const backupDir = path.join(TI_DIR, `backup-${ts}`);
  const backupFile = path.join(backupDir, "ruleset.nft");
  const rollbackScript = path.join(TI_DIR, `rollback-${ts}.sh`);
  const steps = buildTiApplySteps({ file, backupFile, rollbackScript });
  const outcome: TiApplyOutcome = {
    gate: gateOn ? "on" : "off",
    applied: false,
    rolledBack: false,
    rollbackReason: null,
    confirmSec,
    confirmDeadlineAt: null,
    ts,
    warnings: plan.gen.warnings,
    counts: plan.gen.counts,
    confHash: plan.gen.confHash,
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
  await fs.mkdir(TI_DIR, { recursive: true });
  void housekeepArtefacts();
  await fs.writeFile(file, plan.file, "utf8");
  const check = await guardedRun(`nft -c -f ${JSON.stringify(file)}`, 10000);
  results.push({ step: "nft -c check", ok: check.ok, detail: check.ok ? undefined : check.stderr });
  if (!check.ok) {
    return outcome;
  }

  // 2. snapshot-first backup — full live ruleset + flush prologue = faithful restore point
  const live = await readNftRuleset();
  if (!live.available) {
    results.push({ step: "backup", ok: false, detail: "cannot read the live ruleset — refusing to apply without a restore point" });
    return outcome;
  }
  const backupContent = composeBackupFile(live.ruleset);
  if (!isRestoreFileContent(backupContent)) {
    results.push({ step: "backup", ok: false, detail: "backup composed without the flush prologue — refusing (would merge instead of restore)" });
    return outcome;
  }
  await fs.mkdir(backupDir, { recursive: true });
  await fs.writeFile(backupFile, backupContent, "utf8");
  results.push({ step: "backup", ok: true, detail: backupFile });

  // 3. arm the detached rollback timer (survives console restarts)
  const confirmFile = path.join(TI_DIR, `confirm-${ts}`);
  await fs.writeFile(
    rollbackScript,
    buildTiRollbackScript({ ts, confirmSec, confirmFile, backupFile, scriptFile: rollbackScript, stateFile: TI_STATE_FILE }),
    "utf8",
  );
  const arm = await guardedRun(`nohup /bin/sh ${JSON.stringify(rollbackScript)} >/dev/null 2>&1 &`, 4000);
  results.push({ step: "rollback timer", ok: arm.ok, detail: arm.ok ? `auto-restore in ${confirmSec}s unless confirmed` : arm.stderr });

  const deadlineAt = new Date(Date.now() + confirmSec * 1000).toISOString();
  const armedAt = new Date().toISOString();
  // a new apply SUPERSEDES any still-pending window: confirm the previous
  // timer so it cannot fire mid-flight and revert the newer policy
  const prior = await readTiState();
  if (prior.pending && prior.state) await fs.writeFile(prior.state.confirmFile, "superseded", "utf8").catch(() => {});
  await writeState({
    confHash: plan.gen.confHash,
    appliedAt: null,
    ts,
    mode,
    armedAt,
    deadlineAt,
    backupFile,
    confirmFile,
  });
  outcome.confirmDeadlineAt = deadlineAt;

  // 4. WAN health baseline (the 2026-11-14 outage class guard)
  const baseline = await probeWanHealth();
  outcome.health.baseline = baseline;

  // 5. apply — atomic destroy+recreate of the utm_ti_block table only
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

  // 7. persistence — nftables unit enablement (best-effort warning only;
  //    the runtime table stands regardless)
  const en = await guardedRun("systemctl enable nftables >/dev/null 2>&1", 10000);
  persistence.push({ step: "systemctl enable nftables", ok: en.ok, detail: en.ok ? undefined : en.stderr });

  // 8. state.json — confHash + appliedAt of the now-live fragment
  await writeState({
    confHash: plan.gen.confHash,
    appliedAt: new Date().toISOString(),
    ts,
    mode,
    armedAt,
    deadlineAt: outcome.confirmDeadlineAt ?? new Date().toISOString(),
    backupFile,
    confirmFile,
  });

  // 9. auto mode self-confirms on healthy apply; manual mode leaves the
  //    commit-confirm window open for the operator (state.json KEEPS the
  //    confHash/appliedAt — the pending window is confirm-file derived)
  if (mode === "auto") {
    await fs.writeFile(confirmFile, new Date().toISOString(), "utf8").catch(() => {});
    await fs.rm(rollbackScript, { force: true }).catch(() => {});
    outcome.confirmDeadlineAt = null;
    persistence.push({ step: "auto-confirm", ok: true, detail: "auto mode — commit confirmed immediately (health verified)" });
  }
  return outcome;
}

// ── confirm / rollback / counters ───────────────────────────────────────────

export async function confirmTiApply(ts: string): Promise<{ confirmed: boolean; ts: string }> {
  const snapshot = await readTiState();
  const target = snapshot.pending?.ts === ts ? snapshot.state : null;
  if (!target) return { confirmed: false, ts };
  await fs.writeFile(target.confirmFile, new Date().toISOString(), "utf8");
  await fs.rm(path.join(TI_DIR, `rollback-${ts}.sh`), { force: true }).catch(() => {});
  return { confirmed: true, ts };
}

export async function rollbackTi(ts?: string): Promise<{ rolledBack: boolean; file: string | null; detail: string }> {
  const snapshot = await readTiState();
  let backupFile: string | null = snapshot.state?.backupFile ?? null;
  if (!backupFile && ts) {
    // traversal guard on the RAW ts — path.join would silently collapse `..`
    // and make the escape look like an ordinary in-dir backup name
    if (ts.includes("..")) {
      throw new Error(`refusing path outside the console threat-intel directory: backup-${ts}`);
    }
    const dir = assertOwnPath(path.join(TI_DIR, `backup-${ts}`), TI_DIR_NAME_BACKUP_RE);
    backupFile = path.join(dir, "ruleset.nft");
  }
  if (!backupFile) {
    // fall back to the newest backup directory on disk
    const dirs = (await fs.readdir(TI_DIR).catch(() => [] as string[]))
      .filter((d) => TI_DIR_NAME_BACKUP_RE.test(d))
      .sort();
    backupFile = dirs.length > 0 ? path.join(TI_DIR, dirs[dirs.length - 1], "ruleset.nft") : null;
  }
  if (!backupFile) return { rolledBack: false, file: null, detail: "no backup available" };
  const res = await guardedRun(`nft -f ${JSON.stringify(backupFile)}`, 10000);
  if (snapshot.state) {
    await fs.writeFile(snapshot.state.confirmFile, "rollback", "utf8").catch(() => {});
    await fs.rm(path.join(TI_DIR, `rollback-${snapshot.state.ts}.sh`), { force: true }).catch(() => {});
  }
  // the restored snapshot no longer reflects the console policy record
  await writeState(null);
  return {
    rolledBack: res.ok,
    file: backupFile,
    detail: res.ok ? "backup restored" : res.stderr || "restore failed",
  };
}

/** Live dump of only the utm_ti_block table (for status UI/counters). */
export async function readTiTableDump(): Promise<string | null> {
  const cmd = `nft list table inet ${TI_TABLE_NAME} 2>/dev/null`;
  if (!tiStepGuarded(cmd)) return null;
  const res = await runTool(cmd, 6000);
  return res.ok && res.stdout.trim() ? res.stdout : null;
}

/**
 * Push kernel counters into AutoBlockRule.hitCount (REAL hits):
 * per-element stateful counters attribute packets to the owning rule via
 * the `ti:<ruleId>:<name>` comments; the chain drop counters are the
 * aggregate reference returned alongside.
 */
export async function syncTiHitsFromKernel(tenantId: number): Promise<{
  updated: number;
  preroutingDrops: number;
  postroutingDrops: number;
  elements: number;
}> {
  const dump = (await readNftRuleset()).ruleset;
  if (!new RegExp(`table inet ${TI_TABLE_NAME}\\b`).test(dump)) {
    return { updated: 0, preroutingDrops: 0, postroutingDrops: 0, elements: 0 };
  }
  const elements = parseTiElements(dump);
  const drops = parseTiDropCounters(dump);
  let updated = 0;
  for (const e of elements) {
    if (e.ruleId === null) continue;
    const row = await db.autoBlockRule.findFirst({ where: { id: e.ruleId, tenantId } }).catch(() => null);
    if (!row) continue;
    await db.autoBlockRule.update({ where: { id: e.ruleId }, data: { hitCount: e.packets } }).catch(() => null);
    updated += 1;
  }
  return {
    updated,
    preroutingDrops: drops.prerouting?.packets ?? 0,
    postroutingDrops: drops.postrouting?.packets ?? 0,
    elements: elements.length,
  };
}

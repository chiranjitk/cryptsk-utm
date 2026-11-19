/**
 * sdwan/os-service — real OS integration for SD-WAN overlays (spec 2.5).
 *
 * GUI SD-WAN overlays previously terminated at the DB (simulated probe only);
 * this module plans (os.ts generateSdwanWgConfigs), SNAPSHOT-BACKS, writes
 * the wg-quick config files, VALIDATES (`wg-quick strip` — a pure parser that
 * does NOT bring interfaces up), arms a commit-confirm rollback timer and
 * records state. Server-only module.
 *
 * Safety architecture (mirror of app-control/os-service.ts + firewall-os.ts):
 *   • gate          CONSOLE_OS_APPLY=1 AND data-plane host mode required
 *                   (off → plan preview only)
 *   • confirm       apply/up/down REQUIRE an explicit confirmSec window —
 *                   the route returns {confirmed:false, ts} on the first call
 *                   (step-guard) and executes only on the confirmed re-issue
 *   • bringUp       `wg-quick up` runs ONLY for enabled overlays AND only
 *                   when the request body carries bringUp=true — tunnels are
 *                   NEVER brought up automatically, apply writes files only
 *   • snapshot      pre-apply copies of touched files → <dir>/backup-<ts>/
 *                   (+ manifest.json); any validation failure auto-restores
 *                   the snapshot immediately; rollback restores files only —
 *                   running tunnels are never torn down implicitly
 *   • namespace     only utm-sdwan-* interfaces/files are touched — never
 *                   ens32/ens34, never the nft baseline, no ip rules
 *   • whitelist     every exec'd command passes sdwanStepGuarded; a failing
 *                   guard aborts the pipeline before the shell runs
 *   • keys          private key material comes from an env/secret source at
 *                   apply time; plans never carry it (placeholders only)
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { hasTool, runTool } from "@/lib/host/tools";
import {
  GENERATED_ON_APPLY,
  PRIVATE_KEY_PLACEHOLDER,
  SDWAN_IFACE_PREFIX,
  SDWAN_KEEPALIVE_DEFAULT,
  SDWAN_WG_DIR,
  buildSdwanRollbackScript,
  generateSdwanWgConfigs,
  parseWgShow,
  sdwanApplyTs,
  sdwanIfacesFromWgShow,
  sdwanStepGuarded,
  type SdwanGenWarning,
  type SdwanOverlayFile,
  type SdwanOverlayShape,
  type SdwanPlan,
  type WgShowIface,
} from "./os";

export const SDWAN_DIR = process.env.CONSOLE_SDWAN_DIR || "/var/lib/console/sdwan";
export const SDWAN_STATE_FILE = path.join(SDWAN_DIR, "state.json");
const CONFIRM_SEC = Math.max(15, Number(process.env.CONSOLE_NFT_CONFIRM_SEC || 60));
const STEM_RE = /^utm-sdwan-[a-z0-9-]+$/;

// ── DB → generator input ────────────────────────────────────────────────────

/** All tenant overlays + sites → deterministic shapes for the pure renderer. */
export async function loadSdwanShapes(tenantId: number): Promise<SdwanOverlayShape[]> {
  const [overlays, sites] = await Promise.all([
    db.sdwanOverlay.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.sdwanSite.findMany({ where: { tenantId }, orderBy: [{ overlayId: "asc" }, { id: "asc" }] }),
  ]);
  const sitesBy = new Map<number, SdwanOverlayShape["sites"]>();
  for (const s of sites) {
    const list = sitesBy.get(s.overlayId) ?? [];
    list.push({
      id: s.id,
      name: s.name,
      role: s.role === "hub" ? "hub" : "spoke",
      publicIp: s.publicIp,
      wgPubKey: s.wgPubKey,
      enabled: s.enabled,
    });
    sitesBy.set(s.overlayId, list);
  }
  return overlays.map((o) => ({
    id: o.id,
    name: o.name,
    topology: o.topology === "full_mesh" ? "full_mesh" : "hub_spoke",
    encryption: o.encryption === "ipsec" ? "ipsec" : "wireguard",
    enabled: o.enabled,
    sites: sitesBy.get(o.id) ?? [],
  }));
}

/** PersistentKeepalive from the tenant system settings (category sdwan). */
export async function readSdwanKeepaliveSec(tenantId: number): Promise<number> {
  const row = await db.systemSetting
    .findUnique({
      where: { tenantId_category_key: { tenantId, category: "sdwan", key: "wireguard" } },
    })
    .catch(() => null);
  if (!row) return SDWAN_KEEPALIVE_DEFAULT;
  try {
    const parsed: unknown = JSON.parse(row.value);
    const v = (parsed as { keepaliveSec?: unknown } | null)?.keepaliveSec;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0 || n > 600) return SDWAN_KEEPALIVE_DEFAULT;
    return n;
  } catch {
    return SDWAN_KEEPALIVE_DEFAULT;
  }
}

// ── OS facts ────────────────────────────────────────────────────────────────

export interface SdwanOsFacts {
  gate: "on" | "off";
  mode: string;
  wgAvailable: boolean;
  wgQuickAvailable: boolean;
  wgVersion: string | null;
}

async function dataPlaneMode(): Promise<string> {
  const { getDataPlaneMode } = await import("@/lib/engine");
  return getDataPlaneMode();
}

/** Platform gate: OS apply is armed only in host data-plane mode. */
export function sdwanGateOn(): boolean {
  return process.env.CONSOLE_OS_APPLY === "1";
}

export async function readSdwanOsFacts(): Promise<SdwanOsFacts> {
  const [wg, wgQuick] = await Promise.all([hasTool("wg"), hasTool("wg-quick")]);
  const [versionRes, mode] = await Promise.all([
    wg ? runTool("wg --version", 3000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no wg" }),
    dataPlaneMode(),
  ]);
  return {
    gate: sdwanGateOn() ? "on" : "off",
    mode,
    wgAvailable: wg,
    wgQuickAvailable: wgQuick,
    wgVersion: versionRes.ok ? versionRes.stdout.trim() || null : null,
  };
}

// ── plan ────────────────────────────────────────────────────────────────────

export async function buildSdwanPlan(tenantId: number, generatedAt?: Date): Promise<SdwanPlan> {
  const [shapes, keepaliveSec] = await Promise.all([loadSdwanShapes(tenantId), readSdwanKeepaliveSec(tenantId)]);
  return generateSdwanWgConfigs({ overlays: shapes, keepaliveSec, generatedAt });
}

// ── private key source (never logged, never returned) ───────────────────────

export interface SdwanKeySource {
  source: "env" | "keyfile" | "absent";
  /** resolve the private key for one managed interface (server-side only) */
  keyFor(iface: string): Promise<string | null>;
}

/**
 * Real keys materialize server-side ONLY:
 *   1. CONSOLE_SDWAN_WG_PRIVATE_KEY (single appliance key), or
 *   2. CONSOLE_SDWAN_KEY_DIR/<iface>.key (per-interface secret files), or
 *   3. absent → the written file carries [GENERATED-ON-APPLY] + a warning
 *      (wg-quick up will fail until a key is provisioned).
 */
export function resolveKeySource(): SdwanKeySource {
  const envKey = process.env.CONSOLE_SDWAN_WG_PRIVATE_KEY?.trim();
  if (envKey && !envKey.startsWith("[")) {
    return { source: "env", keyFor: async () => envKey };
  }
  const keyDir = process.env.CONSOLE_SDWAN_KEY_DIR?.trim();
  if (keyDir) {
    return {
      source: "keyfile",
      keyFor: async (iface) => {
        if (!STEM_RE.test(iface)) return null;
        const raw = await fs.readFile(path.join(keyDir, `${iface}.key`), "utf8").catch(() => null);
        const key = raw?.trim();
        return key && key.length > 0 && !key.startsWith("[") ? key : null;
      },
    };
  }
  return { source: "absent", keyFor: async () => null };
}

// ── guarded exec ────────────────────────────────────────────────────────────

/** Guarded exec — runs the command ONLY when it passes the module whitelist. */
async function guardedRun(cmd: string, timeoutMs: number): Promise<{ ok: boolean; stderr?: string; stdout?: string }> {
  if (!sdwanStepGuarded(cmd)) {
    return { ok: false, stderr: `command rejected by the sdwan whitelist: ${cmd.slice(0, 120)}` };
  }
  const r = await runTool(cmd, timeoutMs);
  return r.ok ? { ok: true, stdout: r.stdout } : { ok: false, stderr: r.stderr || r.error || "exec failed" };
}

// ── apply state (commit-confirm window) ─────────────────────────────────────

interface ApplyState {
  ts: string;
  armedAt: string;
  deadlineAt: string;
  backupDir: string;
  confirmFile: string;
  confHashes: Record<string, string>;
}

async function writeState(state: ApplyState | null): Promise<void> {
  await fs.mkdir(SDWAN_DIR, { recursive: true });
  await fs.writeFile(SDWAN_STATE_FILE, JSON.stringify(state, null, 2), "utf8");
}

export async function readApplyState(): Promise<ApplyState | null> {
  try {
    const raw = await fs.readFile(SDWAN_STATE_FILE, "utf8");
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

function assertOwnStem(stem: string): string {
  if (!STEM_RE.test(stem)) throw new Error(`refusing non-managed file stem: ${stem}`);
  return stem;
}

/** Remove stale artefacts: armed scripts >60min, confirm files >24h, backups >7d. */
async function housekeepArtefacts(): Promise<void> {
  const now = Date.now();
  const files = await fs.readdir(SDWAN_DIR).catch(() => [] as string[]);
  for (const f of files) {
    const full = path.join(SDWAN_DIR, f);
    try {
      const st = await fs.stat(full);
      const ageMin = (now - st.mtimeMs) / 60_000;
      const staleScript = /^rollback-[\w.-]+\.sh$/.test(f) && ageMin > 60;
      const staleConfirm = /^confirm-[\w.-]+$/.test(f) && ageMin > 24 * 60;
      const staleBackup = /^backup-[\w.-]+$/.test(f) && st.isDirectory() && ageMin > 7 * 24 * 60;
      if (staleScript || staleConfirm) await fs.unlink(full).catch(() => {});
      if (staleBackup) await fs.rm(full, { recursive: true, force: true }).catch(() => {});
    } catch {
      // vanished already
    }
  }
}

// ── low-level apply pipeline (no db — unit-testable with mocked exec) ───────

export interface SdwanApplyResults {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface SdwanApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  rolledBack: boolean;
  rollbackReason: string | null;
  confirmSec: number;
  confirmDeadlineAt: string | null;
  ts: string;
  keySource: "env" | "keyfile" | "absent";
  files: Array<{ iface: string; fileName: string; confHash: string; action: "created" | "updated"; validated: boolean }>;
  warnings: SdwanGenWarning[];
  counts: SdwanPlan["counts"] | null;
  results: SdwanApplyResults[];
}

export interface SdwanApplyOptions {
  confirmSec?: number;
}

/**
 * Snapshot-first + validate + arm pipeline over a PURE plan. Never touches
 * db; never brings interfaces up. Every failure surfaces honestly and the
 * pre-apply snapshot is restored automatically when validation fails.
 */
export async function applySdwanPlan(plan: SdwanPlan, opts: SdwanApplyOptions = {}): Promise<SdwanApplyOutcome> {
  const confirmSec = Math.max(15, Number(opts.confirmSec ?? CONFIRM_SEC));
  const ts = sdwanApplyTs();
  const results: SdwanApplyResults[] = [];
  const keySource = resolveKeySource();
  const outcome: SdwanApplyOutcome = {
    gate: sdwanGateOn() ? "on" : "off",
    applied: false,
    rolledBack: false,
    rollbackReason: null,
    confirmSec,
    confirmDeadlineAt: null,
    ts,
    keySource: keySource.source,
    files: [],
    warnings: plan.warnings,
    counts: plan.counts,
    results,
  };

  if (!sdwanGateOn()) {
    results.push({ step: "gate", ok: false, detail: "OS convergence disabled by platform policy — plan is a preview only" });
    return outcome;
  }
  if ((await dataPlaneMode()) !== "host") {
    results.push({ step: "mode", ok: false, detail: "data plane is not in host mode — OS enforcement is preview-only" });
    return outcome;
  }
  const [wg, wgQuick] = await Promise.all([hasTool("wg"), hasTool("wg-quick")]);
  if (!wgQuick || !wg) {
    results.push({ step: "tool", ok: false, detail: "wg / wg-quick binaries not found on host" });
    return outcome;
  }
  if (plan.files.length === 0) {
    results.push({ step: "plan", ok: false, detail: "no enabled WireGuard overlays with sites — nothing to apply" });
    return outcome;
  }

  await fs.mkdir(SDWAN_DIR, { recursive: true });
  void housekeepArtefacts();

  // 1. snapshot-first — copy every touched file into backup-<ts>/ + manifest
  const backupDir = path.join(SDWAN_DIR, `backup-${ts}`);
  await fs.mkdir(backupDir, { recursive: true });
  const updated: string[] = [];
  const created: string[] = [];
  for (const file of plan.files) {
    const stem = assertOwnStem(file.iface);
    const target = path.join(SDWAN_WG_DIR, `${stem}.conf`);
    const existed = await fs
      .access(target)
      .then(() => true)
      .catch(() => false);
    if (existed) {
      const snapshotPath = path.join(backupDir, `${stem}.conf`);
      await fs.copyFile(target, snapshotPath).catch(() => {});
      // backups contain private keys — never world-readable (mirror vpn/os.ts)
      await fs.chmod(snapshotPath, 0o600).catch(() => {});
      updated.push(stem);
      results.push({ step: `snapshot ${stem}`, ok: true, detail: `previous config backed up to ${backupDir}` });
    } else {
      created.push(stem);
      results.push({ step: `snapshot ${stem}`, ok: true, detail: "new file (nothing to back up)" });
    }
  }
  await fs.writeFile(
    path.join(backupDir, "manifest.json"),
    JSON.stringify({ ts, created, updated }, null, 2),
    "utf8",
  );

  // 2. write files — private key substituted server-side, NEVER logged
  const writtenHashes: Record<string, string> = {};
  const { createHash } = await import("crypto");
  for (const file of plan.files) {
    const stem = assertOwnStem(file.iface);
    const key = await keySource.keyFor(stem).catch(() => null);
    const written =
      key !== null
        ? file.conf.replace(PRIVATE_KEY_PLACEHOLDER, key)
        : file.conf.replace(PRIVATE_KEY_PLACEHOLDER, GENERATED_ON_APPLY);
    const hash = createHash("sha256").update(written, "utf8").digest("hex");
    try {
      const confPath = path.join(SDWAN_WG_DIR, `${stem}.conf`);
      await fs.writeFile(confPath, written, "utf8");
      // WireGuard confs carry private keys — mirror the vpn/os.ts guarded 0600 pattern
      await fs.chmod(confPath, 0o600).catch(() => {});
      writtenHashes[`${SDWAN_WG_DIR}/${stem}.conf`] = hash;
      outcome.files.push({ iface: stem, fileName: `${SDWAN_WG_DIR}/${stem}.conf`, confHash: hash, action: updated.includes(stem) ? "updated" : "created", validated: false });
      results.push({
        step: `write ${stem}`,
        ok: true,
        detail:
          key !== null
            ? `written (${hash.slice(0, 12)}…, key source: ${keySource.source})`
            : `written (${hash.slice(0, 12)}…) — no private key source configured (CONSOLE_SDWAN_WG_PRIVATE_KEY or CONSOLE_SDWAN_KEY_DIR) — file carries ${GENERATED_ON_APPLY}; wg-quick up will fail until a key is provisioned`,
      });
    } catch (err) {
      results.push({ step: `write ${stem}`, ok: false, detail: err instanceof Error ? err.message : "write failed" });
    }
  }

  // 3. validate — `wg-quick strip` is a PURE parse (does NOT bring up)
  let allValid = true;
  for (const file of plan.files) {
    const stem = assertOwnStem(file.iface);
    const check = await guardedRun(`wg-quick strip ${stem}`, 6000);
    results.push({ step: `validate ${stem}`, ok: check.ok, detail: check.ok ? "wg-quick strip parse ok" : check.stderr });
    if (!check.ok) allValid = false;
    const entry = outcome.files.find((f) => f.iface === stem);
    if (entry) entry.validated = check.ok;
  }
  if (!allValid) {
    // snapshot-first + auto-restore — the pre-apply state is re-established
    const restore = await restoreFromManifest(backupDir, SDWAN_WG_DIR);
    results.push({ step: "auto-restore", ok: restore.restored, detail: restore.detail });
    outcome.rolledBack = true;
    outcome.rollbackReason = "wg-quick strip validation failed — pre-apply snapshot restored (files only, running tunnels untouched)";
    await writeState(null);
    return outcome;
  }

  // 4. arm the detached rollback timer (survives console restarts)
  const confirmFile = path.join(SDWAN_DIR, `confirm-${ts}`);
  const rollbackScript = path.join(SDWAN_DIR, `rollback-${ts}.sh`);
  await fs.writeFile(
    rollbackScript,
    buildSdwanRollbackScript({ ts, confirmSec, confirmFile, backupDir, stateFile: SDWAN_STATE_FILE, scriptFile: rollbackScript, wgDir: SDWAN_WG_DIR, updated, created }),
    "utf8",
  );
  const arm = await guardedRun(`nohup /bin/sh ${JSON.stringify(rollbackScript)} >/dev/null 2>&1 &`, 4000);
  results.push({
    step: "rollback timer",
    ok: arm.ok,
    detail: arm.ok ? `auto-restore of config files in ${confirmSec}s unless confirmed (running tunnels are not torn down)` : arm.stderr,
  });

  const deadlineAt = new Date(Date.now() + confirmSec * 1000).toISOString();
  // a new apply SUPERSEDES any still-pending window: confirm the previous
  // timer so it cannot fire mid-flight and revert the newer config
  const prior = await readApplyState();
  if (prior) await fs.writeFile(prior.confirmFile, "superseded", "utf8").catch(() => {});
  await writeState({ ts, armedAt: new Date().toISOString(), deadlineAt, backupDir, confirmFile, confHashes: writtenHashes });
  outcome.confirmDeadlineAt = deadlineAt;
  outcome.applied = true;
  return outcome;
}

// ── restore / rollback ──────────────────────────────────────────────────────

interface SnapshotManifest {
  ts: string;
  created: string[];
  updated: string[];
}

/** Restore a snapshot dir's manifest into the wg config dir (files only). */
async function restoreFromManifest(
  backupDir: string,
  wgDir: string,
): Promise<{ restored: boolean; restoredCount: number; removedCount: number; detail: string }> {
  try {
    const manifest = JSON.parse(await fs.readFile(path.join(backupDir, "manifest.json"), "utf8")) as SnapshotManifest;
    let restoredCount = 0;
    let removedCount = 0;
    for (const stem of manifest.updated) {
      assertOwnStem(stem);
      const confPath = path.join(wgDir, `${stem}.conf`);
      await fs.copyFile(path.join(backupDir, `${stem}.conf`), confPath);
      // restored confs carry private keys — keep them owner-only
      await fs.chmod(confPath, 0o600).catch(() => {});
      restoredCount += 1;
    }
    for (const stem of manifest.created) {
      assertOwnStem(stem);
      await fs.rm(path.join(wgDir, `${stem}.conf`), { force: true });
      removedCount += 1;
    }
    return { restored: true, restoredCount, removedCount, detail: `restored ${restoredCount} file(s), removed ${removedCount} created file(s) from ${backupDir}` };
  } catch (err) {
    return { restored: false, restoredCount: 0, removedCount: 0, detail: err instanceof Error ? err.message : "restore failed" };
  }
}

/** Commit-confirm: mark the window confirmed → the rollback timer exits. */
export async function confirmSdwanApply(ts: string): Promise<{ confirmed: boolean; ts: string }> {
  const state = await readApplyState();
  const target = state?.ts === ts ? state : null;
  if (!target) return { confirmed: false, ts };
  await fs.writeFile(target.confirmFile, new Date().toISOString(), "utf8");
  await writeState(null);
  await fs.rm(path.join(SDWAN_DIR, `rollback-${ts}.sh`), { force: true }).catch(() => {});
  return { confirmed: true, ts };
}

/** Restore the newest (or ts-specific) pre-apply snapshot. Files only. */
export async function rollbackSdwan(
  ts?: string,
): Promise<{ rolledBack: boolean; dir: string | null; restoredCount: number; detail: string }> {
  let backupDir: string | null = (await readApplyState())?.backupDir ?? null;
  if (!backupDir && ts) {
    const candidate = path.join(SDWAN_DIR, `backup-${ts}`);
    const ok = await fs
      .stat(candidate)
      .then((s) => s.isDirectory())
      .catch(() => false);
    if (ok) backupDir = candidate;
  }
  if (!backupDir) {
    const dirs = (await fs.readdir(SDWAN_DIR).catch(() => [] as string[]))
      .filter((d) => /^backup-[\w.-]+$/.test(d))
      .sort();
    backupDir = dirs.length > 0 ? path.join(SDWAN_DIR, dirs[dirs.length - 1]) : null;
  }
  if (!backupDir) return { rolledBack: false, dir: null, restoredCount: 0, detail: "no backup snapshot available" };
  const restore = await restoreFromManifest(backupDir, SDWAN_WG_DIR);
  const state = await readApplyState();
  if (state) {
    await fs.writeFile(state.confirmFile, "rollback", "utf8").catch(() => {});
    await writeState(null);
    await fs.rm(path.join(SDWAN_DIR, `rollback-${state.ts}.sh`), { force: true }).catch(() => {});
  }
  return {
    rolledBack: restore.restored,
    dir: backupDir,
    restoredCount: restore.restoredCount,
    detail: restore.restored
      ? `${restore.detail} — running tunnels were not torn down (wg-quick down them explicitly)`
      : restore.detail,
  };
}

// ── gate-checked service entry points ───────────────────────────────────────

/** DB-backed apply: gate → plan → snapshot/write/validate/arm pipeline. */
export async function applySdwanToOs(tenantId: number, opts: SdwanApplyOptions = {}): Promise<SdwanApplyOutcome> {
  const plan = await buildSdwanPlan(tenantId);
  return applySdwanPlan(plan, opts);
}

export interface SdwanUpOutcome {
  gate: "on" | "off";
  requested: number;
  broughtUp: number;
  confirmSec: number | null;
  results: SdwanApplyResults[];
  warnings: SdwanGenWarning[];
}

/**
 * `wg-quick up utm-sdwan-<slug>` per enabled overlay — ONLY when the caller
 * already confirmed bringUp (route step-guard) and the config file was
 * applied. A successful up CONFIRMS the pending commit-confirm window (the
 * files are in active use). Tunnels are never brought up automatically.
 */
export async function upSdwanOverlays(tenantId: number, opts: SdwanApplyOptions = {}): Promise<SdwanUpOutcome> {
  const confirmSec = opts.confirmSec ?? null;
  const results: SdwanApplyResults[] = [];
  const plan = await buildSdwanPlan(tenantId);
  const outcome: SdwanUpOutcome = { gate: sdwanGateOn() ? "on" : "off", requested: plan.files.length, broughtUp: 0, confirmSec, results, warnings: plan.warnings };

  if (!sdwanGateOn()) {
    results.push({ step: "gate", ok: false, detail: "OS convergence disabled by platform policy — up is a preview only" });
    return outcome;
  }
  if ((await dataPlaneMode()) !== "host") {
    results.push({ step: "mode", ok: false, detail: "data plane is not in host mode — up is preview-only" });
    return outcome;
  }
  const [wg, wgQuick] = await Promise.all([hasTool("wg"), hasTool("wg-quick")]);
  if (!wgQuick || !wg) {
    results.push({ step: "tool", ok: false, detail: "wg / wg-quick binaries not found on host" });
    return outcome;
  }

  for (const file of plan.files) {
    const stem = assertOwnStem(file.iface);
    const exists = await fs
      .access(path.join(SDWAN_WG_DIR, `${stem}.conf`))
      .then(() => true)
      .catch(() => false);
    if (!exists) {
      results.push({ step: stem, ok: false, detail: "config not applied to OS yet — run apply first" });
      continue;
    }
    const up = await guardedRun(`wg-quick up ${stem}`, 10000);
    results.push({ step: stem, ok: up.ok, detail: up.ok ? `interface up (${file.peers.length} peer(s))` : up.stderr });
    if (up.ok) outcome.broughtUp += 1;
  }

  // using the applied files confirms the commit-confirm window
  if (outcome.broughtUp > 0) {
    const state = await readApplyState();
    if (state) {
      await fs.writeFile(state.confirmFile, "up", "utf8").catch(() => {});
      await writeState(null);
      await fs.rm(path.join(SDWAN_DIR, `rollback-${state.ts}.sh`), { force: true }).catch(() => {});
      results.push({ step: "confirm", ok: true, detail: "pending apply window confirmed by up" });
    }
  }
  return outcome;
}

export interface SdwanDownOutcome {
  gate: "on" | "off";
  requested: number;
  broughtDown: number;
  results: SdwanApplyResults[];
  warnings: SdwanGenWarning[];
}

/** `wg-quick down` for RUNNING utm-sdwan-* interfaces only (never others). */
export async function downSdwanOverlays(): Promise<SdwanDownOutcome> {
  const results: SdwanApplyResults[] = [];
  const warnings: SdwanGenWarning[] = [];
  const outcome: SdwanDownOutcome = { gate: sdwanGateOn() ? "on" : "off", requested: 0, broughtDown: 0, results, warnings };
  warnings.push({
    scope: "plan",
    overlayId: null,
    siteId: null,
    name: "sdwan",
    code: "traffic-affecting",
    message: "bringing overlays down tears down live tunnel traffic on the managed interfaces",
  });

  if (!sdwanGateOn()) {
    results.push({ step: "gate", ok: false, detail: "OS convergence disabled by platform policy — down is a preview only" });
    return outcome;
  }
  if ((await dataPlaneMode()) !== "host") {
    results.push({ step: "mode", ok: false, detail: "data plane is not in host mode — down is preview-only" });
    return outcome;
  }
  const [wg, wgQuick] = await Promise.all([hasTool("wg"), hasTool("wg-quick")]);
  if (!wgQuick || !wg) {
    results.push({ step: "tool", ok: false, detail: "wg / wg-quick binaries not found on host" });
    return outcome;
  }

  const show = await guardedRun("wg show", 6000);
  if (!show.ok) {
    results.push({ step: "wg show", ok: false, detail: show.stderr ?? "wg show failed" });
    return outcome;
  }
  const running = sdwanIfacesFromWgShow(parseWgShow(show.stdout ?? ""));
  outcome.requested = running.length;
  if (running.length === 0) {
    results.push({ step: "wg show", ok: true, detail: "no running utm-sdwan-* interfaces" });
    return outcome;
  }
  for (const iface of running) {
    const stem = assertOwnStem(iface.iface);
    const down = await guardedRun(`wg-quick down ${stem}`, 10000);
    results.push({ step: stem, ok: down.ok, detail: down.ok ? "interface down" : down.stderr });
    if (down.ok) outcome.broughtDown += 1;
  }
  return outcome;
}

// ── status (GET) ────────────────────────────────────────────────────────────

export interface SdwanFileState {
  iface: string;
  fileName: string;
  exists: boolean;
  planHash: string;
  diskHash: string | null;
  appliedHash: string | null;
  running: boolean;
  liveListenPort: number | null;
  livePeers: number | null;
  /** missing | in-sync | matches-plan | drift */
  state: string;
  reasons: string[];
}

export interface SdwanOsStatus {
  gate: "on" | "off";
  mode: string;
  available: boolean;
  wgVersion: string | null;
  keepaliveSec: number;
  keySource: "env" | "keyfile" | "absent";
  plan: SdwanPlan;
  files: SdwanFileState[];
  runningIfaces: WgShowIface[];
  pendingConfirm: { ts: string; deadlineAt: string; backupDir: string } | null;
  drift: { appliedFiles: number; inSyncFiles: number; reasons: string[] };
}

async function sha256File(file: string): Promise<string | null> {
  try {
    const { createHash } = await import("crypto");
    return createHash("sha256").update(await fs.readFile(file, "utf8"), "utf8").digest("hex");
  } catch {
    return null;
  }
}

/** Live status: facts + plan + per-file disk state + wg-show interface state. */
export async function readSdwanStatus(tenantId: number): Promise<SdwanOsStatus> {
  const [plan, facts, state] = await Promise.all([buildSdwanPlan(tenantId), readSdwanOsFacts(), readApplyState()]);
  const available = facts.wgAvailable && facts.wgQuickAvailable;

  let runningIfaces: WgShowIface[] = [];
  if (facts.wgAvailable) {
    const cmd = "wg show";
    if (sdwanStepGuarded(cmd)) {
      const dump = await runTool(cmd, 6000);
      if (dump.ok) runningIfaces = sdwanIfacesFromWgShow(parseWgShow(dump.stdout));
    }
  }

  const files: SdwanFileState[] = [];
  for (const file of plan.files) {
    const exists = await fs
      .access(file.fileName)
      .then(() => true)
      .catch(() => false);
    const diskHash = exists ? await sha256File(file.fileName) : null;
    const appliedHash = state?.confHashes[file.fileName] ?? null;
    const live = runningIfaces.find((i) => i.iface === file.iface);
    let fileState: string;
    const reasons: string[] = [];
    if (!exists) {
      fileState = "missing";
      reasons.push("config file not on disk — apply once to install it");
    } else if (appliedHash !== null && diskHash === appliedHash) {
      fileState = "in-sync";
    } else if (diskHash === file.confHash) {
      fileState = "matches-plan";
      if (appliedHash !== null) reasons.push("file matches the current plan but not the last applied hash (key substitution drift)");
    } else {
      fileState = "drift";
      reasons.push("file on disk differs from the plan and the last applied hash — re-apply to converge");
    }
    files.push({
      iface: file.iface,
      fileName: file.fileName,
      exists,
      planHash: file.confHash,
      diskHash,
      appliedHash,
      running: !!live,
      liveListenPort: live?.listenPort ?? null,
      livePeers: live?.peers ?? null,
      state: fileState,
      reasons,
    });
  }

  const appliedFiles = files.filter((f) => f.exists).length;
  const inSyncFiles = files.filter((f) => f.state === "in-sync" || f.state === "matches-plan").length;
  const driftReasons: string[] = [];
  if (!available) driftReasons.push("wg / wg-quick unavailable — kernel state unreadable (sandbox degrades to preview)");
  if (appliedFiles === 0) driftReasons.push("no overlay config files installed — apply once to write them");
  else if (inSyncFiles < appliedFiles) driftReasons.push("some overlay files differ from the current plan — re-apply to converge");

  return {
    gate: facts.gate,
    mode: facts.mode,
    available,
    wgVersion: facts.wgVersion,
    keepaliveSec: await readSdwanKeepaliveSec(tenantId),
    keySource: resolveKeySource().source,
    plan,
    files,
    runningIfaces,
    pendingConfirm: state ? { ts: state.ts, deadlineAt: state.deadlineAt, backupDir: state.backupDir } : null,
    drift: { appliedFiles, inSyncFiles, reasons: driftReasons },
  };
}

// re-export for the route/panel type surface
export type { SdwanOverlayFile, SdwanPlan, WgShowIface };
export const SDWAN_MANAGED_PREFIX = SDWAN_IFACE_PREFIX;

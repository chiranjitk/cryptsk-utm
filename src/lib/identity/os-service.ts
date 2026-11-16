/**
 * RADIUS OS service — resolves console RadiusProfile rows into the
 * clients.conf render and executes/reads live state for the identity os
 * route. Pure mapping lives in os.ts; everything touching db/exec/fs is here.
 *
 * Server-only (fs/exec/db imports).
 */

import { readFile, writeFile, mkdir, readdir, unlink } from "fs/promises";
import { db } from "@/lib/db";
import {
  buildRadiusApplyPlan,
  computeRadiusDrift,
  hardRadiusRefusal,
  parseSsForAuthPort,
  radiusConfHash,
  radiusStepGuarded,
  renderRadiusClientsConf,
  RADIUS_AUTH_PORT,
  RADIUS_BACKUP_DIR_RE,
  RADIUS_MANAGED_FILE,
  RADIUS_STAGE_FILE,
  RADIUS_STATE_DIR,
  RADIUS_STATE_FILE,
  RADIUS_UNIT,
  type RadiusApplyPlan,
  type RadiusProfileShape,
} from "./os";

export interface RadiusStateFile {
  confHash: string;
  appliedAt: string;
  profileIds: number[];
  empty?: boolean;
  note?: string;
}

export async function readRadiusState(): Promise<RadiusStateFile | null> {
  try {
    const raw = await readFile(RADIUS_STATE_FILE, "utf8");
    const parsed = JSON.parse(raw) as RadiusStateFile;
    if (!parsed || typeof parsed.confHash !== "string" || !Array.isArray(parsed.profileIds)) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeRadiusState(content: string): Promise<void> {
  await mkdir(RADIUS_STATE_DIR, { recursive: true });
  await writeFile(RADIUS_STATE_FILE, content, "utf8");
}

/** Live managed file — sha256-16 hash, or null when missing/unreadable. */
export async function readRadiusLiveHash(): Promise<string | null> {
  try {
    const raw = await readFile(RADIUS_MANAGED_FILE, "utf8");
    return radiusConfHash(raw);
  } catch {
    return null;
  }
}

/**
 * DB rows → pure renderer shapes. The M07 RadiusProfile model has NO enabled
 * column — every row is a NAS client (documented in os.ts); the shape keeps
 * the flag so an additive schema change later needs no renderer change.
 */
export async function buildRadiusShapes(tenantId: number): Promise<RadiusProfileShape[]> {
  const rows = await db.radiusProfile.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    serverIp: r.serverIp,
    authPort: r.authPort,
    sharedSecret: r.sharedSecret,
    timeoutSec: r.timeoutSec,
    retries: r.retries,
    enabled: true,
  }));
}

async function unitActiveOrNull(): Promise<{ unitState: string | null; unitActive: boolean | null }> {
  const { runTool } = await import("@/lib/host/tools");
  // `systemctl is-active` exits non-zero for inactive units → ok:false, but the
  // state word is in stdout either way.
  const r = await runTool(`systemctl is-active ${RADIUS_UNIT}`, 5000);
  const unitState = (r.stdout || r.stderr).trim() || null;
  return { unitState, unitActive: unitState === "active" ? true : unitState ? false : null };
}

/** udp/1812 bound probe via ss — null when the probe itself fails. */
async function authPortBoundOrNull(): Promise<boolean | null> {
  const { runTool } = await import("@/lib/host/tools");
  const r = await runTool(`ss -lun '( sport = :${RADIUS_AUTH_PORT} )'`, 5000);
  if (!r.ok) return null;
  return parseSsForAuthPort(r.stdout);
}

/** Managed file present on disk? (drives whether the plan takes a snapshot) */
async function managedFileExists(): Promise<boolean> {
  try {
    await readFile(RADIUS_MANAGED_FILE, "utf8");
    return true;
  } catch {
    return false;
  }
}

// ── status ──────────────────────────────────────────────────────────────────

export interface RadiusProfileOsStatus {
  id: number;
  name: string;
  serverIp: string;
  authPort: number;
  timeoutSec: number;
  retries: number;
  /** no enabled column in M07 — true for every row */
  enabled: boolean;
  /** client block name the renderer will emit; null when not rendered */
  slug: string | null;
  /** sha256-16 of the rendered client block; null when not rendered */
  renderHash: string | null;
}

export async function readRadiusOsStatus(tenantId: number): Promise<{
  available: boolean;
  dataPlaneMode: string;
  gate: "on" | "off";
  note: string;
  unitState: string | null;
  portBound: boolean | null;
  managedFile: string;
  inSync: boolean | null;
  driftReasons: string[];
  state: RadiusStateFile | null;
  profiles: RadiusProfileOsStatus[];
  warnings: string[];
}> {
  const [{ getDataPlaneMode }, { hasTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);
  const mode = getDataPlaneMode();
  const available = (await hasTool("freeradius")) && (await hasTool("ss")) && mode === "host";

  const shapes = await buildRadiusShapes(tenantId);
  const rendered = renderRadiusClientsConf(shapes);
  const state = await readRadiusState();
  const hasEnabled = shapes.some((s) => s.enabled);

  let unitState: string | null = null;
  let unitActive: boolean | null = null;
  let portBound: boolean | null = null;
  let liveHash: string | null = null;
  let inSync: boolean | null = null;
  let driftReasons: string[] = [];

  if (available) {
    ({ unitState, unitActive } = await unitActiveOrNull());
    portBound = await authPortBoundOrNull();
    liveHash = await readRadiusLiveHash();
    const drift = computeRadiusDrift({
      renderedContent: rendered.content,
      liveFileHash: liveHash,
      unitActive,
      hasEnabledProfiles: hasEnabled,
    });
    inSync = drift.inSync;
    driftReasons = drift.driftReasons;
  }

  const hashById = new Map(rendered.profiles.map((p) => [p.id, p.renderHash]));
  const profiles: RadiusProfileOsStatus[] = shapes.map((p) => ({
    id: p.id,
    name: p.name,
    serverIp: p.serverIp,
    authPort: p.authPort,
    timeoutSec: p.timeoutSec,
    retries: p.retries,
    enabled: p.enabled,
    slug: rendered.profiles.find((r) => r.id === p.id)?.slug ?? null,
    renderHash: hashById.get(p.id) ?? null,
  }));

  return {
    available,
    dataPlaneMode: mode,
    gate: process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off",
    note: available
      ? "freeradius + ss present — NAS clients apply to /etc/freeradius/3.0/clients.conf on Apply"
      : "freeradius/ss unavailable or data plane in simulated mode — OS enforcement is preview-only",
    unitState,
    portBound,
    managedFile: RADIUS_MANAGED_FILE,
    inSync,
    driftReasons,
    state,
    profiles,
    warnings: rendered.warnings,
  };
}

// ── apply executor (mirrors the logs/qos/HA route pattern) ─────────────────

export interface RadiusStepResult {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface RadiusApplyOutcome {
  applied: boolean;
  refused?: string;
  reason?: string;
  /** zero-churn: live hash + unit state already matched — nothing touched */
  skipped?: boolean;
  rolledBack: boolean;
  confHash?: string;
  backupDir?: string;
  plan: { steps: { step: string; cmd: string; kind: string }[]; profiles: unknown };
  results: RadiusStepResult[];
}

/**
 * Inert header-only clients.conf — the restore target when NO managed file
 * existed pre-apply (mirrors the logs convention of restoring a known-good
 * default when the snapshot is empty).
 */
function renderInertClientsConf(): string {
  return renderRadiusClientsConf([]).content;
}

/**
 * Execute the convergence plan on the appliance (exec gate checked by caller).
 * Snapshot-first; any failure after the install step auto-restores the
 * pre-apply clients.conf from backup-<ts>/ (or the inert header-only file when
 * none existed) and restarts freeradius. The state file is the LAST plan step
 * — only written when every verify passed.
 */
export async function applyRadiusToOs(tenantId: number, exec: boolean): Promise<RadiusApplyOutcome> {
  const [{ getDataPlaneMode }, { runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);

  const shapes = await buildRadiusShapes(tenantId);
  const refusal = hardRadiusRefusal(shapes);
  const fileExisted = await managedFileExists();
  const mode: RadiusApplyPlan["mode"] = exec && getDataPlaneMode() === "host" ? "exec" : "plan";
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  const plan: RadiusApplyPlan = buildRadiusApplyPlan({
    profiles: shapes,
    managedFileExists: fileExisted,
    mode,
    ts,
  });
  const preview = () => ({ steps: plan.steps, profiles: plan.profiles });

  if (refusal) {
    return { applied: false, refused: refusal, rolledBack: false, plan: preview(), results: [] };
  }
  if (!exec || mode !== "exec") {
    return {
      applied: false,
      refused: !exec
        ? "CONSOLE_OS_APPLY is off — plan preview only (freeradius command sequence attached)"
        : "data plane is not in host mode — OS enforcement is preview-only",
      rolledBack: false,
      plan: preview(),
      results: [],
    };
  }

  // ── zero-churn: live file already matches the render AND unit state fits ──
  const [liveHash, { unitActive }] = await Promise.all([readRadiusLiveHash(), unitActiveOrNull()]);
  const unitMatches = plan.empty ? unitActive === false : unitActive === true;
  if (liveHash === plan.confHash && unitMatches) {
    return {
      applied: true,
      skipped: true,
      reason: `clients.conf already matches the render (hash ${plan.confHash}) and freeradius state is as expected — no restart`,
      rolledBack: false,
      confHash: plan.confHash,
      plan: preview(),
      results: [],
    };
  }

  const results: RadiusStepResult[] = [];
  let failed = false;
  let failDetail = "";
  /** set once the managed file may have been mutated → restore is required */
  let mutated = false;

  for (const s of plan.steps) {
    if (s.kind === "stage") {
      try {
        await mkdir(RADIUS_STATE_DIR, { recursive: true });
        await writeFile(RADIUS_STAGE_FILE, plan.content, "utf8");
        results.push({ step: s.step, ok: true, detail: `${plan.content.length} bytes → ${RADIUS_STAGE_FILE}` });
      } catch (err) {
        failed = true;
        failDetail = `stage failed: ${(err as Error).message.slice(0, 200)}`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      continue;
    }

    if (s.kind === "writefile") {
      await writeRadiusState(plan.stateContent);
      results.push({ step: s.step, ok: true, detail: RADIUS_STATE_FILE });
      continue;
    }

    if (s.kind === "verify" && s.cmd === "") {
      // verify managed file hash (fs read — the only verify without a command)
      const live = await readRadiusLiveHash();
      const ok = live === plan.confHash;
      results.push({ step: s.step, ok, detail: ok ? live ?? "" : `live ${live ?? "missing"} — expected ${plan.confHash}` });
      if (!ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: live hash ${live ?? "missing"} — expected ${plan.confHash}`;
      }
      continue;
    }

    if (!radiusStepGuarded(s.cmd)) {
      failed = true;
      failDetail = `step '${s.step}' failed the freeradius command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    if (s.kind === "snapshot") {
      // backup dir via fs (listing snapshot is forensic, not a whitelisted shell op)
      try {
        await mkdir(plan.backupDir, { recursive: true });
        const listing = await readdir("/etc/freeradius/3.0").catch(() => []);
        await writeFile(`${plan.backupDir}/3.0-dir-listing.txt`, listing.sort().join("\n") + "\n", "utf8");
      } catch {
        /* listing is best-effort — the cp below is the actual backup */
      }
    }

    const r = await runTool(s.cmd, 20000);

    if (s.kind === "install") mutated = true;

    if (!r.ok) {
      failed = true;
      failDetail = `step '${s.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    if (s.kind === "verify" && s.cmd === `systemctl is-active ${RADIUS_UNIT}`) {
      // expectation flips with the desired state: active with NAS clients,
      // NOT active in the console-off empty state
      const state = r.stdout.trim();
      const ok = plan.empty ? state !== "active" : state === "active";
      if (!ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: unit state '${state || "unknown"}' — expected ${plan.empty ? "inactive (console-off)" : "active"}`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      results.push({ step: s.step, ok: true, detail: state });
      continue;
    }

    if (s.kind === "verify" && s.cmd.startsWith("ss -lun")) {
      const bound = parseSsForAuthPort(r.stdout);
      const ok = plan.empty ? !bound : bound;
      if (!ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: udp/${RADIUS_AUTH_PORT} ${bound ? "bound" : "not bound"} — expected ${plan.empty ? "unbound (stopped)" : "bound"}`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      results.push({ step: s.step, ok: true, detail: bound ? `udp/${RADIUS_AUTH_PORT} bound` : "unbound" });
      continue;
    }

    results.push({ step: s.step, ok: true, detail: r.stdout.trim().slice(0, 200) || undefined });
  }

  // ── auto-restore: pre-apply clients.conf back + restart (logs convention) ──
  let rolledBack = false;
  if (failed && mutated) {
    const backupFile = `${plan.backupDir}/clients.conf`;
    let src: string | null = null;
    let srcLabel = "";
    try {
      await readFile(backupFile, "utf8");
      src = backupFile; // pre-apply file existed → install the backup copy back
      srcLabel = `pre-apply backup ${backupFile}`;
    } catch {
      // no pre-apply file existed → restore the inert header-only file instead
      try {
        await mkdir(RADIUS_STATE_DIR, { recursive: true });
        await writeFile(RADIUS_STAGE_FILE, renderInertClientsConf(), "utf8");
        src = RADIUS_STAGE_FILE;
        srcLabel = "the inert header-only file (no pre-apply file existed)";
      } catch {
        src = null;
      }
    }
    if (src != null) {
      const install = await runTool(`install -m 0640 -o root -g freerad ${src} ${RADIUS_MANAGED_FILE}`, 10000);
      const restart = await runTool(`systemctl restart ${RADIUS_UNIT}`, 20000);
      rolledBack = install.ok && restart.ok;
      results.push({
        step: "auto-restore",
        ok: rolledBack,
        detail: rolledBack
          ? `pre-apply config restored from ${srcLabel} and freeradius restarted`
          : "restore failed — inspect /etc/freeradius/3.0/clients.conf manually",
      });
    } else {
      results.push({ step: "auto-restore", ok: false, detail: "could not stage the restore source — inspect the managed file manually" });
    }
  }

  // backup dirs are forensic records of pre-apply state — always kept

  return {
    applied: !failed,
    reason: failed ? failDetail : plan.empty
      ? "clients.conf emptied (no NAS clients) and freeradius stopped (console-off)"
      : `freeradius NAS clients converged (hash ${plan.confHash})`,
    rolledBack,
    confHash: plan.confHash,
    backupDir: plan.backupDir,
    plan: preview(),
    results,
  };
}

// ── rollback (restore the newest console backup) ───────────────────────────

export interface RadiusRollbackOutcome {
  rolledBack: boolean;
  refused?: string;
  reason?: string;
  backupFile?: string;
  results: RadiusStepResult[];
}

/**
 * Restore the newest backup-<ts>/clients.conf (the stock Debian file when
 * only console applies have run), re-validate it with `freeradius -CX`, then
 * restart (config valid) or stop (config broken — never run a bad config).
 * The state.json is removed so status reads console-unmanaged afterwards.
 */
export async function rollbackRadiusToOs(exec: boolean): Promise<RadiusRollbackOutcome> {
  const { runTool } = await import("@/lib/host/tools");
  const results: RadiusStepResult[] = [];

  if (!exec || process.env.CONSOLE_OS_APPLY !== "1" || (await import("@/lib/engine")).getDataPlaneMode() !== "host") {
    return {
      rolledBack: false,
      refused: !exec || process.env.CONSOLE_OS_APPLY !== "1"
        ? "CONSOLE_OS_APPLY is off — rollback preview only"
        : "data plane is not in host mode — OS enforcement is preview-only",
      results,
    };
  }

  // newest console-owned backup with a clients.conf inside
  let backupFile: string | null = null;
  try {
    const dirs = (await readdir(RADIUS_STATE_DIR)).filter((d) => RADIUS_BACKUP_DIR_RE.test(d)).sort().reverse();
    for (const d of dirs) {
      const candidate = `${RADIUS_STATE_DIR}/${d}/clients.conf`;
      try {
        await readFile(candidate, "utf8");
        backupFile = candidate;
        break;
      } catch {
        // backup dir without a clients.conf — try the next one
      }
    }
  } catch {
    backupFile = null;
  }

  if (!backupFile) {
    return {
      rolledBack: false,
      refused: "no console backup exists — nothing to roll back (apply once to create backup-<ts>/)",
      results,
    };
  }

  results.push({ step: "select backup", ok: true, detail: backupFile });

  const install = await runTool(`install -m 0640 -o root -g freerad ${backupFile} ${RADIUS_MANAGED_FILE}`, 10000);
  results.push({ step: "install backup", ok: install.ok, detail: install.ok ? RADIUS_MANAGED_FILE : (install.stderr || install.error || "").slice(0, 200) });
  if (!install.ok) {
    return { rolledBack: false, reason: "installing the backup failed — managed file untouched since the last apply", backupFile, results };
  }

  const validate = await runTool("freeradius -CX", 20000);
  const valid = validate.ok;
  results.push({ step: "validate restored config", ok: valid, detail: valid ? "freeradius -CX passed" : (validate.stderr || validate.error || "freeradius -CX failed").slice(0, 300) });

  const unit = valid ? await runTool(`systemctl restart ${RADIUS_UNIT}`, 20000) : await runTool(`systemctl stop ${RADIUS_UNIT}`, 20000);
  results.push({
    step: valid ? `restart ${RADIUS_UNIT}` : `stop ${RADIUS_UNIT} (restored config invalid)`,
    ok: unit.ok,
    detail: unit.ok ? (valid ? "restarted" : "stopped") : (unit.stderr || unit.error || "").slice(0, 200),
  });

  await unlink(RADIUS_STATE_FILE).catch(() => {});
  results.push({ step: "clear state file", ok: true, detail: RADIUS_STATE_FILE });

  const rolledBack = install.ok && unit.ok;
  return {
    rolledBack,
    reason: rolledBack
      ? `restored ${backupFile}${valid ? " and restarted freeradius" : " — restored config failed freeradius -CX, unit stopped"}`
      : "rollback did not fully converge — inspect the results",
    backupFile,
    results,
  };
}

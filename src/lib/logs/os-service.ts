/**
 * Syslog OS service — resolves console SyslogTarget rows into the rsyslog
 * managed-file render and executes/reads live state for the os-status + apply
 * routes. Pure mapping lives in os.ts; everything touching db/exec/fs is here.
 *
 * Server-only (fs/exec/db imports).
 */

import { readFile, writeFile, mkdir, readdir } from "fs/promises";
import { db } from "@/lib/db";
import {
  buildRsyslogApplyPlan,
  computeRsyslogDrift,
  hardRsyslogRefusal,
  parseSsForTarget,
  renderRsyslogConf,
  RSYSLOG_BEGIN_MARKER,
  RSYSLOG_END_MARKER,
  RSYSLOG_MANAGED_FILE,
  RSYSLOG_STAGE_FILE,
  RSYSLOG_STATE_DIR,
  RSYSLOG_STATE_FILE,
  RSYSLOG_UNIT,
  rsyslogConfHash,
  rsyslogStepGuarded,
  type RsyslogApplyPlan,
  type SyslogMinSeverity,
  type SyslogProtocol,
  type SyslogTargetShape,
} from "./os";

export interface RsyslogStateFile {
  confHash: string;
  appliedAt: string;
  targetIds: number[];
}

export async function readRsyslogState(): Promise<RsyslogStateFile | null> {
  try {
    const raw = await readFile(RSYSLOG_STATE_FILE, "utf8");
    const parsed = JSON.parse(raw) as RsyslogStateFile;
    if (!parsed || typeof parsed.confHash !== "string" || !Array.isArray(parsed.targetIds)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function writeRsyslogState(content: string): Promise<void> {
  await mkdir(RSYSLOG_STATE_DIR, { recursive: true });
  await writeFile(RSYSLOG_STATE_FILE, content, "utf8");
}

/** Live managed file — sha256-16 hash, or null when missing/unreadable. */
export async function readRsyslogLiveHash(): Promise<string | null> {
  try {
    const raw = await readFile(RSYSLOG_MANAGED_FILE, "utf8");
    return rsyslogConfHash(raw);
  } catch {
    return null;
  }
}

/** DB rows → pure renderer shapes (defensive enum fallbacks). */
export async function buildRsyslogShapes(tenantId: number): Promise<SyslogTargetShape[]> {
  const rows = await db.syslogTarget.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    host: r.host,
    port: r.port,
    protocol: (["udp", "tcp", "tls"].includes(r.protocol) ? r.protocol : "udp") as SyslogProtocol,
    minSeverity: (["info", "low", "medium", "high", "critical"].includes(r.minSeverity)
      ? r.minSeverity
      : "info") as SyslogMinSeverity,
    enabled: r.enabled,
  }));
}

async function unitActiveOrNull(): Promise<{ unitState: string | null; unitActive: boolean | null }> {
  const { runTool } = await import("@/lib/host/tools");
  // `systemctl is-active` exits non-zero for inactive units → ok:false, but the
  // state word is in stdout either way.
  const r = await runTool(`systemctl is-active ${RSYSLOG_UNIT}`, 5000);
  const unitState = (r.stdout || r.stderr).trim() || null;
  return { unitState, unitActive: unitState === "active" ? true : unitState ? false : null };
}

// ── status ──────────────────────────────────────────────────────────────────

export interface RsyslogTargetOsStatus {
  id: number;
  name: string;
  host: string;
  port: number;
  protocol: SyslogProtocol;
  minSeverity: SyslogMinSeverity;
  enabled: boolean;
  /** live omfwd socket seen by `ss` — informational, never flips inSync */
  socketConnected: boolean | null;
  /** per-target render identity (sha256-16 of its action line); null when disabled */
  renderHash: string | null;
}

export async function readRsyslogOsStatus(tenantId: number): Promise<{
  available: boolean;
  dataPlaneMode: string;
  note: string;
  unitState: string | null;
  managedFile: string;
  inSync: boolean | null;
  driftReasons: string[];
  state: RsyslogStateFile | null;
  targets: RsyslogTargetOsStatus[];
  warnings: string[];
}> {
  const [{ getDataPlaneMode }, { hasTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);
  const mode = getDataPlaneMode();
  const available = (await hasTool("rsyslogd")) && (await hasTool("ss")) && mode === "host";

  const shapes = await buildRsyslogShapes(tenantId);
  const rendered = renderRsyslogConf(shapes);
  const state = await readRsyslogState();

  let unitState: string | null = null;
  let unitActive: boolean | null = null;
  let liveHash: string | null = null;
  let inSync: boolean | null = null;
  let driftReasons: string[] = [];

  const sockets = new Map<number, boolean | null>();
  if (available) {
    const { runTool } = await import("@/lib/host/tools");
    ({ unitState, unitActive } = await unitActiveOrNull());
    liveHash = await readRsyslogLiveHash();
    const drift = computeRsyslogDrift({ renderedContent: rendered.content, liveFileHash: liveHash, unitActive });
    inSync = drift.inSync;
    driftReasons = drift.driftReasons;

    // one ss sweep, reused for every target — sockets are informational only
    const [ssUdp, ssTcp] = await Promise.all([runTool("ss -a -u -p", 5000), runTool("ss -a -t -p", 5000)]);
    for (const t of shapes.filter((s) => s.enabled)) {
      const out = t.protocol === "udp" ? ssUdp.stdout : ssTcp.stdout;
      sockets.set(t.id, parseSsForTarget(out, t.host, t.port, t.protocol));
    }
  }

  const hashById = new Map(rendered.targets.map((t) => [t.id, t.renderHash]));
  const targets: RsyslogTargetOsStatus[] = shapes.map((t) => ({
    id: t.id,
    name: t.name,
    host: t.host,
    port: t.port,
    protocol: t.protocol,
    minSeverity: t.minSeverity,
    enabled: t.enabled,
    socketConnected: t.enabled ? (sockets.get(t.id) ?? null) : null,
    renderHash: hashById.get(t.id) ?? null,
  }));

  return {
    available,
    dataPlaneMode: mode,
    note: available
      ? "rsyslogd + ss present — forwarding applies to /etc/rsyslog.d/99-utm-console.conf on Apply"
      : "rsyslogd/ss unavailable or data plane in simulated mode — OS enforcement is preview-only",
    unitState,
    managedFile: RSYSLOG_MANAGED_FILE,
    inSync,
    driftReasons,
    state,
    targets,
    warnings: rendered.warnings,
  };
}

// ── apply executor (mirrors the qos/HA route pattern) ───────────────────────

export interface RsyslogStepResult {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface RsyslogApplyOutcome {
  applied: boolean;
  refused?: string;
  reason?: string;
  /** zero-churn: live hash + unit already matched — nothing touched */
  skipped?: boolean;
  rolledBack: boolean;
  confHash?: string;
  backupDir?: string;
  plan: { steps: { step: string; cmd: string; kind: string }[]; targets: unknown };
  results: RsyslogStepResult[];
}

/** Managed file present on disk? (drives whether the plan takes a snapshot) */
async function managedFileExists(): Promise<boolean> {
  try {
    await readFile(RSYSLOG_MANAGED_FILE, "utf8");
    return true;
  } catch {
    return false;
  }
}

/**
 * Inert fragment (empty console block) — the restore target when NO managed
 * file existed pre-apply (mirrors the qos convention of restoring a known-good
 * default when the snapshot is empty).
 */
function renderInertFragment(): string {
  return `${RSYSLOG_BEGIN_MARKER}\n${RSYSLOG_END_MARKER}\n`;
}

/**
 * Execute the convergence plan on the appliance (exec gate checked by caller).
 * Snapshot-first; any failure after the install step auto-restores the
 * pre-apply managed file from backup-<ts>/ (or the inert empty fragment when
 * none existed) and restarts rsyslog. The state file is the LAST plan step —
 * only written when every verify passed.
 */
export async function applyRsyslogToOs(tenantId: number, exec: boolean): Promise<RsyslogApplyOutcome> {
  const [{ getDataPlaneMode }, { runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);

  const shapes = await buildRsyslogShapes(tenantId);
  const refusal = hardRsyslogRefusal(shapes);
  const fileExisted = await managedFileExists();
  const mode: RsyslogApplyPlan["mode"] = exec && getDataPlaneMode() === "host" ? "exec" : "plan";
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  const plan: RsyslogApplyPlan = buildRsyslogApplyPlan({
    targets: shapes,
    managedFileExists: fileExisted,
    mode,
    ts,
  });
  const preview = () => ({ steps: plan.steps, targets: plan.targets });

  if (refusal) {
    return { applied: false, refused: refusal, rolledBack: false, plan: preview(), results: [] };
  }
  if (!exec || mode !== "exec") {
    return {
      applied: false,
      refused: !exec
        ? "CONSOLE_OS_APPLY is off — plan preview only (rsyslog command sequence attached)"
        : "data plane is not in host mode — OS enforcement is preview-only",
      rolledBack: false,
      plan: preview(),
      results: [],
    };
  }

  // ── zero-churn: live file already matches the render AND unit is active ──
  const [liveHash, { unitActive }] = await Promise.all([readRsyslogLiveHash(), unitActiveOrNull()]);
  if (liveHash === plan.confHash && unitActive === true) {
    return {
      applied: true,
      skipped: true,
      reason: `managed file already matches the render (hash ${plan.confHash}) and rsyslog is active — no restart`,
      rolledBack: false,
      confHash: plan.confHash,
      plan: preview(),
      results: [],
    };
  }

  const results: RsyslogStepResult[] = [];
  let failed = false;
  let failDetail = "";
  /** set once the managed file may have been mutated → restore is required */
  let mutated = false;

  for (const s of plan.steps) {
    if (s.kind === "stage") {
      try {
        await mkdir(RSYSLOG_STATE_DIR, { recursive: true });
        await writeFile(RSYSLOG_STAGE_FILE, plan.content, "utf8");
        results.push({ step: s.step, ok: true, detail: `${plan.content.length} bytes → ${RSYSLOG_STAGE_FILE}` });
      } catch (err) {
        failed = true;
        failDetail = `stage failed: ${(err as Error).message.slice(0, 200)}`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      continue;
    }

    if (s.kind === "writefile") {
      await writeRsyslogState(plan.stateContent);
      results.push({ step: s.step, ok: true, detail: RSYSLOG_STATE_FILE });
      continue;
    }

    if (s.kind === "verify" && s.cmd === "") {
      // verify managed file hash (fs read — the only verify without a command)
      const live = await readRsyslogLiveHash();
      const ok = live === plan.confHash;
      results.push({ step: s.step, ok, detail: ok ? live ?? "" : `live ${live ?? "missing"} — expected ${plan.confHash}` });
      if (!ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: live hash ${live ?? "missing"} — expected ${plan.confHash}`;
      }
      continue;
    }

    if (!rsyslogStepGuarded(s.cmd)) {
      failed = true;
      failDetail = `step '${s.step}' failed the rsyslog command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    if (s.kind === "snapshot") {
      // backup dir via fs (listing snapshot is forensic, not a whitelisted shell op)
      try {
        await mkdir(plan.backupDir, { recursive: true });
        const listing = await readdir("/etc/rsyslog.d").catch(() => []);
        await writeFile(`${plan.backupDir}/rsyslog.d-listing.txt`, listing.sort().join("\n") + "\n", "utf8");
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

    if (s.kind === "verify" && s.cmd.startsWith("systemctl is-active") && r.stdout.trim() !== "active") {
      failed = true;
      failDetail = `step '${s.step}' failed: unit state '${r.stdout.trim() || "unknown"}' — expected 'active'`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    results.push({ step: s.step, ok: true, detail: r.stdout.trim().slice(0, 200) || undefined });
  }

  // ── auto-restore: pre-apply managed file back + restart (qos convention) ──
  let rolledBack = false;
  if (failed && mutated) {
    const backupFile = `${plan.backupDir}/99-utm-console.conf`;
    let src: string | null = null;
    let srcLabel: string;
    try {
      await readFile(backupFile, "utf8");
      src = backupFile; // pre-apply file existed → install the backup copy back
      srcLabel = `pre-apply backup ${backupFile}`;
    } catch {
      // no pre-apply file existed → restore the inert empty fragment instead
      try {
        await mkdir(RSYSLOG_STATE_DIR, { recursive: true });
        await writeFile(RSYSLOG_STAGE_FILE, renderInertFragment(), "utf8");
        src = RSYSLOG_STAGE_FILE;
        srcLabel = "the inert empty fragment (no pre-apply file existed)";
      } catch {
        src = null;
        srcLabel = "";
      }
    }
    if (src != null) {
      const install = await runTool(`install -m 0644 ${src} ${RSYSLOG_MANAGED_FILE}`, 10000);
      const restart = await runTool(`systemctl restart ${RSYSLOG_UNIT}`, 20000);
      rolledBack = install.ok && restart.ok;
      results.push({
        step: "auto-restore",
        ok: rolledBack,
        detail: rolledBack
          ? `pre-apply config restored from ${srcLabel} and rsyslog restarted`
          : "restore failed — inspect /etc/rsyslog.d/99-utm-console.conf manually",
      });
    } else {
      results.push({ step: "auto-restore", ok: false, detail: "could not stage the restore source — inspect the managed file manually" });
    }
  }

  // backup dirs are forensic records of pre-apply state — always kept

  return {
    applied: !failed,
    reason: failed ? failDetail : `rsyslog forwarding converged (hash ${plan.confHash})`,
    rolledBack,
    confHash: plan.confHash,
    backupDir: plan.backupDir,
    plan: preview(),
    results,
  };
}

/** re-export for tests that want the hash helper without importing crypto */
export { rsyslogConfHash };

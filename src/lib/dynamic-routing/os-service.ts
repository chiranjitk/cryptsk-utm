/**
 * Dynamic Routing OS service — resolves the console routing config (BGP
 * settings/neighbors, OSPF settings/interfaces, policy objects, BFD profiles)
 * into the deterministic FRR render and executes/reads live state for the
 * os-status + validate + apply routes and the real-RIB sync. Pure mapping
 * lives in os.ts; everything touching db/exec/fs is here.
 *
 * Target: Debian 13, FRR 10.3 ACTIVE, vtysh at /usr/bin/vtysh. NOTE:
 * frr-reload.py is NOT installed — validation is `vtysh -C -f <file>` (parse
 * without applying).
 *
 * Server-only (fs/exec/db imports).
 */

import osMod from "os";
import { readFile, writeFile, mkdir, rm } from "fs/promises";
import { db } from "@/lib/db";
import {
  buildDrApplyPlan,
  computeDrDrift,
  daemonSetMatches,
  drStepGuarded,
  expectedDaemonSet,
  frrConfHash,
  interpretVtyshValidate,
  isDrBackupPath,
  parseBgpSummaryJson,
  parseDaemonsFile,
  parseOspfNeighborJson,
  parseVtyshRouteJson,
  renderFrrConf,
  renderFrrDaemons,
  DR_STAGE_CONF,
  DR_STAGE_DAEMONS,
  DR_STATE_DIR,
  DR_STATE_FILE,
  FRR_CONF,
  FRR_DAEMONS,
  FRR_DAEMON_KEYS,
  verifyRunningConfig,
  type BfdProfileShape,
  type BgpNeighborShape,
  type BgpSettingsShape,
  type CommunityListShape,
  type FrrRenderInput,
  type OspfInterfaceShape,
  type OspfSettingsShape,
  type PrefixListShape,
  type RouteMapShape,
} from "./os";

// ── DB rows → pure renderer shapes ──────────────────────────────────────────

interface ParsedEntries {
  ok: boolean;
  value: unknown[];
}

function parseEntriesJson(json: string): ParsedEntries {
  try {
    const parsed = JSON.parse(json) as unknown;
    if (Array.isArray(parsed)) return { ok: true, value: parsed };
    return { ok: false, value: [] };
  } catch {
    return { ok: false, value: [] };
  }
}

/** All routing config rows for one tenant → FrrRenderInput (server-only). */
export async function buildDrShapes(tenantId: number): Promise<FrrRenderInput & { tenantId: number }> {
  const [bgpSettings, neighbors, ospfSettings, ospfIfaces, prefixLists, routeMaps, communityLists, bfdProfiles] =
    await Promise.all([
      db.bgpSettings.findFirst({ where: { tenantId } }),
      db.bgpNeighbor.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
      db.ospfSettings.findFirst({ where: { tenantId } }),
      db.ospfInterface.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
      db.prefixList.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
      db.routeMap.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
      db.communityList.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
      db.bfdProfile.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    ]);

  const bgp: BgpSettingsShape | null = bgpSettings
    ? { localAs: bgpSettings.localAs, routerId: bgpSettings.routerId, gracefulRestart: bgpSettings.gracefulRestart, enabled: bgpSettings.enabled }
    : null;

  const neighborShapes: BgpNeighborShape[] = neighbors.map((n) => ({
    id: n.id,
    name: n.name,
    remoteAs: n.remoteAs,
    peerIp: n.peerIp,
    password: n.password,
    keepaliveSec: n.keepaliveSec,
    holdtimeSec: n.holdtimeSec,
    gracefulRestart: n.gracefulRestart,
    bfdEnabled: n.bfdEnabled,
    bfdProfileId: n.bfdProfileId,
    prefixListInId: n.prefixListInId,
    prefixListOutId: n.prefixListOutId,
    routeMapInId: n.routeMapInId,
    routeMapOutId: n.routeMapOutId,
    localAs: n.localAs,
    ebgpMultihop: n.ebgpMultihop,
    enabled: n.enabled,
  }));

  const ospf: OspfSettingsShape | null = ospfSettings
    ? {
        routerId: ospfSettings.routerId,
        referenceBandwidth: ospfSettings.referenceBandwidth,
        gracefulRestart: ospfSettings.gracefulRestart,
        enabled: ospfSettings.enabled,
      }
    : null;

  const ifaceShapes: OspfInterfaceShape[] = ospfIfaces.map((i) => ({
    id: i.id,
    interfaceName: i.interfaceName,
    area: i.area,
    helloSec: i.helloSec,
    deadSec: i.deadSec,
    cost: i.cost,
    networkType: (["broadcast", "p2p", "nbma"].includes(i.networkType) ? i.networkType : "broadcast") as OspfInterfaceShape["networkType"],
    passive: i.passive,
    enabled: i.enabled,
  }));

  const plShapes: PrefixListShape[] = prefixLists.map((p) => {
    const entries = parseEntriesJson(p.entries);
    return {
      id: p.id,
      name: p.name,
      family: (p.family === "ipv6" ? "ipv6" : "ipv4") as PrefixListShape["family"],
      entries: (entries.ok ? (entries.value as PrefixListShape["entries"]) : []).filter(
        (e) => typeof e === "object" && e !== null && typeof (e as { seq?: unknown }).seq === "number",
      ),
    };
  });

  const rmShapes: RouteMapShape[] = routeMaps.map((r) => {
    const entries = parseEntriesJson(r.entries);
    return {
      id: r.id,
      name: r.name,
      entries: (entries.ok ? (entries.value as RouteMapShape["entries"]) : []).filter(
        (e) => typeof e === "object" && e !== null && typeof (e as { seq?: unknown }).seq === "number",
      ),
    };
  });

  const clShapes: CommunityListShape[] = communityLists.map((c) => {
    const entries = parseEntriesJson(c.entries);
    return {
      id: c.id,
      name: c.name,
      type: (c.type === "expanded" ? "expanded" : "standard") as CommunityListShape["type"],
      entries: (entries.ok ? entries.value : []).filter((e): e is string => typeof e === "string"),
    };
  });

  const bfdShapes: BfdProfileShape[] = bfdProfiles.map((b) => ({
    id: b.id,
    name: b.name,
    rxIntervalMs: b.rxIntervalMs,
    txIntervalMs: b.txIntervalMs,
    detectMultiplier: b.detectMultiplier,
    enabled: b.enabled,
  }));

  return {
    tenantId,
    hostname: osMod.hostname(),
    bgp,
    neighbors: neighborShapes,
    ospf,
    ospfIfaces: ifaceShapes,
    prefixLists: plShapes,
    routeMaps: rmShapes,
    communityLists: clShapes,
    bfdProfiles: bfdShapes,
  };
}

export interface RenderedTenantFrr {
  confText: string;
  confHash: string;
  daemonsText: string;
  daemonSet: Record<string, boolean>;
  warnings: string[];
}

/** Deterministic render for one tenant (pure output, DB-derived input). */
export function renderTenantFrr(input: FrrRenderInput): RenderedTenantFrr {
  const rendered = renderFrrConf(input);
  const daemonSet = expectedDaemonSet(input);
  return {
    confText: rendered.confText,
    confHash: frrConfHash(rendered.confText),
    daemonsText: renderFrrDaemons(daemonSet),
    daemonSet,
    warnings: rendered.warnings,
  };
}

async function readFileOrNull(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}

export interface DrStateFile {
  confHash: string;
  daemonSet: Record<string, boolean>;
  appliedAt: string;
}

export async function readDrState(): Promise<DrStateFile | null> {
  try {
    const raw = await readFile(DR_STATE_FILE, "utf8");
    const parsed = JSON.parse(raw) as DrStateFile;
    if (!parsed || typeof parsed.confHash !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeDrState(content: string): Promise<void> {
  await mkdir(DR_STATE_DIR, { recursive: true });
  await writeFile(DR_STATE_FILE, content, "utf8");
}

/** BgpSettings singleton get-or-create (defaults: localAs 65000, routerId 10.10.0.1).
 *  Transactional: concurrent first-touches serialize on SQLite's write lock;
 *  a lost create race (P2002) re-finds and returns the winner's row. */
export async function getOrCreateBgpSettings(tenantId: number) {
  return db.$transaction(async (tx) => {
    const existing = await tx.bgpSettings.findFirst({ where: { tenantId } });
    if (existing) return existing;
    try {
      return await tx.bgpSettings.create({
        data: { tenantId, localAs: 65000, routerId: "10.10.0.1", gracefulRestart: false, enabled: false },
      });
    } catch (err) {
      // P2002 — a concurrent create won the race; re-find and return it
      const raced = await tx.bgpSettings.findFirst({ where: { tenantId } });
      if (raced) return raced;
      throw err;
    }
  });
}

// ── status (+ drift + live state write-back) ────────────────────────────────

export interface DrNeighborOsStatus {
  id: number;
  name: string;
  peerIp: string;
  remoteAs: number;
  liveState: string | null;
  liveUptimeSec: number | null;
  livePrefixesReceived: number | null;
}

export interface DrOsStatus {
  available: boolean;
  dataPlaneMode: string;
  gateOn: boolean;
  note: string;
  serviceState: string | null;
  confPath: string;
  daemonsPath: string;
  /** live frr.conf hash (null when missing) */
  liveConfHash: string | null;
  /** rendered conf hash — the convergence target */
  expectedConfHash: string;
  osConfHash: string | null;
  managedByConsole: boolean;
  inSync: boolean | null;
  driftReasons: string[];
  /** rendered daemon set vs live /etc/frr/daemons */
  daemonSet: Record<string, boolean>;
  liveDaemonSet: Record<string, boolean> | null;
  daemonsChanged: boolean | null;
  state: DrStateFile | null;
  neighbors: DrNeighborOsStatus[];
  /** rendered frr.conf preview (same text an apply would install) */
  confPreview: string;
  warnings: string[];
  /** BGP session start/stop in the UI still writes DB state — on a real
   *  appliance FRR owns session state and the os-status write-back corrects
   *  it on the next poll. */
  simulatedSessionNote: string;
}

export async function readDynamicRoutingOsStatus(tenantId: number): Promise<DrOsStatus> {
  const [{ getDataPlaneMode }, { hasTool, runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);
  const mode = getDataPlaneMode();
  const gateOn = process.env.CONSOLE_OS_APPLY === "1" && mode === "host";
  const available = mode === "host" && (await hasTool("vtysh"));

  const input = await buildDrShapes(tenantId);
  const rendered = renderTenantFrr(input);
  const daemonSet = rendered.daemonSet;
  const settings = await getOrCreateBgpSettings(tenantId);

  let serviceState: string | null = null;
  let liveConfHash: string | null = null;
  let liveDaemonSet: Record<string, boolean> | null = null;
  let daemonsChanged: boolean | null = null;
  let inSync: boolean | null = null;
  let driftReasons: string[] = [];

  const liveConfText = available ? await readFileOrNull(FRR_CONF) : null;
  if (liveConfText) liveConfHash = frrConfHash(liveConfText);
  const liveDaemonsText = available ? await readFileOrNull(FRR_DAEMONS) : null;
  if (liveDaemonsText) {
    liveDaemonSet = parseDaemonsFile(liveDaemonsText);
    daemonsChanged = !daemonSetMatches(liveDaemonSet, daemonSet);
  }

  if (available) {
    // systemctl is-active exits non-zero for inactive units — the word is in stdout
    const r = await runTool("systemctl is-active frr", 5000);
    serviceState = (r.stdout || r.stderr).trim() || null;
    const serviceActive = serviceState === "active";
    const drift = computeDrDrift({
      available,
      serviceActive,
      liveConfText,
      liveConfHash,
      osConfHash: settings.osConfHash,
      expectedHash: rendered.confHash,
      daemonSetMatch: liveDaemonSet ? !daemonsChanged : null,
      bgpEnabled: input.bgp?.enabled ?? false,
      bgpLocalAs: input.bgp?.localAs ?? null,
      ospfEnabled: input.ospf?.enabled ?? false,
    });
    inSync = drift.inSync;
    driftReasons = drift.reasons;
  }

  // ── live state write-back (only when frr is actually serving queries) ───
  const neighbors: DrNeighborOsStatus[] = input.neighbors.map((n) => ({
    id: n.id,
    name: n.name,
    peerIp: n.peerIp,
    remoteAs: n.remoteAs,
    liveState: null,
    liveUptimeSec: null,
    livePrefixesReceived: null,
  }));

  if (available && serviceState === "active") {
    const bgpRes = await runTool('vtysh -c "show bgp summary json"', 10000);
    if (bgpRes.ok && !bgpRes.stderr.trim()) {
      const { peers, parseError } = parseBgpSummaryJson(bgpRes.stdout);
      if (!parseError && peers.length > 0) {
        for (const peer of peers) {
          const row = await db.bgpNeighbor.findFirst({ where: { tenantId, peerIp: peer.ip } });
          if (!row) continue;
          const idx = neighbors.findIndex((n) => n.id === row.id);
          if (idx >= 0) {
            neighbors[idx].liveState = peer.state;
            neighbors[idx].liveUptimeSec = peer.uptimeSec;
            neighbors[idx].livePrefixesReceived = peer.prefixesReceived;
          }
          const next =
            peer.state === "established"
              ? {
                  state: "established" as const,
                  uptimeSec: peer.uptimeSec ?? row.uptimeSec,
                  prefixesReceived: peer.prefixesReceived ?? row.prefixesReceived,
                }
              : { state: peer.state as typeof row.state, uptimeSec: 0, prefixesReceived: 0 };
          if (
            row.state !== next.state ||
            row.uptimeSec !== next.uptimeSec ||
            row.prefixesReceived !== next.prefixesReceived
          ) {
            await db.bgpNeighbor
              .update({ where: { id: row.id }, data: next })
              .catch(() => {});
          }
        }
      }
    }

    const ospfRes = await runTool('vtysh -c "show ip ospf neighbor json"', 10000);
    if (ospfRes.ok && !ospfRes.stderr.trim()) {
      const { adjacencies, parseError } = parseOspfNeighborJson(ospfRes.stdout);
      if (!parseError && adjacencies.length > 0) {
        for (const adj of adjacencies) {
          const ifName = adj.ifaceName;
          if (!ifName) continue;
          const row = await db.ospfInterface.findFirst({ where: { tenantId, interfaceName: ifName } });
          if (!row || row.neighborState === adj.state) continue;
          await db.ospfInterface
            .update({
              where: { id: row.id },
              data: { neighborState: adj.state, neighborIp: adj.neighborIp },
            })
            .catch(() => {});
        }
      }
    }
  }

  const state = await readDrState();

  return {
    available,
    dataPlaneMode: mode,
    gateOn,
    note: available
      ? "vtysh present — Apply converges /etc/frr/frr.conf + /etc/frr/daemons (reload, restart on daemon-set change)"
      : "vtysh unavailable or data plane in simulated mode — OS enforcement is preview-only",
    serviceState,
    confPath: FRR_CONF,
    daemonsPath: FRR_DAEMONS,
    liveConfHash,
    expectedConfHash: rendered.confHash,
    osConfHash: settings.osConfHash,
    managedByConsole: Boolean(settings.osConfHash && liveConfHash && settings.osConfHash === liveConfHash),
    inSync,
    driftReasons,
    daemonSet,
    liveDaemonSet,
    daemonsChanged,
    state,
    neighbors,
    confPreview: rendered.confText,
    warnings: rendered.warnings,
    simulatedSessionNote:
      "BGP session start/stop buttons write the simulated DB state machine; on a real appliance FRR owns session state — os-status polls correct neighbor.state/uptime/prefixes from `show bgp summary json`.",
  };
}

// ── validate (render + `vtysh -C -f stage` on a temp file, NO OS change) ────

export interface DrValidateResult {
  available: boolean;
  ok: boolean | null;
  confText: string;
  confHash: string;
  daemonsText: string;
  daemonSet: Record<string, boolean>;
  detail: string;
  warnings: string[];
}

export async function validateDynamicRouting(tenantId: number): Promise<DrValidateResult> {
  const [{ getDataPlaneMode }, { hasTool, runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);
  const input = await buildDrShapes(tenantId);
  const rendered = renderTenantFrr(input);
  const base: DrValidateResult = {
    available: false,
    ok: null,
    confText: rendered.confText,
    confHash: rendered.confHash,
    daemonsText: rendered.daemonsText,
    daemonSet: rendered.daemonSet,
    detail: "vtysh not available on this host — frr.conf rendered for preview only (validation unavailable)",
    warnings: rendered.warnings,
  };
  if (getDataPlaneMode() !== "host" || !(await hasTool("vtysh"))) return base;

  const cmd = `vtysh -C -f ${DR_STAGE_CONF}`;
  if (!drStepGuarded(cmd)) {
    return { ...base, ok: false, detail: "validation command failed the command whitelist" };
  }
  let staged = false;
  try {
    await mkdir(DR_STATE_DIR, { recursive: true });
    await writeFile(DR_STAGE_CONF, rendered.confText, "utf8");
    staged = true;
  } catch (err) {
    return { ...base, ok: false, detail: `stage write failed: ${(err as Error).message.slice(0, 200)}` };
  }
  const r = await runTool(cmd, 15000);
  if (staged) await rm(DR_STAGE_CONF, { force: true }).catch(() => {});
  const verdict = interpretVtyshValidate(`${r.stderr}${r.stdout}`, r.ok);
  return {
    ...base,
    available: true,
    ok: verdict.ok,
    detail: verdict.detail,
    warnings: [...rendered.warnings, ...verdict.warnings],
  };
}

// ── apply executor (mirrors the logs/HA route pattern) ──────────────────────

export interface DrStepResult {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface DrApplyOutcome {
  applied: boolean;
  refused?: string;
  reason?: string;
  /** zero-churn: live hash + daemon set + unit already matched — nothing touched */
  skipped?: boolean;
  rolledBack: boolean;
  confHash?: string;
  backupConf?: string;
  backupDaemons?: string;
  daemonsChanged?: boolean;
  plan: { steps: { step: string; cmd: string; kind: string }[]; confText: string; daemonsText: string };
  results: DrStepResult[];
}

export async function applyDynamicRoutingToOs(tenantId: number, exec: boolean): Promise<DrApplyOutcome> {
  const [{ getDataPlaneMode }, { hasTool, runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);

  const input = await buildDrShapes(tenantId);
  const rendered = renderTenantFrr(input);
  const settings = await getOrCreateBgpSettings(tenantId);
  const mode = getDataPlaneMode();
  const gateOn = exec && mode === "host" && (await hasTool("vtysh"));
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  const liveDaemonsText = gateOn ? await readFileOrNull(FRR_DAEMONS) : null;
  const daemonsChanged = liveDaemonsText
    ? !daemonSetMatches(parseDaemonsFile(liveDaemonsText), rendered.daemonSet)
    : true; // unknown live state → take the restart path (safest for daemon ops)

  const plan = buildDrApplyPlan({
    confText: rendered.confText,
    confHash: rendered.confHash,
    daemonSet: rendered.daemonSet,
    daemonsChanged,
    bgpEnabled: input.bgp?.enabled ?? false,
    bgpLocalAs: input.bgp?.localAs ?? null,
    ospfEnabled: input.ospf?.enabled ?? false,
    mode: gateOn ? "exec" : "plan",
    ts,
  });
  const preview = () => ({ steps: plan.steps, confText: plan.confText, daemonsText: plan.daemonsText });

  if (!gateOn) {
    return {
      applied: false,
      refused: !exec
        ? "CONSOLE_OS_APPLY is off — plan preview only (frr.conf + command sequence attached)"
        : "vtysh unavailable or data plane is not in host mode — OS enforcement is preview-only",
      rolledBack: false,
      confHash: plan.confHash,
      daemonsChanged,
      plan: preview(),
      results: [],
    };
  }

  // ── zero-churn: live conf already matches the render AND unit is active ──
  const [liveConfText, svc] = await Promise.all([readFileOrNull(FRR_CONF), runTool("systemctl is-active frr", 5000)]);
  if (liveConfText && frrConfHash(liveConfText) === plan.confHash && !daemonsChanged && svc.stdout.trim() === "active") {
    return {
      applied: true,
      skipped: true,
      reason: `frr.conf already matches the render (hash ${plan.confHash}) and frr is active — no restart`,
      rolledBack: false,
      confHash: plan.confHash,
      daemonsChanged,
      plan: preview(),
      results: [],
    };
  }

  const results: DrStepResult[] = [];
  let failed = false;
  let failDetail = "";
  /** set once /etc/frr may have been mutated → restore is required */
  let mutated = false;

  for (const s of plan.steps) {
    if (s.kind === "stage") {
      try {
        await mkdir(DR_STATE_DIR, { recursive: true });
        if (s.step === "stage frr.conf") await writeFile(DR_STAGE_CONF, plan.confText, "utf8");
        else await writeFile(DR_STAGE_DAEMONS, plan.daemonsText, "utf8");
        results.push({ step: s.step, ok: true });
      } catch (err) {
        failed = true;
        failDetail = `stage failed: ${(err as Error).message.slice(0, 200)}`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      continue;
    }

    if (s.kind === "writefile") {
      await writeDrState(plan.stateContent);
      results.push({ step: s.step, ok: true, detail: DR_STATE_FILE });
      continue;
    }

    if (s.kind === "verify" && s.cmd === 'vtysh -c "show running-config"') {
      if (!drStepGuarded(s.cmd)) {
        failed = true;
        failDetail = `step '${s.step}' failed the dynamic-routing command whitelist — execution aborted`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      const r = await runTool(s.cmd, 15000);
      const check = verifyRunningConfig(r.ok ? r.stdout : "", {
        bgpEnabled: input.bgp?.enabled ?? false,
        bgpLocalAs: input.bgp?.localAs ?? null,
        ospfEnabled: input.ospf?.enabled ?? false,
      });
      if (!r.ok || !check.ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: missing ${check.missing.join(", ") || "output"} in show running-config`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      results.push({ step: s.step, ok: true, detail: "expected router blocks present in running-config" });
      continue;
    }

    if (!drStepGuarded(s.cmd)) {
      failed = true;
      failDetail = `step '${s.step}' failed the dynamic-routing command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
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

  // ── auto-rollback: restore both backups + restart frr (post-install only) ──
  let rolledBack = false;
  if (failed && mutated && isDrBackupPath(plan.backupConf) && isDrBackupPath(plan.backupDaemons)) {
    const installConf = await runTool(
      `install -m 0640 -o frr -g frr ${plan.backupConf} ${FRR_CONF}`,
      10000,
    );
    const installDaemons = await runTool(
      `install -m 0640 -o frr -g frr ${plan.backupDaemons} ${FRR_DAEMONS}`,
      10000,
    );
    const restart = await runTool("systemctl restart frr", 20000);
    rolledBack = installConf.ok && installDaemons.ok && restart.ok;
    results.push({
      step: "auto-rollback",
      ok: rolledBack,
      detail: rolledBack
        ? "previous frr.conf + daemons restored and frr restarted"
        : `restore failed: ${installConf.error ?? installDaemons.error ?? restart.error ?? "unknown"} — inspect /etc/frr manually`,
    });
  }

  // ── persist the applied hash LAST (only on a fully converged apply) ──────
  if (!failed) {
    await db.bgpSettings
      .update({ where: { id: settings.id }, data: { osConfHash: plan.confHash, osAppliedAt: new Date() } })
      .catch(() => {});
  }

  return {
    applied: !failed,
    reason: failed ? failDetail : `frr.conf converged (hash ${plan.confHash})`,
    rolledBack,
    confHash: plan.confHash,
    backupConf: plan.backupConf,
    backupDaemons: plan.backupDaemons,
    daemonsChanged,
    plan: preview(),
    results,
  };
}

// ── real-RIB sync (`vtysh -c "show ip route json"` → rib_routes) ────────────

export interface RibSyncResult {
  added: number;
  updated: number;
  removed: number;
  total: number;
  byProtocol: { bgp: number; ospf: number; static: number; connected: number };
  source: "live-frr";
}

/**
 * Read the REAL kernel/FRR routing table and upsert it into rib_routes
 * (tenant-scoped), replacing stale rows. Returns null when the live read is
 * impossible (simulated mode, vtysh missing, frr inactive, unparseable json)
 * — the caller then falls back to the simulated regenerateRib honestly.
 */
export async function syncRibFromVtysh(tenantId: number): Promise<RibSyncResult | null> {
  const [{ getDataPlaneMode }, { hasTool, runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);
  if (getDataPlaneMode() !== "host") return null;
  if (!(await hasTool("vtysh"))) return null;
  const svc = await runTool("systemctl is-active frr", 4000);
  if (svc.stdout.trim() !== "active") return null;

  const cmd = 'vtysh -c "show ip route json"';
  if (!drStepGuarded(cmd)) return null;
  const r = await runTool(cmd, 10000);
  if (!r.ok) return null;
  const parsed = parseVtyshRouteJson(r.stdout);
  if (parsed.parseError) return null;

  const { rows } = parsed;
  const existing = await db.ribRoute.findMany({ where: { tenantId } });
  const byKey = new Map(existing.map((row) => [`${row.protocol}|${row.prefix}`, row]));

  let added = 0;
  let updated = 0;
  const keptIds: number[] = [];

  for (const row of rows) {
    const match = byKey.get(`${row.protocol}|${row.prefix}`);
    if (match) {
      await db.ribRoute.update({
        where: { id: match.id },
        data: {
          nextHop: row.nextHop,
          interfaceName: row.interfaceName,
          metric: row.metric,
          localPref: row.localPref,
          asPath: row.asPath,
        },
      });
      keptIds.push(match.id);
      updated++;
    } else {
      const created = await db.ribRoute.create({
        data: {
          tenantId,
          protocol: row.protocol,
          prefix: row.prefix,
          nextHop: row.nextHop,
          interfaceName: row.interfaceName,
          metric: row.metric,
          localPref: row.localPref,
          asPath: row.asPath,
        },
      });
      keptIds.push(created.id);
      added++;
    }
  }

  const stale = existing.filter((row) => !keptIds.includes(row.id));
  if (stale.length > 0) {
    await db.ribRoute.deleteMany({ where: { id: { in: stale.map((row) => row.id) } } });
  }

  const byProtocol = { bgp: 0, ospf: 0, static: 0, connected: 0 };
  for (const row of rows) byProtocol[row.protocol]++;

  return { added, updated, removed: stale.length, total: rows.length, byProtocol, source: "live-frr" };
}

// re-export for tests that want the hash helper without importing crypto
export { frrConfHash, parseDaemonsFile, daemonSetMatches, FRR_DAEMON_KEYS };

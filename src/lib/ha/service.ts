/**
 * HA service (M10) — HaConfig singleton + runtime status.
 * Per M10-SYSTEM.md §5.1 (Keepalived semantics):
 *   - priority HIGHER wins master election (SCHEMA.md correction);
 *   - HOST mode (ADR-021): REAL runtime — keepalived unit state via systemd,
 *     VIP presence from the live interface address list, peer reachability via
 *     real ICMP ping, tracked interfaces from real operstate;
 *   - SIMULATED mode (legacy demo): the sandbox peer is fictional — heartbeat
 *     is deterministic (reachable while HA is enabled, age 0-4 s);
 *   - tracked interfaces map to real link state in host mode, else
 *     NetworkInterface.enabled (Keepalived `track_interface` semantics).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { getDataPlaneMode } from "@/lib/engine";
import { pingHost, readServiceStates, runTool, hasTool } from "@/lib/host/tools";
import { readInterfaces } from "@/lib/host/proc";
import {
  KEEPALIVED_CONF,
  haConfHash,
  parseKeepalivedConf,
  parseVrrpStateFromJournal,
  computeHaDrift,
  type HaKeepalivedInput,
  type HaOsFacts,
} from "@/lib/ha/os";
import { readFile } from "fs/promises";
import type { HaConfigInput } from "@/lib/validators/system";

// ── DTOs ────────────────────────────────────────────────────────────────────

export type HaConfigDTO = {
  id: number;
  enabled: boolean;
  role: string;
  priority: number;
  virtualIp: string | null;
  ifaceName: string;
  peerIp: string | null;
  syncConfig: boolean;
  sessionSync: boolean;
  trackedInterfaces: string[];
  failAfterSec: number;
  holdDownSec: number;
  vrid: number;
  advertIntSec: number;
  /** write-only secret — DTOs carry presence only; reveal via POST /ha/config/reveal */
  hasAuthPass: boolean;
  preempt: boolean;
  osConfHash: string | null;
  osAppliedAt: string | null;
};

export type HaTrackedIfaceState = {
  name: string;
  up: boolean;
};

export type HaStatusDTO = {
  localRole: "disabled" | "active" | "standby";
  enabled: boolean;
  virtualIp: string | null;
  ifaceName: string;
  peerIp: string | null;
  peerReachable: boolean;
  /** true ONLY in simulated mode; host mode reports real reachability */
  peerReachabilitySimulated: boolean;
  heartbeatAgeSec: number;
  priority: number;
  failAfterSec: number;
  holdDownSec: number;
  holdDownRemainingSec: number;
  lastFailover: string | null;
  failoverCount: number;
  trackedInterfaces: HaTrackedIfaceState[];
  configSynced: boolean;
  sessionSynced: boolean;
  /** real Keepalived runtime on the appliance (host mode only) */
  os: HaOsStatus;
};

export type HaOsStatus = {
  available: boolean;
  serviceState: string | null;
  vrrpState: "master" | "backup" | "fault" | null;
  vipPresent: boolean;
  managedByConsole: boolean;
  inSync: boolean;
  driftReasons: string[];
  instanceName: string | null;
  conntrackdState: string | null;
  confHash: string | null;
  osAppliedAt: string | null;
};

const fieldErr = (field: string, message: string) =>
  ApiError.validation(message, { fieldErrors: { [field]: [message] } });

// ── Config singleton (transactional get-or-create per tenant) ──────────────

const HA_CONFIG_DEFAULTS = {
  enabled: false,
  role: "disabled",
  priority: 100,
  ifaceName: "lan0",
  trackedInterfaces: "[]",
  vrid: 51,
  advertIntSec: 1,
  preempt: true,
} as const;

/**
 * Transactional get-or-create for the per-tenant singleton. Two concurrent
 * first-touches serialize on SQLite's write lock inside the transaction; a
 * lost create race (P2002) re-finds and returns the winner's row.
 */
export async function getHaConfigRow(tenantId: number) {
  return db.$transaction(async (tx) => {
    const existing = await tx.haConfig.findFirst({ where: { tenantId } });
    if (existing) return existing;
    try {
      return await tx.haConfig.create({ data: { tenantId, ...HA_CONFIG_DEFAULTS } });
    } catch (err) {
      // P2002 — a concurrent create won the race; re-find inside and return it
      const raced = await tx.haConfig.findFirst({ where: { tenantId } });
      if (raced) return raced;
      throw err;
    }
  });
}

function toConfigDTO(row: {
  id: number;
  enabled: boolean;
  role: string;
  priority: number;
  virtualIp: string | null;
  ifaceName: string;
  peerIp: string | null;
  syncConfig: boolean;
  sessionSync: boolean;
  trackedInterfaces: string;
  failAfterSec: number;
  holdDownSec: number;
  vrid: number;
  advertIntSec: number;
  authPass: string | null;
  preempt: boolean;
  osConfHash: string | null;
  osAppliedAt: Date | null;
}): HaConfigDTO {
  return {
    id: row.id,
    enabled: row.enabled,
    role: row.role,
    priority: row.priority,
    virtualIp: row.virtualIp,
    ifaceName: row.ifaceName,
    peerIp: row.peerIp,
    syncConfig: row.syncConfig,
    sessionSync: row.sessionSync,
    trackedInterfaces: parseJson<string[]>(row.trackedInterfaces, []),
    failAfterSec: row.failAfterSec,
    holdDownSec: row.holdDownSec,
    vrid: row.vrid,
    advertIntSec: row.advertIntSec,
    hasAuthPass: row.authPass !== null && row.authPass.length > 0,
    preempt: row.preempt,
    osConfHash: row.osConfHash,
    osAppliedAt: row.osAppliedAt ? row.osAppliedAt.toISOString() : null,
  };
}

export async function getHaConfig(tenantId: number): Promise<HaConfigDTO> {
  const row = await getHaConfigRow(tenantId);
  return toConfigDTO(row);
}

/** Collect every IPv4 literal found in interface config JSON blobs (peerIp sanity check). */
async function localIfaceIps(tenantId: number): Promise<Set<string>> {
  const rows = await db.networkInterface.findMany({ where: { tenantId }, select: { config: true } });
  const ips = new Set<string>();
  const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const walk = (v: unknown): void => {
    if (typeof v === "string") {
      if (IPV4.test(v)) ips.add(v);
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  for (const r of rows) walk(parseJson<unknown>(r.config, {}));
  return ips;
}

export async function putHaConfig(tenantId: number, body: HaConfigInput): Promise<HaConfigDTO> {
  // referenced ifaces must exist (logical refs into interfaces.name)
  const ifaces = await db.networkInterface.findMany({
    where: { tenantId },
    select: { name: true, enabled: true },
  });
  const names = new Set(ifaces.map((i) => i.name));
  if (!names.has(body.ifaceName)) {
    throw fieldErr("ifaceName", `Interface "${body.ifaceName}" does not exist`);
  }
  for (const t of body.trackedInterfaces) {
    if (!names.has(t)) throw fieldErr("trackedInterfaces", `Interface "${t}" does not exist`);
  }

  // VIP and peer must not collide (split-brain sanity, M10 §5.1)
  const vipAddr = body.virtualIp?.split("/")[0];
  if (vipAddr && body.peerIp && vipAddr === body.peerIp) {
    throw fieldErr("peerIp", "Peer IP must differ from the virtual IP");
  }
  // peerIp must not be any local interface address (M10 §5.1)
  if (body.peerIp) {
    const local = await localIfaceIps(tenantId);
    if (local.has(body.peerIp)) {
      throw fieldErr("peerIp", "Peer IP must not be an address of a local interface (split-brain)");
    }
  }

  const existing = await db.haConfig.findFirst({ where: { tenantId } });
  const data = {
    enabled: body.enabled,
    role: body.role,
    priority: body.priority,
    virtualIp: body.virtualIp ?? null,
    ifaceName: body.ifaceName,
    peerIp: body.peerIp ?? null,
    syncConfig: body.syncConfig,
    sessionSync: body.sessionSync,
    trackedInterfaces: stringifyJson(body.trackedInterfaces),
    failAfterSec: body.failAfterSec,
    holdDownSec: body.holdDownSec,
    vrid: body.vrid,
    advertIntSec: body.advertIntSec,
    // authPass is write-only (mirrors the BGP neighbor password pattern):
    // absent field keeps the stored value, explicit null clears it.
    ...(body.authPass === undefined ? {} : { authPass: body.authPass ?? null }),
    preempt: body.preempt,
  };
  const row = existing
    ? await db.haConfig.update({ where: { id: existing.id }, data })
    : await db.haConfig.create({ data: { tenantId, ...data } });
  return toConfigDTO(row);
}

// ── Runtime status (M10 §4 `#/ha` status panel) ─────────────────────────

/**
 * HOST mode (ADR-021): every field comes from the real host —
 *   • keepalived state via `systemctl is-active keepalived`;
 *   • VIP presence from the live interface address list (os.networkInterfaces);
 *   • peer reachability via real ICMP ping (null when ping unavailable);
 *   • tracked interfaces from real operstate.
 * SIMULATED mode (legacy demo): deterministic fictional peer, heartbeat age
 * cycles 0-4 s like a VRRP advert interval. No failover is staged in either
 * mode → lastFailover stays null and hold-down has no countdown to show.
 */
export async function getHaStatus(tenantId: number): Promise<HaStatusDTO> {
  const row = await getHaConfigRow(tenantId);
  const config = toConfigDTO(row);
  const enabled = config.enabled && config.role !== "disabled";
  const hostMode = getDataPlaneMode() === "host";

  let tracked: HaTrackedIfaceState[] = [];
  let realIfaces: Awaited<ReturnType<typeof readInterfaces>> = [];

  if (hostMode) {
    realIfaces = await readInterfaces();
    const operstate = new Map(realIfaces.map((i) => [i.name, i.operState]));
    tracked = config.trackedInterfaces.map((name) => ({
      name,
      up: (operstate.get(name) ?? "unknown") === "up", // REAL link state
    }));
  } else if (config.trackedInterfaces.length > 0) {
    const rows = await db.networkInterface.findMany({
      where: { tenantId, name: { in: config.trackedInterfaces } },
      select: { name: true, enabled: true },
    });
    const byName = new Map(rows.map((r) => [r.name, r.enabled]));
    tracked = config.trackedInterfaces.map((name) => ({ name, up: byName.get(name) ?? false }));
  }

  if (!hostMode) {
    const heartbeatAgeSec = enabled ? Math.floor((Date.now() % 5000) / 1000) : 0;
    return {
      localRole: enabled ? (config.role as "active" | "standby") : "disabled",
      enabled: config.enabled,
      virtualIp: config.virtualIp,
      ifaceName: config.ifaceName,
      peerIp: config.peerIp,
      peerReachable: enabled,
      peerReachabilitySimulated: true,
      heartbeatAgeSec,
      priority: config.priority,
      failAfterSec: config.failAfterSec,
      holdDownSec: config.holdDownSec,
      holdDownRemainingSec: 0,
      lastFailover: null,
      failoverCount: 0,
      trackedInterfaces: tracked,
      configSynced: enabled && config.syncConfig,
      sessionSynced: enabled && config.sessionSync,
      os: {
        available: false,
        serviceState: null,
        vrrpState: null,
        vipPresent: false,
        managedByConsole: false,
        inSync: false,
        driftReasons: [],
        instanceName: null,
        conntrackdState: null,
        confHash: null,
        osAppliedAt: config.osAppliedAt,
      },
    };
  }

  // ── HOST mode: real keepalived + VIP + peer checks ──
  const facts = await buildHaFacts(tenantId);
  const states = await readServiceStates(["keepalived"]);
  const keepalivedActive = states?.keepalived === "active";
  const serviceObserved = states !== null;

  // drift between console intent and OS reality (pure, from ha/os.ts)
  const drift = computeHaDrift(toKeepalivedInput(row), facts);
  const osStatus: HaOsStatus = {
    available: facts.available,
    serviceState: facts.serviceState,
    vrrpState: facts.vrrpState,
    vipPresent: facts.vipPresent,
    managedByConsole: drift.managedByConsole,
    inSync: drift.inSync,
    driftReasons: drift.reasons,
    instanceName: facts.confText ? (parseKeepalivedConf(facts.confText)[0]?.name ?? null) : null,
    conntrackdState: facts.conntrackdState,
    confHash: facts.confHash,
    osAppliedAt: config.osAppliedAt,
  };

  const peerReachable = config.peerIp ? ((await pingHost(config.peerIp)) ?? false) : false;

  // honest election view: configured role is the intent, keepalived state is
  // the reality — VRRP master (or VIP present) maps to "active", backup to
  // "standby", and the configured role is shown when keepalived has not yet
  // elected (initial hint).
  let localRole: "disabled" | "active" | "standby" = "disabled";
  if (serviceObserved && !keepalivedActive) {
    localRole = "disabled"; // unit installed but not running → no VRRP
  } else if (enabled) {
    if (facts.vrrpState === "master" || facts.vipPresent) localRole = "active";
    else if (facts.vrrpState === "backup") localRole = "standby";
    else localRole = config.role === "active" ? "active" : "standby";
  }

  return {
    localRole,
    enabled: config.enabled,
    virtualIp: config.virtualIp,
    ifaceName: config.ifaceName,
    peerIp: config.peerIp,
    peerReachable,
    peerReachabilitySimulated: false,
    // advert freshness: keepalived active ⇒ adverts flowing (sub-second age)
    heartbeatAgeSec: 0,
    priority: config.priority,
    failAfterSec: config.failAfterSec,
    holdDownSec: config.holdDownSec,
    holdDownRemainingSec: 0,
    lastFailover: null,
    failoverCount: 0,
    trackedInterfaces: tracked,
    configSynced: keepalivedActive && enabled && config.syncConfig,
    sessionSynced: keepalivedActive && enabled && config.sessionSync,
    os: osStatus,
  };
}

// ── host-mode facts + helpers ────────────────────────────────────────────

/** Minimal keepalived-bearing input — the RAW singleton row (authPass included);
 *  DTOs no longer carry the secret. Accepts either the row (trackedInterfaces
 *  still a JSON string) or an already-parsed input. */
type HaKeepalivedSource = {
  enabled: boolean;
  role: string;
  priority: number;
  virtualIp: string | null;
  ifaceName: string;
  peerIp: string | null;
  trackedInterfaces: string | string[];
  failAfterSec: number;
  holdDownSec: number;
  vrid: number;
  advertIntSec: number;
  authPass: string | null;
  preempt: boolean;
};

/** Map the DB config row onto the keepalived-bearing slice used by ha/os.ts. */
export function toKeepalivedInput(cfg: HaKeepalivedSource): HaKeepalivedInput {
  return {
    enabled: cfg.enabled,
    role: cfg.role,
    priority: cfg.priority,
    virtualIp: cfg.virtualIp,
    ifaceName: cfg.ifaceName,
    peerIp: cfg.peerIp,
    trackedInterfaces: Array.isArray(cfg.trackedInterfaces)
      ? cfg.trackedInterfaces
      : parseJson<string[]>(cfg.trackedInterfaces, []),
    failAfterSec: cfg.failAfterSec,
    holdDownSec: cfg.holdDownSec,
    vrid: cfg.vrid,
    advertIntSec: cfg.advertIntSec,
    authPass: cfg.authPass,
    preempt: cfg.preempt,
  };
}

/**
 * REAL Keepalived facts from the appliance — every field best-effort,
 * never simulated: service states, live conf + hash, journal-derived VRRP
 * state, VIP presence on the live interface, conntrackd unit state.
 */
export async function buildHaFacts(tenantId: number): Promise<HaOsFacts & { confText: string | null }> {
  const [available, states, confText, journal] = await Promise.all([
    hasTool("keepalived"),
    readServiceStates(["keepalived", "conntrackd"]),
    readFile(KEEPALIVED_CONF, "utf8").catch(() => null),
    readKeepalivedJournal(),
  ]);

  let realIfaces: Awaited<ReturnType<typeof readInterfaces>> = [];
  try {
    realIfaces = await readInterfaces();
  } catch {
    // sysfs unreadable — VIP detection degrades to false
  }

  const cfg = await getHaConfig(tenantId).catch(() => null);
  const vip = cfg?.virtualIp?.split("/")[0] ?? null;
  const ifaceName = cfg?.ifaceName ?? null;
  const iface = ifaceName ? realIfaces.find((i) => i.name === ifaceName) : undefined;
  const vipPresent = Boolean(vip && iface && (iface.ipv4.includes(vip) || iface.ipv6.includes(vip)));

  return {
    available,
    serviceState: states?.keepalived ?? null,
    conntrackdState: states?.conntrackd ?? null,
    confText,
    confHash: confText ? haConfHash(confText) : null,
    osConfHash: cfg?.osConfHash ?? null,
    vrrpState: journal ? parseVrrpStateFromJournal(journal) : null,
    vipPresent,
    localIfaceIp: iface?.ipv4[0] ?? null,
  };
}

/** Last 120 keepalived journal lines — used to derive the live VRRP state. */
async function readKeepalivedJournal(): Promise<string | null> {
  if (!(await hasTool("journalctl"))) return null;
  const res = await runTool("journalctl -u keepalived -n 120 --no-pager -q", 6000);
  return res.ok ? res.stdout : null;
}

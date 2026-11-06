/**
 * HA service (M10) — HaConfig singleton + simulated runtime status.
 * Per M10-SYSTEM.md §5.1 (Keepalived semantics, simulated peer):
 *   - priority HIGHER wins master election (SCHEMA.md correction);
 *   - the sandbox peer is fictional — heartbeat is deterministic
 *     (reachable while HA is enabled with role ≠ disabled, age 0-4 s);
 *   - syncConfig/sessionSync are cosmetic in sandbox (no peer exists);
 *   - tracked interfaces map to NetworkInterface.enabled (Keepalived
 *     `track_interface` — any down iface pins the node out of election).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
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
  peerReachabilitySimulated: true;
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
};

const fieldErr = (field: string, message: string) =>
  ApiError.validation(message, { fieldErrors: { [field]: [message] } });

// ── Config singleton (upsert per tenant) ────────────────────────────────────

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
  };
}

export async function getHaConfig(tenantId: number): Promise<HaConfigDTO> {
  const row = await db.haConfig.findFirst({ where: { tenantId } });
  if (row) return toConfigDTO(row);
  // singleton row is seeded — create a default on first touch (defensive)
  const created = await db.haConfig.create({
    data: {
      tenantId,
      enabled: false,
      role: "disabled",
      priority: 100,
      ifaceName: "lan0",
      trackedInterfaces: "[]",
    },
  });
  return toConfigDTO(created);
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
  };
  const row = existing
    ? await db.haConfig.update({ where: { id: existing.id }, data })
    : await db.haConfig.create({ data: { tenantId, ...data } });
  return toConfigDTO(row);
}

// ── Simulated runtime status (M10 §4 `#/ha` status panel) ───────────────────

/**
 * Deterministic heartbeat (SIMULATION_LAYER §5, sandbox): the fictional peer
 * answers advertisements while HA is enabled with role ≠ disabled. Heartbeat
 * age cycles 0-4 s so the "x s ago" readout ticks like a real VRRP advert
 * interval. No failover is staged in Phase 1 → lastFailover stays null and
 * hold-down has no countdown to show.
 */
export async function getHaStatus(tenantId: number): Promise<HaStatusDTO> {
  const config = await getHaConfig(tenantId);
  const enabled = config.enabled && config.role !== "disabled";

  let tracked: HaTrackedIfaceState[] = [];
  if (config.trackedInterfaces.length > 0) {
    const rows = await db.networkInterface.findMany({
      where: { tenantId, name: { in: config.trackedInterfaces } },
      select: { name: true, enabled: true },
    });
    const byName = new Map(rows.map((r) => [r.name, r.enabled]));
    tracked = config.trackedInterfaces.map((name) => ({ name, up: byName.get(name) ?? false }));
  }

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
  };
}

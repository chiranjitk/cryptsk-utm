/**
 * Network response shapers (M02) — the pinned response contract for the
 * frontend (M02 §3/§4). JSON columns become real arrays/objects (ADR-005).
 */

import { parseIdArray } from "@/lib/json";

export function shapeMirror(m: {
  id: number;
  name: string;
  srcIface: string;
  dstIface: string;
  direction: string;
  enabled: boolean;
  description: string | null;
  createdAt: Date;
}) {
  return {
    id: m.id,
    name: m.name,
    srcIface: m.srcIface,
    dstIface: m.dstIface,
    direction: m.direction,
    enabled: m.enabled,
    description: m.description,
    createdAt: m.createdAt,
  };
}

export function shapeStaticRoute(r: {
  id: number;
  name: string | null;
  destinationCidr: string;
  gateway: string | null;
  interfaceName: string | null;
  distance: number;
  bfd: boolean;
  blackhole: boolean;
  enabled: boolean;
  description: string | null;
  createdAt: Date;
}) {
  // BFD chip state (M02 §4 tab 1): engine-simulated next-hop reachability —
  // null when bfd is off; up only for enabled, non-blackhole routes with a gateway
  const bfdState = r.bfd ? (r.enabled && r.gateway && !r.blackhole ? "up" : "down") : null;
  return {
    id: r.id,
    name: r.name,
    destinationCidr: r.destinationCidr,
    gateway: r.gateway,
    interfaceName: r.interfaceName,
    distance: r.distance,
    bfd: r.bfd,
    blackhole: r.blackhole,
    enabled: r.enabled,
    description: r.description,
    bfdState,
    createdAt: r.createdAt,
  };
}

export function shapePbrRule(r: {
  id: number;
  name: string;
  position: number;
  enabled: boolean;
  srcAddrIds: string;
  dstAddrIds: string;
  serviceIds: string;
  outgoingIface: string | null;
  gateway: string | null;
  description: string | null;
  createdAt: Date;
}) {
  return {
    id: r.id,
    name: r.name,
    position: r.position,
    enabled: r.enabled,
    srcAddrIds: parseIdArray(r.srcAddrIds),
    dstAddrIds: parseIdArray(r.dstAddrIds),
    serviceIds: parseIdArray(r.serviceIds),
    outgoingIface: r.outgoingIface,
    gateway: r.gateway,
    description: r.description,
    createdAt: r.createdAt,
  };
}

export function shapeWanPolicy(
  p: {
    id: number;
    interfaceName: string;
    mode: string;
    weight: number;
    priority: number;
    probeType: string;
    probeTarget: string;
    intervalSec: number;
    timeoutMs: number;
    failThreshold: number;
    okThreshold: number;
    state: string;
    enabled: boolean;
  },
  live?: { state: string; latencyMs?: number | null; detail?: string | null },
) {
  return {
    id: p.id,
    interfaceName: p.interfaceName,
    mode: p.mode,
    weight: p.weight,
    priority: p.priority,
    probeType: p.probeType,
    probeTarget: p.probeTarget,
    intervalSec: p.intervalSec,
    timeoutMs: p.timeoutMs,
    failThreshold: p.failThreshold,
    okThreshold: p.okThreshold,
    // live engine state wins when the probe map knows the iface (M02 §5)
    state: live?.state ?? p.state,
    // last real probe telemetry (G5) — null when the engine has not probed yet
    probeLatencyMs: live?.latencyMs ?? null,
    probeDetail: live?.detail ?? null,
    enabled: p.enabled,
  };
}

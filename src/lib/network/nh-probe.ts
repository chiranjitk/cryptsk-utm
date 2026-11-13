/**
 * Next-hop reachability probe (honest BFD-adjacent state).
 *
 * The route table's BFD chip used to derive "up" from config booleans — a lie
 * on a host appliance. This module probes the gateway with the real `ping`
 * binary (tools.ts pingHost) and caches the result for 30 s so list endpoints
 * stay cheap. The UI wording says "next-hop" because full BFD (RFC 5880
 * sessions) needs a userspace BFD daemon — this is ping-based reachability,
 * the same model OPNsense uses for gateway monitoring.
 */

import { pingHost } from "@/lib/host/tools";

export type NhState = "up" | "down" | "unknown";

interface NhEntry {
  state: NhState;
  at: number;
  latencyMs: number | null;
}

const CACHE = new Map<string, NhEntry>();
const TTL_MS = 30_000;

export interface NhProbeResult {
  state: NhState;
  latencyMs: number | null;
  checkedAt: string | null;
}

/** Probe one gateway (cached 30 s). Errors → "unknown" (honest absence). */
export async function probeNextHop(gateway: string): Promise<NhProbeResult> {
  const hit = CACHE.get(gateway);
  if (hit && Date.now() - hit.at < TTL_MS) {
    return { state: hit.state, latencyMs: hit.latencyMs, checkedAt: new Date(hit.at).toISOString() };
  }
  const t0 = Date.now();
  let state: NhState = "unknown";
  let latencyMs: number | null = null;
  try {
    const ok = await pingHost(gateway, 2);
    if (ok !== null) {
      state = ok ? "up" : "down";
      latencyMs = ok ? Date.now() - t0 : null;
    }
  } catch {
    state = "unknown";
  }
  CACHE.set(gateway, { state, at: Date.now(), latencyMs });
  return { state, latencyMs, checkedAt: new Date().toISOString() };
}

/** Probe a unique set of gateways concurrently. */
export async function probeNextHops(gateways: string[]): Promise<Map<string, NhProbeResult>> {
  const uniq = [...new Set(gateways.filter(Boolean))];
  const results = await Promise.all(uniq.map((g) => probeNextHop(g)));
  return new Map(uniq.map((g, i) => [g, results[i]]));
}

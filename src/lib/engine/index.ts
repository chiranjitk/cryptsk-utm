/**
 * Engine factory (ADR-021) — selects the data-plane engine by ADAPTER_MODE:
 *   • "host"      (default) → HostCollector  : REAL host telemetry, zero simulation
 *   • "simulated"           → MockEngine     : legacy sandbox demo traffic
 *   • "agent"               → HostCollector  : (Go-agent HTTP transport arrives with
 *                                              the appliance build; host collector is
 *                                              the local data plane until then)
 *
 * Both engines expose the same read surface (ENGINE_LIKE) so every consumer —
 * dashboard summary, interface stats, WAN probes, DNS query logs, system vitals,
 * realtime event tail — is written once and works on either plane.
 */

import type { MetricsTick, IpsEventEntry, FirewallLogEntry } from "./events";
import type { DnsQueryLogEntry } from "./generators/dns-queries";
import { getMockEngine, type LogRingEntry } from "./mock-engine";
import { getHostCollector, type HostLogRingEntry } from "./host-collector";

/** The engine surface consumers rely on (structural union of both engines). */
export interface EngineLike {
  readonly metricsRing: MetricsTick[];
  readonly logsRing: LogRingEntry[] | HostLogRingEntry[];
  readonly dnsRing: DnsQueryLogEntry[];
  readonly uptimeSec: number;
  readonly tickNumber: number;
  readonly wanStates: Array<{ iface: string; state: string }>;
  systemVitals(): { cpuPct: number; memPct: number; diskPct: number; tempC: number };
  forceProbe(iface: string): Promise<"up" | "degraded" | "down" | "unknown" | null> | ("up" | "degraded" | "down" | "unknown" | null);
  start(): Promise<void>;
}

export type DataPlaneMode = "host" | "simulated";

export function getDataPlaneMode(): DataPlaneMode {
  const mode = (process.env.ADAPTER_MODE ?? "host").toLowerCase();
  return mode === "simulated" ? "simulated" : "host";
}

export function getEngine(): EngineLike {
  return getDataPlaneMode() === "simulated" ? getMockEngine() : getHostCollector();
}

/** Label for the system view ("Data plane" field). */
export function dataPlaneLabel(): string {
  return getDataPlaneMode() === "simulated" ? "simulated (MockEngine)" : "host (real telemetry)";
}

export type { FirewallLogEntry, IpsEventEntry, MetricsTick, DnsQueryLogEntry, LogRingEntry, HostLogRingEntry };

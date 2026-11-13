/**
 * Engine factory (ADR-021) — selects the data-plane engine by ADAPTER_MODE:
 *   • "host"      (default) → HostCollector  : REAL local telemetry, zero simulation
 *   • "agent"               → AgentEngine    : REAL remote-sensor telemetry
 *                                              (Go agent :8080 snapshot transport)
 *   • "simulated"           → MockEngine     : legacy sandbox demo traffic
 *                                              (FORBIDDEN in production — throws)
 *
 * Both engines expose the same read surface (ENGINE_LIKE) so every consumer —
 * dashboard summary, interface stats, WAN probes, DNS query logs, system vitals,
 * realtime event tail — is written once and works on any plane.
 */

import type { MetricsTick, IpsEventEntry, FirewallLogEntry } from "./events";
import type { DnsQueryLogEntry } from "./generators/dns-queries";
import type { WanSlaStats, WanTransitionEvent } from "@/lib/network/wan-sla";
import { getMockEngine, type LogRingEntry } from "./mock-engine";
import { getHostCollector, type HostLogRingEntry } from "./host-collector";
import { getAgentEngine } from "./agent-engine";
import { getAdapterMode } from "@/lib/adapters";

/** The engine surface consumers rely on (structural union of all three engines). */
export interface EngineLike {
  readonly metricsRing: MetricsTick[];
  readonly logsRing: LogRingEntry[] | HostLogRingEntry[];
  readonly dnsRing: DnsQueryLogEntry[];
  readonly uptimeSec: number;
  readonly tickNumber: number;
  readonly wanStates: Array<{ iface: string; state: string; latencyMs?: number | null; detail?: string; sla?: WanSlaStats }>;
  /** optional: host data plane failover event log (real up/down transitions) */
  readonly wanTransitionEvents?: WanTransitionEvent[];
  systemVitals(): { cpuPct: number; memPct: number; diskPct: number; tempC: number };
  forceProbe(iface: string): Promise<"up" | "degraded" | "down" | "unknown" | null> | ("up" | "degraded" | "down" | "unknown" | null);
  /** optional: host data plane supports kernel multi-WAN convergence (G2) */
  wanOsReconverge?(): void;
  start(): Promise<void>;
}

export type DataPlaneMode = "host" | "agent" | "simulated";

export function getDataPlaneMode(): DataPlaneMode {
  return getAdapterMode();
}

export function getEngine(): EngineLike {
  switch (getDataPlaneMode()) {
    case "simulated":
      return getMockEngine();
    case "agent":
      return getAgentEngine();
    default:
      return getHostCollector();
  }
}

/** Label for the system view ("Data plane" field). */
export function dataPlaneLabel(): string {
  switch (getDataPlaneMode()) {
    case "simulated":
      return "simulated (MockEngine)";
    case "agent":
      return "agent (remote sensor telemetry)";
    default:
      return "host (real telemetry)";
  }
}

export type { FirewallLogEntry, IpsEventEntry, MetricsTick, DnsQueryLogEntry, LogRingEntry, HostLogRingEntry };

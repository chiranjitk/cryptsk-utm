/**
 * SystemAdapter — the dual-mode boundary (ADR-004, ARCHITECTURE §4).
 * All UI/API code is written once against this interface; SimulatedAdapter
 * backs it with the MockEngine (sandbox), AgentAdapter with the Go agent
 * (appliance, Phase 2+).
 */

import type { MetricsTick, IpsEventEntry } from "@/lib/engine/events";

export type ConfigSection =
  | "firewall" | "nat" | "interfaces" | "routing" | "dns" | "dhcp"
  | "vpn" | "ips" | "qos" | "ha" | "identity" | "system";

export interface DashboardSummary {
  health: {
    cpuPct: number;
    memPct: number;
    diskPct: number;
    tempC: number;
    uptimeSec: number;
  };
  throughput: MetricsTick;
  /** backfill for the dashboard live chart (last ~60 ticks; additive field) */
  throughputHistory: MetricsTick[];
  sessions: { active: number; conntrackCount: number };
  alerts24h: { total: number; bySeverity: Record<string, number> };
  topApps: Array<{ app: string; bytes: number }>;
  topTalkers: Array<{ ip: string; userName: string | null; bytes: number }>;
  wanStatus: Array<{ iface: string; state: string; rxKbps: number; txKbps: number }>;
  vpnStatus: Array<{
    id: number;
    name: string;
    type: string;
    status: string;
    statusMessage?: string | null;
    activeSessions: number;
  }>;
  /** last high/critical ips events for the threat feed (additive field) */
  recentThreats: IpsEventEntry[];
}

export interface SystemAdapter {
  readonly mode: "simulated" | "agent";
  getDashboardSummary(tenantId: number): Promise<DashboardSummary>;
}

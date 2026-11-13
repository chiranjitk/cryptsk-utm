/**
 * HostAdapter — ACTIVE in host mode (default, ADR-021).
 * Backed by the HostCollector (real /proc, sysfs, gateway probes) + the
 * shared console-authoritative DB aggregates (dashboard-aggregates.ts) over
 * rows written by REAL sources (Suricata, nftables kernel logs, WireGuard,
 * Kea). Where a source has produced nothing yet the aggregates are honestly
 * zero — no simulated fill-in.
 */

import { db } from "@/lib/db";
import { getHostCollector } from "@/lib/engine/host-collector";
import type { MetricsTick } from "@/lib/engine/events";
import { dashboardDbAggregates } from "./dashboard-aggregates";
import type { DashboardSummary, SystemAdapter } from "./types";

const EMPTY_TICK: MetricsTick = {
  ts: new Date().toISOString(),
  ifaces: [],
  cpuPct: 0,
  memPct: 0,
  conntrackCount: 0,
};

export class HostAdapter implements SystemAdapter {
  readonly mode = "host" as const;

  async getDashboardSummary(tenantId: number): Promise<DashboardSummary> {
    const collector = getHostCollector();

    const latest: MetricsTick = collector.metricsRing[collector.metricsRing.length - 1] ?? EMPTY_TICK;
    const history = collector.metricsRing.slice(-70);

    const [agg, wanPolicies] = await Promise.all([
      dashboardDbAggregates(tenantId),
      db.wanPolicy.findMany({ where: { tenantId }, select: { interfaceName: true, state: true } }),
    ]);

    const wanTickMap = new Map(latest.ifaces.map((i) => [i.name, i]));
    const engineWan = new Map(collector.wanStates.map((w) => [w.iface, w.state]));
    const wanStatus = wanPolicies.map((w) => {
      const t = wanTickMap.get(w.interfaceName);
      return {
        iface: w.interfaceName,
        state: engineWan.get(w.interfaceName) ?? w.state,
        rxKbps: t?.rxKbps ?? 0,
        txKbps: t?.txKbps ?? 0,
      };
    });

    // REAL health — disk/temp measured by the collector (0 when no sensor)
    const vitals = collector.systemVitals();
    const sessions = collector.sessionTotals;

    return {
      health: {
        cpuPct: vitals.cpuPct,
        memPct: vitals.memPct,
        diskPct: vitals.diskPct,
        tempC: vitals.tempC,
        uptimeSec: collector.uptimeSec,
      },
      throughput: latest,
      throughputHistory: history,
      sessions: { active: sessions.established + sessions.udp, conntrackCount: latest.conntrackCount },
      alerts24h: agg.alerts24h,
      topApps: agg.topApps,
      topTalkers: agg.topTalkers,
      wanStatus,
      vpnStatus: agg.vpnStatus,
      recentThreats: agg.recentThreats,
    };
  }
}

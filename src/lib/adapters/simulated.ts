/**
 * SimulatedAdapter — ACTIVE in sandbox mode (ADR-004).
 * Backed by the MockEngine ring buffers + SQLite aggregates.
 */

import { db } from "@/lib/db";
import { getMockEngine } from "@/lib/engine/mock-engine";
import type { MetricsTick } from "@/lib/engine/events";
import type { DashboardSummary, SystemAdapter } from "./types";

const ENGINE_BASE_TEMP = 46;
const ENGINE_BASE_DISK = 41;

export class SimulatedAdapter implements SystemAdapter {
  readonly mode = "simulated" as const;

  async getDashboardSummary(tenantId: number): Promise<DashboardSummary> {
    const engine = getMockEngine();
    const now = Date.now();
    const since24h = new Date(now - 24 * 3600_000);

    const latest: MetricsTick =
      engine.metricsRing[engine.metricsRing.length - 1] ?? {
        ts: new Date().toISOString(),
        ifaces: [],
        cpuPct: 20,
        memPct: 45,
        conntrackCount: 8000,
      };
    const history = engine.metricsRing.slice(-70);

    // db aggregates (single tenant in sandbox; tenantId filters everything)
    const [alertGroups, appGroups, talkerGroups, vpns, vpnSessionCounts, wanPolicies, threats] = await Promise.all([
      db.ipsEvent.groupBy({
        by: ["severity"],
        _count: { _all: true },
        where: { tenantId, timestamp: { gte: since24h } },
      }),
      db.firewallLog.groupBy({
        by: ["appName"],
        _sum: { bytes: true },
        where: { tenantId, timestamp: { gte: since24h }, appName: { not: null } },
      }),
      db.firewallLog.groupBy({
        by: ["srcIp"],
        _sum: { bytes: true },
        where: { tenantId, timestamp: { gte: since24h }, srcIp: { not: null } },
      }),
      db.vpnConfig.findMany({ where: { tenantId }, select: { id: true, name: true, type: true, status: true, statusMessage: true } }),
      db.vpnSession.groupBy({
        by: ["vpnId"],
        _count: { _all: true },
        where: { tenantId, status: { in: ["active", "idle"] } },
      }),
      db.wanPolicy.findMany({ where: { tenantId }, select: { interfaceName: true, state: true } }),
      db.ipsEvent.findMany({
        where: { tenantId, severity: { in: ["high", "critical"] } },
        orderBy: { timestamp: "desc" },
        take: 10,
      }),
    ]);

    const bySeverity: Record<string, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    let alertsTotal = 0;
    for (const g of alertGroups) {
      bySeverity[g.severity] = g._count._all;
      alertsTotal += g._count._all;
    }

    const topApps = appGroups
      .map((g) => ({ app: g.appName ?? "other", bytes: g._sum.bytes ?? 0 }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 10);

    const identities = await db.identitySession.findMany({
      where: { tenantId, state: "active" },
      select: { sourceIp: true, userName: true },
    });
    const ipUser = new Map(identities.map((i) => [i.sourceIp, i.userName]));
    const topTalkers = talkerGroups
      .map((g) => ({ ip: g.srcIp ?? "0.0.0.0", userName: ipUser.get(g.srcIp ?? "") ?? null, bytes: g._sum.bytes ?? 0 }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 10);

    const wanTickMap = new Map(latest.ifaces.map((i) => [i.name, i]));
    const engineWan = new Map(engine.wanStates.map((w) => [w.iface, w.state]));
    const wanStatus = wanPolicies.map((w) => {
      const t = wanTickMap.get(w.interfaceName);
      return {
        iface: w.interfaceName,
        state: engineWan.get(w.interfaceName) ?? w.state,
        rxKbps: t?.rxKbps ?? 0,
        txKbps: t?.txKbps ?? 0,
      };
    });

    const sessionCountMap = new Map(vpnSessionCounts.map((s) => [s.vpnId, s._count._all]));
    const vpnStatus = vpns.map((v) => ({
      id: v.id,
      name: v.name,
      type: v.type,
      status: v.status,
      statusMessage: v.statusMessage,
      activeSessions: sessionCountMap.get(v.id) ?? 0,
    }));

    // disk/temp: slow deterministic drift around the base values
    const drift = Math.sin(now / 3_600_000);
    const cpu = latest.cpuPct;

    return {
      health: {
        cpuPct: cpu,
        memPct: latest.memPct,
        diskPct: Math.round((ENGINE_BASE_DISK + drift * 2) * 10) / 10,
        tempC: Math.round((ENGINE_BASE_TEMP + cpu * 0.08 + drift * 1.5) * 10) / 10,
        uptimeSec: engine.uptimeSec,
      },
      throughput: latest,
      throughputHistory: history,
      sessions: { active: latest.conntrackCount, conntrackCount: latest.conntrackCount },
      alerts24h: { total: alertsTotal, bySeverity },
      topApps,
      topTalkers,
      wanStatus,
      vpnStatus,
      recentThreats: threats.map((t) => ({
        id: t.id,
        ts: t.timestamp.toISOString(),
        srcIp: t.srcIp,
        srcPort: t.srcPort,
        dstIp: t.dstIp,
        dstPort: t.dstPort,
        action: t.action,
        sid: t.sid,
        severity: t.severity,
        category: t.category,
        message: t.message,
      })),
    };
  }
}

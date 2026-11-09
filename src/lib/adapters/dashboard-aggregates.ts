/**
 * Dashboard DB aggregates — console-authoritative data shared by both real
 * adapters (ADR-021). Rows come from REAL sources only:
 *   • ipsEvent      — written by HostCollector (eve.json) or AgentEngine
 *                     (agent logsTail) — never generated
 *   • firewallLog   — written by HostCollector (kernel logs) or AgentEngine
 *   • vpnConfig/vpnSession — real `wg show` sync (host) / config plane
 *   • wanPolicy     — the admin's real config rows (states merge separately)
 * Where a source has produced nothing yet the aggregates are honestly zero.
 */

import { db } from "@/lib/db";
import type { IpsEventEntry } from "@/lib/engine/events";

export interface DashboardDbAggregates {
  alerts24h: { total: number; bySeverity: Record<string, number> };
  topApps: Array<{ app: string; bytes: number }>;
  topTalkers: Array<{ ip: string; userName: string | null; bytes: number }>;
  vpnStatus: Array<{
    id: number;
    name: string;
    type: string;
    status: string;
    statusMessage?: string | null;
    activeSessions: number;
  }>;
  recentThreats: IpsEventEntry[];
}

export async function dashboardDbAggregates(tenantId: number): Promise<DashboardDbAggregates> {
  const now = Date.now();
  const since24h = new Date(now - 24 * 3600_000);

  const [alertGroups, appGroups, talkerGroups, vpns, vpnSessionCounts, threats, identities] = await Promise.all([
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
    db.ipsEvent.findMany({
      where: { tenantId, severity: { in: ["high", "critical"] } },
      orderBy: { timestamp: "desc" },
      take: 10,
    }),
    db.identitySession.findMany({
      where: { tenantId, state: "active" },
      select: { sourceIp: true, userName: true },
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

  const ipUser = new Map(identities.map((i) => [i.sourceIp, i.userName]));
  const topTalkers = talkerGroups
    .map((g) => ({ ip: g.srcIp ?? "0.0.0.0", userName: ipUser.get(g.srcIp ?? "") ?? null, bytes: g._sum.bytes ?? 0 }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  const sessionCountMap = new Map(vpnSessionCounts.map((s) => [s.vpnId, s._count._all]));
  const vpnStatus = vpns.map((v) => ({
    id: v.id,
    name: v.name,
    type: v.type,
    status: v.status,
    statusMessage: v.statusMessage,
    activeSessions: sessionCountMap.get(v.id) ?? 0,
  }));

  const recentThreats: IpsEventEntry[] = threats.map((t) => ({
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
  }));

  return { alerts24h: { total: alertsTotal, bySeverity }, topApps, topTalkers, vpnStatus, recentThreats };
}

/**
 * WAF stats (M17 §2.4.6) — 24h counters + top attacked rules + per-vhost
 * volume: { blocked24h, logged24h, passed24h, topRules[5], byVhost }.
 * Summary rows (ruleId null) count towards the action totals but never enter
 * topRules; topRules messages come from the most recent row of that ruleId.
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { CRSTitle } from "@/app/api/v1/waf/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "waf" }, async ({ auth }) => {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const [byAction, byRule, byVhostRows, recentPerRule] = await Promise.all([
    db.wafLog.groupBy({
      by: ["action"],
      where: { tenantId: auth.tenantId, createdAt: { gte: since } },
      _count: { _all: true },
    }),
    db.wafLog.groupBy({
      by: ["ruleId"],
      where: { tenantId: auth.tenantId, createdAt: { gte: since }, ruleId: { not: null } },
      _count: { _all: true },
      orderBy: { _count: { ruleId: "desc" } },
      take: 5,
    }),
    db.wafLog.groupBy({
      by: ["vhostId"],
      where: { tenantId: auth.tenantId, createdAt: { gte: since }, vhostId: { not: null } },
      _count: { _all: true },
    }),
    // messages for the top ruleIds — cheap map instead of a join (logical ref)
    db.wafLog.findMany({
      where: { tenantId: auth.tenantId, ruleId: { not: null } },
      orderBy: { createdAt: "desc" },
      select: { ruleId: true, ruleMsg: true },
      take: 200,
    }),
  ]);

  const countOf = (action: string): number =>
    byAction.find((a) => a.action === action)?._count._all ?? 0;

  const msgByRule = new Map<number, string>();
  for (const row of recentPerRule) {
    if (row.ruleId !== null && row.ruleMsg && !msgByRule.has(row.ruleId)) {
      msgByRule.set(row.ruleId, row.ruleMsg);
    }
  }

  const byVhost: Record<string, number> = {};
  for (const v of byVhostRows) {
    if (v.vhostId !== null) byVhost[String(v.vhostId)] = v._count._all;
  }

  return {
    data: {
      blocked24h: countOf("block"),
      logged24h: countOf("log"),
      passed24h: countOf("pass"),
      topRules: byRule.map((r) => ({
        ruleId: r.ruleId ?? 0,
        msg: (r.ruleId !== null && msgByRule.get(r.ruleId)) || CRSTitle(r.ruleId ?? 0),
        count: r._count._all,
      })),
      byVhost,
    },
  };
});

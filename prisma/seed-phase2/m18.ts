/**
 * M18 seed — Enhanced Application Control (spec 2.2). Idempotent, tenantId 1:
 * "Branch Office Control" (default allow, unknown apps logged, enabled) with 8
 * nDPI rules (bittorrent/tiktok block, youtube/netflix limit, teams/zoom/
 * github/ssh allow) and "Kiosk Lockdown" (default block, unknown apps blocked,
 * disabled) with no rules, plus 10 sample AppControlLog rows spread over the
 * last 24h (only seeded when the tenant has no logs — logs have no natural
 * unique key).
 *
 * Run via: bun prisma/seed-phase2.ts (orchestrator tolerates missing modules).
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;

const POLICIES = [
  { name: "Branch Office Control", defaultAction: "allow", unknownAppAction: "log", enabled: true },
  { name: "Kiosk Lockdown", defaultAction: "block", unknownAppAction: "block", enabled: false },
] as const;

/** 8 rules on Branch Office Control — hitCounts make the stats card meaningful. */
const BRANCH_RULES = [
  { appName: "bittorrent", category: "filesharing", action: "block", bandwidthLimitMbps: null, hitCount: 12 },
  { appName: "tiktok", category: "social", action: "block", bandwidthLimitMbps: null, hitCount: 18 },
  { appName: "youtube", category: "media", action: "limit", bandwidthLimitMbps: 25, hitCount: 40 },
  { appName: "netflix", category: "media", action: "limit", bandwidthLimitMbps: 50, hitCount: 25 },
  { appName: "teams", category: "collaboration", action: "allow", bandwidthLimitMbps: null, hitCount: 60 },
  { appName: "zoom", category: "collaboration", action: "allow", bandwidthLimitMbps: null, hitCount: 35 },
  { appName: "github", category: "devops", action: "allow", bandwidthLimitMbps: null, hitCount: 55 },
  { appName: "ssh", category: "remote", action: "allow", bandwidthLimitMbps: null, hitCount: 20 },
] as const;

/** Sample log rows — hoursAgo spreads them over the last 24h window. */
const SAMPLE_LOGS = [
  { hoursAgo: 1, appName: "teams", action: "allowed", clientIp: "192.168.1.24", bytes: 182_400 },
  { hoursAgo: 2, appName: "youtube", action: "limited", clientIp: "192.168.1.31", bytes: 340_120 },
  { hoursAgo: 3, appName: "bittorrent", action: "blocked", clientIp: "192.168.2.18", bytes: 96_250 },
  { hoursAgo: 5, appName: "github", action: "allowed", clientIp: "192.168.1.52", bytes: 44_800 },
  { hoursAgo: 7, appName: "tiktok", action: "blocked", clientIp: "192.168.3.10", bytes: 51_000 },
  { hoursAgo: 9, appName: "netflix", action: "limited", clientIp: "192.168.2.44", bytes: 478_900 },
  { hoursAgo: 12, appName: "zoom", action: "allowed", clientIp: "192.168.1.77", bytes: 225_600 },
  { hoursAgo: 15, appName: "bittorrent", action: "blocked", clientIp: "192.168.4.9", bytes: 88_430 },
  { hoursAgo: 20, appName: "ssh", action: "allowed", clientIp: "192.168.1.90", bytes: 12_300 },
  { hoursAgo: 23, appName: "youtube", action: "limited", clientIp: "192.168.1.24", bytes: 260_750 },
] as const;

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── policies — upsert by (tenantId, name) ─────────────────────────────────
  const branch = await prisma.appControlPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "Branch Office Control" } },
    update: { defaultAction: "allow", unknownAppAction: "log", enabled: true },
    create: {
      tenantId: TENANT,
      name: "Branch Office Control",
      defaultAction: "allow",
      unknownAppAction: "log",
      enabled: true,
    },
  });

  await prisma.appControlPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "Kiosk Lockdown" } },
    update: { defaultAction: "block", unknownAppAction: "block", enabled: false },
    create: {
      tenantId: TENANT,
      name: "Kiosk Lockdown",
      defaultAction: "block",
      unknownAppAction: "block",
      enabled: false,
    },
  });

  // ── branch rules — upsert all 8 (unique tenant+policy+appName) ────────────
  for (const rule of BRANCH_RULES) {
    await prisma.appControlRule.upsert({
      where: {
        tenantId_policyId_appName: {
          tenantId: TENANT,
          policyId: branch.id,
          appName: rule.appName,
        },
      },
      update: {
        category: rule.category,
        action: rule.action,
        bandwidthLimitMbps: rule.bandwidthLimitMbps,
        hitCount: rule.hitCount,
        enabled: true,
      },
      create: {
        tenantId: TENANT,
        policyId: branch.id,
        appName: rule.appName,
        category: rule.category,
        action: rule.action,
        bandwidthLimitMbps: rule.bandwidthLimitMbps,
        direction: "both",
        userGroupIds: JSON.stringify([]),
        enabled: true,
        hitCount: rule.hitCount,
      },
    });
  }

  // ── sample logs — only when the tenant has none (no natural unique key) ───
  const logCount = await prisma.appControlLog.count({ where: { tenantId: TENANT } });
  if (logCount === 0) {
    const rules = await prisma.appControlRule.findMany({
      where: { tenantId: TENANT, policyId: branch.id },
      select: { id: true, appName: true },
    });
    const ruleByApp = new Map(rules.map((r) => [r.appName, r.id]));
    const now = Date.now();
    await prisma.appControlLog.createMany({
      data: SAMPLE_LOGS.map((l) => ({
        tenantId: TENANT,
        appName: l.appName,
        action: l.action,
        clientIp: l.clientIp,
        bytes: l.bytes,
        ruleId: ruleByApp.get(l.appName) ?? null,
        createdAt: new Date(now - l.hoursAgo * 60 * 60 * 1000),
      })),
    });
  }

  // ── summary from actual DB state (idempotent re-runs report real totals) ──
  const [policyTotal, ruleTotal, logTotal] = await Promise.all([
    prisma.appControlPolicy.count({ where: { tenantId: TENANT } }),
    prisma.appControlRule.count({ where: { tenantId: TENANT } }),
    prisma.appControlLog.count({ where: { tenantId: TENANT } }),
  ]);
  return `M18: ${policyTotal} policies, ${ruleTotal} rules, ${logTotal} logs`;
}

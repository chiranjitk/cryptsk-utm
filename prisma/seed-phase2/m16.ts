/**
 * M16 seed — URL Filtering / Web Security (spec 2.3). Idempotent, tenantId 1:
 * one "Corporate Web Filter" policy (default allow + SafeSearch + HTTPS
 * inspection + transparent proxy, blocks exe/bat/scr/js), all 13 category
 * rules (7 block / 2 warn / 4 allow), 4 custom list entries (3 block, 1 allow)
 * and 10 sample UrlFilterLog rows spread over the last 24h (only seeded when
 * the tenant has no logs yet — logs have no natural unique key).
 *
 * Run via: bun prisma/seed-phase2.ts (orchestrator tolerates missing modules).
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;
const POLICY_NAME = "Corporate Web Filter";

// category → action for the 13 locked web categories
const CATEGORY_RULES: Array<{ category: string; action: "allow" | "block" | "warn" }> = [
  { category: "gambling", action: "block" },
  { category: "adult", action: "block" },
  { category: "malware", action: "block" },
  { category: "phishing", action: "block" },
  { category: "p2p", action: "block" },
  { category: "weapons", action: "block" },
  { category: "hate", action: "block" },
  { category: "social_media", action: "warn" },
  { category: "streaming", action: "warn" },
  { category: "news", action: "allow" },
  { category: "shopping", action: "allow" },
  { category: "games", action: "allow" },
  { category: "custom", action: "allow" },
];

const CUSTOM_LISTS: Array<{ listType: "block" | "allow"; matchType: "domain" | "wildcard" | "url"; value: string; note: string }> = [
  { listType: "block", matchType: "domain", value: "badsite.example", note: "Known malware distribution site" },
  { listType: "block", matchType: "domain", value: "trackers.example", note: "Advertising trackers" },
  { listType: "block", matchType: "wildcard", value: "*.gambling-cdn.example", note: "Gambling CDN assets" },
  { listType: "allow", matchType: "domain", value: "company-docs.example", note: "Internal documentation portal" },
];

/** Sample log rows — hoursAgo spreads them over the last 24h window. */
const SAMPLE_LOGS: Array<{
  hoursAgo: number;
  clientIp: string;
  url: string;
  domain: string;
  category: string;
  action: "allowed" | "blocked" | "warned";
  reason: string;
}> = [
  { hoursAgo: 1, clientIp: "192.168.1.24", url: "https://gamble-site.net/play", domain: "gamble-site.net", category: "gambling", action: "blocked", reason: "category" },
  { hoursAgo: 2, clientIp: "192.168.1.31", url: "https://github.com/cryptsk/firewall", domain: "github.com", category: "custom", action: "allowed", reason: "category" },
  { hoursAgo: 4, clientIp: "192.168.1.52", url: "https://youtube.com/watch?v=dQw4w9WgXcQ", domain: "youtube.com", category: "streaming", action: "warned", reason: "category" },
  { hoursAgo: 5, clientIp: "192.168.2.18", url: "https://phishing-login.example/secure", domain: "phishing-login.example", category: "phishing", action: "blocked", reason: "category" },
  { hoursAgo: 7, clientIp: "192.168.1.77", url: "https://malware-cdn.xyz/payload.exe", domain: "malware-cdn.xyz", category: "malware", action: "blocked", reason: "category" },
  { hoursAgo: 9, clientIp: "192.168.3.10", url: "https://google.com/search?q=network+security", domain: "google.com", category: "uncategorized", action: "allowed", reason: "safe_search" },
  { hoursAgo: 12, clientIp: "192.168.2.44", url: "http://updates.example/downloads/setup.exe", domain: "updates.example", category: "uncategorized", action: "blocked", reason: "file_type" },
  { hoursAgo: 15, clientIp: "192.168.1.24", url: "https://social.example/feed", domain: "social.example", category: "social_media", action: "warned", reason: "category" },
  { hoursAgo: 20, clientIp: "192.168.4.9", url: "https://trackers.example/pixel.gif", domain: "trackers.example", category: "uncategorized", action: "blocked", reason: "custom_block" },
  { hoursAgo: 23, clientIp: "192.168.1.90", url: "https://internal.corp.example/intranet", domain: "internal.corp.example", category: "uncategorized", action: "allowed", reason: "default" },
];

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── policy — upsert by (tenantId, name) ───────────────────────────────────
  const policy = await prisma.urlFilterPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: POLICY_NAME } },
    update: {},
    create: {
      tenantId: TENANT,
      name: POLICY_NAME,
      defaultAction: "allow",
      safeSearchEnforce: true,
      fileTypesBlocked: JSON.stringify(["exe", "bat", "scr", "js"]),
      httpsInspection: true,
      transparentProxy: true,
      enabled: true,
    },
  });

  // ── category rules — upsert all 13 (unique tenant+policy+category) ────────
  for (const rule of CATEGORY_RULES) {
    await prisma.urlCategoryRule.upsert({
      where: {
        tenantId_policyId_category: {
          tenantId: TENANT,
          policyId: policy.id,
          category: rule.category,
        },
      },
      update: { action: rule.action, listSource: "aggregated", enabled: true },
      create: {
        tenantId: TENANT,
        policyId: policy.id,
        category: rule.category,
        action: rule.action,
        listSource: "aggregated",
        enabled: true,
      },
    });
  }

  // ── custom lists — find-or-create per (policy, listType, value) ───────────
  for (const entry of CUSTOM_LISTS) {
    const existing = await prisma.urlCustomList.findFirst({
      where: { tenantId: TENANT, policyId: policy.id, listType: entry.listType, value: entry.value },
    });
    if (existing) continue;
    await prisma.urlCustomList.create({
      data: {
        tenantId: TENANT,
        policyId: policy.id,
        listType: entry.listType,
        matchType: entry.matchType,
        value: entry.value,
        note: entry.note,
      },
    });
  }

  // ── sample logs — only when the tenant has none (no natural unique key) ───
  const logCount = await prisma.urlFilterLog.count({ where: { tenantId: TENANT } });
  if (logCount === 0) {
    const now = Date.now();
    await prisma.urlFilterLog.createMany({
      data: SAMPLE_LOGS.map((l) => ({
        tenantId: TENANT,
        clientIp: l.clientIp,
        method: "GET",
        url: l.url,
        domain: l.domain,
        category: l.category,
        action: l.action,
        reason: l.reason,
        policyId: policy.id,
        createdAt: new Date(now - l.hoursAgo * 60 * 60 * 1000),
      })),
    });
  }

  // ── summary from actual DB state (idempotent re-runs report real totals) ──
  const [ruleTotal, listTotal, logTotal] = await Promise.all([
    prisma.urlCategoryRule.count({ where: { tenantId: TENANT, policyId: policy.id } }),
    prisma.urlCustomList.count({ where: { tenantId: TENANT, policyId: policy.id } }),
    prisma.urlFilterLog.count({ where: { tenantId: TENANT } }),
  ]);
  return `M16: 1 policy, ${ruleTotal} category rules, ${listTotal} custom lists, ${logTotal} logs`;
}

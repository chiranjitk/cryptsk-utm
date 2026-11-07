/**
 * M13 — Threat Intelligence seed (spec 2.11). Idempotent upserts, tenantId 1:
 * 3 feeds (Abuse.ch URLhaus, Spamhaus DROP, OTX C2 watch), 18 IOCs across the
 * feeds (mix of ip/cidr/domain/url/hash; 4 critical, 8 warning, 6 info),
 * 3 auto-block rules (1 manual + 2 auto-feed) and 6 IocHit rows spread over
 * the last 24h (only created when the hit table is empty, so re-runs never
 * duplicate).
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;
const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000);

interface FeedSeed {
  name: string;
  provider: string;
  url: string;
  format: string;
  category: string;
  intervalMinutes: number;
  autoBlock: boolean;
}

const FEEDS: FeedSeed[] = [
  {
    name: "Abuse.ch URLhaus",
    provider: "abusech",
    url: "https://urlhaus.abuse.ch/downloads/csv_recent/",
    format: "csv",
    category: "malware",
    intervalMinutes: 60,
    autoBlock: true,
  },
  {
    name: "Spamhaus DROP",
    provider: "spamhaus",
    url: "https://www.spamhaus.org/drop/drop.txt",
    format: "csv",
    category: "botnet",
    intervalMinutes: 1440,
    autoBlock: false,
  },
  {
    name: "OTX C2 watch",
    provider: "otx",
    url: "https://otx.alienvault.com/api/v1/indicators/export",
    format: "json",
    category: "c2",
    intervalMinutes: 30,
    autoBlock: false,
  },
];

interface IocSeed {
  feed: string;
  type: string;
  value: string;
  severity: string;
  confidence: number;
  description: string;
}

/** 18 IOCs — 4 critical, 8 warning, 6 info; confidence 60–95. */
const IOCS: IocSeed[] = [
  // Abuse.ch URLhaus (malware)
  { feed: "Abuse.ch URLhaus", type: "ip", value: "45.155.205.233", severity: "critical", confidence: 95, description: "AsyncRAT C2 observed in URLhaus payloads" },
  { feed: "Abuse.ch URLhaus", type: "ip", value: "185.156.73.54", severity: "warning", confidence: 80, description: "Dridex delivery node (historic abuse)" },
  { feed: "Abuse.ch URLhaus", type: "domain", value: "payloadz.ru", severity: "critical", confidence: 92, description: "Malware payload distribution domain" },
  { feed: "Abuse.ch URLhaus", type: "domain", value: "update-check-service.top", severity: "warning", confidence: 70, description: "Fake software update domain" },
  { feed: "Abuse.ch URLhaus", type: "hash", value: "e6e5c4a1b0d29f3fa8f39d31e1b4a4d0", severity: "warning", confidence: 75, description: "MD5 of known trojan dropper sample" },
  { feed: "Abuse.ch URLhaus", type: "url", value: "http://payloadz.ru/bin/loader.exe", severity: "info", confidence: 65, description: "Direct payload URL — loader binary" },
  // Spamhaus DROP (botnet)
  { feed: "Spamhaus DROP", type: "cidr", value: "185.222.57.0/24", severity: "critical", confidence: 95, description: "SBL DROP netblock — bulletproof hosting" },
  { feed: "Spamhaus DROP", type: "cidr", value: "45.9.148.0/24", severity: "warning", confidence: 85, description: "DROP list — spam/malware distribution range" },
  { feed: "Spamhaus DROP", type: "cidr", value: "103.75.190.0/24", severity: "warning", confidence: 80, description: "DROP list — botnet command range" },
  { feed: "Spamhaus DROP", type: "cidr", value: "91.215.85.0/24", severity: "info", confidence: 60, description: "DROP list — phishing infrastructure" },
  { feed: "Spamhaus DROP", type: "ip", value: "45.9.148.57", severity: "warning", confidence: 82, description: "Single host inside DROP range — direct C2" },
  { feed: "Spamhaus DROP", type: "cidr", value: "5.34.180.0/24", severity: "info", confidence: 62, description: "DROP list — formerly abusive, low activity" },
  // OTX C2 watch (c2)
  { feed: "OTX C2 watch", type: "domain", value: "telemetry-sync-cdn.com", severity: "critical", confidence: 91, description: "APT implant beacon domain (OTX pulse #4412)" },
  { feed: "OTX C2 watch", type: "domain", value: "api-cloud-metrics.net", severity: "warning", confidence: 78, description: "Cobalt Strike malleable C2 profile" },
  { feed: "OTX C2 watch", type: "ip", value: "193.27.228.114", severity: "warning", confidence: 84, description: "Known C2 listener — OTX pulse #4398" },
  { feed: "OTX C2 watch", type: "domain", value: "cdn-analytics-portal.com", severity: "info", confidence: 68, description: "Suspected data-exfil landing zone" },
  { feed: "OTX C2 watch", type: "hash", value: "9f2b6e0c7d84a15f3e21c9b0a6d4e8f2", severity: "info", confidence: 64, description: "SHA-256 fragment of implant dropper" },
  { feed: "OTX C2 watch", type: "ip", value: "5.188.206.18", severity: "info", confidence: 66, description: "Scanner / brute-force host feeding C2" },
];

function reputationFor(severity: string): number {
  switch (severity) {
    case "critical":
      return 5;
    case "warning":
      return 20;
    default:
      return 45;
  }
}

/** Hit seeds — iocKey must match an IOC above; spread over the last 24h. */
const HITS: Array<{ iocKey: string; sourceIp: string; destIp: string; action: string; hoursAgo: number }> = [
  { iocKey: "ip:45.155.205.233", sourceIp: "45.155.205.233", destIp: "192.168.1.10", action: "blocked", hoursAgo: 2 },
  { iocKey: "cidr:185.222.57.0/24", sourceIp: "185.222.57.19", destIp: "192.168.1.23", action: "blocked", hoursAgo: 5 },
  { iocKey: "domain:telemetry-sync-cdn.com", sourceIp: "192.168.1.10", destIp: "193.27.228.114", action: "quarantined", hoursAgo: 8 },
  { iocKey: "domain:payloadz.ru", sourceIp: "192.168.1.31", destIp: "45.155.205.233", action: "blocked", hoursAgo: 12 },
  { iocKey: "domain:api-cloud-metrics.net", sourceIp: "192.168.1.44", destIp: "5.188.206.18", action: "blocked", hoursAgo: 18 },
  { iocKey: "cidr:5.34.180.0/24", sourceIp: "5.34.180.9", destIp: "192.168.1.10", action: "allowed", hoursAgo: 23 },
];

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── feeds (upsert by tenantId+name; dynamic sync state only on create) ──
  for (const f of FEEDS) {
    await prisma.threatFeed.upsert({
      where: { tenantId_name: { tenantId: TENANT, name: f.name } },
      create: {
        ...f,
        tenantId: TENANT,
        lastSyncAt: hoursAgo(1),
        lastStatus: "ok",
        lastCount: 8,
      },
      update: {
        provider: f.provider,
        url: f.url,
        format: f.format,
        category: f.category,
        intervalMinutes: f.intervalMinutes,
        autoBlock: f.autoBlock,
      },
    });
  }

  const feedIds = new Map(
    (await prisma.threatFeed.findMany({ where: { tenantId: TENANT } })).map((f) => [f.name, f.id]),
  );

  // ── IOCs (upsert by tenantId+type+value) ─────────────────────────────────
  const iocIds = new Map<string, number>();
  for (const i of IOCS) {
    const source = `feed:${i.feed}`;
    const row = await prisma.ioc.upsert({
      where: { tenantId_type_value: { tenantId: TENANT, type: i.type, value: i.value } },
      create: {
        tenantId: TENANT,
        feedId: feedIds.get(i.feed) ?? null,
        type: i.type,
        value: i.value,
        category: FEEDS.find((f) => f.name === i.feed)?.category ?? "malware",
        severity: i.severity,
        confidence: i.confidence,
        reputation: reputationFor(i.severity),
        source,
        description: i.description,
        firstSeen: hoursAgo(20),
        lastSeen: hoursAgo(1),
      },
      update: {
        severity: i.severity,
        confidence: i.confidence,
        reputation: reputationFor(i.severity),
        description: i.description,
        feedId: feedIds.get(i.feed) ?? null,
        source,
      },
    });
    iocIds.set(`${i.type}:${i.value}`, row.id);
  }

  // ── auto-block rules (upsert by tenantId+matchType+matchValue) ───────────
  await prisma.autoBlockRule.upsert({
    where: { tenantId_matchType_matchValue: { tenantId: TENANT, matchType: "cidr", matchValue: "198.51.100.0/24" } },
    create: {
      tenantId: TENANT,
      name: "Block ransomware net",
      iocId: null,
      matchType: "cidr",
      matchValue: "198.51.100.0/24",
      action: "drop",
      direction: "both",
      source: "manual",
      hitCount: 12,
      enabled: true,
      createdBy: "admin",
    },
    update: { name: "Block ransomware net", action: "drop", direction: "both", enabled: true },
  });
  await prisma.autoBlockRule.upsert({
    where: { tenantId_matchType_matchValue: { tenantId: TENANT, matchType: "cidr", matchValue: "185.222.57.0/24" } },
    create: {
      tenantId: TENANT,
      name: "auto:185.222.57.0/24",
      iocId: iocIds.get("cidr:185.222.57.0/24") ?? null,
      matchType: "cidr",
      matchValue: "185.222.57.0/24",
      action: "drop",
      direction: "both",
      source: "auto-feed",
      hitCount: 5,
      enabled: true,
      createdBy: "threat-feed",
    },
    update: { iocId: iocIds.get("cidr:185.222.57.0/24") ?? null, source: "auto-feed", enabled: true },
  });
  await prisma.autoBlockRule.upsert({
    where: { tenantId_matchType_matchValue: { tenantId: TENANT, matchType: "domain", matchValue: "telemetry-sync-cdn.com" } },
    create: {
      tenantId: TENANT,
      name: "auto:telemetry-sync-cdn.com",
      iocId: iocIds.get("domain:telemetry-sync-cdn.com") ?? null,
      matchType: "domain",
      matchValue: "telemetry-sync-cdn.com",
      action: "drop",
      direction: "both",
      source: "auto-feed",
      hitCount: 3,
      enabled: true,
      createdBy: "threat-feed",
    },
    update: { iocId: iocIds.get("domain:telemetry-sync-cdn.com") ?? null, source: "auto-feed", enabled: true },
  });

  // ── hits (create once — never duplicated on re-run) ──────────────────────
  const hitCount = await prisma.iocHit.count({ where: { tenantId: TENANT } });
  if (hitCount === 0) {
    for (const h of HITS) {
      const iocId = iocIds.get(h.iocKey);
      if (!iocId) continue;
      await prisma.iocHit.create({
        data: {
          tenantId: TENANT,
          iocId,
          sourceIp: h.sourceIp,
          destIp: h.destIp,
          action: h.action,
          createdAt: hoursAgo(h.hoursAgo),
        },
      });
    }
  }

  return "M13: 3 feeds, 18 IOCs, 3 auto-block rules, 6 hits";
}

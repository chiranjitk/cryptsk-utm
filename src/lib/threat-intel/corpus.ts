/**
 * M13 threat-intel server lib — per-provider sample corpus + simulated
 * ingestion engine (spec 2.11, sandbox mode). The appliance performs real
 * fetch/parse; the console replays this deterministic corpus on
 * POST /feeds/[id]/sync and upserts IOCs (unique tenant+type+value),
 * auto-block rules for new critical IOCs (feed.autoBlock) and 2-3 sample
 * IocHit rows so the console has data to display.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { ThreatSeverity } from "@/lib/validators/threat-intel";

// ── sample corpus (per provider — ~8 entries each) ──────────────────────────

export type CorpusEntryType = "ip" | "cidr" | "domain" | "url" | "hash";

export interface CorpusEntry {
  type: CorpusEntryType;
  value: string;
  severity: ThreatSeverity;
  /** 0-100 — how sure the provider is (drives the confidence meter). */
  confidence: number;
  description: string;
}

export const SAMPLE_CORPUS: Record<string, CorpusEntry[]> = {
  // Abuse.ch — botnet C2s / payload distributers (URLhaus style)
  abusech: [
    { type: "ip", value: "45.155.205.233", severity: "critical", confidence: 95, description: "AsyncRAT C2 observed in URLhaus payloads" },
    { type: "ip", value: "185.156.73.54", severity: "critical", confidence: 92, description: "Dridex banking trojan delivery node" },
    { type: "ip", value: "89.44.201.135", severity: "warning", confidence: 78, description: "Emotet downloader endpoint (historic)" },
    { type: "ip", value: "179.43.141.220", severity: "warning", confidence: 74, description: "Cobalt Strike team server candidate" },
    { type: "domain", value: "payloadz.ru", severity: "critical", confidence: 90, description: "Malware payload distribution domain" },
    { type: "domain", value: "update-check-service.top", severity: "warning", confidence: 72, description: "Fake software update domain" },
    { type: "url", value: "http://payloadz.ru/bin/loader.exe", severity: "critical", confidence: 88, description: "Direct payload URL — loader binary" },
    { type: "hash", value: "e6e5c4a1b0d29f3fa8f39d31e1b4a4d0", severity: "warning", confidence: 80, description: "MD5 of known trojan dropper sample" },
  ],
  // OTX — C2 watchlist (AlienVault pulses)
  otx: [
    { type: "domain", value: "telemetry-sync-cdn.com", severity: "critical", confidence: 91, description: "APT implant beacon domain (OTX pulse #4412)" },
    { type: "domain", value: "api-cloud-metrics.net", severity: "critical", confidence: 87, description: "Cobalt Strike malleable C2 profile" },
    { type: "domain", value: "cdn-analytics-portal.com", severity: "warning", confidence: 76, description: "Suspected data-exfil landing zone" },
    { type: "domain", value: "status-health-node.info", severity: "warning", confidence: 70, description: "RAT heartbeat domain, low volume" },
    { type: "ip", value: "193.27.228.114", severity: "critical", confidence: 89, description: "Known C2 listener — OTX pulse #4398" },
    { type: "ip", value: "5.188.206.18", severity: "warning", confidence: 73, description: "Scanner / brute-force host feeding C2" },
    { type: "hash", value: "9f2b6e0c7d84a15f3e21c9b0a6d4e8f2", severity: "critical", confidence: 85, description: "SHA-256 fragment of implant dropper" },
    { type: "url", value: "https://telemetry-sync-cdn.com/gate.php", severity: "critical", confidence: 84, description: "Implant gate endpoint" },
  ],
  // Spamhaus — DROP netblocks (don't-route lists)
  spamhaus: [
    { type: "cidr", value: "185.222.57.0/24", severity: "critical", confidence: 96, description: "SBL DROP netblock — bulletproof hosting" },
    { type: "cidr", value: "45.9.148.0/24", severity: "critical", confidence: 94, description: "DROP list — spam/malware distribution range" },
    { type: "cidr", value: "103.75.190.0/24", severity: "warning", confidence: 82, description: "DROP list — botnet command range" },
    { type: "cidr", value: "194.165.16.0/24", severity: "warning", confidence: 80, description: "DROP-adjacent — repeated abuse reports" },
    { type: "cidr", value: "91.215.85.0/24", severity: "warning", confidence: 77, description: "DROP list — phishing infrastructure" },
    { type: "ip", value: "45.9.148.57", severity: "critical", confidence: 90, description: "Single host inside DROP range — direct C2" },
    { type: "domain", value: "drop-watch-sbl.info", severity: "info", confidence: 60, description: "Informational — SBL listing mirror" },
    { type: "cidr", value: "5.34.180.0/24", severity: "info", confidence: 65, description: "DROP list — formerly abusive, low activity" },
  ],
  // custom — manually curated blocklist placeholder
  custom: [
    { type: "ip", value: "203.0.113.66", severity: "warning", confidence: 70, description: "Tenant-curated scanner (internal report)" },
    { type: "ip", value: "203.0.113.99", severity: "info", confidence: 55, description: "Watchlist — repeated port scans" },
    { type: "cidr", value: "198.51.100.0/24", severity: "info", confidence: 60, description: "Vendor test range — block at edge" },
    { type: "domain", value: "old-portal.example.net", severity: "info", confidence: 50, description: "Deprecated partner portal" },
    { type: "url", value: "https://old-portal.example.net/login", severity: "warning", confidence: 68, description: "Credential-harvest clone of portal" },
    { type: "hash", value: "1a2b3c4d5e6f70819a2b3c4d5e6f7081", severity: "warning", confidence: 72, description: "Internal IR sample — ransomware pre-loader" },
    { type: "domain", value: "secure-login-verify.example.com", severity: "critical", confidence: 85, description: "Phishing kit domain (IR case #2214)" },
    { type: "ip", value: "192.0.2.140", severity: "critical", confidence: 88, description: "Ransomware leak-site contact host" },
  ],
};

/** Reputation (0-100, 100 = fully benign) derived from severity at ingest. */
export function reputationFor(severity: string): number {
  switch (severity) {
    case "critical":
      return 5;
    case "warning":
      return 20;
    default:
      return 45;
  }
}

// ── simulated ingestion engine ───────────────────────────────────────────────

export interface FeedSyncResult {
  feedId: number;
  feedName: string;
  entriesApplied: number;
  newIocs: number;
  updatedIocs: number;
  autoBlockCreated: number;
  hitsCreated: number;
  /** auto-block rules DISABLED (not deleted) because their IOC left this feed's corpus */
  autoBlockDisabled: number;
  /** names of the disabled rules — carried into the route's audit entry */
  disabledRuleNames: string[];
  syncedAt: string;
}

const SAMPLE_HIT_SOURCES = ["198.51.100.24", "203.0.113.7", "192.0.2.55", "203.0.113.201"];
const SAMPLE_HIT_DESTS = ["192.168.1.10", "192.168.1.23", "10.0.0.5"];

/**
 * Replay the provider corpus for one feed: upsert IOCs for the feed's
 * category (unique tenant+type+value; severity/confidence/lastSeen refreshed
 * on match), optionally auto-block NEW critical IOCs, mint 2-3 sample hits,
 * then stamp lastSyncAt/lastStatus/lastCount on the feed.
 *
 * ATOMICITY: the whole replay (upsert loop + hits + reconciliation + feed
 * stamp) runs in ONE db.$transaction — a mid-loop failure leaves no partial
 * state and the feed status stamp only lands when the corpus write succeeds.
 *
 * FEED RECONCILIATION: after a successful sync, auto-block rules sourced from
 * this feed (auto-feed, IOC attributed to it) whose value is no longer in the
 * provider corpus are DISABLED — never deleted (hit history + provenance
 * stay; a later re-appearance re-enables nothing automatically, that is an
 * operator decision). The disabled rule names ride the result → the route's
 * `threat_feed.sync` audit entry records the reconciliation.
 */
export async function syncFeed(tenantId: number, feedId: number): Promise<FeedSyncResult> {
  const feed = await db.threatFeed.findFirst({ where: { id: feedId, tenantId } });
  if (!feed) throw ApiError.notFound("Threat feed not found");

  const entries = SAMPLE_CORPUS[feed.provider] ?? SAMPLE_CORPUS.custom;
  const now = new Date();

  return db.$transaction(async (tx) => {
    let newIocs = 0;
    let updatedIocs = 0;
    let autoBlockCreated = 0;

    for (const entry of entries) {
      const existing = await tx.ioc.findUnique({
        where: { tenantId_type_value: { tenantId, type: entry.type, value: entry.value } },
      });

      let iocId: number;
      if (existing) {
        const row = await tx.ioc.update({
          where: { id: existing.id },
          data: {
            severity: entry.severity,
            confidence: entry.confidence,
            lastSeen: now,
            feedId: feed.id,
            source: `feed:${feed.name}`,
          },
        });
        iocId = row.id;
        updatedIocs++;
      } else {
        const row = await tx.ioc.create({
          data: {
            tenantId,
            feedId: feed.id,
            type: entry.type,
            value: entry.value,
            category: feed.category,
            severity: entry.severity,
            confidence: entry.confidence,
            reputation: reputationFor(entry.severity),
            source: `feed:${feed.name}`,
            description: entry.description,
            lastSeen: now,
          },
        });
        iocId = row.id;
        newIocs++;

        // feed.autoBlock → drop rule per NEW critical IOC
        if (feed.autoBlock && entry.severity === "critical") {
          const ruleExists = await tx.autoBlockRule.findUnique({
            where: { tenantId_matchType_matchValue: { tenantId, matchType: entry.type, matchValue: entry.value } },
          });
          if (!ruleExists) {
            await tx.autoBlockRule.create({
              data: {
                tenantId,
                name: `auto:${entry.value}`.slice(0, 64),
                iocId: row.id,
                matchType: entry.type,
                matchValue: entry.value,
                action: "drop",
                direction: "both",
                source: "auto-feed",
                enabled: true,
                createdBy: "threat-feed",
              },
            });
            autoBlockCreated++;
          }
        }
      }
      void iocId; // retained for future per-IOC sync reporting
    }

    // 2-3 sample hits from existing IOCs — deterministic rotation over the pool.
    // EXPIRY ENFORCEMENT: IOCs past expiresAt no longer feed the sample-hit
    // findings (matched live IOCs only).
    const pool = await tx.ioc.findMany({
      where: {
        tenantId,
        enabled: true,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      orderBy: { id: "asc" },
      take: 50,
      select: { id: true, value: true, severity: true },
    });
    const hitCount = pool.length === 0 ? 0 : 2 + (Math.floor(now.getTime() / 60_000) % 2); // 2|3
    let hitsCreated = 0;
    for (let i = 0; i < hitCount; i++) {
      const pick = pool[(Math.floor(now.getTime() / 60_000) + i * 7) % pool.length];
      const blocked = pick.severity === "critical" || pick.severity === "warning";
      await tx.iocHit.create({
        data: {
          tenantId,
          iocId: pick.id,
          sourceIp: SAMPLE_HIT_SOURCES[(i + Math.floor(now.getTime() / 60_000)) % SAMPLE_HIT_SOURCES.length],
          destIp: SAMPLE_HIT_DESTS[i % SAMPLE_HIT_DESTS.length],
          action: blocked ? "blocked" : "allowed",
          createdAt: now,
        },
      });
      hitsCreated++;
      await tx.ioc.update({ where: { id: pick.id }, data: { hits: { increment: 1 } } });
      if (blocked) {
        await tx.autoBlockRule.updateMany({
          where: { tenantId, matchValue: pick.value, enabled: true },
          data: { hitCount: { increment: 1 } },
        });
      }
    }

    // feed reconciliation — auto-feed rules whose IOC is attributed to this
    // feed but no longer reported by its corpus are disabled (kept, audited)
    const corpusKeys = new Set(entries.map((e) => `${e.type}|${e.value}`));
    const feedIocs = await tx.ioc.findMany({
      where: { tenantId, feedId: feed.id },
      select: { id: true, type: true, value: true },
    });
    const iocById = new Map(feedIocs.map((i) => [i.id, i]));
    const feedRules = await tx.autoBlockRule.findMany({
      where: { tenantId, source: "auto-feed", enabled: true },
      select: { id: true, name: true, iocId: true },
    });
    const disabledRuleNames: string[] = [];
    for (const r of feedRules) {
      const ioc = r.iocId != null ? iocById.get(r.iocId) : undefined;
      if (!ioc || corpusKeys.has(`${ioc.type}|${ioc.value}`)) continue;
      await tx.autoBlockRule.update({ where: { id: r.id }, data: { enabled: false } });
      disabledRuleNames.push(r.name);
    }

    // feed status stamp — INSIDE the same tx (a failed replay never reports ok)
    await tx.threatFeed.update({
      where: { id: feed.id },
      data: { lastSyncAt: now, lastStatus: "ok", lastCount: entries.length },
    });

    return {
      feedId: feed.id,
      feedName: feed.name,
      entriesApplied: entries.length,
      newIocs,
      updatedIocs,
      autoBlockCreated,
      hitsCreated,
      autoBlockDisabled: disabledRuleNames.length,
      disabledRuleNames,
      syncedAt: now.toISOString(),
    };
  });
}

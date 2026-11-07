/**
 * M22 seed — Email Security (spec 2.8). Idempotent, tenantId 1: two gateways
 * ("mx01" inline proxy on :25/starttls, "mx02" relay to smtp-out.corp.example
 * over enforced implicit TLS/wrapper on :587), the "Default Email Policy"
 * singleton (Rspamd-like defaults), four routing rules ("partner-mail" relay
 * → 10.30.0.50 p10, "legacy-mx-relay" → 10.30.0.51 p20, "bulk-sender-quarantine"
 * p30, "junk-tld" reject @zip p90) plus 40 sample EmailLog rows spread over the
 * last 48h — 28 delivered (mostly clean), 7 quarantined (spam_score/dmarc_fail)
 * and 5 rejected (phishing/malware/blocked_extension/size) with realistic
 * external senders. Logs have no natural unique key, so they are only seeded
 * when the tenant has none.
 *
 * Run via: bun prisma/seed-phase2.ts (orchestrator tolerates missing modules).
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;
const POLICY_NAME = "Default Email Policy";

const GATEWAYS: Array<{
  name: string;
  mode: "proxy" | "relay";
  listenPort: number;
  relayDomains: string[];
  upstreamHost: string | null;
  tlsMode: "none" | "starttls" | "wrapper";
  enabled: boolean;
}> = [
  { name: "mx01", mode: "proxy", listenPort: 25, relayDomains: ["corp.example"], upstreamHost: null, tlsMode: "starttls", enabled: true },
  { name: "mx02", mode: "relay", listenPort: 587, relayDomains: [], upstreamHost: "smtp-out.corp.example", tlsMode: "wrapper", enabled: true },
];

const ROUTING_RULES: Array<{
  name: string;
  matchDomain: string;
  action: "deliver" | "relay" | "reject" | "quarantine";
  targetHost: string | null;
  priority: number;
  enabled: boolean;
}> = [
  { name: "partner-mail", matchDomain: "partner.com", action: "relay", targetHost: "10.30.0.50", priority: 10, enabled: true },
  { name: "legacy-mx-relay", matchDomain: "legacy.corp.example", action: "relay", targetHost: "10.30.0.51", priority: 20, enabled: true },
  { name: "bulk-sender-quarantine", matchDomain: "bulk-mailer.example", action: "quarantine", targetHost: null, priority: 30, enabled: true },
  { name: "junk-tld", matchDomain: "@zip", action: "reject", targetHost: null, priority: 90, enabled: true },
];

type Verdict = "delivered" | "quarantined" | "rejected";
type Auth = "pass" | "fail" | "softfail" | "none";

interface SampleLog {
  hoursAgo: number;
  fromAddr: string;
  toAddr: string;
  subject: string;
  spamScore: number;
  verdict: Verdict;
  reasons: string[];
  spfResult: Auth;
  dkimResult: Auth;
  dmarcResult: Auth;
  attachmentsScanned: number;
  sizeKb: number;
}

const P = "pass" as const;
const F = "fail" as const;

/**
 * 40 rows over 48h — 28 delivered (clean), 7 quarantined (spam_score /
 * dmarc_fail through the quarantine DMARC policy), 5 rejected (phishing,
 * malware, blocked_extension, size). Bad sender domains (throwaway.mx,
 * spamsource.example) fail SPF/DKIM like the engine simulates; scores above
 * the 6.0 threshold carry the spam_score reason.
 */
const SAMPLE_LOGS: SampleLog[] = [
  // ── delivered — normal business + SaaS traffic ─────────────────────────────
  { hoursAgo: 0.5, fromAddr: "ceo@corp.example", toAddr: "all-hands@corp.example", subject: "Q3 planning deck attached", spamScore: 1.2, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 1840 },
  { hoursAgo: 1.2, fromAddr: "notifications@github.com", toAddr: "dev@corp.example", subject: "[cryptsk/utm] PR #4182: harden TLS defaults", spamScore: 0.6, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 34 },
  { hoursAgo: 2.0, fromAddr: "receipts@stripe.com", toAddr: "billing@corp.example", subject: "Your receipt from Stripe — 490.00 EUR", spamScore: 0.9, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 96 },
  { hoursAgo: 2.8, fromAddr: "no-reply@accounts.google.com", toAddr: "admin@corp.example", subject: "Security alert: new sign-in on macOS", spamScore: 1.8, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 28 },
  { hoursAgo: 3.5, fromAddr: "vendor@partner.com", toAddr: "sales@corp.example", subject: "Purchase order PO-4417", spamScore: 0.8, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 320 },
  { hoursAgo: 4.2, fromAddr: "updates@linkedin.com", toAddr: "ceo@corp.example", subject: "You appeared in 27 searches this week", spamScore: 2.4, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 88 },
  { hoursAgo: 5.0, fromAddr: "hr@corp.example", toAddr: "all@corp.example", subject: "Updated holiday schedule", spamScore: 1.5, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 21 },
  { hoursAgo: 6.1, fromAddr: "no-reply@dropboxmail.com", toAddr: "dev@corp.example", subject: "shared 'infra-runbook.docx' with you", spamScore: 1.1, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 45 },
  { hoursAgo: 7.0, fromAddr: "newsletter@shop.example", toAddr: "ceo@corp.example", subject: "Weekly deals roundup", spamScore: 3.4, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 42 },
  { hoursAgo: 8.0, fromAddr: "no-reply-aws@amazon.com", toAddr: "ops@corp.example", subject: "AWS Cost Report — October", spamScore: 0.7, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 210 },
  { hoursAgo: 9.0, fromAddr: "dev@corp.example", toAddr: "release@corp.example", subject: "Nightly build artifacts", spamScore: 2.3, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 2, sizeKb: 20480 },
  { hoursAgo: 10.2, fromAddr: "dmarc-reports@google.com", toAddr: "postmaster@corp.example", subject: "Report domain: corp.example", spamScore: 0.4, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 64 },
  { hoursAgo: 11.0, fromAddr: "it-support@corp.example", toAddr: "newhire@corp.example", subject: "Welcome — account setup guide", spamScore: 0.9, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 15 },
  { hoursAgo: 12.0, fromAddr: "updates@shop.example", toAddr: "ceo@corp.example", subject: "Your order has shipped", spamScore: 2.1, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 88 },
  { hoursAgo: 13.4, fromAddr: "status@linkedin.com", toAddr: "hr@corp.example", subject: "3 new job applicants for Senior SRE", spamScore: 1.6, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 52 },
  { hoursAgo: 14.5, fromAddr: "vendor@partner.com", toAddr: "finance@corp.example", subject: "Invoice INV-2026-0112 due Nov 30", spamScore: 0.5, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 140 },
  { hoursAgo: 16.0, fromAddr: "alerts@monitor.corp.example", toAddr: "ops@corp.example", subject: "[OK] wan0 latency back under SLA", spamScore: 0.3, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 8 },
  { hoursAgo: 17.2, fromAddr: "gitlab@ourgit.corp.example", toAddr: "dev@corp.example", subject: "Pipeline #9921 passed", spamScore: 0.6, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 19 },
  { hoursAgo: 18.5, fromAddr: "newsletter@shop.example", toAddr: "marketing@corp.example", subject: "Autumn collection preview", spamScore: 3.1, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 61 },
  { hoursAgo: 20.0, fromAddr: "ceo@corp.example", toAddr: "legal@corp.example", subject: "Contract redlines for review", spamScore: 1.0, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 640 },
  { hoursAgo: 21.3, fromAddr: "no-reply@accounts.google.com", toAddr: "admin@corp.example", subject: "Recovery email changed", spamScore: 1.7, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 24 },
  { hoursAgo: 22.6, fromAddr: "receipts@stripe.com", toAddr: "billing@corp.example", subject: "Your receipt from Stripe — 1250.00 EUR", spamScore: 0.8, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 31 },
  { hoursAgo: 24.0, fromAddr: "updates@linkedin.com", toAddr: "hr@corp.example", subject: "Your weekly news digest", spamScore: 2.7, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 74 },
  { hoursAgo: 26.0, fromAddr: "hr@corp.example", toAddr: "all@corp.example", subject: "Open enrollment closes Friday", spamScore: 1.4, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 18 },
  { hoursAgo: 28.0, fromAddr: "no-reply-aws@amazon.com", toAddr: "ops@corp.example", subject: "Action required: rotate IAM access keys", spamScore: 2.2, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 26 },
  { hoursAgo: 31.0, fromAddr: "dev@corp.example", toAddr: "release@corp.example", subject: "Sprint 42 retro notes", spamScore: 0.9, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 12 },
  { hoursAgo: 36.0, fromAddr: "vendor@partner.com", toAddr: "sales@corp.example", subject: "RFQ response attached", spamScore: 0.7, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 2, sizeKb: 880 },
  { hoursAgo: 44.0, fromAddr: "it-support@corp.example", toAddr: "all@corp.example", subject: "Scheduled maintenance window Sat 02:00", spamScore: 0.5, verdict: "delivered", reasons: [], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 11 },

  // ── quarantined — spam score over threshold / DMARC fail (policy=quarantine) ─
  { hoursAgo: 1.8, fromAddr: "deals@mailer-dealz.biz", toAddr: "marketing@corp.example", subject: "Winner — claim your free money prize", spamScore: 12.0, verdict: "quarantined", reasons: ["spam_score"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 18 },
  { hoursAgo: 4.5, fromAddr: "promo@throwaway.mx", toAddr: "marketing@corp.example", subject: "Flash sale — 90% off today only", spamScore: 8.4, verdict: "quarantined", reasons: ["dmarc_fail", "spam_score"], spfResult: F, dkimResult: F, dmarcResult: F, attachmentsScanned: 0, sizeKb: 22 },
  { hoursAgo: 9.5, fromAddr: "docs@archive.zip", toAddr: "ceo@corp.example", subject: "Documents for your review", spamScore: 6.4, verdict: "quarantined", reasons: ["spam_score"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 24500 },
  { hoursAgo: 13.0, fromAddr: "bounce@spamsource.example", toAddr: "postmaster@corp.example", subject: "Undelivered mail returned to sender", spamScore: 7.5, verdict: "quarantined", reasons: ["dmarc_fail", "spam_score"], spfResult: F, dkimResult: F, dmarcResult: F, attachmentsScanned: 0, sizeKb: 9 },
  { hoursAgo: 19.0, fromAddr: "marketing@bulk-mailer.example", toAddr: "marketing@corp.example", subject: "Boost your reach — limited slots", spamScore: 9.2, verdict: "quarantined", reasons: ["spam_score"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 36 },
  { hoursAgo: 27.5, fromAddr: "lotto@lucky-draws.info", toAddr: "ceo@corp.example", subject: "You are our lucky winner — act now", spamScore: 10.6, verdict: "quarantined", reasons: ["spam_score"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 15 },
  { hoursAgo: 38.0, fromAddr: "career@headhunter-digest.biz", toAddr: "hr@corp.example", subject: "5 interview invites waiting", spamScore: 7.1, verdict: "quarantined", reasons: ["spam_score"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 25 },

  // ── rejected — phishing / malware / blocked extension / size hard blocks ────
  { hoursAgo: 3.0, fromAddr: "security-alert@paypa1-security.example", toAddr: "ceo@corp.example", subject: "Verify your account now", spamScore: 9.8, verdict: "rejected", reasons: ["phishing"], spfResult: F, dkimResult: F, dmarcResult: F, attachmentsScanned: 0, sizeKb: 12 },
  { hoursAgo: 6.5, fromAddr: "invoice@fast-invoices.example", toAddr: "finance@corp.example", subject: "Overdue invoice — login-verify your payment", spamScore: 8.9, verdict: "rejected", reasons: ["phishing"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 14 },
  { hoursAgo: 12.5, fromAddr: "dev@corp.example", toAddr: "release@corp.example", subject: "Build tools update", spamScore: 3.2, verdict: "rejected", reasons: ["blocked_extension", "malware"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 2, sizeKb: 20480 },
  { hoursAgo: 22.0, fromAddr: "it@corp.example", toAddr: "ops@corp.example", subject: "Remote support tool", spamScore: 2.6, verdict: "rejected", reasons: ["malware"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 1, sizeKb: 5120 },
  { hoursAgo: 33.0, fromAddr: "ceo@corp.example", toAddr: "archive@corp.example", subject: "Video recording of board meeting", spamScore: 1.2, verdict: "rejected", reasons: ["size"], spfResult: P, dkimResult: P, dmarcResult: P, attachmentsScanned: 0, sizeKb: 61440 },
];

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── gateways — upsert by (tenantId, name) ─────────────────────────────────
  for (const gw of GATEWAYS) {
    await prisma.emailGateway.upsert({
      where: { tenantId_name: { tenantId: TENANT, name: gw.name } },
      update: {},
      create: {
        tenantId: TENANT,
        name: gw.name,
        mode: gw.mode,
        listenPort: gw.listenPort,
        relayDomains: JSON.stringify(gw.relayDomains),
        upstreamHost: gw.upstreamHost,
        tlsMode: gw.tlsMode,
        enabled: gw.enabled,
      },
    });
  }

  // ── policy singleton — upsert by (tenantId, name) ─────────────────────────
  await prisma.emailPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: POLICY_NAME } },
    update: {},
    create: {
      tenantId: TENANT,
      name: POLICY_NAME,
      spamThreshold: 6.0,
      blockPhishing: true,
      blockMalware: true,
      scanArchives: true,
      maxMessageSizeMb: 25,
      blockedExtensions: JSON.stringify(["exe", "js", "vbs", "scr", "bat"]),
      spfVerify: true,
      dkimVerify: true,
      dmarcPolicy: "quarantine",
      quarantineRetentionDays: 14,
      enabled: true,
    },
  });

  // ── routing rules — upsert by (tenantId, name) ────────────────────────────
  for (const rule of ROUTING_RULES) {
    await prisma.emailRoutingRule.upsert({
      where: { tenantId_name: { tenantId: TENANT, name: rule.name } },
      update: {},
      create: {
        tenantId: TENANT,
        name: rule.name,
        matchDomain: rule.matchDomain,
        action: rule.action,
        targetHost: rule.targetHost,
        priority: rule.priority,
        enabled: rule.enabled,
      },
    });
  }

  // ── sample logs — only when the tenant has none (no natural unique key) ───
  const logCount = await prisma.emailLog.count({ where: { tenantId: TENANT } });
  if (logCount === 0) {
    const now = Date.now();
    await prisma.emailLog.createMany({
      data: SAMPLE_LOGS.map((l) => ({
        tenantId: TENANT,
        fromAddr: l.fromAddr,
        toAddr: l.toAddr,
        subject: l.subject,
        spamScore: l.spamScore,
        verdict: l.verdict,
        reasons: JSON.stringify(l.reasons),
        spfResult: l.spfResult,
        dkimResult: l.dkimResult,
        dmarcResult: l.dmarcResult,
        attachmentsScanned: l.attachmentsScanned,
        sizeKb: l.sizeKb,
        createdAt: new Date(now - l.hoursAgo * 60 * 60 * 1000),
      })),
    });
  }

  // ── summary from actual DB state (idempotent re-runs report real totals) ──
  const [gatewayTotal, policyTotal, ruleTotal, logTotal] = await Promise.all([
    prisma.emailGateway.count({ where: { tenantId: TENANT } }),
    prisma.emailPolicy.count({ where: { tenantId: TENANT } }),
    prisma.emailRoutingRule.count({ where: { tenantId: TENANT } }),
    prisma.emailLog.count({ where: { tenantId: TENANT } }),
  ]);
  return `M22: ${gatewayTotal} gateways, ${policyTotal} policy, ${ruleTotal} routing rules, ${logTotal} logs`;
}

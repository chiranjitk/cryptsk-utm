/**
 * M15 seed — SSL/TLS Inspection (spec 2.1). Idempotent, tenantId = 1.
 * One selective MITM policy ("Default MITM") signed by the M14 "Cryptsk
 * Issuing CA" (looked up by NAME — never a hardcoded id; null when missing),
 * three bypass rules and ~8 inspection log rows spread over the last 24h.
 * NOTE: `*.bank.example` is seeded with matchType "domain" per the spec —
 * the API validator is stricter for API-created rules, but the decision
 * engine treats a leading `*.` on any rule value as a suffix match.
 *
 * Run via: bun prisma/seed-phase2.ts (orchestrator tolerates missing modules).
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;

const HOUR = 60 * 60 * 1000;

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── policy — signing CA resolved by name (m14 seed creates it) ─────────────
  const issuing = await prisma.certificateAuthority.findFirst({
    where: { tenantId: TENANT, name: "Cryptsk Issuing CA" },
    select: { id: true },
  });

  const policyData = {
    mode: "selective",
    signingCaId: issuing?.id ?? null,
    hstsHandling: "honor",
    certPinningAction: "bypass",
    invalidCertAction: "block",
    minTlsVersion: "1.2",
    enabled: true,
  } as const;

  const policy = await prisma.sslInspectionPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "Default MITM" } },
    update: policyData, // re-run repairs the signing-CA link once m14 has run
    create: { tenantId: TENANT, name: "Default MITM", ...policyData },
  });

  // ── bypass rules (no unique constraint — find-then-create per triplet) ────
  const rules = [
    { matchType: "domain", matchValue: "*.bank.example", reason: "banking HSTS" },
    { matchType: "cidr", matchValue: "10.0.0.0/8", reason: "internal" },
    { matchType: "wildcard", matchValue: "*.apple.com", reason: "pinning-heavy" },
  ] as const;

  let createdRules = 0;
  for (const rule of rules) {
    const existing = await prisma.sslBypassRule.findFirst({
      where: { tenantId: TENANT, policyId: policy.id, matchType: rule.matchType, matchValue: rule.matchValue },
      select: { id: true },
    });
    if (existing) continue;
    await prisma.sslBypassRule.create({
      data: { tenantId: TENANT, policyId: policy.id, ...rule, enabled: true },
    });
    createdRules += 1;
  }

  // ── inspection logs (~8 mixed decisions over the last 24h, seeded once) ───
  const existingLogs = await prisma.sslInspectionLog.count({ where: { tenantId: TENANT } });
  let createdLogs = 0;
  if (existingLogs === 0) {
    const rows: Array<{
      clientIp: string;
      serverSni: string;
      action: string;
      reason: string;
      tlsVersion: string;
      cipher: string;
      hoursAgo: number;
    }> = [
      { clientIp: "10.2.3.4", serverSni: "www.bank.example", action: "bypassed", reason: "bypass_rule", tlsVersion: "1.3", cipher: "TLS_AES_256_GCM_SHA384", hoursAgo: 0.5 },
      { clientIp: "10.1.1.15", serverSni: "intranet.corp.local", action: "bypassed", reason: "bypass_rule", tlsVersion: "1.2", cipher: "ECDHE-RSA-AES256-GCM-SHA384", hoursAgo: 2 },
      { clientIp: "192.168.10.44", serverSni: "api.googleapis.com", action: "bypassed", reason: "pinning", tlsVersion: "1.3", cipher: "TLS_AES_128_GCM_SHA256", hoursAgo: 4 },
      { clientIp: "192.168.10.51", serverSni: "old-portal.expired.com", action: "blocked", reason: "invalid_cert", tlsVersion: "1.2", cipher: "ECDHE-RSA-AES128-GCM-SHA256", hoursAgo: 7 },
      { clientIp: "192.168.10.51", serverSni: "self-signed.dev.example", action: "blocked", reason: "invalid_cert", tlsVersion: "1.3", cipher: "TLS_CHACHA20_POLY1305_SHA256", hoursAgo: 9 },
      { clientIp: "10.4.9.7", serverSni: "pay.example.com", action: "bypassed", reason: "hsts", tlsVersion: "1.3", cipher: "TLS_AES_256_GCM_SHA384", hoursAgo: 13 },
      { clientIp: "192.168.10.23", serverSni: "news.example.org", action: "inspected", reason: "inspected", tlsVersion: "1.3", cipher: "TLS_AES_256_GCM_SHA384", hoursAgo: 18 },
      { clientIp: "10.9.8.7", serverSni: "cdn.assets.example.com", action: "inspected", reason: "inspected", tlsVersion: "1.2", cipher: "ECDHE-RSA-AES256-GCM-SHA384", hoursAgo: 22 },
    ];
    const now = Date.now();
    for (const row of rows) {
      await prisma.sslInspectionLog.create({
        data: {
          tenantId: TENANT,
          clientIp: row.clientIp,
          serverSni: row.serverSni,
          action: row.action,
          reason: row.reason,
          tlsVersion: row.tlsVersion,
          cipher: row.cipher,
          policyId: policy.id,
          createdAt: new Date(now - row.hoursAgo * HOUR),
        },
      });
      createdLogs += 1;
    }
  }

  return `M15: 1 policy, 3 bypass rules, 8 inspection logs` +
    (createdRules < 3 ? ` (${3 - createdRules} rules already seeded)` : "") +
    (createdLogs === 0 ? " (logs already seeded)" : "") +
    (issuing ? "" : " — signing CA left null (Cryptsk Issuing CA not found)");
}

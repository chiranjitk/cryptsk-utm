/**
 * M17 seed — Web Application Firewall (spec 2.4). Idempotent: upserts by the
 * module's natural keys (tenantId=1). Two demo vhosts (shop TLS-bound to the
 * M14 "waf-vhost-demo" certificate when present + plain-HTTP api), one policy
 * per vhost, two false-positive exclusions and ~10 WafLog rows (pass/log/block
 * with realistic CRS rule ids) spread over the trailing 24h.
 *
 * Run via: bun prisma/seed-phase2.ts (orchestrator tolerates missing modules).
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── vhosts ──────────────────────────────────────────────────────────────────
  // TLS cert binding uses the M14 demo server cert (issuedFor "waf") when the
  // PKI seed has already run — otherwise the vhost stays TLS with no binding.
  const demoCert = await prisma.certificate.findFirst({
    where: { tenantId: TENANT, name: "waf-vhost-demo", status: "active" },
    select: { id: true },
  });

  const shopVhost = await prisma.wafVhost.upsert({
    where: { tenantId_hostname: { tenantId: TENANT, hostname: "shop.corp.example" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "Shop frontend",
      hostname: "shop.corp.example",
      backendHost: "10.20.30.11",
      backendPort: 8080,
      listenPort: 443,
      tls: true,
      certId: demoCert?.id ?? null,
      mode: "waf",
      enabled: true,
    },
  });

  const apiVhost = await prisma.wafVhost.upsert({
    where: { tenantId_hostname: { tenantId: TENANT, hostname: "api.corp.example" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "Public API",
      hostname: "api.corp.example",
      backendHost: "10.20.30.12",
      backendPort: 9000,
      listenPort: 80,
      tls: false,
      certId: null,
      mode: "waf",
      enabled: true,
    },
  });

  // ── policies (one per vhost) ───────────────────────────────────────────────
  const shopPolicy = await prisma.wafPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "Shop WAF" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "Shop WAF",
      vhostId: shopVhost.id,
      owaspCrsEnabled: true,
      crsVersion: "4.0",
      paranoiaLevel: 1,
      anomalyInThreshold: 5,
      anomalyOutThreshold: 4,
      learningMode: false,
      geoBlockCountries: JSON.stringify(["CN", "RU"]),
      rateLimitRpm: 300,
      rateLimitBurst: null,
      apiProtection: false,
      enabled: true,
    },
  });

  await prisma.wafPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "API WAF" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "API WAF",
      vhostId: apiVhost.id,
      owaspCrsEnabled: true,
      crsVersion: "4.0",
      paranoiaLevel: 2,
      anomalyInThreshold: 5,
      anomalyOutThreshold: 4,
      learningMode: false,
      geoBlockCountries: "[]",
      rateLimitRpm: null,
      rateLimitBurst: null,
      apiProtection: true,
      enabled: true,
    },
  });

  // ── exclusions (Shop WAF false positives) ──────────────────────────────────
  const existingExclusions = await prisma.wafExclusion.findMany({
    where: { tenantId: TENANT, policyId: shopPolicy.id },
    select: { scope: true, matchValue: true },
  });
  const has = (scope: string, matchValue: string): boolean =>
    existingExclusions.some((e) => e.scope === scope && e.matchValue === matchValue);

  if (!has("rule_id", "942100")) {
    await prisma.wafExclusion.create({
      data: {
        tenantId: TENANT,
        policyId: shopPolicy.id,
        scope: "rule_id",
        matchValue: "942100",
        ruleId: 942100,
        note: "FP on checkout coupon",
        enabled: true,
      },
    });
  }
  if (!has("param", "password")) {
    await prisma.wafExclusion.create({
      data: {
        tenantId: TENANT,
        policyId: shopPolicy.id,
        scope: "param",
        matchValue: "password",
        ruleId: null,
        note: null,
        enabled: true,
      },
    });
  }

  // ── WafLog rows (~10, mixed actions over the trailing 24h) ─────────────────
  const logCount = await prisma.wafLog.count({ where: { tenantId: TENANT } });
  if (logCount === 0) {
    const minAgo = (m: number): Date => new Date(Date.now() - m * 60_000);
    const base = { tenantId: TENANT };
    await prisma.wafLog.createMany({
      data: [
        // pass — clean requests (summary rows, ruleId null)
        { ...base, vhostId: shopVhost.id, clientIp: "203.0.113.24", method: "GET", url: "/shop/products?page=2", ruleId: null, ruleMsg: "no rule matches", anomalyScore: 0, action: "pass", createdAt: minAgo(700) },
        { ...base, vhostId: apiVhost.id, clientIp: "198.51.100.7", method: "GET", url: "/api/v1/orders/4711", ruleId: null, ruleMsg: "no rule matches", anomalyScore: 0, action: "pass", createdAt: minAgo(650) },
        { ...base, vhostId: shopVhost.id, clientIp: "192.0.2.44", method: "GET", url: "/shop/cart", ruleId: null, ruleMsg: "no rule matches", anomalyScore: 0, action: "pass", createdAt: minAgo(540) },
        // log — sub-threshold anomalies
        { ...base, vhostId: apiVhost.id, clientIp: "192.0.2.203", method: "POST", url: "/api/v1/export", ruleId: 920420, ruleMsg: "Request Missing a Content-Type Header (parameter-less POST body)", anomalyScore: 2, action: "log", payloadSnippet: "raw export manifest", createdAt: minAgo(430) },
        { ...base, vhostId: shopVhost.id, clientIp: "198.51.100.88", method: "GET", url: "/shop/backup-old.sql", ruleId: 920440, ruleMsg: "URL File Extension is Restricted (.env/.bak/.conf/…)", anomalyScore: 3, action: "log", createdAt: minAgo(320) },
        { ...base, vhostId: shopVhost.id, clientIp: "203.0.113.99", method: "GET", url: "/shop/search?q=<b>tea</b>", ruleId: 941160, ruleMsg: "XSS Filter - Category 5: Disallowed HTML Attributes", anomalyScore: 5, action: "log", payloadSnippet: "q=<b>tea</b>", createdAt: minAgo(200) },
        // block — anomalies at/above the in-threshold (5)
        { ...base, vhostId: shopVhost.id, clientIp: "203.0.113.66", method: "POST", url: "/shop/login", ruleId: 942100, ruleMsg: "SQL Injection Attack Detected via libinjection (' OR 1=1)", anomalyScore: 5, action: "block", payloadSnippet: "user=admin' OR 1=1--&pass=x", createdAt: minAgo(150) },
        { ...base, vhostId: shopVhost.id, clientIp: "203.0.113.66", method: "GET", url: "/shop/download?file=../../../../etc/passwd", ruleId: 930100, ruleMsg: "Path Traversal Attack (/../) Detected", anomalyScore: 5, action: "block", createdAt: minAgo(148) },
        { ...base, vhostId: apiVhost.id, clientIp: "198.51.100.23", method: "POST", url: "/api/v1/debug/ping", ruleId: 932100, ruleMsg: "Unix Command Injection Detected (; cat /etc/passwd)", anomalyScore: 5, action: "block", payloadSnippet: "host=127.0.0.1; cat /etc/passwd", createdAt: minAgo(90) },
        { ...base, vhostId: shopVhost.id, clientIp: "192.0.2.10", method: "GET", url: "/shop/item/1", ruleId: 913100, ruleMsg: "Found User-Agent associated with security scanner (sqlmap, nikto, …)", anomalyScore: 5, action: "block", payloadSnippet: "UA: sqlmap/1.7", createdAt: minAgo(45) },
      ],
    });
  }

  return "M17: 2 vhosts, 2 policies, 2 exclusions, 10 logs";
}

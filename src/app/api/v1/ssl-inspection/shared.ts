/**
 * SSL/TLS Inspection shared service (M15 §2.1) — DTO shaping, the SIMULATED
 * decision engine (the appliance enforces for real; the sandbox replays the
 * same branch order against the DB policy + bypass rules), log queries and
 * stats. All reads/writes are tenant-scoped. Bypass rules are evaluated in
 * insertion order (id asc) per policy — first hit wins.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import {
  assertMatchValue,
  type SslBypassRuleCreate,
  type SslBypassRuleQuery,
  type SslBypassRuleUpdate,
  type SslLogQuery,
  type SslMode,
  type SslPolicyCreate,
  type SslPolicyUpdate,
} from "@/lib/validators/ssl-inspection";

// ── DTO shapes (mirrored by components/views/ssl-inspection/ssl-inspection-api.ts) ──

export type SslDecision = "inspected" | "bypassed" | "blocked";

export interface SslPolicyDTO {
  id: number;
  name: string;
  mode: SslMode;
  signingCaId: number | null;
  signingCaName: string | null;
  signingCaExpiresAt: string | null;
  hstsHandling: "honor" | "bypass";
  certPinningAction: "bypass" | "block";
  invalidCertAction: "block" | "warn_bypass";
  minTlsVersion: "1.2" | "1.3";
  enabled: boolean;
  bypassRuleCount: number;
  createdAt: string;
}

export interface SslBypassRuleDTO {
  id: number;
  policyId: number;
  policyName: string | null;
  matchType: "domain" | "wildcard" | "category" | "ip" | "cidr";
  matchValue: string;
  reason: string | null;
  enabled: boolean;
  createdAt: string;
}

export interface SslInspectionLogDTO {
  id: number;
  clientIp: string;
  sni: string;
  decision: SslDecision;
  reason: string; // policy | pinning | invalid_cert | bypass_rule | hsts | inspected
  tlsVersion: string | null;
  cipher: string | null;
  policyId: number | null;
  createdAt: string;
}

export interface SslTestResultDTO {
  sni: string;
  decision: SslDecision;
  reason: string;
  tlsVersion: string;
  cipher: string;
  policyId: number | null;
  policyName: string | null;
  matchedRule: string | null;
  logId: number;
}

export interface SslStatsDTO {
  inspected24h: number;
  bypassed24h: number;
  blocked24h: number;
  byReason: Record<string, number>;
  certExpiring: {
    count: number;
    nearest: Array<{ name: string; notAfter: string | null }>;
  };
}

// ── simulated handshake material (deterministic per SNI — no flaky tests) ───

const TLS13_CIPHERS = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"];
const TLS12_CIPHERS = ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"];

/** FNV-1a 32-bit — stable pseudo-selection of TLS version/cipher per SNI. */
function hash32(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function simulatedHandshake(sni: string, minTlsVersion: string): { tlsVersion: string; cipher: string } {
  const h = hash32(sni.toLowerCase());
  const tlsVersion = minTlsVersion === "1.3" ? "1.3" : h % 10 < 6 ? "1.3" : "1.2";
  const ciphers = tlsVersion === "1.3" ? TLS13_CIPHERS : TLS12_CIPHERS;
  return { tlsVersion, cipher: ciphers[h % ciphers.length]! };
}

// ── matching helpers ────────────────────────────────────────────────────────

/** `*.foo.com` matches foo.com itself and any subdomain. */
function wildcardMatch(pattern: string, sni: string): boolean {
  const suffix = pattern.slice(1); // ".foo.com"
  const base = suffix.slice(1); // "foo.com"
  return sni === base || sni.endsWith(suffix);
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split(".");
  return (
    ((Number(parts[0]) << 24) | (Number(parts[1]) << 16) | (Number(parts[2]) << 8) | Number(parts[3])) >>> 0
  );
}

function cidrMatch(cidr: string, value: string): boolean {
  const slash = cidr.indexOf("/");
  if (slash < 0) return false;
  const net = cidr.slice(0, slash);
  const bits = Number(cidr.slice(slash + 1));
  const ip = value.split("/")[0] ?? value;
  if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(ip)) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(net) & mask);
}

/** Sample pinning-heavy domains (spec §2.1 — appliance keeps the full list). */
const PINNING_DOMAINS = ["*.apple.com", "*.googleapis.com"];

/** Category keyword expansion for the simulated engine. */
const CATEGORY_KEYWORDS: Record<string, string[]> = {
  banking: ["bank", "pay"],
  streaming: ["video", "stream", "tv"],
  social: ["social", "facebook", "twitter", "instagram"],
  shopping: ["shop", "store", "cart"],
  gaming: ["game", "steam", "xbox"],
};

function categoryMatch(category: string, sni: string): boolean {
  const keywords = CATEGORY_KEYWORDS[category.toLowerCase()];
  if (keywords) return keywords.some((k) => sni.includes(k));
  return sni.includes(category.toLowerCase());
}

/** Banking-ish hostnames trigger the HSTS-honor branch. */
const BANKING_KEYWORDS = ["bank", "pay"];

function ruleMatches(matchType: string, matchValue: string, sni: string): boolean {
  const v = sni.toLowerCase();
  const m = matchValue.toLowerCase();
  switch (matchType) {
    case "domain":
      // defensive: seeded/imported rows may carry a `*.` value with domain type
      return m.startsWith("*.") ? wildcardMatch(m, v) : v === m;
    case "wildcard":
      return wildcardMatch(m, v);
    case "category":
      return categoryMatch(m, v);
    case "ip":
      return v === m;
    case "cidr":
      return cidrMatch(m, v);
    default:
      return false;
  }
}

// ── mappers ─────────────────────────────────────────────────────────────────

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);

type PolicyRow = {
  id: number;
  name: string;
  mode: string;
  signingCaId: number | null;
  hstsHandling: string;
  certPinningAction: string;
  invalidCertAction: string;
  minTlsVersion: string;
  enabled: boolean;
  createdAt: Date;
};

function toPolicyDto(
  p: PolicyRow,
  caById: Map<number, { name: string; notAfter: Date | null }>,
  ruleCount: number,
): SslPolicyDTO {
  const ca = p.signingCaId !== null ? caById.get(p.signingCaId) : undefined;
  return {
    id: p.id,
    name: p.name,
    mode: p.mode as SslPolicyDTO["mode"],
    signingCaId: p.signingCaId,
    signingCaName: ca?.name ?? null,
    signingCaExpiresAt: iso(ca?.notAfter ?? null),
    hstsHandling: p.hstsHandling as SslPolicyDTO["hstsHandling"],
    certPinningAction: p.certPinningAction as SslPolicyDTO["certPinningAction"],
    invalidCertAction: p.invalidCertAction as SslPolicyDTO["invalidCertAction"],
    minTlsVersion: p.minTlsVersion as SslPolicyDTO["minTlsVersion"],
    enabled: p.enabled,
    bypassRuleCount: ruleCount,
    createdAt: p.createdAt.toISOString(),
  };
}

function toLogDto(row: {
  id: number;
  clientIp: string;
  serverSni: string;
  action: string;
  reason: string;
  tlsVersion: string | null;
  cipher: string | null;
  policyId: number | null;
  createdAt: Date;
}): SslInspectionLogDTO {
  return {
    id: row.id,
    clientIp: row.clientIp,
    sni: row.serverSni,
    decision: row.action as SslInspectionLogDTO["decision"],
    reason: row.reason,
    tlsVersion: row.tlsVersion,
    cipher: row.cipher,
    policyId: row.policyId,
    createdAt: row.createdAt.toISOString(),
  };
}

// ── signing CA validation (spec §2.1 — VALIDATION_ERROR, see report note) ───

async function resolveSigningCa(
  tenantId: number,
  mode: SslMode,
  signingCaId: number | null | undefined,
): Promise<number | null> {
  // mode=none → no MITM ⇒ no signing CA needed (stored as null).
  if (mode === "none") return null;
  const ca =
    signingCaId == null
      ? null
      : await db.certificateAuthority.findFirst({ where: { id: signingCaId, tenantId } });
  if (!ca) {
    throw ApiError.validation("signingCaId is required for selective/full mode and must reference an existing CA");
  }
  if (ca.status !== "active") {
    throw ApiError.validation(`Signing CA "${ca.name}" is not active`);
  }
  if (ca.type !== "root" && ca.type !== "subordinate") {
    throw ApiError.validation(`Signing CA "${ca.name}" has unsupported type '${ca.type}'`);
  }
  return ca.id;
}

// ── policies ────────────────────────────────────────────────────────────────

export async function listPolicies(tenantId: number): Promise<SslPolicyDTO[]> {
  const [policies, ruleCounts] = await Promise.all([
    db.sslInspectionPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.sslBypassRule.groupBy({ by: ["policyId"], where: { tenantId }, _count: { _all: true } }),
  ]);
  const caIds = policies.map((p) => p.signingCaId).filter((v): v is number => v !== null);
  const cas = caIds.length
    ? await db.certificateAuthority.findMany({ where: { tenantId, id: { in: caIds } } })
    : [];
  const caById = new Map(cas.map((c) => [c.id, { name: c.name, notAfter: c.notAfter }]));
  const countBy = new Map(ruleCounts.map((r) => [r.policyId, r._count._all]));
  return policies.map((p) => toPolicyDto(p, caById, countBy.get(p.id) ?? 0));
}

export async function createPolicy(tenantId: number, body: SslPolicyCreate): Promise<SslPolicyDTO> {
  const signingCaId = await resolveSigningCa(tenantId, body.mode, body.signingCaId);
  const created = await db.sslInspectionPolicy.create({
    data: {
      tenantId,
      name: body.name,
      mode: body.mode,
      signingCaId,
      hstsHandling: body.hstsHandling,
      certPinningAction: body.certPinningAction,
      invalidCertAction: body.invalidCertAction,
      minTlsVersion: body.minTlsVersion,
      enabled: body.enabled,
    },
  });
  return toPolicyDto(created, new Map(), 0);
}

export async function updatePolicy(tenantId: number, id: number, body: SslPolicyUpdate): Promise<SslPolicyDTO> {
  const row = await db.sslInspectionPolicy.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("SSL inspection policy not found");

  // Re-validate the EFFECTIVE mode/CA pair (a partial update may change only one half).
  const nextMode = body.mode ?? (row.mode as SslMode);
  const nextCaId = body.signingCaId !== undefined ? body.signingCaId : row.signingCaId;
  const signingCaId = await resolveSigningCa(tenantId, nextMode, nextCaId);

  const updated = await db.sslInspectionPolicy.update({
    where: { id: row.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.mode !== undefined ? { mode: body.mode } : {}),
      signingCaId,
      ...(body.hstsHandling !== undefined ? { hstsHandling: body.hstsHandling } : {}),
      ...(body.certPinningAction !== undefined ? { certPinningAction: body.certPinningAction } : {}),
      ...(body.invalidCertAction !== undefined ? { invalidCertAction: body.invalidCertAction } : {}),
      ...(body.minTlsVersion !== undefined ? { minTlsVersion: body.minTlsVersion } : {}),
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
    },
  });
  return toPolicyDto(updated, new Map(), 0);
}

export async function deletePolicy(tenantId: number, id: number): Promise<{ name: string }> {
  const row = await db.sslInspectionPolicy.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("SSL inspection policy not found");
  // Bypass rules hang off the policy — remove them with it (logical refs, no FK cascade).
  await db.sslBypassRule.deleteMany({ where: { tenantId, policyId: id } });
  await db.sslInspectionPolicy.delete({ where: { id: row.id } });
  return { name: row.name };
}

// ── bypass rules ────────────────────────────────────────────────────────────

export async function listBypassRules(tenantId: number, query: SslBypassRuleQuery): Promise<SslBypassRuleDTO[]> {
  const [rules, policies] = await Promise.all([
    db.sslBypassRule.findMany({
      where: { tenantId, ...(query.policyId !== undefined ? { policyId: query.policyId } : {}) },
      orderBy: [{ policyId: "asc" }, { id: "asc" }],
    }),
    db.sslInspectionPolicy.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  const nameBy = new Map(policies.map((p) => [p.id, p.name]));
  return rules.map((r) => ({
    id: r.id,
    policyId: r.policyId,
    policyName: nameBy.get(r.policyId) ?? null,
    matchType: r.matchType as SslBypassRuleDTO["matchType"],
    matchValue: r.matchValue,
    reason: r.reason,
    enabled: r.enabled,
    createdAt: r.createdAt.toISOString(),
  }));
}

/** Default policy for rules created without an explicit policyId. */
async function defaultPolicyId(tenantId: number): Promise<number> {
  const first = await db.sslInspectionPolicy.findFirst({
    where: { tenantId, enabled: true },
    orderBy: { id: "asc" },
  });
  if (first) return first.id;
  const any = await db.sslInspectionPolicy.findFirst({ where: { tenantId }, orderBy: { id: "asc" } });
  if (!any) throw ApiError.validation("No SSL inspection policy exists yet — create one first");
  return any.id;
}

async function assertPolicyExists(tenantId: number, policyId: number): Promise<void> {
  const row = await db.sslInspectionPolicy.findFirst({ where: { id: policyId, tenantId }, select: { id: true } });
  if (!row) throw ApiError.notFound("SSL inspection policy not found");
}

export async function createBypassRule(tenantId: number, body: SslBypassRuleCreate): Promise<SslBypassRuleDTO> {
  assertMatchValue(body.matchType, body.matchValue);
  const policyId = body.policyId ?? (await defaultPolicyId(tenantId));
  await assertPolicyExists(tenantId, policyId);
  const created = await db.sslBypassRule.create({
    data: {
      tenantId,
      policyId,
      matchType: body.matchType,
      matchValue: body.matchValue,
      reason: body.reason ?? null,
      enabled: body.enabled,
    },
  });
  return {
    id: created.id,
    policyId: created.policyId,
    policyName: null,
    matchType: created.matchType as SslBypassRuleDTO["matchType"],
    matchValue: created.matchValue,
    reason: created.reason,
    enabled: created.enabled,
    createdAt: created.createdAt.toISOString(),
  };
}

export async function updateBypassRule(
  tenantId: number,
  id: number,
  body: SslBypassRuleUpdate,
): Promise<SslBypassRuleDTO> {
  const row = await db.sslBypassRule.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Bypass rule not found");

  // Re-validate the EFFECTIVE type/value pair (a partial update may change only one half).
  const matchType = body.matchType ?? (row.matchType as SslBypassRuleDTO["matchType"]);
  const matchValue = body.matchValue ?? row.matchValue;
  assertMatchValue(matchType, matchValue);

  const policyId = body.policyId ?? row.policyId;
  if (body.policyId !== undefined && body.policyId !== row.policyId) {
    await assertPolicyExists(tenantId, body.policyId);
  }

  const updated = await db.sslBypassRule.update({
    where: { id: row.id },
    data: {
      policyId,
      matchType,
      matchValue,
      ...(body.reason !== undefined ? { reason: body.reason } : {}),
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
    },
  });
  return {
    id: updated.id,
    policyId: updated.policyId,
    policyName: null,
    matchType: updated.matchType as SslBypassRuleDTO["matchType"],
    matchValue: updated.matchValue,
    reason: updated.reason,
    enabled: updated.enabled,
    createdAt: updated.createdAt.toISOString(),
  };
}

export async function deleteBypassRule(tenantId: number, id: number): Promise<{ matchValue: string }> {
  const row = await db.sslBypassRule.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Bypass rule not found");
  await db.sslBypassRule.delete({ where: { id: row.id } });
  return { matchValue: row.matchValue };
}

// ── simulated decision engine (spec §2.1 test endpoint) ─────────────────────

/**
 * Branch order (first match wins):
 *   1. enabled bypass rules (insertion order)      → bypassed / bypass_rule
 *   2. no enabled policy or mode=none              → bypassed / policy
 *   3. pinning list (`*.apple.com`, `*.googleapis.com`)
 *        + certPinningAction=block                 → blocked  / pinning
 *        else                                      → bypassed / pinning
 *   4. SNI contains "expired"|"self-signed"
 *        + invalidCertAction=block                 → blocked  / invalid_cert
 *        else (warn_bypass)                        → bypassed / invalid_cert
 *   5. banking-ish SNI (bank/pay) + HSTS honor     → bypassed / hsts
 *   6. default                                     → inspected / inspected
 * The decision is persisted as an SslInspectionLog row.
 */
export async function runDecisionEngine(
  tenantId: number,
  sni: string,
  clientIp: string,
  preferPolicyId?: number | null,
): Promise<SslTestResultDTO> {
  let policy = preferPolicyId
    ? await db.sslInspectionPolicy.findFirst({ where: { id: preferPolicyId, tenantId, enabled: true } })
    : null;
  if (!policy) {
    policy = await db.sslInspectionPolicy.findFirst({
      where: { tenantId, enabled: true },
      orderBy: { id: "asc" },
    });
  }

  let decision: SslDecision = "inspected";
  let reason = "inspected";
  let matchedRule: string | null = null;

  const rules = policy
    ? await db.sslBypassRule.findMany({
        where: { tenantId, policyId: policy.id, enabled: true },
        orderBy: { id: "asc" },
      })
    : [];
  const hit = rules.find((r) => ruleMatches(r.matchType, r.matchValue, sni));

  if (hit) {
    decision = "bypassed";
    reason = "bypass_rule";
    matchedRule = hit.matchValue;
  } else if (!policy || policy.mode === "none") {
    decision = "bypassed";
    reason = "policy";
  } else if (PINNING_DOMAINS.some((p) => wildcardMatch(p, sni))) {
    if (policy.certPinningAction === "block") {
      decision = "blocked";
    } else {
      decision = "bypassed";
    }
    reason = "pinning";
  } else if (sni.includes("expired") || sni.includes("self-signed")) {
    if (policy.invalidCertAction === "block") {
      decision = "blocked";
    } else {
      decision = "bypassed";
    }
    reason = "invalid_cert";
  } else if (policy.hstsHandling === "honor" && BANKING_KEYWORDS.some((k) => sni.includes(k))) {
    decision = "bypassed";
    reason = "hsts";
  }

  const { tlsVersion, cipher } = simulatedHandshake(sni, policy?.minTlsVersion ?? "1.2");
  const log = await db.sslInspectionLog.create({
    data: {
      tenantId,
      clientIp,
      serverSni: sni,
      action: decision,
      reason,
      tlsVersion,
      cipher,
      policyId: policy?.id ?? null,
    },
  });

  return {
    sni,
    decision,
    reason,
    tlsVersion,
    cipher,
    policyId: policy?.id ?? null,
    policyName: policy?.name ?? null,
    matchedRule,
    logId: log.id,
  };
}

// ── logs (paged-lite) ───────────────────────────────────────────────────────

export async function listLogs(tenantId: number, query: SslLogQuery): Promise<SslInspectionLogDTO[]> {
  const where = {
    tenantId,
    ...(query.decision !== undefined ? { action: query.decision } : {}),
    ...(query.q
      ? { OR: [{ serverSni: { contains: query.q } }, { clientIp: { contains: query.q } }] }
      : {}),
  };
  const rows = await db.sslInspectionLog.findMany({
    where,
    orderBy: { createdAt: "desc" },
    take: query.limit,
  });
  return rows.map(toLogDto);
}

// ── stats ───────────────────────────────────────────────────────────────────

export async function getStats(tenantId: number): Promise<SslStatsDTO> {
  const now = new Date();
  const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const in45d = new Date(now.getTime() + 45 * 24 * 60 * 60 * 1000);

  const [byAction, byReason, expiringCerts, expiringCas] = await Promise.all([
    db.sslInspectionLog.groupBy({
      by: ["action"],
      where: { tenantId, createdAt: { gte: since24h } },
      _count: { _all: true },
    }),
    db.sslInspectionLog.groupBy({
      by: ["reason"],
      where: { tenantId, createdAt: { gte: since24h } },
      _count: { _all: true },
    }),
    // certificates + CAs — active and expiring within 45 days
    db.certificate.findMany({
      where: { tenantId, status: "active", notAfter: { gte: now, lte: in45d } },
      orderBy: { notAfter: "asc" },
      select: { name: true, notAfter: true },
    }),
    db.certificateAuthority.findMany({
      where: { tenantId, status: "active", notAfter: { gte: now, lte: in45d } },
      orderBy: { notAfter: "asc" },
      select: { name: true, notAfter: true },
    }),
  ]);

  const actionCount: Record<string, number> = { inspected: 0, bypassed: 0, blocked: 0 };
  for (const row of byAction) actionCount[row.action] = row._count._all;

  const reasonCount: Record<string, number> = {};
  for (const row of byReason) reasonCount[row.reason] = row._count._all;

  const nearest = [...expiringCerts, ...expiringCas]
    .sort((a, b) => (a.notAfter?.getTime() ?? 0) - (b.notAfter?.getTime() ?? 0))
    .slice(0, 5)
    .map((c) => ({ name: c.name, notAfter: iso(c.notAfter) }));

  return {
    inspected24h: actionCount.inspected ?? 0,
    bypassed24h: actionCount.bypassed ?? 0,
    blocked24h: actionCount.blocked ?? 0,
    byReason: reasonCount,
    certExpiring: { count: expiringCerts.length + expiringCas.length, nearest },
  };
}

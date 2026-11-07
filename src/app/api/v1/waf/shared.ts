/**
 * WAF API shared plumbing (M17) — DTO shaping + guards used by the routes
 * under /api/v1/waf. WafPolicy.vhostId and WafVhost.certId are *logical*
 * refs (no Prisma relation), so cross-table names are resolved with small
 * lookup maps instead of includes.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { CRS_RULES } from "@/lib/waf/rules";
import type { WafPolicy } from "@prisma/client";

/** Human title for a sample CRS rule id (fallback for stats without rows). */
export function CRSTitle(ruleId: number): string {
  return CRS_RULES.find((r) => r.id === ruleId)?.msg ?? `CRS rule ${ruleId}`;
}

// ── cert binding guard (M17 §2.4.1: cert must exist + active + issuedFor) ───

/**
 * Validates a vhost TLS cert binding and returns the id to persist.
 * - tls=false  → binding is dropped (null).
 * - certId set → certificate must exist, be active (status + not expired)
 *   and be issuedFor `waf` | `general` (M14 PKI provides the material).
 */
export async function assertCertUsable(
  tenantId: number,
  certId: number | null | undefined,
  tls: boolean,
): Promise<number | null> {
  if (!tls || certId == null) return null;
  const cert = await db.certificate.findFirst({ where: { id: certId, tenantId } });
  if (!cert) throw ApiError.validation("Certificate not found for this tenant");
  const notExpired = !cert.notAfter || cert.notAfter.getTime() > Date.now();
  if (cert.status !== "active" || !notExpired) {
    throw ApiError.validation("Certificate is not active (revoked or expired)");
  }
  if (cert.issuedFor !== "waf" && cert.issuedFor !== "general") {
    throw ApiError.validation("Certificate must be issued for 'waf' or 'general'");
  }
  return cert.id;
}

// ── row → DTO shaping ───────────────────────────────────────────────────────

export interface VhostDTO {
  id: number;
  name: string;
  hostname: string;
  backendHost: string;
  backendPort: number;
  listenPort: number;
  tls: boolean;
  certId: number | null;
  certName: string | null;
  mode: string;
  enabled: boolean;
  createdAt: string;
  policy: { id: number; name: string; enabled: boolean } | null;
}

export async function listVhosts(tenantId: number): Promise<VhostDTO[]> {
  const [rows, policies, certs] = await Promise.all([
    db.wafVhost.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.wafPolicy.findMany({
      where: { tenantId },
      select: { id: true, name: true, vhostId: true, enabled: true },
    }),
    db.certificate.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  const policyByVhost = new Map(policies.map((p) => [p.vhostId, p]));
  const certNames = new Map(certs.map((c) => [c.id, c.name]));
  return rows.map((v) => {
    const pol = policyByVhost.get(v.id);
    return {
      id: v.id,
      name: v.name,
      hostname: v.hostname,
      backendHost: v.backendHost,
      backendPort: v.backendPort,
      listenPort: v.listenPort,
      tls: v.tls,
      certId: v.certId,
      certName: v.certId ? (certNames.get(v.certId) ?? null) : null,
      mode: v.mode,
      enabled: v.enabled,
      createdAt: v.createdAt.toISOString(),
      policy: pol ? { id: pol.id, name: pol.name, enabled: pol.enabled } : null,
    };
  });
}

export interface PolicyDTO {
  id: number;
  name: string;
  vhostId: number;
  vhostName: string | null;
  vhostHostname: string | null;
  owaspCrsEnabled: boolean;
  crsVersion: string;
  paranoiaLevel: number;
  anomalyInThreshold: number;
  anomalyOutThreshold: number;
  learningMode: boolean;
  geoBlockCountries: string[];
  rateLimitRpm: number | null;
  rateLimitBurst: number | null;
  apiProtection: boolean;
  enabled: boolean;
  createdAt: string;
}

export async function listPolicies(tenantId: number): Promise<PolicyDTO[]> {
  const [rows, vhosts] = await Promise.all([
    db.wafPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.wafVhost.findMany({ where: { tenantId }, select: { id: true, name: true, hostname: true } }),
  ]);
  const vhostById = new Map(vhosts.map((v) => [v.id, v]));
  return rows.map((p) => {
    const vhost = vhostById.get(p.vhostId);
    return {
      id: p.id,
      name: p.name,
      vhostId: p.vhostId,
      vhostName: vhost?.name ?? null,
      vhostHostname: vhost?.hostname ?? null,
      owaspCrsEnabled: p.owaspCrsEnabled,
      crsVersion: p.crsVersion,
      paranoiaLevel: p.paranoiaLevel,
      anomalyInThreshold: p.anomalyInThreshold,
      anomalyOutThreshold: p.anomalyOutThreshold,
      learningMode: p.learningMode,
      geoBlockCountries: safeCountries(p.geoBlockCountries),
      rateLimitRpm: p.rateLimitRpm,
      rateLimitBurst: p.rateLimitBurst,
      apiProtection: p.apiProtection,
      enabled: p.enabled,
      createdAt: p.createdAt.toISOString(),
    };
  });
}

/** Parse the geoBlockCountries JSON column defensively (default "[]"). */
export function safeCountries(json: string): string[] {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((c): c is string => typeof c === "string");
  } catch {
    return [];
  }
}

export function shapePolicy(
  row: WafPolicy,
  vhost?: { name: string; hostname: string } | null,
): PolicyDTO {
  return {
    id: row.id,
    name: row.name,
    vhostId: row.vhostId,
    vhostName: vhost?.name ?? null,
    vhostHostname: vhost?.hostname ?? null,
    owaspCrsEnabled: row.owaspCrsEnabled,
    crsVersion: row.crsVersion,
    paranoiaLevel: row.paranoiaLevel,
    anomalyInThreshold: row.anomalyInThreshold,
    anomalyOutThreshold: row.anomalyOutThreshold,
    learningMode: row.learningMode,
    geoBlockCountries: safeCountries(row.geoBlockCountries),
    rateLimitRpm: row.rateLimitRpm,
    rateLimitBurst: row.rateLimitBurst,
    apiProtection: row.apiProtection,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

/** 404 when the policy does not exist in the tenant. */
export async function policyOr404(tenantId: number, id: number) {
  const policy = await db.wafPolicy.findFirst({ where: { id, tenantId } });
  if (!policy) throw ApiError.notFound("Policy not found");
  return policy;
}

export interface ExclusionDTO {
  id: number;
  policyId: number;
  scope: string;
  matchValue: string;
  ruleId: number | null;
  note: string | null;
  enabled: boolean;
  createdAt: string;
}

export function shapeExclusion(row: {
  id: number;
  policyId: number;
  scope: string;
  matchValue: string;
  ruleId: number | null;
  note: string | null;
  enabled: boolean;
  createdAt: Date;
}): ExclusionDTO {
  return {
    id: row.id,
    policyId: row.policyId,
    scope: row.scope,
    matchValue: row.matchValue,
    ruleId: row.ruleId,
    note: row.note,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

export interface WafLogDTO {
  id: number;
  vhostId: number | null;
  vhostHostname: string | null;
  clientIp: string;
  method: string;
  url: string;
  ruleId: number | null;
  ruleMsg: string | null;
  anomalyScore: number;
  action: string;
  payloadSnippet: string | null;
  createdAt: string;
}

export function shapeLog(
  row: {
    id: number;
    vhostId: number | null;
    clientIp: string;
    method: string;
    url: string;
    ruleId: number | null;
    ruleMsg: string | null;
    anomalyScore: number;
    action: string;
    payloadSnippet: string | null;
    createdAt: Date;
  },
  vhostNames: Map<number, string>,
): WafLogDTO {
  return {
    id: row.id,
    vhostId: row.vhostId,
    vhostHostname: row.vhostId !== null ? (vhostNames.get(row.vhostId) ?? null) : null,
    clientIp: row.clientIp,
    method: row.method,
    url: row.url,
    ruleId: row.ruleId,
    ruleMsg: row.ruleMsg,
    anomalyScore: row.anomalyScore,
    action: row.action,
    payloadSnippet: row.payloadSnippet,
    createdAt: row.createdAt.toISOString(),
  };
}

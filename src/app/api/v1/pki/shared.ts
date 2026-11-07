/**
 * PKI API shared plumbing (M14) — DTO shaping + security guards used by every
 * route under /api/v1/pki. SECURITY CONTRACT: `keyPem` (private keys) NEVER
 * leaves the server through list/GET JSON — rows are sanitized to
 * `keyFingerprint` (sha256 of DER, first 16 hex chars) + `hasKey: true`, and
 * raw material only flows through the *download* endpoints with part=key,
 * which additionally require super_admin/tenant_admin.
 */

import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { daysUntil, fingerprint, statusOf, type PkiStatus } from "@/lib/pki/x509";

type CertificateAuthorityRow = {
  id: number;
  name: string;
  type: string;
  commonName: string;
  org: string | null;
  keyType: string;
  validityDays: number;
  parentCaId: number | null;
  serial: string;
  certPem: string;
  keyPem: string;
  status: string;
  crlUrl: string | null;
  ocspUrl: string | null;
  autoRenew: boolean;
  notBefore: Date | null;
  notAfter: Date | null;
  createdAt: Date;
};

type CertificateRow = {
  id: number;
  caId: number;
  name: string;
  commonName: string;
  sans: string;
  type: string;
  issuedFor: string;
  keyType: string;
  validityDays: number;
  serial: string;
  certPem: string;
  keyPem: string;
  status: string;
  revocationReason: string | null;
  autoRenew: boolean;
  notBefore: Date | null;
  notAfter: Date | null;
  createdAt: Date;
};

// ── DTO shapes (mirrored by components/views/pki/pki-api.ts) ────────────────

export interface CaDto {
  id: number;
  name: string;
  type: string; // root | subordinate
  commonName: string;
  org: string | null;
  keyType: string;
  validityDays: number;
  parentCaId: number | null;
  parentName: string | null;
  serial: string;
  /** Public material — certificates are not secret. */
  certPem: string;
  /** NEVER keyPem — sha256(DER) truncated to 16 hex chars. */
  keyFingerprint: string | null;
  hasKey: boolean;
  /** Recomputed on read (expiry), persisted status stays the stored column. */
  status: PkiStatus;
  crlUrl: string | null;
  ocspUrl: string | null;
  autoRenew: boolean;
  notBefore: string | null;
  notAfter: string | null;
  daysUntilExpiry: number | null;
  issuedCount: number;
  createdAt: string;
}

export interface CertDto {
  id: number;
  caId: number;
  caName: string | null;
  name: string;
  commonName: string;
  sans: string[];
  type: string; // server | client | device | user
  issuedFor: string; // ssl_inspect | waf | vpn | email | general
  keyType: string;
  validityDays: number;
  serial: string;
  certPem: string;
  keyFingerprint: string | null;
  hasKey: boolean;
  status: PkiStatus;
  revocationReason: string | null;
  autoRenew: boolean;
  notBefore: string | null;
  notAfter: string | null;
  daysUntilExpiry: number | null;
  createdAt: string;
}

// ── sanitizers ──────────────────────────────────────────────────────────────

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);

function parseSans(json: string): string[] {
  try {
    const parsed: unknown = JSON.parse(json);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

export function sanitizeCa(ca: CertificateAuthorityRow, issuedCount = 0, parentName: string | null = null): CaDto {
  return {
    id: ca.id,
    name: ca.name,
    type: ca.type,
    commonName: ca.commonName,
    org: ca.org,
    keyType: ca.keyType,
    validityDays: ca.validityDays,
    parentCaId: ca.parentCaId,
    parentName,
    serial: ca.serial,
    certPem: ca.certPem,
    keyFingerprint: ca.keyPem ? fingerprint(ca.keyPem) : null,
    hasKey: ca.keyPem.length > 0,
    status: statusOf(ca.notAfter, ca.status === "revoked"),
    crlUrl: ca.crlUrl,
    ocspUrl: ca.ocspUrl,
    autoRenew: ca.autoRenew,
    notBefore: iso(ca.notBefore),
    notAfter: iso(ca.notAfter),
    daysUntilExpiry: daysUntil(ca.notAfter),
    issuedCount,
    createdAt: ca.createdAt.toISOString(),
  };
}

export function sanitizeCert(cert: CertificateRow, caName: string | null = null): CertDto {
  return {
    id: cert.id,
    caId: cert.caId,
    caName,
    name: cert.name,
    commonName: cert.commonName,
    sans: parseSans(cert.sans),
    type: cert.type,
    issuedFor: cert.issuedFor,
    keyType: cert.keyType,
    validityDays: cert.validityDays,
    serial: cert.serial,
    certPem: cert.certPem,
    keyFingerprint: cert.keyPem ? fingerprint(cert.keyPem) : null,
    hasKey: cert.keyPem.length > 0,
    status: statusOf(cert.notAfter, cert.status === "revoked"),
    revocationReason: cert.revocationReason,
    autoRenew: cert.autoRenew,
    notBefore: iso(cert.notBefore),
    notAfter: iso(cert.notAfter),
    daysUntilExpiry: daysUntil(cert.notAfter),
    createdAt: cert.createdAt.toISOString(),
  };
}

// ── security ────────────────────────────────────────────────────────────────

/** part=key exports are admin-class: super_admin / tenant_admin only. */
export function requireKeyAdmin(role: string): void {
  if (role !== "super_admin" && role !== "tenant_admin") {
    throw ApiError.forbidden("Private key export requires super_admin or tenant_admin role");
  }
}

// ── chain walking ───────────────────────────────────────────────────────────

/**
 * CA chain for `caId` — [ca, parent, grandparent, … root] cert PEMs, tenant
 * scoped, cycle-safe. Returns [] when the CA does not exist in the tenant.
 */
export async function caChainPems(tenantId: number, caId: number): Promise<string[]> {
  const chain: string[] = [];
  const visited = new Set<number>();
  let currentId: number | null = caId;
  while (currentId !== null && !visited.has(currentId) && visited.size < 8) {
    visited.add(currentId);
    const ca = await db.certificateAuthority.findFirst({ where: { id: currentId, tenantId } });
    if (!ca) break;
    chain.push(ca.certPem);
    currentId = ca.parentCaId;
  }
  return chain;
}

// ── download responses ──────────────────────────────────────────────────────

const FILENAME_SAFE = /[^a-z0-9._-]+/gi;

export function slugFilename(name: string): string {
  return (name.toLowerCase().replace(FILENAME_SAFE, "-").replace(/^-+|-+$/g, "") || "pki");
}

/** PEM/CRL text download — attachment with a stable filename. */
export function pemResponse(pem: string, filename: string, contentType = "text/plain; charset=utf-8"): NextResponse {
  return new NextResponse(pem, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}

/** Normalize SAN entries to canonical "DNS:x" / "IP:y" form before storing. */
export function normalizeSans(sans: string[]): string[] {
  return sans.map((s) => {
    const entry = s.trim();
    if (/^DNS:/i.test(entry)) return `DNS:${entry.slice(4).trim()}`;
    if (/^IP:/i.test(entry)) return `IP:${entry.slice(3).trim()}`;
    return `DNS:${entry}`;
  });
}

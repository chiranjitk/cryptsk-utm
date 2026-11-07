"use client";

/**
 * SSL/TLS Inspection typed client (M15) — mirrors the threat-intel-api.ts
 * contract: module-local envelope unwrapping that preserves zod `details`,
 * flat endpoint object, DTO types declared here (server routes live under
 * /api/v1/ssl-inspection/*, service DTOs are structurally identical).
 * Signing-CA options are reused from the PKI client (GET /api/v1/pki/cas).
 */

// ── DTOs (mirror app/api/v1/ssl-inspection/shared.ts) ───────────────────────

export type SslMode = "none" | "selective" | "full";
export type SslMatchType = "domain" | "wildcard" | "category" | "ip" | "cidr";
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
  matchType: SslMatchType;
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
  reason: string;
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

// ── display constants ───────────────────────────────────────────────────────

export const SSL_MODES: SslMode[] = ["none", "selective", "full"];
export const SSL_MATCH_TYPES: SslMatchType[] = ["domain", "wildcard", "category", "ip", "cidr"];
export const HSTS_OPTIONS: Array<"honor" | "bypass"> = ["honor", "bypass"];
export const PINNING_OPTIONS: Array<"bypass" | "block"> = ["bypass", "block"];
export const INVALID_CERT_OPTIONS: Array<"block" | "warn_bypass"> = ["block", "warn_bypass"];
export const MIN_TLS_OPTIONS: Array<"1.2" | "1.3"> = ["1.2", "1.3"];

/** Per-type hint + placeholder for the bypass-rule editor. */
export const MATCH_HINTS: Record<SslMatchType, { hint: string; placeholder: string }> = {
  domain: { hint: "exact hostname, e.g. portal.example.com", placeholder: "portal.example.com" },
  wildcard: { hint: "*.domain.tld shape, e.g. *.example.com", placeholder: "*.example.com" },
  category: { hint: "category word, e.g. banking (matches bank/pay hosts)", placeholder: "banking" },
  ip: { hint: "single IPv4 address, e.g. 10.0.0.5", placeholder: "10.0.0.5" },
  cidr: { hint: "IPv4 CIDR, e.g. 10.0.0.0/8", placeholder: "10.0.0.0/8" },
};

// ── fetch plumbing (same shape as threat-intel-api.ts) ──────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class SslInspectionApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "SslInspectionApiError";
    this.code = code;
    this.details = details;
  }
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new SslInspectionApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SslInspectionApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from a SslInspectionApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof SslInspectionApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const sslInspectionApi = {
  // policies
  listPolicies: () => fetchJson<SslPolicyDTO[]>("/api/v1/ssl-inspection/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<SslPolicyDTO>("/api/v1/ssl-inspection/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<SslPolicyDTO>(`/api/v1/ssl-inspection/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/ssl-inspection/policies/${id}`, { method: "DELETE" }),

  // simulated decision test (id may be a policy id or "auto" — server pins
  // the policy when it exists, else resolves the first enabled one)
  testPolicy: (id: number | "auto", sni: string) =>
    fetchJson<SslTestResultDTO>(`/api/v1/ssl-inspection/policies/${id}/test`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ sni }),
    }),

  // bypass rules
  listBypassRules: (policyId?: number) =>
    fetchJson<SslBypassRuleDTO[]>(`/api/v1/ssl-inspection/bypass-rules${policyId ? `?policyId=${policyId}` : ""}`),
  createBypassRule: (body: Record<string, unknown>) =>
    fetchJson<SslBypassRuleDTO>("/api/v1/ssl-inspection/bypass-rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateBypassRule: (id: number, body: Record<string, unknown>) =>
    fetchJson<SslBypassRuleDTO>(`/api/v1/ssl-inspection/bypass-rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteBypassRule: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/ssl-inspection/bypass-rules/${id}`, { method: "DELETE" }),

  // logs + stats
  listLogs: (params: string) =>
    fetchJson<SslInspectionLogDTO[]>(`/api/v1/ssl-inspection/logs${params ? `?${params}` : ""}`),
  getStats: () => fetchJson<SslStatsDTO>("/api/v1/ssl-inspection/stats"),
};

// ── shared param builder ────────────────────────────────────────────────────

/** URLSearchParams joiner that skips empty values — keeps query keys stable. */
export function qs(params: Record<string, string | number | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  return sp.toString();
}

// ── time formatting (console-side, avoids pulling date-fns into views) ──────

export function fmtRelative(value: string | null): string {
  if (!value) return "never";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return value;
  const diff = Date.now() - ts;
  if (diff < 0) return "just now";
  const sec = Math.floor(diff / 1000);
  if (sec < 45) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

"use client";

/**
 * WAF typed client (M17) — mirrors the logs-api.ts contract: module-local
 * envelope unwrapping that preserves zod `details`, flat endpoint object, DTO
 * types declared here (server routes live under /api/v1/waf/*; shapes mirror
 * src/app/api/v1/waf/shared.ts).
 */

// ── DTOs (mirror app/api/v1/waf/shared.ts) ──────────────────────────────────

export type WafMode = "waf" | "reverse_proxy";
export type CrsVersion = "3.3" | "4.0";
export type ExclusionScope = "rule_id" | "param" | "url";
export type WafAction = "pass" | "log" | "block";
export type TestMethod = "GET" | "POST" | "PUT" | "DELETE";

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
  mode: WafMode;
  enabled: boolean;
  createdAt: string;
  policy: { id: number; name: string; enabled: boolean } | null;
}

export interface PolicyDTO {
  id: number;
  name: string;
  vhostId: number;
  vhostName: string | null;
  vhostHostname: string | null;
  owaspCrsEnabled: boolean;
  crsVersion: CrsVersion;
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

export interface ExclusionDTO {
  id: number;
  policyId: number;
  scope: ExclusionScope;
  matchValue: string;
  ruleId: number | null;
  note: string | null;
  enabled: boolean;
  createdAt: string;
}

export interface TestMatchDTO {
  id: number;
  msg: string;
  category: string;
  score: number;
}

export interface TestResultDTO {
  action: WafAction;
  reason: "anomaly" | "geo" | "rate_limit" | null;
  anomalyScore: number;
  threshold: number;
  matched: TestMatchDTO[];
  learningMode: boolean;
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
  action: WafAction;
  payloadSnippet: string | null;
  createdAt: string;
}

export interface WafStats {
  blocked24h: number;
  logged24h: number;
  passed24h: number;
  topRules: Array<{ ruleId: number; msg: string; count: number }>;
  byVhost: Record<string, number>;
}

/** Active certificate entry for the vhost TLS binding (from M14 PKI list). */
export interface CertOption {
  id: number;
  name: string;
  commonName: string;
  issuedFor: string;
  status: string;
}

// ── envelope plumbing (same recipe as logs-api.ts) ──────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class WafApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "WafApiError";
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
    throw new WafApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new WafApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from a WafApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof WafApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const wafApi = {
  // vhosts
  listVhosts: () => fetchJson<VhostDTO[]>("/api/v1/waf/vhosts"),
  createVhost: (body: Record<string, unknown>) =>
    fetchJson<VhostDTO>("/api/v1/waf/vhosts", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateVhost: (id: number, body: Record<string, unknown>) =>
    fetchJson<VhostDTO>(`/api/v1/waf/vhosts/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteVhost: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/waf/vhosts/${id}`, { method: "DELETE" }),

  // policies
  listPolicies: () => fetchJson<PolicyDTO[]>("/api/v1/waf/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<PolicyDTO>("/api/v1/waf/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<PolicyDTO>(`/api/v1/waf/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/waf/policies/${id}`, { method: "DELETE" }),

  // exclusions (scoped to a policy)
  listExclusions: (policyId: number) => fetchJson<ExclusionDTO[]>(`/api/v1/waf/policies/${policyId}/exclusions`),
  createExclusion: (policyId: number, body: Record<string, unknown>) =>
    fetchJson<ExclusionDTO>(`/api/v1/waf/policies/${policyId}/exclusions`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  updateExclusion: (policyId: number, exclusionId: number, body: Record<string, unknown>) =>
    fetchJson<ExclusionDTO>(`/api/v1/waf/policies/${policyId}/exclusions/${exclusionId}`, {
      method: "PUT",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deleteExclusion: (policyId: number, exclusionId: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/waf/policies/${policyId}/exclusions/${exclusionId}`, { method: "DELETE" }),

  // simulated CRS test
  testPolicy: (policyId: number, body: { method: TestMethod; url: string; payload?: string }) =>
    fetchJson<TestResultDTO>(`/api/v1/waf/policies/${policyId}/test`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),

  // logs + stats
  listLogs: (params: string) =>
    fetchJson<WafLogDTO[]>(`/api/v1/waf/logs${params ? `?${params}` : ""}`),
  getStats: () => fetchJson<WafStats>("/api/v1/waf/stats"),

  // M14 PKI reuse — active certs for the TLS binding select (endpoint owned by M14)
  listActiveCerts: () =>
    fetchJson<CertOption[]>("/api/v1/pki/certificates?status=active").then((rows) =>
      rows.filter((c) => c.issuedFor === "waf" || c.issuedFor === "general"),
    ),
};

// ── shared param builder (skips empty values — keeps query keys stable) ─────

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

// ── display constants ───────────────────────────────────────────────────────

export const TEST_METHODS: TestMethod[] = ["GET", "POST", "PUT", "DELETE"];
export const CRS_VERSIONS: CrsVersion[] = ["3.3", "4.0"];
export const EXCLUSION_SCOPES: ExclusionScope[] = ["rule_id", "param", "url"];

/** Sample payloads for the test card — one per attack category. */
export const TEST_PRESETS: Array<{ label: string; method: TestMethod; url: string; payload: string }> = [
  { label: "SQLi ' OR 1=1", method: "POST", url: "/shop/login", payload: "user=admin' OR 1=1--&pass=x" },
  { label: "XSS <script>", method: "GET", url: "/shop/search?q=<script>alert(1)</script>", payload: "" },
  { label: "LFI ../", method: "GET", url: "/shop/download?file=../../../../etc/passwd", payload: "" },
  { label: "RCE ; cat", method: "POST", url: "/shop/ping", payload: "host=127.0.0.1; cat /etc/passwd" },
  { label: "Scanner sqlmap", method: "GET", url: "/shop/item/1", payload: "" },
  { label: "Clean request", method: "GET", url: "/shop/products?page=2", payload: "" },
  { label: "Geo-block sim (country=CN)", method: "GET", url: "/shop/checkout", payload: "country=CN" },
];

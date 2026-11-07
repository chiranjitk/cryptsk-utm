"use client";

/**
 * URL Filtering typed client (M16) — mirrors the threat-intel-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO types declared here (server routes live under
 * /api/v1/url-filter/*, service DTOs are structurally identical).
 */

// ── DTOs (mirror app/api/v1/url-filter/service.ts) ──────────────────────────

export type PolicyAction = "allow" | "block";
export type RuleAction = "allow" | "block" | "warn";
export type ListType = "block" | "allow";
export type MatchType = "domain" | "wildcard" | "url";
export type UrlLogAction = "allowed" | "blocked" | "warned";
export type UrlFilterReason =
  | "category"
  | "custom_block"
  | "custom_allow"
  | "safe_search"
  | "file_type"
  | "default";
export type UrlCategory =
  | "gambling"
  | "adult"
  | "social_media"
  | "malware"
  | "phishing"
  | "p2p"
  | "streaming"
  | "games"
  | "news"
  | "shopping"
  | "weapons"
  | "hate"
  | "custom";

export interface UrlPolicyDTO {
  id: number;
  name: string;
  defaultAction: PolicyAction;
  safeSearchEnforce: boolean;
  fileTypesBlocked: string[];
  httpsInspection: boolean;
  transparentProxy: boolean;
  enabled: boolean;
  ruleCount: number;
  customListCount: number;
  createdAt: string;
}

export interface CategoryRuleDTO {
  category: string;
  action: RuleAction;
  listSource: "aggregated" | "custom";
  enabled: boolean;
  configured: boolean;
}

export interface CustomListDTO {
  id: number;
  policyId: number;
  listType: ListType;
  matchType: MatchType;
  value: string;
  note: string | null;
  createdAt: string;
}

export interface UrlFilterLogDTO {
  id: number;
  clientIp: string;
  method: string;
  url: string;
  domain: string;
  category: string;
  action: UrlLogAction;
  reason: string;
  policyId: number | null;
  createdAt: string;
}

export interface UrlTestResultDTO {
  decision: UrlLogAction;
  reason: UrlFilterReason;
  category?: string;
}

export interface UrlFilterStatsDTO {
  allowed24h: number;
  blocked24h: number;
  warned24h: number;
  topBlocked: Array<{ domain: string; count: number }>;
  categoryBreakdown: Record<string, number>;
}

export interface ImportResultDTO {
  created: number;
  skipped: number;
}

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface Paged<T> {
  data: T[];
  meta: PageMeta;
}

// ── fetch plumbing (same shape as threat-intel-api.ts) ──────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class UrlFilterApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "UrlFilterApiError";
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
    throw new UrlFilterApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new UrlFilterApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new UrlFilterApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new UrlFilterApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from a UrlFilterApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof UrlFilterApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const urlFilterApi = {
  // policies
  listPolicies: () => fetchJson<UrlPolicyDTO[]>("/api/v1/url-filter/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<UrlPolicyDTO>("/api/v1/url-filter/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<UrlPolicyDTO>(`/api/v1/url-filter/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/url-filter/policies/${id}`, { method: "DELETE" }),

  // category rules (replace-all semantics on PUT)
  listCategoryRules: (policyId: number) =>
    fetchJson<CategoryRuleDTO[]>(`/api/v1/url-filter/policies/${policyId}/categories`),
  replaceCategoryRules: (policyId: number, rules: Array<Record<string, unknown>>) =>
    fetchJson<CategoryRuleDTO[]>(`/api/v1/url-filter/policies/${policyId}/categories`, {
      method: "PUT",
      headers: JSON_HEADERS,
      body: JSON.stringify({ rules }),
    }),

  // simulated test
  testUrl: (policyId: number, url: string) =>
    fetchJson<UrlTestResultDTO>(`/api/v1/url-filter/policies/${policyId}/test`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ url }),
    }),

  // custom lists
  listCustomLists: (params: string) =>
    fetchJson<CustomListDTO[]>(`/api/v1/url-filter/custom-lists${params ? `?${params}` : ""}`),
  createCustomList: (body: Record<string, unknown>) =>
    fetchJson<CustomListDTO>("/api/v1/url-filter/custom-lists", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteCustomList: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/url-filter/custom-lists/${id}`, { method: "DELETE" }),
  importCustomLists: (body: { policyId: number; listType: ListType; text: string }) =>
    fetchJson<ImportResultDTO>("/api/v1/url-filter/custom-lists/import", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),

  // logs + stats
  listLogs: (params: string) => fetchJsonList<UrlFilterLogDTO>("/api/v1/url-filter/logs", params),
  getStats: () => fetchJson<UrlFilterStatsDTO>("/api/v1/url-filter/stats"),
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

export const URL_CATEGORIES: UrlCategory[] = [
  "gambling",
  "adult",
  "social_media",
  "malware",
  "phishing",
  "p2p",
  "streaming",
  "games",
  "news",
  "shopping",
  "weapons",
  "hate",
  "custom",
];

export const RULE_ACTIONS: RuleAction[] = ["allow", "block", "warn"];
export const LIST_TYPES: ListType[] = ["block", "allow"];
export const MATCH_TYPES: MatchType[] = ["domain", "wildcard", "url"];
export const LOG_ACTIONS: UrlLogAction[] = ["allowed", "blocked", "warned"];

/** snake_case → short label for category chips/tables. */
export function categoryLabel(c: string): string {
  return c.replace(/_/g, " ");
}

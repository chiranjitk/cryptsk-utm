"use client";

/**
 * Application Control typed client (M18) — mirrors the url-filter-api.ts
 * contract: module-local envelope unwrapping that preserves zod `details`,
 * flat endpoint object, DTO types declared here (server routes live under
 * /api/v1/app-control/*, service DTOs are structurally identical).
 */

// ── DTOs (mirror app/api/v1/app-control/service.ts) ─────────────────────────

export type PolicyAction = "allow" | "block";
export type UnknownAppAction = "allow" | "block" | "log";
export type RuleAction = "allow" | "block" | "limit";
export type Direction = "both" | "upload" | "download";
export type AppLogAction = "allowed" | "blocked" | "limited";
export type AppCategory =
  | "media"
  | "collaboration"
  | "remote"
  | "filesharing"
  | "social"
  | "gaming"
  | "devops";
export type AppTestReason = "rule" | "unknown_app" | "default";

export interface AppPolicyDTO {
  id: number;
  name: string;
  defaultAction: PolicyAction;
  unknownAppAction: UnknownAppAction;
  enabled: boolean;
  ruleCount: number;
  createdAt: string;
}

export interface AppRuleDTO {
  id: number;
  policyId: number;
  appName: string;
  category: string;
  action: RuleAction;
  bandwidthLimitMbps: number | null;
  direction: Direction;
  userGroupIds: number[];
  enabled: boolean;
  hitCount: number;
}

export interface AppCatalogEntryDTO {
  name: string;
  category: AppCategory;
  description: string;
}

export interface AppLogDTO {
  id: number;
  appName: string;
  action: AppLogAction;
  clientIp: string;
  bytes: number;
  ruleId: number | null;
  createdAt: string;
}

export interface AppTestResultDTO {
  decision: AppLogAction;
  appName: string;
  ruleId?: number;
  bandwidthLimitMbps?: number;
  reason: AppTestReason;
}

export interface AppStatsDTO {
  allowed24h: number;
  blocked24h: number;
  limited24h: number;
  topApps: Array<{ appName: string; count: number; bytes: number }>;
  ruleHitCounts: Array<{ appName: string; hitCount: number }>;
}

export interface UserGroupOptionDTO {
  id: number;
  name: string;
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

// ── fetch plumbing (same shape as url-filter-api.ts) ────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class AppControlApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "AppControlApiError";
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
    throw new AppControlApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new AppControlApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new AppControlApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new AppControlApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from an AppControlApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof AppControlApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

/** referencedBy rows from a 409 CONFLICT (policy delete blocked by rules). */
export interface RefRow {
  ruleName: string;
  ruleType: string;
}

export function referencedByOf(err: unknown): RefRow[] {
  if (!(err instanceof AppControlApiError) || !err.details || typeof err.details !== "object") return [];
  const raw = (err.details as { referencedBy?: unknown }).referencedBy;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((r): r is RefRow => Boolean(r) && typeof r === "object" && typeof (r as RefRow).ruleName === "string")
    .map((r) => ({ ruleName: r.ruleName, ruleType: String(r.ruleType ?? "app_control") }));
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const appControlApi = {
  // policies
  listPolicies: () => fetchJson<AppPolicyDTO[]>("/api/v1/app-control/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<AppPolicyDTO>("/api/v1/app-control/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<AppPolicyDTO>(`/api/v1/app-control/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/app-control/policies/${id}`, { method: "DELETE" }),

  // rules
  listRules: (policyId: number) =>
    fetchJson<AppRuleDTO[]>(`/api/v1/app-control/policies/${policyId}/rules`),
  createRule: (policyId: number, body: Record<string, unknown>) =>
    fetchJson<AppRuleDTO>(`/api/v1/app-control/policies/${policyId}/rules`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateRule: (ruleId: number, body: Record<string, unknown>) =>
    fetchJson<AppRuleDTO>(`/api/v1/app-control/rules/${ruleId}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRule: (ruleId: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/app-control/rules/${ruleId}`, { method: "DELETE" }),

  // static nDPI catalog
  getCatalog: () =>
    fetchJson<{ apps: AppCatalogEntryDTO[]; categories: AppCategory[] }>("/api/v1/app-control/catalog"),

  // simulated test
  testApp: (policyId: number, appName: string) =>
    fetchJson<AppTestResultDTO>(`/api/v1/app-control/policies/${policyId}/test`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ appName }),
    }),

  // logs + stats
  listLogs: (params: string) => fetchJsonList<AppLogDTO>("/api/v1/app-control/logs", params),
  getStats: () => fetchJson<AppStatsDTO>("/api/v1/app-control/stats"),

  /**
   * User groups for rule scoping chips — endpoint may not exist yet in every
   * sandbox; ANY failure (404, shape drift, offline) degrades to [].
   */
  listUserGroups: async (limit = 100): Promise<UserGroupOptionDTO[]> => {
    try {
      const res = await fetch(`/api/v1/user-groups?limit=${limit}`, { credentials: "same-origin" });
      if (!res.ok) return [];
      const body = (await res.json()) as { data?: unknown };
      const raw = body?.data;
      if (!Array.isArray(raw)) return [];
      return raw
        .filter((g): g is UserGroupOptionDTO => Boolean(g) && typeof g === "object" && typeof (g as UserGroupOptionDTO).id === "number" && typeof (g as UserGroupOptionDTO).name === "string")
        .map((g) => ({ id: g.id, name: g.name }));
    } catch {
      return [];
    }
  },
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

// ── time + bytes formatting (console-side, avoids pulling date-fns in) ──────

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

/** Humanized byte volume (KB / MB / GB) for log + stats rows. */
export function humanBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return `${v >= 100 || u === 0 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

// ── display constants ───────────────────────────────────────────────────────

export const RULE_ACTIONS: RuleAction[] = ["allow", "block", "limit"];
export const DIRECTIONS: Direction[] = ["both", "upload", "download"];
export const POLICY_ACTIONS: PolicyAction[] = ["allow", "block"];
export const UNKNOWN_APP_ACTIONS: UnknownAppAction[] = ["allow", "block", "log"];
export const LOG_ACTIONS: AppLogAction[] = ["allowed", "blocked", "limited"];

/** snake/none → short label for category chips. */
export function categoryLabel(c: string): string {
  return c.replace(/_/g, " ");
}

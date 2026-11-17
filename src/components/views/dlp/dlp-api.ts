"use client";

/**
 * DLP typed client (Phase 3 §3.3) — mirrors the threat-intel-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO types declared here (server routes live under /api/v1/dlp/*,
 * service DTOs are structurally identical).
 */

// ── DTOs (mirror lib/dlp/service.ts) ────────────────────────────────────────

export type DlpKind = "regex" | "keyword";
export type DlpSeverity = "low" | "medium" | "high" | "critical";
export type DlpCategory = "pii" | "financial" | "credentials" | "custom";
export type DlpAction = "alert" | "block" | "quarantine";
export type DlpProtocol = "http" | "https" | "smtp" | "ftp" | "dns";
export type DlpIncidentStatus = "new" | "reviewing" | "resolved" | "false_positive";

export interface DlpPatternDTO {
  id: number;
  name: string;
  kind: DlpKind;
  value: string;
  severity: DlpSeverity;
  category: DlpCategory;
  enabled: boolean;
  /** resolved keyword list (kind=keyword) — empty for regex patterns */
  keywords: string[];
  createdAt: string;
}

export interface DlpPolicyDTO {
  id: number;
  name: string;
  protocols: string[];
  patternIds: number[];
  /** resolved pattern names keyed by pattern id (missing ones render as #id) */
  patternNames: Record<number, string>;
  fileTypes: string[];
  action: DlpAction;
  notifyUser: boolean;
  enabled: boolean;
  createdAt: string;
}

export interface DlpIncidentDTO {
  id: number;
  policyId: number;
  policyName: string | null;
  patternId: number;
  patternName: string | null;
  severity: DlpSeverity;
  protocol: string;
  sourceIp: string;
  userName: string | null;
  /** engine-redacted excerpt — matched span is masked, never raw content */
  excerpt: string;
  status: DlpIncidentStatus;
  detail: { matchedPattern?: string; action?: DlpAction; offset?: number; fileTypeBlocked?: boolean };
  createdAt: string;
}

export interface DlpStats {
  totalIncidents: number;
  openIncidents: number;
  bySeverity: Record<DlpSeverity, number>;
  byStatus: Record<DlpIncidentStatus, number>;
  patterns: number;
  enabledPatterns: number;
  policies: number;
  enabledPolicies: number;
  trend7d: Array<{ date: string; count: number }>;
}

export interface DlpMatchDTO {
  patternId: number;
  severity: DlpSeverity;
  category: DlpCategory;
  excerpt: string;
  index: number;
  end: number;
  kind: DlpKind;
  policyId: number;
  policyName: string;
  action: DlpAction;
}

export interface DlpScanResult {
  incidents: number;
  matches: DlpMatchDTO[];
  severity: DlpSeverity | null;
  warnings: string[];
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

export class DlpApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "DlpApiError";
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
    throw new DlpApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new DlpApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new DlpApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new DlpApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from a DlpApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof DlpApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const dlpApi = {
  // patterns
  listPatterns: () => fetchJson<DlpPatternDTO[]>("/api/v1/dlp/patterns"),
  createPattern: (body: Record<string, unknown>) =>
    fetchJson<DlpPatternDTO>("/api/v1/dlp/patterns", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePattern: (id: number, body: Record<string, unknown>) =>
    fetchJson<DlpPatternDTO>(`/api/v1/dlp/patterns/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePattern: (id: number) =>
    fetchJson<{ ok: boolean; scrubbedPolicies: number }>(`/api/v1/dlp/patterns/${id}`, { method: "DELETE" }),

  // policies
  listPolicies: () => fetchJson<DlpPolicyDTO[]>("/api/v1/dlp/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<DlpPolicyDTO>("/api/v1/dlp/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<DlpPolicyDTO>(`/api/v1/dlp/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/dlp/policies/${id}`, { method: "DELETE" }),

  // incidents (server-paged) + status workflow
  listIncidents: (params: string) => fetchJsonList<DlpIncidentDTO>("/api/v1/dlp/incidents", params),
  setIncidentStatus: (id: number, status: DlpIncidentStatus) =>
    fetchJson<DlpIncidentDTO>(`/api/v1/dlp/incidents/${id}/status`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ status }),
    }),

  // scan + stats
  scan: (body: Record<string, unknown>) =>
    fetchJson<DlpScanResult>("/api/v1/dlp/scan", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  getStats: () => fetchJson<DlpStats>("/api/v1/dlp/stats"),
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

export function fmtDateTime(value: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ── display constants (locked enums, SCHEMA §3) ─────────────────────────────

export const KINDS: DlpKind[] = ["regex", "keyword"];
export const SEVERITIES: DlpSeverity[] = ["low", "medium", "high", "critical"];
export const CATEGORIES: DlpCategory[] = ["pii", "financial", "credentials", "custom"];
export const ACTIONS: DlpAction[] = ["alert", "block", "quarantine"];
export const PROTOCOLS: DlpProtocol[] = ["http", "https", "smtp", "ftp", "dns"];
export const STATUSES: DlpIncidentStatus[] = ["new", "reviewing", "resolved", "false_positive"];

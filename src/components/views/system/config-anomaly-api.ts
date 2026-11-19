"use client";

/**
 * Config anomaly typed client (spec §4.5 rule-based pass) — mirrors the
 * incidents-api contract: module-local envelope unwrapping that preserves zod
 * `details`, DTO types declared here (server routes live under
 * /api/v1/config-anomaly/*, service DTOs are structurally identical).
 */

// ── DTOs (mirror lib/firewall/anomaly-service.ts) ───────────────────────────

export type ConfigAnomalyKind =
  | "any_any_rule"
  | "wan_permissive"
  | "unused_object"
  | "shadowed_rule"
  | "log_disabled"
  | "duplicate_rule";

export type ConfigAnomalySeverity = "low" | "medium" | "high";
export type ConfigAnomalyStatus = "open" | "resolved" | "ignored";

export interface ConfigAnomalyDetail {
  message: string;
  ruleIds: number[];
  suggestion: string;
}

export interface ConfigAnomalyFindingDTO {
  id: number;
  kind: ConfigAnomalyKind;
  severity: ConfigAnomalySeverity;
  subjectRef: string;
  detail: ConfigAnomalyDetail;
  status: ConfigAnomalyStatus;
  detectedAt: string;
  resolvedAt: string | null;
}

export interface ConfigAnomalyStats {
  openTotal: number;
  openByKind: Record<ConfigAnomalyKind, number>;
  openBySeverity: Record<ConfigAnomalySeverity, number>;
  total: number;
  lastScanAt: string | null;
}

export interface ScanSummary {
  detected: number;
  newOpen: number;
  autoResolved: number;
  byKind: Record<ConfigAnomalyKind, number>;
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

// ── fetch plumbing (same shape as incidents-api.ts) ─────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class ConfigAnomalyApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ConfigAnomalyApiError";
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
    throw new ConfigAnomalyApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new ConfigAnomalyApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new ConfigAnomalyApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new ConfigAnomalyApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const configAnomalyApi = {
  scan: () =>
    fetchJson<ScanSummary>("/api/v1/config-anomaly/scan", {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
  list: (params: string) => fetchJsonList<ConfigAnomalyFindingDTO>("/api/v1/config-anomaly/findings", params),
  triage: (id: number, status: "resolved" | "ignored") =>
    fetchJson<ConfigAnomalyFindingDTO>(`/api/v1/config-anomaly/findings/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ status }),
    }),
  getStats: () => fetchJson<ConfigAnomalyStats>("/api/v1/config-anomaly/stats"),
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

// ── display constants (palette per UI_DESIGN_SYSTEM §2 — no indigo/blue) ────

export const KINDS: ConfigAnomalyKind[] = [
  "any_any_rule",
  "wan_permissive",
  "unused_object",
  "shadowed_rule",
  "log_disabled",
  "duplicate_rule",
];
export const SEVERITIES: ConfigAnomalySeverity[] = ["high", "medium", "low"];
export const STATUSES: ConfigAnomalyStatus[] = ["open", "resolved", "ignored"];

export const KIND_LABEL: Record<ConfigAnomalyKind, string> = {
  any_any_rule: "Any-Any Allow",
  wan_permissive: "WAN Permissive",
  unused_object: "Unused Object",
  shadowed_rule: "Shadowed Rule",
  log_disabled: "Logging Off",
  duplicate_rule: "Duplicate Rule",
};

export const SEVERITY_TONE: Record<ConfigAnomalySeverity, { chip: string; dot: string }> = {
  high: { chip: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", dot: "bg-rose-500" },
  medium: { chip: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", dot: "bg-amber-500" },
  low: { chip: "border-zinc-400/60 bg-zinc-500/5 text-zinc-500 dark:border-zinc-600 dark:text-zinc-400", dot: "bg-zinc-400" },
};

export const STATUS_TONE: Record<ConfigAnomalyStatus, string> = {
  open: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  resolved: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  ignored: "border-zinc-400/60 bg-zinc-500/5 text-zinc-500 dark:border-zinc-600 dark:text-zinc-400",
};

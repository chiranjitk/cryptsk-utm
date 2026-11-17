"use client";

/**
 * Incident Response typed client (Phase 3 §3.5) — mirrors the threat-intel-api
 * contract: module-local envelope unwrapping that preserves zod `details`,
 * DTO types declared here (server routes live under /api/v1/incidents/*,
 * service DTOs are structurally identical).
 */

// ── DTOs (mirror lib/incidents/service.ts) ──────────────────────────────────

export type IncidentSource = "manual" | "ips_event" | "dlp_incident" | "dns_tunnel" | "threat_intel" | "ai";
export type IncidentSeverity = "info" | "low" | "medium" | "high" | "critical";
export type IncidentStatus = "new" | "investigating" | "contained" | "resolved";
export type TimelineAction = "created" | "status_change" | "assigned" | "blocked" | "quarantine" | "note" | "resolved";

export interface IncidentDetail {
  description?: string | null;
  srcIps?: string[];
  tags?: string[];
  blockedRuleId?: number;
  blockedAddressId?: number;
  [key: string]: unknown;
}

export interface IncidentTimelineDTO {
  id: number;
  actor: string;
  action: TimelineAction;
  detail: string;
  createdAt: string;
}

export interface IncidentDTO {
  id: number;
  ref: string;
  title: string;
  source: IncidentSource;
  sourceRef: string | null;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assignedTo: string | null;
  detail: IncidentDetail;
  resolvedAt: string | null;
  createdAt: string;
  timeline?: IncidentTimelineDTO[];
}

export interface IncidentStats {
  openTotal: number;
  openBySeverity: Record<IncidentSeverity, number>;
  created7d: number;
  resolvedTotal: number;
  mttrHours: number | null;
}

export interface CreateIncidentBody {
  title: string;
  source?: IncidentSource;
  sourceRef?: string | null;
  severity?: IncidentSeverity;
  assignedTo?: string | null;
  detail?: Record<string, unknown>;
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

export interface BlockSourceResult {
  incident: IncidentDTO;
  addressObjectId: number;
  firewallRuleId: number;
}

// ── workflow graph (mirrors the service TRANSITIONS map) ────────────────────

const NEXT_STATUSES: Record<IncidentStatus, IncidentStatus[]> = {
  new: ["investigating", "resolved"],
  investigating: ["contained"],
  contained: ["resolved"],
  resolved: [],
};

/** Statuses the workflow may move `status` to (empty for resolved). */
export function allowedNext(status: IncidentStatus): IncidentStatus[] {
  return NEXT_STATUSES[status] ?? [];
}

// ── fetch plumbing (same shape as threat-intel-api.ts) ──────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class IncidentsApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "IncidentsApiError";
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
    throw new IncidentsApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new IncidentsApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new IncidentsApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new IncidentsApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const incidentsApi = {
  list: (params: string) => fetchJsonList<IncidentDTO>("/api/v1/incidents", params),
  get: (id: number) => fetchJson<IncidentDTO>(`/api/v1/incidents/${id}`),
  create: (body: CreateIncidentBody) =>
    fetchJson<{ incident: IncidentDTO; deduped: boolean }>("/api/v1/incidents", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  transition: (id: number, status: IncidentStatus) =>
    fetchJson<IncidentDTO>(`/api/v1/incidents/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ kind: "status", status }),
    }),
  assign: (id: number, assignedTo: string | null) =>
    fetchJson<IncidentDTO>(`/api/v1/incidents/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ kind: "assign", assignedTo }),
    }),
  addNote: (id: number, note: string) =>
    fetchJson<IncidentDTO>(`/api/v1/incidents/${id}/notes`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ note }),
    }),
  blockSource: (id: number) =>
    fetchJson<BlockSourceResult>(`/api/v1/incidents/${id}/block-source`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
  deleteIncident: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/incidents/${id}`, { method: "DELETE" }),
  getStats: () => fetchJson<IncidentStats>("/api/v1/incidents/stats"),
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

// ── display constants ───────────────────────────────────────────────────────

export const SOURCES: IncidentSource[] = ["manual", "ips_event", "dlp_incident", "dns_tunnel", "threat_intel", "ai"];
export const SEVERITIES: IncidentSeverity[] = ["info", "low", "medium", "high", "critical"];
export const STATUSES: IncidentStatus[] = ["new", "investigating", "contained", "resolved"];

"use client";

/**
 * SOAR typed client (Phase 4 §4.6) — mirrors the incidents-api contract:
 * module-local envelope unwrapping that preserves zod `details`, DTO types
 * declared here (server routes live under /api/v1/soar/*, service DTOs are
 * structurally identical).
 */

// ── DTOs (mirror lib/soar/service.ts) ───────────────────────────────────────

export type SoarTriggerKind = "incident_created" | "incident_severity" | "dlp_incident" | "dns_tunnel" | "ioc_hit";
export type SoarActionKind = "block_ip" | "notify" | "create_incident" | "delay" | "webhook";
export type SoarSeverity = "info" | "low" | "medium" | "high" | "critical";
export type SoarRunStatus = "running" | "success" | "failed" | "skipped";
export type BlockDirection = "in" | "out" | "both";

export interface SoarAction {
  kind: SoarActionKind;
  params: Record<string, unknown>;
}

export interface SoarTriggerFilter {
  severities: SoarSeverity[];
  sources: string[];
  kinds: string[];
}

export interface SoarPlaybookDTO {
  id: number;
  name: string;
  enabled: boolean;
  triggerKind: SoarTriggerKind;
  triggerFilter: SoarTriggerFilter;
  actions: SoarAction[];
  dedupeKey: string;
  lastRunAt: string | null;
  createdAt: string;
}

export interface SoarStep {
  kind: string;
  status: string;
  detail: string;
}

export interface SoarRunDTO {
  id: number;
  playbookId: number;
  playbookName: string;
  triggerRef: string;
  status: SoarRunStatus;
  steps: SoarStep[];
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
}

export interface SoarStats {
  playbooks: { total: number; enabled: number };
  runs: {
    total: number;
    success: number;
    failed: number;
    skipped: number;
    running: number;
    last7d: number;
    successRate: number | null;
  };
  byTriggerKind: Record<SoarTriggerKind, number>;
}

export interface SavePlaybookBody {
  name: string;
  enabled: boolean;
  triggerKind: SoarTriggerKind;
  triggerFilter: SoarTriggerFilter;
  actions: SoarAction[];
  dedupeKey: string;
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

// ── display constants ───────────────────────────────────────────────────────

export const TRIGGER_KINDS: SoarTriggerKind[] = [
  "incident_created",
  "incident_severity",
  "dlp_incident",
  "dns_tunnel",
  "ioc_hit",
];

export const ACTION_KINDS: SoarActionKind[] = ["block_ip", "notify", "create_incident", "delay", "webhook"];

export const SEVERITIES: SoarSeverity[] = ["info", "low", "medium", "high", "critical"];

export const SOURCES: string[] = ["manual", "ips_event", "dlp_incident", "dns_tunnel", "threat_intel", "ai"];

export const RUN_STATUSES: SoarRunStatus[] = ["running", "success", "failed", "skipped"];

export const BLOCK_DIRECTIONS: BlockDirection[] = ["in", "out", "both"];

// ── fetch plumbing (same shape as incidents-api.ts) ─────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class SoarApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "SoarApiError";
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
    throw new SoarApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SoarApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new SoarApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SoarApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const soarApi = {
  listPlaybooks: () => fetchJson<SoarPlaybookDTO[]>("/api/v1/soar/playbooks"),
  getPlaybook: (id: number) => fetchJson<SoarPlaybookDTO>(`/api/v1/soar/playbooks/${id}`),
  createPlaybook: (body: SavePlaybookBody) =>
    fetchJson<SoarPlaybookDTO>("/api/v1/soar/playbooks", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  updatePlaybook: (id: number, body: Partial<SavePlaybookBody>) =>
    fetchJson<SoarPlaybookDTO>(`/api/v1/soar/playbooks/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deletePlaybook: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/soar/playbooks/${id}`, { method: "DELETE" }),
  runPlaybook: (id: number, triggerRef: string, payload: Record<string, unknown> = {}) =>
    fetchJson<SoarRunDTO>(`/api/v1/soar/playbooks/${id}/run`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ triggerRef, payload }),
    }),
  listRuns: (params: string) => fetchJsonList<SoarRunDTO>("/api/v1/soar/runs", params),
  getStats: () => fetchJson<SoarStats>("/api/v1/soar/stats"),
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

export function fmtDuration(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}

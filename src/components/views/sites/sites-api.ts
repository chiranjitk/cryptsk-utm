"use client";

/**
 * Multi-Site Central Manager typed client (Phase 4 §4.1) — mirrors the
 * incidents-api contract: module-local envelope unwrapping that preserves
 * zod `details`, DTO types declared here (server routes live under
 * /api/v1/sites/*, service DTOs are structurally identical).
 */

// ── DTOs (mirror lib/sites/service.ts) ──────────────────────────────────────

export type SiteRole = "hub" | "spoke" | "standalone";
export type SiteStatus = "online" | "offline" | "degraded" | "never_seen";
export type DeploymentKind = "policy" | "template" | "firmware";
export type DeploymentStatus = "pending" | "pushing" | "applied" | "failed";
export type FirmwareChannel = "stable" | "beta";

export interface SiteLimits {
  maxRules?: number;
  maxCpuPct?: number;
  maxTunnelCount?: number;
  [key: string]: unknown;
}

export interface SiteDTO {
  id: number;
  name: string;
  region: string;
  role: SiteRole;
  publicEndpoint: string;
  version: string;
  status: SiteStatus;
  lastSeenAt: string | null;
  resourceLimits: SiteLimits;
  notes: string;
  createdAt: string;
}

export interface TemplateDTO {
  id: number;
  name: string;
  description: string;
  version: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface DeploymentResult {
  applied: string[];
  skipped: string[];
  errors: string[];
}

export interface DeploymentDTO {
  id: number;
  siteId: number;
  siteName: string | null;
  templateId: number | null;
  kind: DeploymentKind;
  status: DeploymentStatus;
  payload: Record<string, unknown>;
  result: DeploymentResult;
  pushedAt: string | null;
  appliedAt: string | null;
  createdAt: string;
}

export interface FirmwareDTO {
  id: number;
  version: string;
  channel: FirmwareChannel;
  sha256: string;
  releaseNotes: string;
  releasedAt: string | null;
  createdAt: string;
}

export interface SiteStats {
  total: number;
  byStatus: Record<SiteStatus, number>;
  byRole: Record<SiteRole, number>;
  deployments7d: number;
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

export interface CreateSiteBody {
  name: string;
  region?: string;
  role?: SiteRole;
  publicEndpoint?: string;
  version?: string;
  status?: SiteStatus;
  resourceLimits?: Record<string, unknown>;
  notes?: string;
}

export interface UpdateSiteBody {
  name?: string;
  region?: string;
  role?: SiteRole;
  publicEndpoint?: string;
  version?: string;
  status?: SiteStatus;
  resourceLimits?: Record<string, unknown>;
  notes?: string;
}

export interface PushBody {
  kind: DeploymentKind;
  templateId?: number;
  firmwareVersion?: string;
  payload?: Record<string, unknown>;
}

export interface CreateTemplateBody {
  name: string;
  description?: string;
  version?: string;
  payload?: Record<string, unknown>;
}

export interface UpdateTemplateBody {
  name?: string;
  description?: string;
  version?: string;
  payload?: Record<string, unknown>;
}

export interface CreateFirmwareBody {
  version: string;
  channel?: FirmwareChannel;
  sha256: string;
  releaseNotes?: string;
}

// ── fetch plumbing (same shape as incidents-api.ts) ─────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class SitesApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "SitesApiError";
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
    throw new SitesApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SitesApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new SitesApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SitesApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const sitesApi = {
  list: (params: string) => fetchJsonList<SiteDTO>("/api/v1/sites", params),
  get: (id: number) => fetchJson<SiteDTO>(`/api/v1/sites/${id}`),
  create: (body: CreateSiteBody) =>
    fetchJson<SiteDTO>("/api/v1/sites", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  update: (id: number, body: UpdateSiteBody) =>
    fetchJson<SiteDTO>(`/api/v1/sites/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deleteSite: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/sites/${id}`, { method: "DELETE" }),
  push: (id: number, body: PushBody) =>
    fetchJson<DeploymentDTO>(`/api/v1/sites/${id}/push`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  listDeployments: (params: string) => fetchJsonList<DeploymentDTO>("/api/v1/sites/deployments", params),
  listTemplates: () => fetchJson<TemplateDTO[]>("/api/v1/sites/templates"),
  createTemplate: (body: CreateTemplateBody) =>
    fetchJson<TemplateDTO>("/api/v1/sites/templates", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  updateTemplate: (id: number, body: UpdateTemplateBody) =>
    fetchJson<TemplateDTO>(`/api/v1/sites/templates/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deleteTemplate: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sites/templates/${id}`, { method: "DELETE" }),
  listFirmware: () => fetchJson<FirmwareDTO[]>("/api/v1/sites/firmware"),
  createFirmware: (body: CreateFirmwareBody) =>
    fetchJson<FirmwareDTO>("/api/v1/sites/firmware", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  getStats: () => fetchJson<SiteStats>("/api/v1/sites/stats"),
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

export const ROLES: SiteRole[] = ["hub", "spoke", "standalone"];
export const SITE_STATUSES: SiteStatus[] = ["online", "offline", "degraded", "never_seen"];
export const KINDS: DeploymentKind[] = ["policy", "template", "firmware"];
export const DEPLOY_STATUSES: DeploymentStatus[] = ["pending", "pushing", "applied", "failed"];
export const CHANNELS: FirmwareChannel[] = ["stable", "beta"];

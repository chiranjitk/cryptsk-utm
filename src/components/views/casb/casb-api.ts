"use client";

/**
 * CASB typed client (Phase 4 §4.3) — mirrors the incidents-api contract:
 * module-local envelope unwrapping that preserves zod `details`, DTO types
 * declared here (server routes live under /api/v1/casb/*, service DTOs are
 * structurally identical). Includes the bytes humanizer used by the
 * discoveries table.
 */

// ── DTOs (mirror lib/casb/service.ts) ───────────────────────────────────────

export type SaasAppCategory = "collaboration" | "storage" | "crm" | "productivity" | "devops" | "other";
export type SaasVerdict = "sanctioned" | "shadow" | "unknown";
export type CasbVendor = "google_workspace" | "microsoft_365" | "salesforce" | "dropbox" | "slack";
export type ConnectorStatus = "disconnected" | "connected" | "error";

export interface SaasAppDTO {
  id: number;
  name: string;
  vendor: string;
  category: SaasAppCategory;
  domains: string[];
  riskScore: number;
  createdAt: string;
}

export interface SaasDiscoveryDTO {
  id: number;
  clientIp: string;
  appId: number | null;
  appName: string | null;
  appHint: string;
  verdict: SaasVerdict;
  sessions: number;
  bytesIn: number;
  bytesOut: number;
  category: SaasAppCategory | null;
  riskScore: number | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface CasbConnectorDTO {
  id: number;
  vendor: CasbVendor;
  vendorLabel: string;
  status: ConnectorStatus;
  config: Record<string, unknown>;
  requiredKeys: string[];
  missingKeys: string[];
  lastSyncAt: string | null;
  createdAt: string;
}

export interface ScanSummary {
  scanned: number;
  upserted: number;
  sanctioned: number;
  shadow: number;
  unknown: number;
}

export interface CasbStats {
  total: number;
  byVerdict: Record<SaasVerdict, number>;
  topShadowApps: Array<{ appHint: string; sessions: number; bytes: number }>;
  topTalkers: Array<{ clientIp: string; sessions: number; bytes: number }>;
}

export interface ConnectorTestResult {
  id: number;
  vendor: CasbVendor;
  status: ConnectorStatus;
  ok: boolean;
  message: string;
  missingKeys: string[];
}

export interface SaasAppBody {
  name: string;
  vendor: string;
  category: SaasAppCategory;
  domains: string[];
  riskScore: number;
}

export interface ConnectorBody {
  vendor: CasbVendor;
  config: Record<string, unknown>;
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

export const CATEGORIES: SaasAppCategory[] = ["collaboration", "storage", "crm", "productivity", "devops", "other"];
export const VERDICTS: SaasVerdict[] = ["sanctioned", "shadow", "unknown"];

export const VENDORS: Array<{ value: CasbVendor; label: string }> = [
  { value: "google_workspace", label: "Google Workspace" },
  { value: "microsoft_365", label: "Microsoft 365" },
  { value: "salesforce", label: "Salesforce" },
  { value: "dropbox", label: "Dropbox" },
  { value: "slack", label: "Slack" },
];

export function vendorLabel(vendor: CasbVendor): string {
  return VENDORS.find((v) => v.value === vendor)?.label ?? vendor;
}

// ── fetch plumbing (same shape as incidents-api.ts) ─────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class CasbApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "CasbApiError";
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
    throw new CasbApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new CasbApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new CasbApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new CasbApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const casbApi = {
  listCatalog: (params: string) => fetchJsonList<SaasAppDTO>("/api/v1/casb/catalog", params),
  createApp: (body: SaasAppBody) =>
    fetchJson<SaasAppDTO>("/api/v1/casb/catalog", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  updateApp: (id: number, body: Partial<SaasAppBody>) =>
    fetchJson<SaasAppDTO>(`/api/v1/casb/catalog/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deleteApp: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/casb/catalog/${id}`, { method: "DELETE" }),
  seed: () =>
    fetchJson<{ created: number; total: number }>("/api/v1/casb/seed", {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
  scan: (windowMinutes: number) =>
    fetchJson<ScanSummary>("/api/v1/casb/scan", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ windowMinutes }),
    }),
  listDiscoveries: (params: string) => fetchJsonList<SaasDiscoveryDTO>("/api/v1/casb/discoveries", params),
  listConnectors: () => fetchJson<CasbConnectorDTO[]>("/api/v1/casb/connectors"),
  createConnector: (body: ConnectorBody) =>
    fetchJson<CasbConnectorDTO>("/api/v1/casb/connectors", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  updateConnector: (id: number, body: { config?: Record<string, unknown>; status?: ConnectorStatus }) =>
    fetchJson<CasbConnectorDTO>(`/api/v1/casb/connectors/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deleteConnector: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/casb/connectors/${id}`, { method: "DELETE" }),
  testConnector: (id: number) =>
    fetchJson<ConnectorTestResult>(`/api/v1/casb/connectors/${id}/test`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
  getStats: () => fetchJson<CasbStats>("/api/v1/casb/stats"),
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

// ── formatting helpers ──────────────────────────────────────────────────────

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

/** 1234567 → "1.2 MB" (binary-ish rounding, 1 decimal below GB). */
export function humanizeBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

"use client";

/**
 * Threat Intelligence typed client (M13) — mirrors the logs-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO types declared here (server routes live under
 * /api/v1/threat-intel/*, service DTOs are structurally identical).
 */

import type { HitsQuery, IocQuery } from "@/lib/validators/threat-intel";

// ── DTOs (mirror lib/threat-intel/service.ts) ───────────────────────────────

export type FeedProvider = "abusech" | "otx" | "spamhaus" | "custom";
export type FeedFormat = "csv" | "json" | "stix" | "taxii";
export type ThreatSeverity = "info" | "warning" | "critical";
export type ThreatCategory = "botnet" | "malware" | "phishing" | "c2" | "ransomware" | "scanner";
export type IocType = "ip" | "cidr" | "domain" | "url" | "hash";

export interface FeedDTO {
  id: number;
  name: string;
  provider: FeedProvider;
  url: string;
  format: FeedFormat;
  category: string;
  intervalMinutes: number;
  autoBlock: boolean;
  enabled: boolean;
  lastSyncAt: string | null;
  lastStatus: "ok" | "error" | "never";
  lastCount: number;
}

export interface IocDTO {
  id: number;
  feedId: number | null;
  type: IocType;
  value: string;
  category: string;
  severity: ThreatSeverity;
  confidence: number;
  reputation: number;
  source: string;
  description: string | null;
  hits: number;
  enabled: boolean;
  firstSeen: string;
  lastSeen: string;
  expiresAt: string | null;
}

export interface AutoBlockRuleDTO {
  id: number;
  name: string;
  iocId: number | null;
  matchType: string;
  matchValue: string;
  action: "drop" | "reject" | "quarantine_vlan";
  direction: "in" | "out" | "both";
  source: "manual" | "auto-feed";
  hitCount: number;
  enabled: boolean;
  createdBy: string;
  createdAt: string;
}

export interface IocHitDTO {
  id: number;
  ioc: { id: number; value: string; type: string; severity: string };
  sourceIp: string;
  destIp: string | null;
  action: string; // allowed | blocked | quarantined
  createdAt: string;
}

export interface FeedSyncResultDTO {
  feedId: number;
  feedName: string;
  entriesApplied: number;
  newIocs: number;
  updatedIocs: number;
  autoBlockCreated: number;
  hitsCreated: number;
  syncedAt: string;
}

export interface ThreatStats {
  totalIocs: number;
  bySeverity: { info: number; warning: number; critical: number };
  byCategory: Record<string, number>;
  activeFeeds: number;
  autoBlockRules: number;
  hits24h: number;
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

export type { HitsQuery, IocQuery };

// ── fetch plumbing (same shape as logs-api.ts) ──────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class ThreatIntelApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ThreatIntelApiError";
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
    throw new ThreatIntelApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new ThreatIntelApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new ThreatIntelApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new ThreatIntelApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from a ThreatIntelApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof ThreatIntelApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const threatIntelApi = {
  // feeds
  listFeeds: () => fetchJson<FeedDTO[]>("/api/v1/threat-intel/feeds"),
  createFeed: (body: Record<string, unknown>) =>
    fetchJson<FeedDTO>("/api/v1/threat-intel/feeds", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateFeed: (id: number, body: Record<string, unknown>) =>
    fetchJson<FeedDTO>(`/api/v1/threat-intel/feeds/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteFeed: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/threat-intel/feeds/${id}`, { method: "DELETE" }),
  syncFeed: (id: number) =>
    fetchJson<FeedSyncResultDTO>(`/api/v1/threat-intel/feeds/${id}/sync`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  // IOCs
  listIocs: (params: string) => fetchJsonList<IocDTO>("/api/v1/threat-intel/iocs", params),
  createIoc: (body: Record<string, unknown>) =>
    fetchJson<IocDTO>("/api/v1/threat-intel/iocs", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteIoc: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/threat-intel/iocs/${id}`, { method: "DELETE" }),
  disableIoc: (id: number) =>
    fetchJson<IocDTO>(`/api/v1/threat-intel/iocs/${id}/disable`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  /** Switch helper — POST /disable with { enabled } (default false per spec). */
  setIocEnabled: (id: number, enabled: boolean) =>
    fetchJson<IocDTO>(`/api/v1/threat-intel/iocs/${id}/disable`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ enabled }),
    }),

  // auto-block rules
  listAutoBlockRules: () => fetchJson<AutoBlockRuleDTO[]>("/api/v1/threat-intel/auto-block-rules"),
  createAutoBlockRule: (body: Record<string, unknown>) =>
    fetchJson<AutoBlockRuleDTO>("/api/v1/threat-intel/auto-block-rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateAutoBlockRule: (id: number, body: Record<string, unknown>) =>
    fetchJson<AutoBlockRuleDTO>(`/api/v1/threat-intel/auto-block-rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteAutoBlockRule: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/threat-intel/auto-block-rules/${id}`, { method: "DELETE" }),

  // hits + stats
  listHits: (params: string) => fetchJson<IocHitDTO[]>(`/api/v1/threat-intel/hits${params ? `?${params}` : ""}`),
  getStats: () => fetchJson<ThreatStats>("/api/v1/threat-intel/stats"),
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

export const SEVERITIES: ThreatSeverity[] = ["info", "warning", "critical"];
export const CATEGORIES: ThreatCategory[] = ["botnet", "malware", "phishing", "c2", "ransomware", "scanner"];
export const IOC_TYPES: IocType[] = ["ip", "cidr", "domain", "url", "hash"];
export const PROVIDERS: FeedProvider[] = ["abusech", "otx", "spamhaus", "custom"];
export const FORMATS: FeedFormat[] = ["csv", "json", "stix", "taxii"];

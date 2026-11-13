"use client";

/**
 * M04 frontend API layer — typed fetch helpers for the IPS views.
 * Mirrors fw-api.ts: preserves envelope `details` (409 referencedBy,
 * per-line custom-rule errors) that lib/realtime's fetchApi drops.
 */

import type { ExceptionRow, IpsPolicyDto, PreprocessorMap, ThresholdRow } from "@/lib/ips/catalog";

export type { ExceptionRow, IpsPolicyDto, PreprocessorMap, ThresholdRow };

export type IpsMode = "inline_drop" | "inline_tap" | "passive";
export type IpsSeverity = "info" | "low" | "medium" | "high" | "critical";
export type IpsAction = "alert" | "drop" | "reject" | "bypass" | "suppressed";
export type IpsPreset = "conservative" | "balanced" | "aggressive";

export interface CategoryDefDto {
  name: string;
  label: string;
  baseSeverity: IpsSeverity;
  family: "stream" | "http" | "tls" | "ssh" | "generic";
  sidRange: string;
  description: string;
}

export interface IpsEventDto {
  id: number;
  timestamp: string;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  action: IpsAction;
  sid: string | null;
  severity: IpsSeverity;
  category: string | null;
  message: string | null;
  suppressedUntil: string | null;
}

export interface UpdateSettingsDto {
  enabled: boolean;
  interval: "daily" | "weekly";
  time: string;
  source: string;
  lastUpdateAt: string | null;
  nextUpdateAt: string | null;
}

export interface IpsPolicyBody {
  name?: string;
  mode?: IpsMode;
  enabled?: boolean;
  ruleCategories?: Record<string, boolean>;
  customRules?: string[];
  exceptions?: ExceptionRow[];
  thresholds?: ThresholdRow[];
  preprocessors?: PreprocessorMap;
  tiBlocklist?: boolean;
}

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

// ── error handling (same contract as fw-api) ────────────────────────────────

export class IpsApiError extends Error {
  code: string;
  details?: unknown;

  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "IpsApiError";
    this.code = code;
    this.details = details;
  }
}

export async function ipsFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data: T; meta?: PageMeta }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new IpsApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  return (json as { data: T }).data;
}

export async function ipsFetchList<T>(path: string, params: string): Promise<{ data: T[]; meta: PageMeta }> {
  const res = await fetch(`${path}?${params}`, { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data?: T[]; meta?: PageMeta }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new IpsApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  const payload = json as { data?: T[]; meta?: PageMeta };
  return {
    data: Array.isArray(payload.data) ? payload.data : [],
    meta: payload.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

export function referencedByOf(err: unknown): Array<{ ruleId: number; ruleName: string; ruleType: string }> {
  if (err instanceof IpsApiError && err.details && typeof err.details === "object") {
    const raw = (err.details as Record<string, unknown>).referencedBy;
    if (Array.isArray(raw)) {
      return raw.filter(
        (r): r is { ruleId: number; ruleName: string; ruleType: string } =>
          Boolean(r) && typeof r === "object" && typeof (r as { ruleName?: unknown }).ruleName === "string",
      );
    }
  }
  return [];
}

/** Per-line custom-rule validation errors from details.lines (zod fieldErrors). */
export function customRuleLineErrors(err: unknown): Array<{ line: number; message: string }> {
  if (!(err instanceof IpsApiError) || !err.details || typeof err.details !== "object") return [];
  const fieldErrors = (err.details as Record<string, unknown>).fieldErrors as Record<string, string[]> | undefined;
  const out: Array<{ line: number; message: string }> = [];
  for (const [path, messages] of Object.entries(fieldErrors ?? {})) {
    // paths look like "customRules.0"
    const m = path.match(/^customRules\.(\d+)$/);
    if (m) out.push({ line: Number(m[1]) + 1, message: messages.join("; ") });
  }
  return out;
}

// ── endpoint helpers ────────────────────────────────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export const ipsApi = {
  listPolicies: () => ipsFetch<IpsPolicyDto[]>("/api/v1/ips/policies"),
  createPolicy: (body: IpsPolicyBody) =>
    ipsFetch<IpsPolicyDto>("/api/v1/ips/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: IpsPolicyBody) =>
    ipsFetch<IpsPolicyDto>(`/api/v1/ips/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) => ipsFetch<{ ok: boolean }>(`/api/v1/ips/policies/${id}`, { method: "DELETE" }),
  applyPreset: (preset: IpsPreset, name?: string, replacePolicyId?: number) =>
    ipsFetch<IpsPolicyDto>("/api/v1/ips/policies/apply-preset", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ preset, ...(name ? { name } : {}), ...(replacePolicyId ? { replacePolicyId } : {}) }),
    }),
  listCategories: () =>
    ipsFetch<{ categories: CategoryDefDto[]; total: number }>("/api/v1/ips/rule-categories"),
  getUpdateSettings: () => ipsFetch<UpdateSettingsDto & { engine?: RuleUpdateEngineResult }>("/api/v1/ips/update-settings"),
  saveUpdateSettings: (body: { enabled: boolean; interval: "daily" | "weekly"; time: string }) =>
    ipsFetch<UpdateSettingsDto>("/api/v1/ips/update-settings", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  runUpdateNow: () =>
    ipsFetch<UpdateSettingsDto & { engine?: RuleUpdateEngineResult }>("/api/v1/ips/update-settings", { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  listEvents: (params: string) => ipsFetchList<IpsEventDto>("/api/v1/ips/events", params),
  suppressEvent: (id: number, duration: "24h" | "7d" | "forever") =>
    ipsFetch<IpsEventDto>(`/api/v1/ips/events/${id}/suppress`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ duration }) }),
  getOs: () => ipsFetch<IpsOsStatus>("/api/v1/ips/os"),
  osApply: () => ipsFetch<IpsOsApplyOutcome>("/api/v1/ips/os", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ action: "apply" }) }),
  osRollback: () => ipsFetch<{ rolledBack: boolean; backupDir: string | null; reloaded: boolean; detail: string }>("/api/v1/ips/os", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ action: "rollback" }) }),
  osUpdateRules: () => ipsFetch<{ ranOnOs: boolean; reloaded: boolean; note: string; outputTail: string | null }>("/api/v1/ips/os", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ action: "update-rules" }) }),
};

// ── OS integration types (/api/v1/ips/os) ───────────────────────────────────

export interface IpsOsFactsDto {
  available: boolean;
  service: string | null;
  version: string | null;
  runningMode: string | null;
  evePath: string | null;
  rulesFiles: Array<{ name: string; sids: number; alert: number; drop: number; pass: number; bytes: number }>;
  updaterInstalled: boolean;
  yamlHasManagedFile: boolean;
  yamlHasThresholdFile: boolean;
  thresholdManagedLines: number;
}

export interface IpsOsDriftDto {
  managedRulesInSync: boolean;
  thresholdInSync: boolean;
  yamlInSync: boolean;
  inSync: boolean;
}

export interface IpsOsStatus {
  gate: "on" | "off";
  facts: IpsOsFactsDto;
  plan: {
    defaultPolicy: { id: number; name: string; mode: string } | null;
    enabledPolicyCount: number;
    managedRuleCount: number;
    thresholdEntryCount: number;
    yamlNeedsManagedFile: boolean;
    yamlNeedsThresholdFile: boolean;
    warnings: string[];
    managedRules: string;
    thresholdBlock: string;
  };
  drift: IpsOsDriftDto;
  lastApply: {
    lastApplyAt: string;
    policyId: number;
    policyName: string;
    backupDir: string;
    validateOk: boolean;
    reloaded: boolean;
  } | null;
}

export interface IpsOsApplyOutcome {
  applied: boolean;
  rolledBack: boolean;
  appliedAt: string | null;
  policyId: number | null;
  policyName: string | null;
  backupDir: string | null;
  validateOk: boolean;
  reloaded: boolean;
  warnings: string[];
  detail: string | null;
}

export interface RuleUpdateEngineResult {
  ranOnOs: boolean;
  reloaded: boolean;
  note: string;
  outputTail: string | null;
}

// ── small helpers ───────────────────────────────────────────────────────────

export function fmtDateTime(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function fmtRelative(ts: string | null): string {
  if (!ts) return "—";
  const diff = Date.parse(ts) - Date.now();
  const abs = Math.abs(diff);
  const mins = Math.round(abs / 60_000);
  const label = mins < 60 ? `${mins} min` : mins < 48 * 60 ? `${Math.round(mins / 60)} h` : `${Math.round(mins / 1440)} d`;
  return diff >= 0 ? `in ${label}` : `${label} ago`;
}

export const SEVERITIES: IpsSeverity[] = ["critical", "high", "medium", "low", "info"];

/** CAT -> preprocessor family (for the "inspector off" hint in the matrix). */
export function familyLabel(family: CategoryDefDto["family"]): string {
  return family === "generic" ? "any inspector" : `${family} inspector`;
}

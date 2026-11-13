/**
 * QoS typed client (M08 §3) — mirrors the dns-dhcp-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details` (lib/realtime's
 * fetchApi drops them), flat endpoint object, DTO types imported from the
 * server services (type-only — erased before bundling).
 */

import type { QosPolicyDTO, QosRuleDTO } from "@/lib/qos/service";

export type { QosPolicyDTO, QosRuleDTO };

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export class QosApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "QosApiError";
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
    throw new QosApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new QosApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from a QosApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof QosApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

/** 409 details — firewall rules referencing a policy (delete ConfirmDialog). */
export interface QosRefRow {
  ruleName: string;
  ruleType: string;
}

export function referencedByOf(err: unknown): QosRefRow[] {
  if (err instanceof QosApiError && err.details && typeof err.details === "object") {
    const raw = (err.details as { referencedBy?: unknown }).referencedBy;
    if (Array.isArray(raw)) {
      return raw
        .filter((r): r is QosRefRow => Boolean(r) && typeof r === "object" && typeof (r as QosRefRow).ruleName === "string")
        .map((r) => ({ ruleName: r.ruleName, ruleType: String(r.ruleType ?? "firewall") }));
    }
  }
  return [];
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const qosApi = {
  listPolicies: () => fetchJson<QosPolicyDTO[]>("/api/v1/qos/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<QosPolicyDTO>("/api/v1/qos/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<QosPolicyDTO>(`/api/v1/qos/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) =>
    fetchJson<{ ok: boolean; cascaded?: { cascadedRules: number } }>(`/api/v1/qos/policies/${id}`, { method: "DELETE" }),

  listRules: (policyId?: number) =>
    fetchJson<QosRuleDTO[]>(`/api/v1/qos/rules${policyId ? `?policyId=${policyId}` : ""}`),
  createRule: (body: Record<string, unknown>) =>
    fetchJson<QosRuleDTO>("/api/v1/qos/rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateRule: (id: number, body: Record<string, unknown>) =>
    fetchJson<QosRuleDTO>(`/api/v1/qos/rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRule: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/qos/rules/${id}`, { method: "DELETE" }),
};

// ── picker meta (apps / users / addresses / ifaces) ─────────────────────────

export interface IfaceLite {
  id: number;
  name: string;
  role: string;
  enabled: boolean;
}

export interface UserLite {
  id: number;
  username: string;
  role: string;
  isActive: boolean;
}

export interface AddressLite {
  id: number;
  name: string;
  value: string;
}

export async function listInterfaceNames(): Promise<IfaceLite[]> {
  const res = await fetch("/api/v1/interfaces?limit=100", { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as { data?: IfaceLite[] };
  return json.data ?? [];
}

export async function listApps(): Promise<string[]> {
  const res = await fetch("/api/v1/network/app-catalog", { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as { data?: { apps?: string[] } };
  return json.data?.apps ?? [];
}

export async function listUsers(): Promise<UserLite[]> {
  const res = await fetch("/api/v1/users?limit=200", { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as { data?: UserLite[] };
  return json.data ?? [];
}

export async function listAddresses(): Promise<AddressLite[]> {
  const res = await fetch("/api/v1/address-objects?limit=200", { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as { data?: AddressLite[] };
  return json.data ?? [];
}

// ── formatters ──────────────────────────────────────────────────────────────

/** Humanize kbps: 50000 → "50 Mbps", 800 → "800 kbps", 1500000 → "1.5 Gbps". */
export function humanizeKbps(kbps: number): string {
  if (kbps >= 1_000_000 && kbps % 1_000_000 === 0) return `${kbps / 1_000_000} Gbps`;
  if (kbps >= 1_000_000) return `${(kbps / 1_000_000).toFixed(1)} Gbps`;
  if (kbps % 1000 === 0) return `${kbps / 1000} Mbps`;
  return `${kbps} kbps`;
}

/** Compact axis format: 50000 → "50M" (kbps scale). */
export function fmtKbpsAxis(v: number): string {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}G`;
  if (v >= 1000) return `${(v / 1000).toFixed(v % 1000 === 0 ? 0 : 1)}M`;
  return `${Math.round(v)}K`;
}

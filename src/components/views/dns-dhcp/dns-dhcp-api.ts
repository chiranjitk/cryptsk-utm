/**
 * DNS & DHCP typed client (M06 §3) — mirrors the vpn-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details` (lib/realtime's
 * fetchApi drops them), flat endpoint object, DTO types imported from the
 * server services (type-only — erased before bundling).
 */

import type {
  DnsPolicyDTO,
  DnsRecordDTO,
  ResolverSettingsDTO,
} from "@/lib/dns/service";
import type {
  DhcpSubnetDTO,
  DhcpReservationDTO,
  DhcpLeaseDTO,
  DhcpRelay,
} from "@/lib/dhcp/service";
import type { DnsQueryLogEntry } from "@/lib/engine/generators/dns-queries";

export type { DnsPolicyDTO, DnsRecordDTO, ResolverSettingsDTO, DhcpSubnetDTO, DhcpReservationDTO, DhcpLeaseDTO, DhcpRelay, DnsQueryLogEntry };

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export class DnsDhcpApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "DnsDhcpApiError";
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
    throw new DnsDhcpApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new DnsDhcpApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<{ data: T[]; meta: PageMeta }> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new DnsDhcpApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new DnsDhcpApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from a DnsDhcpApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof DnsDhcpApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── DNS endpoints ───────────────────────────────────────────────────────────

export const dnsApi = {
  getSettings: () => fetchJson<ResolverSettingsDTO>("/api/v1/dns/settings"),
  putSettings: (body: ResolverSettingsDTO) =>
    fetchJson<ResolverSettingsDTO>("/api/v1/dns/settings", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),

  listPolicies: () => fetchJsonList<DnsPolicyDTO>("/api/v1/dns/policies", "").then((r) => r.data),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<DnsPolicyDTO>("/api/v1/dns/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<DnsPolicyDTO>(`/api/v1/dns/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/dns/policies/${id}`, { method: "DELETE" }),

  listRecords: (params: string) => fetchJsonList<DnsRecordDTO>("/api/v1/dns/records", params),
  createRecord: (body: Record<string, unknown>) =>
    fetchJson<DnsRecordDTO>("/api/v1/dns/records", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateRecord: (id: number, body: Record<string, unknown>) =>
    fetchJson<DnsRecordDTO>(`/api/v1/dns/records/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRecord: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/dns/records/${id}`, { method: "DELETE" }),

  listQueryLogs: (params: string) => fetchJsonList<DnsQueryLogEntry>("/api/v1/dns/query-logs", params),
};

// ── DHCP endpoints ──────────────────────────────────────────────────────────

export const dhcpApi = {
  listSubnets: () => fetchJsonList<DhcpSubnetDTO>("/api/v1/dhcp/subnets", "").then((r) => r.data),
  createSubnet: (body: Record<string, unknown>) =>
    fetchJson<DhcpSubnetDTO>("/api/v1/dhcp/subnets", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateSubnet: (id: number, body: Record<string, unknown>) =>
    fetchJson<DhcpSubnetDTO>(`/api/v1/dhcp/subnets/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteSubnet: (id: number) =>
    fetchJson<{ ok: boolean; cascaded?: { reservations: number; leases: number } }>(`/api/v1/dhcp/subnets/${id}`, { method: "DELETE" }),

  listReservations: (subnetId?: number) =>
    fetchJsonList<DhcpReservationDTO>("/api/v1/dhcp/reservations", subnetId ? `subnetId=${subnetId}` : "").then((r) => r.data),
  createReservation: (body: Record<string, unknown>) =>
    fetchJson<DhcpReservationDTO>("/api/v1/dhcp/reservations", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateReservation: (id: number, body: Record<string, unknown>) =>
    fetchJson<DhcpReservationDTO>(`/api/v1/dhcp/reservations/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteReservation: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/dhcp/reservations/${id}`, { method: "DELETE" }),

  listLeases: (params: string) => fetchJsonList<DhcpLeaseDTO>("/api/v1/dhcp/leases", params),
  releaseLease: (id: number) => fetchJson<DhcpLeaseDTO>(`/api/v1/dhcp/leases/${id}/release`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  getRelay: () => fetchJson<DhcpRelay>("/api/v1/dhcp/relay"),
  putRelay: (body: DhcpRelay) =>
    fetchJson<DhcpRelay>("/api/v1/dhcp/relay", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
};

// ── interfaces (for the subnet editor's interface Select) ───────────────────

export interface IfaceLite {
  id: number;
  name: string;
  role: string;
  enabled: boolean;
}

export async function listInterfaceNames(): Promise<IfaceLite[]> {
  return fetchJsonList<IfaceLite>("/api/v1/interfaces", "limit=100").then((r) => r.data);
}

// ── formatters ──────────────────────────────────────────────────────────────

export function fmtDateTime(ts: string | null): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** Humanize seconds for TTL/lease hints: 86400 → "1d", 3600 → "1h", 90 → "90s". */
export function humanizeSeconds(sec: number): string {
  if (sec % 86400 === 0 && sec >= 86400) return `${sec / 86400}d`;
  if (sec % 3600 === 0 && sec >= 3600) return `${sec / 3600}h`;
  if (sec % 60 === 0 && sec >= 60) return `${sec / 60}m`;
  return `${sec}s`;
}

/** Remaining-time label until an ISO timestamp ("2h 13m", "expired"). */
export function fmtRemaining(endsAt: string): string {
  const ms = new Date(endsAt).getTime() - Date.now();
  if (ms <= 0) return "expired";
  const totalMin = Math.floor(ms / 60_000);
  const d = Math.floor(totalMin / 1440);
  const h = Math.floor((totalMin % 1440) / 60);
  const m = totalMin % 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${Math.max(1, m)}m`;
}

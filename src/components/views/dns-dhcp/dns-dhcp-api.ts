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
import type {
  DnsTunnelFindingDTO,
  DnsTunnelStats,
  RunDetectionResult,
} from "@/lib/dns/tunnel-service";

export type { DnsPolicyDTO, DnsRecordDTO, ResolverSettingsDTO, DhcpSubnetDTO, DhcpReservationDTO, DhcpLeaseDTO, DhcpRelay, DnsQueryLogEntry };
export type { DnsTunnelFindingDTO, DnsTunnelStats, RunDetectionResult };

export type TunnelFindingStatus = "open" | "acknowledged" | "resolved";

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

// ── DNS tunnel detection endpoints (Phase 3 §3.4, rule-based) ─────────────

export const dnsTunnelApi = {
  run: (body: { windowMinutes?: number; stepMinutes?: number; lookbackMinutes?: number }) =>
    fetchJson<RunDetectionResult>("/api/v1/dns/tunnel-detection/run", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  listFindings: (params: string) => fetchJsonList<DnsTunnelFindingDTO>("/api/v1/dns/tunnel-detection/findings", params),
  updateStatus: (id: number, status: TunnelFindingStatus) =>
    fetchJson<DnsTunnelFindingDTO>(`/api/v1/dns/tunnel-detection/findings/${id}/status`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ status }),
    }),
  stats: () => fetchJson<DnsTunnelStats>("/api/v1/dns/tunnel-detection/stats"),
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

// ── OS sync (GUI↔OS honesty view + apply, mirrors vpn-api.ts) ───────────────

export interface OsDriftEntry {
  id: number;
  name: string;
  kind: string;
  osState: "in-sync" | "drift" | "missing" | "disabled" | "unsupported";
  detail: string | null;
}

export interface DnsOsFactsDto {
  gate: "on" | "off";
  available: boolean;
  tools: { unbound: boolean; checkconf: boolean; control: boolean };
  running: boolean;
  ports53Bound: boolean;
  checkconfOk: boolean | null;
  controlOk: boolean;
  version: string | null;
  managedFilePresent: boolean;
  logQueriesEnabled: boolean;
  logFileBytes: number | null;
  effectiveInterfaces: string[];
  drift: OsDriftEntry[];
}

export interface KeaLeaseViewDto {
  address: string;
  hwaddr: string;
  hostname: string;
  subnetId: number;
  state: string;
  expireEpoch: number;
  expiresinSec: number;
}

export interface DhcpOsFactsDto {
  gate: "on" | "off";
  available: boolean;
  tools: { keaDhcp4: boolean; dhcrelay: boolean };
  running: boolean;
  port67Bound: boolean;
  configValid: boolean | null;
  version: string | null;
  confPresent: boolean;
  liveManagedSubnetIds: number[];
  liveForeignSubnetIds: number[];
  relayUnitExists: boolean;
  relayDefaultsPresent: boolean;
  leases: KeaLeaseViewDto[];
  leaseCount: number;
  leaseReadError: string | null;
  mergeError: string | null;
  drift: OsDriftEntry[];
}

export interface DnsDhcpOsStatus {
  dns: DnsOsFactsDto;
  dhcp: DhcpOsFactsDto;
  summary: { total: number; inSync: number; driftCount: number; unsupported: number };
}

export interface OsPlanDto {
  steps: Array<{ cmd: string; summary: string; kind: string; optional?: boolean }>;
  files: Array<{ path: string; content: string; backup: boolean }>;
  managedZones?: string[];
  managedRecords?: string[];
  managedSubnets?: Array<{ id: number; cidr: string; iface: string; pool: string }>;
  preservedSubnets?: string[];
  skipped: Array<{ name: string; reason: string }>;
  reasons: string[];
}

export interface OsOutcomeDto {
  gate: "on" | "off";
  applied: boolean;
  reason: string;
  plan: OsPlanDto;
  results?: Array<{ cmd: string; ok: boolean; stderr?: string }>;
}

export interface DnsDhcpOsApplyOutcome {
  applied: boolean;
  gate: "on" | "off";
  reason: string;
  dns: OsOutcomeDto;
  dhcp: OsOutcomeDto;
}

export const dnsDhcpOsApi = {
  osStatus: () => fetchJson<DnsDhcpOsStatus>("/api/v1/dns-dhcp/os-status"),
  applyOs: () =>
    fetchJson<DnsDhcpOsApplyOutcome>("/api/v1/dns-dhcp/apply", { method: "POST", headers: JSON_HEADERS, body: "{}" }),
};

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

"use client";

/**
 * Advanced Identity & NAC typed client (M23, spec 2.9 + 2.10) — mirrors the
 * sdwan-api.ts contract: module-local envelope unwrapping that preserves zod
 * `details`, flat endpoint object, DTO types declared here (server routes
 * live under /api/v1/identity-advanced/*, service DTOs are structurally
 * identical — type-only imports are erased before bundling).
 */

import type {
  ActivityDTO,
  ByodDTO,
  ByodStatus,
  CoaAction,
  CoaProfileDTO,
  DeviceDTO,
  DeviceType,
  EapType,
  IdpDTO,
  IdpProtocol,
  IdpStatus,
  NacMethod,
  NacProfileDTO,
  NacState,
} from "@/app/api/v1/identity-advanced/_lib/server";

export type {
  ActivityDTO,
  ByodDTO,
  ByodStatus,
  CoaAction,
  CoaProfileDTO,
  DeviceDTO,
  DeviceType,
  EapType,
  IdpDTO,
  IdpProtocol,
  IdpStatus,
  NacMethod,
  NacProfileDTO,
  NacState,
};

// ── locked enums (mirror lib/validators/identity-advanced.ts) ───────────────

export type ActivityEvent = "login" | "logout" | "portal" | "vpn" | "coa" | "vlan_change" | "nac_auth" | "idp_sso";

export const IDP_PROTOCOLS: IdpProtocol[] = ["saml2", "oidc"];
export const COA_ACTIONS: CoaAction[] = ["reauth", "disconnect", "vlan"];
export const NAC_METHODS: NacMethod[] = ["802.1x", "mab", "both"];
export const EAP_TYPES: EapType[] = ["peap", "ttls", "tls"];
export const DEVICE_TYPES: DeviceType[] = ["printer", "phone", "camera", "workstation", "mobile", "iot", "unknown"];
export const NAC_STATES: NacState[] = ["authenticated", "mab", "quarantine", "pending", "denied"];
export const ACTIVITY_EVENTS: ActivityEvent[] = [
  "login",
  "logout",
  "portal",
  "vpn",
  "coa",
  "vlan_change",
  "nac_auth",
  "idp_sso",
];

export const MAC_RE = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

// ── action results ──────────────────────────────────────────────────────────

export interface IdpTestResult {
  ok: boolean;
  latencyMs: number;
  ssoUrl?: string;
  error?: string;
  status: IdpStatus;
}

export interface CoaPacket {
  code: string;
  attributes: Record<string, string | number>;
}

export interface CoaSendResult {
  sent: boolean;
  packet: CoaPacket;
}

export interface ByodCreatedDTO extends ByodDTO {
  /** One-time secret — present ONLY in the enroll response. */
  token: string;
}

export interface RescanSummary {
  rescanned: number;
  typed: number;
}

// ── reference-data pickers (logical refs into M07 / M14 tables) ─────────────

/** Minimal shapes for editor selects — server DTOs carry more fields. */
export interface RadiusProfileRefDTO {
  id: number;
  name: string;
  serverIp: string;
  authPort: number;
}

export interface IdpCertRefDTO {
  id: number;
  name: string;
  commonName: string;
}

// ── envelope plumbing (sdwan-api pattern) ───────────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class IdentityApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "IdentityApiError";
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
    throw new IdentityApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new IdentityApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from an IdentityApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof IdentityApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoint object ─────────────────────────────────────────────────────────

export const identityApi = {
  // federated IdPs (area federation)
  listIdps: () => fetchJson<IdpDTO[]>("/api/v1/identity-advanced/idps"),
  createIdp: (body: Record<string, unknown>) =>
    fetchJson<IdpDTO>("/api/v1/identity-advanced/idps", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateIdp: (id: number, body: Record<string, unknown>) =>
    fetchJson<IdpDTO>(`/api/v1/identity-advanced/idps/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteIdp: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/identity-advanced/idps/${id}`, { method: "DELETE" }),
  testIdp: (id: number) =>
    fetchJson<IdpTestResult>(`/api/v1/identity-advanced/idps/${id}/test`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  // RADIUS CoA profiles + packet send (area identity)
  listCoaProfiles: () => fetchJson<CoaProfileDTO[]>("/api/v1/identity-advanced/coa-profiles"),
  createCoaProfile: (body: Record<string, unknown>) =>
    fetchJson<CoaProfileDTO>("/api/v1/identity-advanced/coa-profiles", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateCoaProfile: (id: number, body: Record<string, unknown>) =>
    fetchJson<CoaProfileDTO>(`/api/v1/identity-advanced/coa-profiles/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteCoaProfile: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/identity-advanced/coa-profiles/${id}`, { method: "DELETE" }),
  sendCoa: (id: number, body: { userName: string; action: CoaAction; vlanId?: number }) =>
    fetchJson<CoaSendResult>(`/api/v1/identity-advanced/coa-profiles/${id}/coa`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),

  // NAC profiles (area identity)
  listNacProfiles: () => fetchJson<NacProfileDTO[]>("/api/v1/identity-advanced/nac-profiles"),
  createNacProfile: (body: Record<string, unknown>) =>
    fetchJson<NacProfileDTO>("/api/v1/identity-advanced/nac-profiles", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateNacProfile: (id: number, body: Record<string, unknown>) =>
    fetchJson<NacProfileDTO>(`/api/v1/identity-advanced/nac-profiles/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteNacProfile: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/identity-advanced/nac-profiles/${id}`, { method: "DELETE" }),

  // devices (area identity)
  listDevices: (params: string) =>
    fetchJson<DeviceDTO[]>(`/api/v1/identity-advanced/devices${params ? `?${params}` : ""}`),
  quarantineDevice: (id: number, body: { vlanId?: number }) =>
    fetchJson<DeviceDTO>(`/api/v1/identity-advanced/devices/${id}/quarantine`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  restoreDevice: (id: number) =>
    fetchJson<DeviceDTO>(`/api/v1/identity-advanced/devices/${id}/restore`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  rescanDevices: () =>
    fetchJson<RescanSummary>("/api/v1/identity-advanced/devices/rescan", { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  // BYOD (area identity)
  listByod: () => fetchJson<ByodDTO[]>("/api/v1/identity-advanced/byod"),
  createByod: (body: { userName: string; deviceId?: number; ttlHours: number }) =>
    fetchJson<ByodCreatedDTO>("/api/v1/identity-advanced/byod", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  revokeByod: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/identity-advanced/byod/${id}`, { method: "DELETE" }),
  approveByod: (id: number) =>
    fetchJson<ByodDTO>(`/api/v1/identity-advanced/byod/${id}/approve`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  // activity timeline (area identity)
  listActivity: (params: string) =>
    fetchJson<ActivityDTO[]>(`/api/v1/identity-advanced/activity${params ? `?${params}` : ""}`),

  // reference data for editor pickers (read-only logical refs)
  listRadiusProfiles: () => fetchJson<RadiusProfileRefDTO[]>("/api/v1/radius-profiles"),
  listIdpCertificates: () => fetchJson<IdpCertRefDTO[]>("/api/v1/pki/certificates?status=active"),
};

// ── query builder (logs-api qs pattern) ─────────────────────────────────────

/** URLSearchParams joiner that skips empty values — keeps query keys stable. */
export function qs(params: Record<string, string | number | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  return sp.toString();
}

// ── formatting helpers ──────────────────────────────────────────────────────

/** Relative time for lastSeen / expires columns (sdwan-api pattern). */
export function fmtRelative(value: string | null): string {
  if (!value) return "never";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return value;
  const diff = Date.now() - ts;
  if (diff < 0) {
    // future timestamps (BYOD expiry) render as "in X"
    const aheadMin = Math.floor(-diff / 60000);
    if (aheadMin < 60) return `in ${aheadMin}m`;
    const aheadH = Math.floor(aheadMin / 60);
    if (aheadH < 24) return `in ${aheadH}h`;
    return `in ${Math.floor(aheadH / 24)}d`;
  }
  const sec = Math.floor(diff / 1000);
  if (sec < 45) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

/** Day-bucket label for the grouped activity timeline ("Today"/"Yesterday"/date). */
export function dayGroupLabel(iso: string): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return "Unknown";
  const d = new Date(ts);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);
  const sameDay = (a: Date, b: Date) =>
    a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (sameDay(d, today)) return "Today";
  if (sameDay(d, yesterday)) return "Yesterday";
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Clock time "14:03" for timeline rows. */
export function clockLabel(iso: string): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return "";
  return new Date(ts).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
}

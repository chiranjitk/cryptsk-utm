/**
 * Identity typed client (M07 §3) — mirrors the dns-dhcp-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO types imported from the server services (type-only — erased
 * before bundling).
 */

import type {
  AuthSettings,
  CaptivePortalDTO,
  DirectorySourceDTO,
  IdentitySessionDTO,
  RadiusProfileDTO,
  UserDTO,
  TotpEnrollResult,
  UserGroupDTO,
} from "@/lib/identity/service";
import type { VoucherDTO } from "@/lib/identity/vouchers";

export type {
  AuthSettings,
  CaptivePortalDTO,
  DirectorySourceDTO,
  IdentitySessionDTO,
  RadiusProfileDTO,
  UserDTO,
  TotpEnrollResult,
  UserGroupDTO,
  VoucherDTO,
};

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

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

// ── users / groups ──────────────────────────────────────────────────────────

export const usersApi = {
  list: (params: string) => fetchJson<UserDTO[]>(`/api/v1/users${params ? `?${params}` : ""}`),
  create: (body: Record<string, unknown>) =>
    fetchJson<UserDTO>("/api/v1/users", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  update: (id: number, body: Record<string, unknown>) =>
    fetchJson<UserDTO & { totpEnrollment?: TotpEnrollResult }>(`/api/v1/users/${id}`, {
      method: "PUT",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  delete: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/users/${id}`, { method: "DELETE" }),
};

export const groupsApi = {
  list: () => fetchJson<UserGroupDTO[]>("/api/v1/user-groups"),
  create: (body: Record<string, unknown>) =>
    fetchJson<UserGroupDTO>("/api/v1/user-groups", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  update: (id: number, body: Record<string, unknown>) =>
    fetchJson<UserGroupDTO>(`/api/v1/user-groups/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  delete: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/user-groups/${id}`, { method: "DELETE" }),
};

// ── auth settings ───────────────────────────────────────────────────────────

export const authSettingsApi = {
  get: () => fetchJson<AuthSettings>("/api/v1/auth-settings"),
  put: (body: AuthSettings) =>
    fetchJson<AuthSettings>("/api/v1/auth-settings", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
};

// ── RADIUS profiles ─────────────────────────────────────────────────────────

export const radiusApi = {
  list: () => fetchJson<RadiusProfileDTO[]>("/api/v1/radius-profiles"),
  create: (body: Record<string, unknown>) =>
    fetchJson<RadiusProfileDTO>("/api/v1/radius-profiles", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  update: (id: number, body: Record<string, unknown>) =>
    fetchJson<RadiusProfileDTO>(`/api/v1/radius-profiles/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  delete: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/radius-profiles/${id}`, { method: "DELETE" }),
  test: (id: number) =>
    fetchJson<{ ok: boolean; latencyMs: number; error?: string }>(`/api/v1/radius-profiles/${id}/test`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
  reveal: (id: number) =>
    fetchJson<{ id: number; name: string; sharedSecret: string }>(`/api/v1/radius-profiles/${id}/reveal`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
};

// ── directory sources (LDAP/AD) ─────────────────────────────────────────────

export const directoryApi = {
  list: () => fetchJson<DirectorySourceDTO[]>("/api/v1/directory-sources"),
  create: (body: Record<string, unknown>) =>
    fetchJson<DirectorySourceDTO>("/api/v1/directory-sources", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  update: (id: number, body: Record<string, unknown>) =>
    fetchJson<DirectorySourceDTO>(`/api/v1/directory-sources/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  delete: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/directory-sources/${id}`, { method: "DELETE" }),
  test: (id: number) =>
    fetchJson<{ ok: boolean; latencyMs: number; userCount?: number; error?: string }>(`/api/v1/directory-sources/${id}/test`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
};

// ── captive portal + vouchers ───────────────────────────────────────────────

export const portalApi = {
  get: () => fetchJson<CaptivePortalDTO>("/api/v1/captive-portal"),
  put: (body: Record<string, unknown>) =>
    fetchJson<CaptivePortalDTO>("/api/v1/captive-portal", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),

  listVouchers: () => fetchJson<VoucherDTO[]>("/api/v1/captive-portal/vouchers"),
  generateVouchers: (body: { count: number; ttlHours?: number; bandwidthKbps?: number }) =>
    fetchJson<Array<{ id: number; code: string; expiresAt: string }>>("/api/v1/captive-portal/vouchers", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  revokeVoucher: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/captive-portal/vouchers/${id}`, { method: "DELETE" }),
};

// ── identity sessions ───────────────────────────────────────────────────────

export const sessionsApi = {
  list: (params: string) =>
    fetchJson<IdentitySessionDTO[]>(`/api/v1/identity/sessions${params ? `?${params}` : ""}`).then((data) => ({
      data,
      meta: { page: 1, limit: 50, total: data.length, totalPages: 1 } as PageMeta,
    })),
  expire: (id: number) =>
    fetchJson<IdentitySessionDTO>(`/api/v1/identity/sessions/${id}/expire`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),
};

// ── formatters ──────────────────────────────────────────────────────────────

export function fmtDateTime(ts: string | null): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

/** "x s ago" / "x m ago" ticking label for lastSeen columns. */
export function fmtAgo(ts: string): string {
  const sec = Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h ${min % 60}m ago`;
  return `${Math.floor(h / 24)}d ago`;
}

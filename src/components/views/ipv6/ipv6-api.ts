"use client";

/**
 * IPv6 typed client (M21, spec 2.7) — mirrors the sdwan-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO types imported from the server service (type-only — erased
 * before bundling). Interface names come from the EXISTING /api/v1/interfaces
 * endpoint; v6 firewall-rule filtering stays in the M03 firewall endpoints.
 */

import type {
  Dhcpv6ServerDTO,
  Ipv6SettingsDTO,
  Ipv6StatusDTO,
  Nat66RuleDTO,
  PrefixDelegationDTO,
} from "@/app/api/v1/ipv6/shared";
import type { Dhcpv6PrefixLength, Nat66Type, PdPrefixLength, RaMode } from "@/lib/validators/ipv6";

export type {
  Dhcpv6ServerDTO,
  Ipv6SettingsDTO,
  Ipv6StatusDTO,
  Nat66RuleDTO,
  PrefixDelegationDTO,
};
export type { Dhcpv6PrefixLength, Nat66Type, PdPrefixLength, RaMode };

// ── constants (mirror lib/validators/ipv6.ts) ───────────────────────────────

export const PD_PREFIX_LENGTHS: PdPrefixLength[] = [48, 52, 56, 60, 64];
export const RA_MODES: RaMode[] = ["disabled", "router_only", "slaac", "slaac_dhcpv6"];
export const NAT66_TYPES: Nat66Type[] = ["nptv6", "masquerade66", "dnat66"];
export const DHCPV6_PREFIX_LENGTHS: Dhcpv6PrefixLength[] = [64, 128];

export const FALLBACK_INTERFACES: string[] = ["wan0", "wan1"];

/** RA mode → human label for badges and the settings select. */
export function raModeLabel(m: RaMode): string {
  switch (m) {
    case "disabled":
      return "disabled";
    case "router_only":
      return "router only";
    case "slaac":
      return "SLAAC only";
    case "slaac_dhcpv6":
      return "SLAAC + DHCPv6";
  }
}

// ── envelope plumbing (sdwan-api pattern) ───────────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class Ipv6ApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "Ipv6ApiError";
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
    throw new Ipv6ApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new Ipv6ApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from an Ipv6ApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof Ipv6ApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoint object ─────────────────────────────────────────────────────────

export const ipv6Api = {
  // settings singleton
  getSettings: () => fetchJson<Ipv6SettingsDTO>("/api/v1/ipv6/settings"),
  updateSettings: (body: Record<string, unknown>) =>
    fetchJson<Ipv6SettingsDTO>("/api/v1/ipv6/settings", {
      method: "PUT",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),

  // NAT66 rules
  listNat66: () => fetchJson<Nat66RuleDTO[]>("/api/v1/ipv6/nat66-rules"),
  createNat66: (body: Record<string, unknown>) =>
    fetchJson<Nat66RuleDTO>("/api/v1/ipv6/nat66-rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateNat66: (id: number, body: Record<string, unknown>) =>
    fetchJson<Nat66RuleDTO>(`/api/v1/ipv6/nat66-rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteNat66: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/ipv6/nat66-rules/${id}`, { method: "DELETE" }),
  simulateNat66: (id: number) =>
    fetchJson<Nat66RuleDTO>(`/api/v1/ipv6/nat66-rules/${id}/simulate`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),

  // DHCPv6 servers
  listDhcpv6: () => fetchJson<Dhcpv6ServerDTO[]>("/api/v1/ipv6/dhcpv6-servers"),
  createDhcpv6: (body: Record<string, unknown>) =>
    fetchJson<Dhcpv6ServerDTO>("/api/v1/ipv6/dhcpv6-servers", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateDhcpv6: (id: number, body: Record<string, unknown>) =>
    fetchJson<Dhcpv6ServerDTO>(`/api/v1/ipv6/dhcpv6-servers/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteDhcpv6: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/ipv6/dhcpv6-servers/${id}`, { method: "DELETE" }),

  // status + simulated IA_PD lease
  getStatus: () => fetchJson<Ipv6StatusDTO>("/api/v1/ipv6/status"),
  getPrefixDelegation: () => fetchJson<PrefixDelegationDTO>("/api/v1/ipv6/prefix-delegation"),

  /** Interface names from the EXISTING /api/v1/interfaces endpoint (paged data). */
  listInterfaceNames: async (): Promise<string[]> => {
    try {
      const rows = await fetchJson<Array<{ name?: string; enabled?: boolean }>>(
        "/api/v1/interfaces?page=1&limit=200",
      );
      const names = rows
        .filter((r) => r.enabled !== false && typeof r.name === "string" && r.name.length > 0)
        .map((r) => r.name as string);
      return names.length > 0 ? names : FALLBACK_INTERFACES;
    } catch {
      return FALLBACK_INTERFACES;
    }
  },
};

// ── formatting helpers ──────────────────────────────────────────────────────

/** Humanize seconds for lifetimes: 43200 → "12h", 86400 → "1d". */
export function fmtLifetime(seconds: number): string {
  if (seconds % 86400 === 0) {
    const d = seconds / 86400;
    return d === 1 ? "1 day" : `${d} days`;
  }
  if (seconds % 3600 === 0) {
    const h = seconds / 3600;
    return h === 1 ? "1 hour" : `${h} hours`;
  }
  if (seconds % 60 === 0) {
    const m = seconds / 60;
    return m === 1 ? "1 min" : `${m} mins`;
  }
  return `${seconds}s`;
}

/** Relative time for lastRenew (sdwan-api pattern). */
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

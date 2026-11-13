"use client";

/**
 * M05 frontend API layer — typed fetch helpers for the VPN views.
 * Mirrors ips-api.ts / fw-api.ts: preserves envelope `details` (409 port
 * collisions, pool-overlap field errors) that lib/realtime's fetchApi drops.
 * DTO + config shapes live in lib/vpn/types.ts (shared with the service layer).
 */

import type {
  ClientBundleDto,
  IpsecConfig,
  OpenVpnConfig,
  VpnConfigBody,
  VpnConfigDto,
  VpnConfigPayload,
  VpnSessionDto,
  VpnStatus,
  VpnStatusDetailDto,
  VpnType,
  VpnUserGroupBody,
  VpnUserGroupDto,
  WgRemoteConfig,
  WgS2sConfig,
} from "@/lib/vpn/types";

export type {
  ClientBundleDto,
  IpsecAuthMethod,
  IpsecConfig,
  OpenVpnConfig,
  VpnConfigBody,
  VpnConfigDto,
  VpnConfigPayload,
  VpnSessionDto,
  VpnSessionStatus,
  VpnStatus,
  VpnStatusDetailDto,
  VpnType,
  VpnUserGroupBody,
  VpnUserGroupDto,
  WgPeer,
  WgRemoteConfig,
  WgS2sConfig,
} from "@/lib/vpn/types";

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

// ── error handling (same contract as fw-api/ips-api) ────────────────────────

export class VpnApiError extends Error {
  code: string;
  details?: unknown;

  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "VpnApiError";
    this.code = code;
    this.details = details;
  }
}

export async function vpnFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data: T; meta?: PageMeta }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new VpnApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  return (json as { data: T }).data;
}

export async function vpnFetchList<T>(path: string, params: string): Promise<{ data: T[]; meta: PageMeta }> {
  const res = await fetch(`${path}?${params}`, { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data?: T[]; meta?: PageMeta }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new VpnApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  const payload = json as { data?: T[]; meta?: PageMeta };
  return {
    data: Array.isArray(payload.data) ? payload.data : [],
    meta: payload.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Per-field validation errors from details.fieldErrors (zod fieldErrors). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof VpnApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as Record<string, unknown>).fieldErrors;
    if (fe && typeof fe === "object") return fe as Record<string, string[]>;
  }
  return {};
}

// ── endpoint helpers ────────────────────────────────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export const vpnApi = {
  listConfigs: () => vpnFetch<VpnConfigDto[]>("/api/v1/vpn/configs"),
  createConfig: (body: VpnConfigBody) =>
    vpnFetch<VpnConfigDto>("/api/v1/vpn/configs", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateConfig: (id: number, body: VpnConfigBody) =>
    vpnFetch<VpnConfigDto>(`/api/v1/vpn/configs/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteConfig: (id: number) => vpnFetch<{ ok: boolean }>(`/api/v1/vpn/configs/${id}`, { method: "DELETE" }),
  getStatus: (id: number) => vpnFetch<VpnStatusDetailDto>(`/api/v1/vpn/configs/${id}/status`),
  clientBundle: (id: number, peerName?: string) =>
    vpnFetch<ClientBundleDto>(`/api/v1/vpn/configs/${id}/client-bundle`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(peerName ? { peerName } : {}),
    }),
  listSessions: (params: string) => vpnFetchList<VpnSessionDto>("/api/v1/vpn/sessions", params),
  disconnectSession: (id: number) =>
    vpnFetch<VpnSessionDto>(`/api/v1/vpn/sessions/${id}/disconnect`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  listGroups: () => vpnFetch<VpnUserGroupDto[]>("/api/v1/vpn/user-groups"),
  createGroup: (body: VpnUserGroupBody) =>
    vpnFetch<VpnUserGroupDto>("/api/v1/vpn/user-groups", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateGroup: (id: number, body: VpnUserGroupBody) =>
    vpnFetch<VpnUserGroupDto>(`/api/v1/vpn/user-groups/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteGroup: (id: number) => vpnFetch<{ ok: boolean }>(`/api/v1/vpn/user-groups/${id}`, { method: "DELETE" }),
};

/** Trigger a browser download for a client-bundle payload (M05 §4). */
export function downloadBundle(bundle: ClientBundleDto): void {
  const blob = new Blob([bundle.content], { type: bundle.contentType || "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = bundle.filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
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
  const diff = Date.now() - Date.parse(ts);
  if (Number.isNaN(diff)) return "—";
  const abs = Math.abs(diff);
  if (abs < 60_000) return "just now";
  const mins = Math.round(abs / 60_000);
  const label = mins < 60 ? `${mins} min` : mins < 48 * 60 ? `${Math.round(mins / 60)} h` : `${Math.round(mins / 1440)} d`;
  return diff >= 0 ? `${label} ago` : `in ${label}`;
}

export function fmtBytes(bytes: number | null | undefined): string {
  if (bytes == null || Number.isNaN(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export const VPN_TYPES: VpnType[] = ["wireguard_s2s", "wireguard_remote", "ipsec_s2s", "ipsec_remote", "openvpn"];

export function typeFamily(type: VpnType): "wireguard" | "ipsec" | "openvpn" {
  if (type.startsWith("wireguard")) return "wireguard";
  if (type.startsWith("ipsec")) return "ipsec";
  return "openvpn";
}

export function subtypeLabel(type: VpnType): string {
  switch (type) {
    case "wireguard_s2s":
      return "site-to-site";
    case "wireguard_remote":
      return "remote access";
    case "ipsec_s2s":
      return "site-to-site";
    case "ipsec_remote":
      return "remote access";
    case "openvpn":
      return "remote access";
  }
}

/** One-line endpoint/pool summary for table rows (M05 §4). */
export function configSummary(type: VpnType, cfg: VpnConfigPayload): string {
  switch (type) {
    case "wireguard_s2s": {
      const c = cfg as WgS2sConfig;
      const peer = c.peers[0];
      return `${c.address} → ${peer?.endpoint ?? `${c.peers.length} peer${c.peers.length === 1 ? "" : "s"}`}`;
    }
    case "wireguard_remote": {
      const c = cfg as WgRemoteConfig;
      return `pool ${c.pool}${c.dns ? ` · dns ${c.dns}` : ""}`;
    }
    case "ipsec_s2s":
    case "ipsec_remote": {
      const c = cfg as IpsecConfig;
      return c.remoteIp
        ? `${c.localIp} ↔ ${c.remoteIp}`
        : `${c.localIp} · ${c.localSubnets.length} local subnet${c.localSubnets.length === 1 ? "" : "s"}`;
    }
    case "openvpn": {
      const c = cfg as OpenVpnConfig;
      return `${c.proto.toUpperCase()} :${c.port} · pool ${c.pool}`;
    }
  }
}

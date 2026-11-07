"use client";

/**
 * Dynamic Routing typed client (M19) — mirrors the logs-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO interfaces declared client-side (server serializes to these
 * shapes; passwords never leave the server — hasPassword flag instead).
 */

export interface BgpNeighborDTO {
  id: number;
  tenantId: number;
  name: string;
  remoteAs: number;
  peerIp: string;
  peerIface: string | null;
  hasPassword: boolean;
  keepaliveSec: number;
  holdtimeSec: number;
  gracefulRestart: boolean;
  bfdEnabled: boolean;
  bfdProfileId: number | null;
  prefixListInId: number | null;
  prefixListOutId: number | null;
  routeMapInId: number | null;
  routeMapOutId: number | null;
  localAs: number | null;
  ebgpMultihop: boolean;
  enabled: boolean;
  state: string; // idle | connect | active | opensent | openconfirm | established
  uptimeSec: number;
  prefixesReceived: number;
  createdAt: string;
}

export interface OspfSettingsDTO {
  id: number;
  tenantId: number;
  routerId: string;
  referenceBandwidth: number;
  gracefulRestart: boolean;
  enabled: boolean;
}

export interface OspfInterfaceDTO {
  id: number;
  tenantId: number;
  interfaceName: string;
  area: string;
  helloSec: number;
  deadSec: number;
  cost: number;
  networkType: string; // broadcast | p2p | nbma
  passive: boolean;
  enabled: boolean;
  neighborState: string; // down | init | 2way | exstart | exchange | loading | full
  neighborIp: string | null;
}

export interface PrefixListEntry {
  seq: number;
  action: "permit" | "deny";
  prefix: string;
  ge?: number | null;
  le?: number | null;
}

export interface PrefixListDTO {
  id: number;
  tenantId: number;
  name: string;
  family: "ipv4" | "ipv6";
  entries: string; // JSON array of PrefixListEntry
  entryCount: number;
  createdAt: string;
}

export interface RouteMapEntry {
  seq: number;
  action: "permit" | "deny";
  matchPrefixListId?: number | null;
  matchCommunity?: string | null;
  setLocalPref?: number | null;
  setMetric?: number | null;
  setCommunity?: string | null;
}

export interface RouteMapDTO {
  id: number;
  tenantId: number;
  name: string;
  entries: string; // JSON array of RouteMapEntry
  entryCount: number;
  createdAt: string;
}

export interface CommunityListDTO {
  id: number;
  tenantId: number;
  name: string;
  type: "standard" | "expanded";
  entries: string; // JSON array of strings
  entryCount: number;
  createdAt: string;
}

export interface BfdProfileDTO {
  id: number;
  tenantId: number;
  name: string;
  rxIntervalMs: number;
  txIntervalMs: number;
  detectMultiplier: number;
  enabled: boolean;
}

export type RibProtocol = "bgp" | "ospf" | "static" | "connected";

export interface RibRouteDTO {
  id: number;
  tenantId: number;
  protocol: RibProtocol;
  prefix: string;
  nextHop: string;
  interfaceName: string;
  metric: number;
  localPref: number | null;
  asPath: string | null;
  communities: string | null;
  updatedAt: string;
}

export interface RibRefreshResult {
  added: number;
  updated: number;
  removed: number;
  total: number;
  byProtocol: { bgp: number; ospf: number; static: number; connected: number };
}

export interface DrOverview {
  bgp: { established: number; total: number };
  ospf: { enabled: boolean; fullAdjacencies: number };
  rib: { bgp: number; ospf: number; static: number; connected: number };
  bfd: { profiles: number; neighborsUsing: number };
}

// ── envelope unwrapping (keeps zod details, like logs-api.ts) ────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class DrApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "DrApiError";
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
    throw new DrApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new DrApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from a DrApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof DrApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

/** Extract details.referencedBy rows from a 409 (fw-ui ConflictDialog shape). */
export function referencedByOf(err: unknown): Array<{ ruleName: string; ruleType: string }> {
  if (err instanceof DrApiError && err.details && typeof err.details === "object") {
    const refs = (err.details as { referencedBy?: Array<{ ruleName: string; ruleType: string }> }).referencedBy;
    if (Array.isArray(refs)) return refs;
  }
  return [];
}

// ── entry JSON helpers ───────────────────────────────────────────────────────

/** Parse an entries JSON column defensively — bad JSON yields []. */
export function parseEntries<T>(json: string | null | undefined): T[] {
  if (!json) return [];
  try {
    const parsed = JSON.parse(json) as unknown;
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

// ── humanized uptime (BGP table column) ──────────────────────────────────────

export function humanizeUptime(sec: number): string {
  if (sec <= 0) return "—";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ── endpoint object ──────────────────────────────────────────────────────────

export const drApi = {
  // ── BGP neighbors ───────────────────────────────────────────────────────
  listBgpNeighbors: () => fetchJson<BgpNeighborDTO[]>("/api/v1/dynamic-routing/bgp/neighbors"),
  createBgpNeighbor: (body: Record<string, unknown>) =>
    fetchJson<BgpNeighborDTO>("/api/v1/dynamic-routing/bgp/neighbors", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateBgpNeighbor: (id: number, body: Record<string, unknown>) =>
    fetchJson<BgpNeighborDTO>(`/api/v1/dynamic-routing/bgp/neighbors/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteBgpNeighbor: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/dynamic-routing/bgp/neighbors/${id}`, { method: "DELETE" }),
  bgpSession: (id: number, action: "start" | "stop") =>
    fetchJson<BgpNeighborDTO>(`/api/v1/dynamic-routing/bgp/neighbors/${id}/session`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ action }) }),

  // ── OSPF ────────────────────────────────────────────────────────────────
  getOspfSettings: () => fetchJson<OspfSettingsDTO>("/api/v1/dynamic-routing/ospf/settings"),
  updateOspfSettings: (body: Record<string, unknown>) =>
    fetchJson<OspfSettingsDTO>("/api/v1/dynamic-routing/ospf/settings", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  listOspfInterfaces: () => fetchJson<OspfInterfaceDTO[]>("/api/v1/dynamic-routing/ospf/interfaces"),
  createOspfInterface: (body: Record<string, unknown>) =>
    fetchJson<OspfInterfaceDTO>("/api/v1/dynamic-routing/ospf/interfaces", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateOspfInterface: (id: number, body: Record<string, unknown>) =>
    fetchJson<OspfInterfaceDTO>(`/api/v1/dynamic-routing/ospf/interfaces/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteOspfInterface: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/dynamic-routing/ospf/interfaces/${id}`, { method: "DELETE" }),

  // ── policy objects ──────────────────────────────────────────────────────
  listPrefixLists: () => fetchJson<PrefixListDTO[]>("/api/v1/dynamic-routing/prefix-lists"),
  createPrefixList: (body: Record<string, unknown>) =>
    fetchJson<PrefixListDTO>("/api/v1/dynamic-routing/prefix-lists", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePrefixList: (id: number, body: Record<string, unknown>) =>
    fetchJson<PrefixListDTO>(`/api/v1/dynamic-routing/prefix-lists/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePrefixList: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/dynamic-routing/prefix-lists/${id}`, { method: "DELETE" }),

  listRouteMaps: () => fetchJson<RouteMapDTO[]>("/api/v1/dynamic-routing/route-maps"),
  createRouteMap: (body: Record<string, unknown>) =>
    fetchJson<RouteMapDTO>("/api/v1/dynamic-routing/route-maps", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateRouteMap: (id: number, body: Record<string, unknown>) =>
    fetchJson<RouteMapDTO>(`/api/v1/dynamic-routing/route-maps/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRouteMap: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/dynamic-routing/route-maps/${id}`, { method: "DELETE" }),

  listCommunityLists: () => fetchJson<CommunityListDTO[]>("/api/v1/dynamic-routing/community-lists"),
  createCommunityList: (body: Record<string, unknown>) =>
    fetchJson<CommunityListDTO>("/api/v1/dynamic-routing/community-lists", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateCommunityList: (id: number, body: Record<string, unknown>) =>
    fetchJson<CommunityListDTO>(`/api/v1/dynamic-routing/community-lists/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteCommunityList: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/dynamic-routing/community-lists/${id}`, { method: "DELETE" }),

  // ── BFD profiles ────────────────────────────────────────────────────────
  listBfdProfiles: () => fetchJson<BfdProfileDTO[]>("/api/v1/dynamic-routing/bfd-profiles"),
  createBfdProfile: (body: Record<string, unknown>) =>
    fetchJson<BfdProfileDTO>("/api/v1/dynamic-routing/bfd-profiles", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateBfdProfile: (id: number, body: Record<string, unknown>) =>
    fetchJson<BfdProfileDTO>(`/api/v1/dynamic-routing/bfd-profiles/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteBfdProfile: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/dynamic-routing/bfd-profiles/${id}`, { method: "DELETE" }),

  // ── RIB + overview ──────────────────────────────────────────────────────
  listRib: (protocol?: string, q?: string) => {
    const sp = new URLSearchParams();
    if (protocol) sp.set("protocol", protocol);
    if (q) sp.set("q", q);
    const params = sp.toString();
    return fetchJson<RibRouteDTO[]>(`/api/v1/dynamic-routing/rib${params ? `?${params}` : ""}`);
  },
  refreshRib: () =>
    fetchJson<RibRefreshResult>("/api/v1/dynamic-routing/rib/refresh", { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  getOverview: () => fetchJson<DrOverview>("/api/v1/dynamic-routing/overview"),
};

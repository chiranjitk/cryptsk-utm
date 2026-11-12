"use client";

/**
 * M02 frontend API layer — typed fetch helpers for the network views
 * (interfaces, LLDP/MAC, mirroring, routing, multi-WAN). Mirrors fw-api.ts:
 * unwraps the standard envelope {data} / {error:{code,message,details}} and
 * preserves `details` on the error (400/409 surfacing needs it).
 */

// ── types (pinned M02 contract) ─────────────────────────────────────────────

export type IfaceType = "physical" | "vlan" | "bridge" | "bond" | "loopback" | "gre" | "ipip";
export type IfaceRole = "wan" | "lan" | "dmz" | "vpn" | "mgmt" | "unused";
export type IfaceMode = "l2" | "l3";
export type WanMode = "priority" | "failover" | "load_balance";
export type ProbeType = "icmp" | "tcp" | "dns" | "http";
export type WanState = "up" | "degraded" | "down" | "unknown";
export type MirrorDirection = "ingress" | "egress" | "both";
export type SecondaryIp = { ip: string; cidrPrefix: number };

export interface OsDriftItem {
  field: string;
  db: string;
  os: string;
}

export interface OsManagedRow {
  name: string;
  type: string;
  role: string;
  enabled: boolean;
  mode: string;
  db: { mtu: number; ip: string | null; adminState: string };
  os: {
    operState: string;
    carrier: boolean | null;
    mtu: number | null;
    ipv4: string[];
    mac: string | null;
    isDefaultRoute: boolean;
  } | null;
  inSync: boolean;
  drift: OsDriftItem[];
}

export interface OsUnmanagedRow {
  name: string;
  operState: string;
  mtu: number | null;
  ipv4: string[];
  mac: string | null;
}

export interface OsStateResp {
  applyEnabled: boolean;
  capturedAt: string;
  managed: OsManagedRow[];
  unmanaged: OsUnmanagedRow[];
}

export interface OsPlanStep {
  cmd: string;
  summary: string;
}

export interface OsPlan {
  name: string;
  osName: string | null;
  steps: OsPlanStep[];
}

export interface OsApplyResp {
  applied: boolean;
  reason: string;
  plans: OsPlan[];
  results?: Array<{ cmd: string; ok: boolean; stderr?: string }>;
}

export interface Iface {
  id: number;
  name: string;
  type: IfaceType;
  mode: IfaceMode;
  role: IfaceRole;
  parentName: string | null;
  vlanId: number | null;
  mtu: number;
  mssClamp: number | null;
  enabled: boolean;
  config: Record<string, unknown>;
  description: string | null;
  zoneId: number | null;
  zoneName: string | null;
  linkUp: boolean;
  degraded: boolean;
  rxKbps: number;
  txKbps: number;
}

export interface IfaceStats {
  id: number;
  name: string;
  rates: { rxKbps: number; txKbps: number };
  totals: { rxBytes: number; txBytes: number; rxPackets: number; txPackets: number; errors: number; drops: number };
  sparkline: Array<{ ts: string; rxKbps: number; txKbps: number }>;
  uptimeSec: number;
}

export interface LldpRow {
  localIface: string;
  chassisId: string;
  systemName: string;
  portId: string;
  portDesc: string | null;
  capabilities: string[];
  lastSeenSec: number;
}

export interface MacRow {
  mac: string;
  vlan: number;
  iface: string;
  type: "dynamic" | "static";
  ageSec: number;
}

export interface Mirror {
  id: number;
  name: string;
  srcIface: string;
  dstIface: string;
  direction: MirrorDirection;
  enabled: boolean;
  description: string | null;
  createdAt: string;
}

export interface StaticRouteRow {
  id: number;
  name: string | null;
  destinationCidr: string;
  gateway: string | null;
  interfaceName: string | null;
  distance: number;
  bfd: boolean;
  blackhole: boolean;
  enabled: boolean;
  description: string | null;
  bfdState: "up" | "down" | null;
  createdAt: string;
}

export interface PbrRow {
  id: number;
  name: string;
  position: number;
  enabled: boolean;
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  outgoingIface: string | null;
  gateway: string | null;
  description: string | null;
  createdAt: string;
}

export interface WanPolicy {
  id: number;
  interfaceName: string;
  mode: WanMode;
  weight: number;
  priority: number;
  probeType: ProbeType;
  probeTarget: string;
  intervalSec: number;
  timeoutMs: number;
  failThreshold: number;
  okThreshold: number;
  state: WanState;
  enabled: boolean;
}

/** Minimal picker/zone shape pinned by the M02 contract (id + name). */
export interface ObjectRef {
  id: number;
  name: string;
}
export interface ZoneRef {
  id: number;
  name: string;
}

// ── request bodies (mirror the M02 zod validators) ──────────────────────────

export interface IfaceBody {
  name?: string;
  type?: IfaceType;
  mode?: IfaceMode | "active-backup" | "802.3ad" | "balance-xor";
  role?: IfaceRole;
  parentName?: string | null;
  vlanId?: number | null;
  mtu?: number;
  mssClamp?: number | null;
  enabled?: boolean;
  config?: Record<string, unknown>;
  description?: string | null;
  zoneId?: number | null;
  // flat per-type create fields (ifaceCreateSchema discriminated union)
  parent?: string;
  members?: string[];
  stp?: boolean;
  stpMode?: "stp" | "rstp";
  igmpSnooping?: boolean;
  local?: string;
  remote?: string;
  ttl?: number;
  ip?: string;
  cidrPrefix?: number;
  // flat physical WAN fields (ifaceUpdateSchema — service applies switch semantics)
  wanType?: "static" | "dhcp" | "pppoe";
  gateway?: string | null;
  dns?: string[];
  pppoe?: { user: string; password: string; service?: string };
  lldp?: boolean;
  // enterprise additions
  secondaryIps?: SecondaryIp[];
  force?: boolean;
  speed?: "auto" | "10" | "100" | "1000" | "10000";
  duplex?: "half" | "full";
}

export interface MirrorBody {
  name: string;
  srcIface: string;
  dstIface: string;
  direction: MirrorDirection;
  enabled: boolean;
  description?: string | null;
}

export interface StaticRouteBody {
  name?: string | null;
  destinationCidr: string;
  gateway?: string | null;
  interfaceName?: string | null;
  distance: number;
  bfd: boolean;
  blackhole: boolean;
  enabled: boolean;
  description?: string | null;
}

export interface PbrBody {
  name: string;
  position: number;
  enabled: boolean;
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  outgoingIface?: string | null;
  gateway?: string | null;
  description?: string | null;
}

export interface WanPolicyBody {
  interfaceName: string;
  mode: WanMode;
  weight: number;
  priority: number;
  probeType: ProbeType;
  probeTarget: string;
  intervalSec: number;
  timeoutMs: number;
  failThreshold: number;
  okThreshold: number;
  enabled: boolean;
}

// ── error handling ──────────────────────────────────────────────────────────

export class NetApiError extends Error {
  code: string;
  details?: unknown;

  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "NetApiError";
    this.code = code;
    this.details = details;
  }
}

export async function netFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data: T; meta?: unknown }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new NetApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  return (json as { data: T }).data;
}

export interface NetPageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export async function netFetchList<T>(path: string, params?: string): Promise<{ data: T[]; meta: NetPageMeta }> {
  // list endpoints return {data: [...], meta: {...}} — unwrapped manually so
  // the page meta survives (netFetch would drop it).
  const qs = params ? `?${params}` : "?limit=200";
  const res = await fetch(`${path}${qs}`, { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data?: T[]; meta?: NetPageMeta }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new NetApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  const payload = json as { data?: T[]; meta?: NetPageMeta };
  return {
    data: Array.isArray(payload.data) ? payload.data : [],
    meta: payload.meta ?? { page: 1, limit: 200, total: 0, totalPages: 1 },
  };
}

// ── endpoint helpers ────────────────────────────────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export const netApi = {
  // interfaces
  listIfaces: (params?: string) => netFetchList<Iface>("/api/v1/interfaces", params),
  getIface: (id: number) => netFetch<Iface>(`/api/v1/interfaces/${id}`),
  createIface: (body: IfaceBody) =>
    netFetch<Iface>("/api/v1/interfaces", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateIface: (id: number, body: IfaceBody) =>
    netFetch<Iface>(`/api/v1/interfaces/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteIface: (id: number) => netFetch<{ ok: boolean }>(`/api/v1/interfaces/${id}`, { method: "DELETE" }),
  ifaceStats: (id: number) => netFetch<IfaceStats>(`/api/v1/interfaces/${id}/stats`),

  // OS-level sync (drift + gated apply)
  ifaceOsState: () => netFetch<OsStateResp>("/api/v1/interfaces/os-state"),
  applyIfaceOs: (name?: string) =>
    netFetch<OsApplyResp>("/api/v1/interfaces/apply", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(name ? { name } : {}),
    }),

  // derived switching tables (engine views — not persisted)
  listLldp: (params?: string) => netFetchList<LldpRow>("/api/v1/network/lldp-neighbors", params),
  listMacTable: (params?: string) => netFetchList<MacRow>("/api/v1/network/mac-table", params),

  // port mirroring (SPAN)
  listMirrors: () => netFetchList<Mirror>("/api/v1/network/port-mirrors"),
  createMirror: (body: MirrorBody) =>
    netFetch<Mirror>("/api/v1/network/port-mirrors", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateMirror: (id: number, body: MirrorBody) =>
    netFetch<Mirror>(`/api/v1/network/port-mirrors/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteMirror: (id: number) => netFetch<{ ok: boolean }>(`/api/v1/network/port-mirrors/${id}`, { method: "DELETE" }),

  // static routes
  listRoutes: () => netFetchList<StaticRouteRow>("/api/v1/routes"),
  createRoute: (body: StaticRouteBody) =>
    netFetch<StaticRouteRow>("/api/v1/routes", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateRoute: (id: number, body: StaticRouteBody) =>
    netFetch<StaticRouteRow>(`/api/v1/routes/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRoute: (id: number) => netFetch<{ ok: boolean }>(`/api/v1/routes/${id}`, { method: "DELETE" }),

  // policy-based routing
  listPbr: () => netFetchList<PbrRow>("/api/v1/pbr-rules"),
  createPbr: (body: PbrBody) =>
    netFetch<PbrRow>("/api/v1/pbr-rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePbr: (id: number, body: PbrBody) =>
    netFetch<PbrRow>(`/api/v1/pbr-rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePbr: (id: number) => netFetch<{ ok: boolean }>(`/api/v1/pbr-rules/${id}`, { method: "DELETE" }),
  togglePbr: (id: number, enabled: boolean) =>
    netFetch<PbrRow>(`/api/v1/pbr-rules/${id}/toggle`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ enabled }),
    }),

  // multi-WAN policies
  listWanPolicies: () => netFetchList<WanPolicy>("/api/v1/wan-policies"),
  createWanPolicy: (body: WanPolicyBody) =>
    netFetch<WanPolicy>("/api/v1/wan-policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateWanPolicy: (id: number, body: WanPolicyBody) =>
    netFetch<WanPolicy>(`/api/v1/wan-policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteWanPolicy: (id: number) => netFetch<{ ok: boolean }>(`/api/v1/wan-policies/${id}`, { method: "DELETE" }),
  probeWanPolicy: (id: number) =>
    netFetch<WanPolicy>(`/api/v1/wan-policies/${id}/probe`, { method: "POST" }),

  // pickers / zone select (same endpoints M03 uses; minimal id+name guarantee)
  listAddressObjects: () => netFetchList<ObjectRef>("/api/v1/address-objects", "limit=200"),
  listAddressGroups: () => netFetchList<ObjectRef>("/api/v1/address-groups", "limit=200"),
  listServiceObjects: () => netFetchList<ObjectRef>("/api/v1/service-objects", "limit=200"),
  listServiceGroups: () => netFetchList<ObjectRef>("/api/v1/service-groups", "limit=200"),
  listZones: () => netFetchList<ZoneRef>("/api/v1/zones", "limit=200"),
};

// ── payload builders ────────────────────────────────────────────────────────

/** Full PUT body from an existing row (toggles must send the complete body). */
export function ifaceBodyOf(iface: Iface, overrides?: Partial<IfaceBody>): IfaceBody {
  return {
    name: iface.name,
    type: iface.type,
    mode: iface.mode,
    role: iface.role,
    parentName: iface.parentName,
    vlanId: iface.vlanId,
    mtu: iface.mtu,
    mssClamp: iface.mssClamp,
    enabled: iface.enabled,
    config: iface.config ?? {},
    description: iface.description,
    zoneId: iface.zoneId,
    ...overrides,
  };
}

export function mirrorBodyOf(mirror: Mirror, overrides?: Partial<MirrorBody>): MirrorBody {
  return {
    name: mirror.name,
    srcIface: mirror.srcIface,
    dstIface: mirror.dstIface,
    direction: mirror.direction,
    enabled: mirror.enabled,
    description: mirror.description,
    ...overrides,
  };
}

export function routeBodyOf(route: StaticRouteRow, overrides?: Partial<StaticRouteBody>): StaticRouteBody {
  return {
    name: route.name,
    destinationCidr: route.destinationCidr,
    gateway: route.gateway,
    interfaceName: route.interfaceName,
    distance: route.distance,
    bfd: route.bfd,
    blackhole: route.blackhole,
    enabled: route.enabled,
    description: route.description,
    ...overrides,
  };
}

// ── validation helpers (client-side mirror of the M02 zod rules) ────────────

export const IFACE_NAME_RE = /^[a-z0-9-]{1,15}$/;
export const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

const CIDR_PARTS_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;

export function isValidIpv4(v: string): boolean {
  return IPV4_RE.test(v.trim());
}

export function isValidCidr(v: string): boolean {
  const m = CIDR_PARTS_RE.exec(v.trim());
  if (!m) return false;
  if (!IPV4_RE.test(m[1])) return false;
  const prefix = Number(m[2]);
  return prefix >= 0 && prefix <= 32;
}

export const BOND_MODES = ["active-backup", "802.3ad", "balance-xor"] as const;
export type BondMode = (typeof BOND_MODES)[number];
export const STP_MODES = ["stp", "rstp"] as const;
export type StpMode = (typeof STP_MODES)[number];

/** Sensible probe-target defaults per type (editable in the WAN editor). */
export const PROBE_TARGET_DEFAULTS: Record<ProbeType, string> = {
  icmp: "1.1.1.1",
  tcp: "1.1.1.1:443",
  dns: "1.1.1.1",
  http: "http://1.1.1.1",
};

// ── formatting helpers ──────────────────────────────────────────────────────

export function fmtKbps(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} Gbps`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)} Mbps`;
  return `${Math.round(n)} Kbps`;
}

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n)) return "—";
  const abs = Math.abs(n);
  if (abs >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)} GB`;
  if (abs >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (abs >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${Math.round(n)} B`;
}

export function fmtAge(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "—";
  if (sec < 60) return `${Math.max(1, Math.round(sec))} s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)} m ago`;
  if (sec < 86_400) return `${Math.floor(sec / 3600)} h ago`;
  return `${Math.floor(sec / 86_400)} d ago`;
}

/** "3 d 4 h" style uptime (no "ago"). */
export function fmtUptime(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "—";
  const d = Math.floor(sec / 86_400);
  const h = Math.floor((sec % 86_400) / 3_600);
  const m = Math.floor((sec % 3_600) / 60);
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} m`;
  return `${m} m`;
}

// ── config JSON readers (NetworkInterface.config is Record<string, unknown>) ─

export function cfgString(config: Record<string, unknown> | undefined, key: string): string | null {
  const v = config?.[key];
  return typeof v === "string" && v.length > 0 ? v : null;
}

export function cfgNumber(config: Record<string, unknown> | undefined, key: string): number | null {
  const v = config?.[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function cfgBool(config: Record<string, unknown> | undefined, key: string): boolean {
  return config?.[key] === true;
}

export function cfgStringArray(config: Record<string, unknown> | undefined, key: string): string[] {
  const v = config?.[key];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string");
}

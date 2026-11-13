"use client";

/**
 * M03 frontend API layer — typed fetch helpers for the firewall/NAT views.
 * Wraps the standard envelope {data} / {error:{code,message,details}} and
 * preserves `details` (fetchApi in lib/realtime drops it — the 409 dialog
 * needs details.referencedBy). Server code is untouched.
 */

// ── types (mirror src/lib/firewall rule-shape.ts / shapes.ts) ───────────────

export type FwAction = "allow" | "deny" | "drop" | "reject";
export type LoggingLevel = "none" | "summary" | "detail";
export type NatType = "snat" | "dnat" | "hairpin" | "exempt";
export type ZoneType = "L3" | "L2" | "VPN";
export type AddressType = "ip" | "range" | "subnet" | "fqdn" | "geo" | "wildcard";
export type ServiceProtocol = "tcp" | "udp" | "icmp" | "any";

export interface FwRule {
  id: number;
  tenantId: number;
  name: string;
  description: string | null;
  enabled: boolean;
  position: number;
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  applicationIds: string[];
  userIds: number[];
  srcMacs: string[];
  scheduleId: number | null;
  action: FwAction;
  logging: LoggingLevel;
  connLimit: number | null;
  rateLimit: number | null;
  synProtection: boolean;
  synThreshold: number | null;
  ipsPolicyId: number | null;
  qosPolicyId: number | null;
  tags: string[];
  comment: string | null;
  hitCount: number;
  lastHitAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface NatRule {
  id: number;
  tenantId: number;
  name: string | null;
  position: number;
  type: NatType;
  enabled: boolean;
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  outgoingIface: string | null;
  /** ip | "masq" | egress iface name (seed compat). */
  translatedSrc: string | null;
  translatedSrcPool: string[];
  overload: boolean;
  translatedDst: string | null;
  translatedPort: number | null;
  translatedPortRange: string | null;
  logging: LoggingLevel;
  comment: string | null;
  hitCount: number;
  lastHitAt: string | null;
  createdAt: string;
}

export interface Zone {
  id: number;
  name: string;
  type: ZoneType;
  interfaceNames: string[];
  description: string | null;
}

export interface AddressObject {
  id: number;
  name: string;
  type: AddressType;
  value: string;
  description: string | null;
  createdAt: string;
}

export interface NamedWithMembers {
  id: number;
  name: string;
  memberIds: number[];
  description: string | null;
}

export interface ServiceObject {
  id: number;
  name: string;
  protocol: ServiceProtocol;
  srcPort: string | null;
  dstPort: string | null;
  icmpType: number | null;
  icmpCode: number | null;
  description: string | null;
}

export interface ScheduleObject {
  id: number;
  name: string;
  type: "always" | "recurring" | "onetime";
  recurrence: { days: number[]; start: string; end: string } | null;
  startsAt: string | null;
  endsAt: string | null;
  timezone: string;
}

export interface UserRow {
  id: number;
  username: string;
  role: string;
  isActive: boolean;
}

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface FwRuleBody {
  name: string;
  description?: string | null;
  enabled: boolean;
  position?: number;
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  applicationIds: string[];
  userIds: number[];
  srcMacs: string[];
  scheduleId?: number | null;
  action: FwAction;
  logging: LoggingLevel;
  connLimit?: number | null;
  rateLimit?: number | null;
  synProtection: boolean;
  synThreshold?: number | null;
  ipsPolicyId?: number | null;
  qosPolicyId?: number | null;
  tags: string[];
  comment?: string | null;
}

export interface NatRuleBody {
  name?: string | null;
  enabled: boolean;
  position?: number;
  type: NatType;
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  outgoingIface?: string | null;
  translatedSrc?: string | null;
  translatedSrcPool: string[];
  overload: boolean;
  translatedDst?: string | null;
  translatedPort?: number | null;
  translatedPortRange?: string | null;
  logging: LoggingLevel;
  comment?: string | null;
}

export interface ConflictRow {
  ruleId: number | null;
  ruleName?: string;
  reason: "shadowed_by" | "conflicts_with" | "redundant";
  withRuleId: number;
  withRuleName: string;
  /** NAT validate rows carry the chain leg the conflict applies to. */
  leg?: "prerouting" | "postrouting";
}

export interface ValidateResult {
  ok: boolean;
  conflicts: ConflictRow[];
  /** NAT validate adds generator-faithful advisories (pools, hairpin, DMZ-style dnat). */
  warnings?: Array<{ code: string; message: string }>;
}

export interface RefRow {
  ruleName: string;
  ruleType: string;
}

export interface ImportRowError {
  row: number;
  message: string;
}

// ── error handling ──────────────────────────────────────────────────────────

export class FwApiError extends Error {
  code: string;
  details?: unknown;

  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "FwApiError";
    this.code = code;
    this.details = details;
  }
}

export async function fwFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data: T; meta?: PageMeta }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new FwApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  return (json as { data: T }).data;
}

export async function fwFetchList<T>(path: string, params?: string): Promise<{ data: T[]; meta: PageMeta }> {
  // list endpoints return {data: [...], meta: {...}} — unwrapped manually so
  // the page meta survives (fwFetch would drop it).
  const qs = params ? `?${params}` : "?limit=200";
  const res = await fetch(`${path}${qs}`, { credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data?: T[]; meta?: PageMeta }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json && json.error) {
    throw new FwApiError(json.error.code, json.error.message || json.error.code, json.error.details);
  }
  const payload = json as { data?: T[]; meta?: PageMeta };
  return {
    data: Array.isArray(payload.data) ? payload.data : [],
    meta: payload.meta ?? { page: 1, limit: 200, total: 0, totalPages: 1 },
  };
}

function detailsOf(err: unknown): Record<string, unknown> | undefined {
  if (err instanceof FwApiError && err.details && typeof err.details === "object") {
    return err.details as Record<string, unknown>;
  }
  return undefined;
}

export function referencedByOf(err: unknown): RefRow[] {
  const details = detailsOf(err);
  const raw = details?.referencedBy;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((r): r is RefRow => Boolean(r) && typeof r === "object" && typeof (r as RefRow).ruleName === "string")
    .map((r) => ({ ruleName: r.ruleName, ruleType: String(r.ruleType ?? "firewall") }));
}

export function importRowErrors(err: unknown): ImportRowError[] {
  const details = detailsOf(err);
  const raw = details?.rows;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((r): r is ImportRowError => Boolean(r) && typeof r === "object")
    .map((r) => ({ row: Number(r.row), message: String(r.message ?? "invalid row") }));
}

// ── endpoint helpers ────────────────────────────────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export const api = {
  listRules: () => fwFetchList<FwRule>("/api/v1/firewall-rules"),
  listNat: () => fwFetchList<NatRule>("/api/v1/nat-rules"),
  listZones: () => fwFetchList<Zone>("/api/v1/zones", "limit=200"),
  listAddressObjects: () => fwFetchList<AddressObject>("/api/v1/address-objects", "limit=200"),
  listAddressGroups: () => fwFetchList<NamedWithMembers>("/api/v1/address-groups", "limit=200"),
  listServiceObjects: () => fwFetchList<ServiceObject>("/api/v1/service-objects", "limit=200"),
  listServiceGroups: () => fwFetchList<NamedWithMembers>("/api/v1/service-groups", "limit=200"),
  listSchedules: () => fwFetchList<ScheduleObject>("/api/v1/schedule-objects", "limit=200"),
  listUsers: () => fwFetchList<UserRow>("/api/v1/users", "limit=200"),
  listApps: () => fwFetch<{ apps: string[]; total: number }>("/api/v1/network/app-catalog"),
  /** lightweight iface list for the Zones editor (real names, not free text) */
  listInterfaceNames: () =>
    fwFetchList<{ id: number; name: string; type: string; enabled: boolean; zoneId: number | null; zoneName: string | null }>("/api/v1/interfaces", "limit=200"),

  createRule: (body: FwRuleBody) =>
    fwFetch<FwRule>("/api/v1/firewall-rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateRule: (id: number, body: FwRuleBody) =>
    fwFetch<FwRule>(`/api/v1/firewall-rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRule: (id: number) => fwFetch<{ ok: boolean }>(`/api/v1/firewall-rules/${id}`, { method: "DELETE" }),
  toggleRule: (id: number, enabled: boolean) =>
    fwFetch<FwRule>(`/api/v1/firewall-rules/${id}/toggle`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ enabled }),
    }),
  reorderRules: (orderedIds: number[]) =>
    fwFetch<{ rules: Array<{ id: number; position: number }> }>("/api/v1/firewall-rules/reorder", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ orderedIds }),
    }),
  ruleHits: (id: number) =>
    fwFetch<{ id: number; name: string; hitCount: number; lastHitAt: string | null }>(`/api/v1/firewall-rules/${id}/hits`),
  resetRuleHits: (id: number) =>
    fwFetch<{ id: number; hitCount: number }>(`/api/v1/firewall-rules/${id}/hits/reset`, { method: "POST" }),
  validateRule: (body: FwRuleBody, excludeRuleId?: number) =>
    fwFetch<ValidateResult>("/api/v1/firewall-rules/validate", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(excludeRuleId ? { rule: body, excludeRuleId } : { rule: body }),
    }),
  importRules: (format: "json" | "csv", payload: string) =>
    fwFetch<{ imported: number; rules: FwRule[] }>("/api/v1/firewall-rules/import", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ format, payload }),
    }),

  createNat: (body: NatRuleBody) =>
    fwFetch<NatRule>("/api/v1/nat-rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  createOneToOne: (oneToOne: { publicIp: string; internalHost: string; iface?: string; name?: string; comment?: string }) =>
    fwFetch<{ dnat: NatRule; snat: NatRule }>("/api/v1/nat-rules", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ oneToOne }),
    }),
  updateNat: (id: number, body: NatRuleBody) =>
    fwFetch<NatRule>(`/api/v1/nat-rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteNat: (id: number) => fwFetch<{ ok: boolean }>(`/api/v1/nat-rules/${id}`, { method: "DELETE" }),
  toggleNat: (id: number, enabled: boolean) =>
    fwFetch<NatRule>(`/api/v1/nat-rules/${id}/toggle`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify({ enabled }),
    }),
  reorderNat: (orderedIds: number[]) =>
    fwFetch<{ rules: Array<{ id: number; position: number }> }>("/api/v1/nat-rules/reorder", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ orderedIds }),
    }),
  natHits: (id: number) =>
    fwFetch<{ id: number; name: string | null; hitCount: number; lastHitAt: string | null }>(`/api/v1/nat-rules/${id}/hits`),
  resetNatHits: (id: number) =>
    fwFetch<{ id: number; hitCount: number }>(`/api/v1/nat-rules/${id}/hits/reset`, { method: "POST" }),
  validateNat: (body: NatRuleBody, excludeRuleId?: number) =>
    fwFetch<ValidateResult>("/api/v1/nat-rules/validate", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(excludeRuleId ? { rule: body, excludeRuleId } : { rule: body }),
    }),
  objectReferences: (type: "address" | "address-group" | "service" | "service-group" | "schedule" | "zone", id: number) =>
    fwFetch<{ type: string; id: number; references: RefRow[]; total: number }>(
      `/api/v1/objects/references?type=${type}&id=${id}`,
    ),

  createZone: (body: { name: string; type: ZoneType; interfaceNames: string[]; description?: string | null }) =>
    fwFetch<Zone>("/api/v1/zones", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateZone: (id: number, body: { name: string; type: ZoneType; interfaceNames: string[]; description?: string | null }) =>
    fwFetch<Zone>(`/api/v1/zones/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteZone: (id: number) => fwFetch<{ ok: boolean }>(`/api/v1/zones/${id}`, { method: "DELETE" }),

  generic: {
    create: <T>(path: string, body: unknown) =>
      fwFetch<T>(path, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
    update: <T>(path: string, body: unknown) =>
      fwFetch<T>(path, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
    remove: (path: string) => fwFetch<{ ok: boolean }>(path, { method: "DELETE" }),
  },
};

// ── small client-side helpers ───────────────────────────────────────────────

export const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export const MAC_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

/** Parse a comma/space separated MAC list → {valid, invalid} entries. */
export function parseMacList(raw: string): { valid: string[]; invalid: string[] } {
  const parts = raw
    .split(/[,\s]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const valid: string[] = [];
  const invalid: string[] = [];
  for (const p of parts) (MAC_RE.test(p) ? valid : invalid).push(p);
  return { valid, invalid };
}

export function fmtDateTime(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** True for WAN/LAN — the service-layer protected zones (delete hidden). */
export function isProtectedZone(name: string): boolean {
  return name === "WAN" || name === "LAN";
}

/** 1:1 NAT pairs share the `1:1:<uuid>` comment marker (nat-rules POST). */
export function isOneToOnePair(comment: string | null): boolean {
  return Boolean(comment && comment.startsWith("1:1:"));
}

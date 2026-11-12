/**
 * Interface service (M02 §2/§5) — per-type config shaping, link-state
 * derivation and create/update/delete with the documented cascade semantics.
 * Routes stay thin; JSON columns are parsed defensively (ADR-005).
 */

import { z } from "zod";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import { getEngine } from "@/lib/engine";
import {
  groupIssues,
  lintIface,
  type IfaceIssue,
  type IfaceRuleView,
} from "./iface-rules";
import {
  bondConfigPatch,
  bridgeConfigPatch,
  greConfigPatch,
  ipipConfigPatch,
  loopbackConfigPatch,
  vlanConfigPatch,
  type IfaceCreateBody,
  type IfaceUpdateBody,
} from "@/lib/validators/network";
import {
  convergeIfaceSafe,
  teardownIfaceSafe,
  type OsApplyOutcome,
} from "./iface-apply";

/** Scalar shape of a NetworkInterface row (config still a raw JSON string). */
export type IfaceRow = {
  id: number;
  tenantId: number;
  name: string;
  type: string;
  mode: string;
  role: string;
  parentName: string | null;
  vlanId: number | null;
  mtu: number;
  mssClamp: number | null;
  enabled: boolean;
  config: string;
  description: string | null;
  zoneId: number | null;
};

export interface ShapedIface {
  id: number;
  name: string;
  type: string;
  mode: string;
  role: string;
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

export interface IfaceLiveRates {
  rxKbps: number;
  txKbps: number;
}

// ── parsing helpers (JSON columns — tolerate garbage, ADR-005) ──────────────

export function parseIfaceConfig(raw: string): Record<string, unknown> {
  const v = parseJson<unknown>(raw, {});
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function strArrJson(raw: string): string[] {
  return strArr(parseJson<unknown>(raw, []));
}

function zodFieldErrors(err: z.ZodError): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const issue of err.issues) {
    const p = issue.path.join(".") || "_";
    (out[p] ??= []).push(issue.message);
  }
  return out;
}

function p2002ToConflict(err: unknown, message: string): unknown {
  if (typeof err === "object" && err !== null && "code" in err && String((err as { code: unknown }).code) === "P2002") {
    return ApiError.conflict(message);
  }
  return err;
}

// ── link states (M02 §5 — simulated, not operator configurable) ─────────────

export function linkStateOf(row: IfaceRow, allRows: IfaceRow[]): { linkUp: boolean; degraded: boolean } {
  const byName = new Map(allRows.map((r) => [r.name, r]));
  const cfg = parseIfaceConfig(row.config);
  // seeds may leave the parentName column null and keep config.parent only
  const effectiveParent =
    row.parentName ?? (typeof cfg.parent === "string" && cfg.parent ? cfg.parent : null);

  switch (row.type) {
    case "loopback": // address-only — always up (M02 §5)
      return { linkUp: true, degraded: false };
    case "vlan": {
      if (!row.enabled) return { linkUp: false, degraded: false };
      const parent = effectiveParent ? byName.get(effectiveParent) : undefined;
      if (!parent) return { linkUp: false, degraded: false };
      // disabled parents visually mark children degraded (M02 §4 tab 1)
      return { linkUp: parent.enabled, degraded: !parent.enabled };
    }
    case "bridge": {
      if (!row.enabled) return { linkUp: false, degraded: false };
      const members = strArr(cfg.members).map((n) => byName.get(n));
      const up = members.filter((m) => m?.enabled).length;
      return { linkUp: up > 0, degraded: up > 0 && up < members.length };
    }
    case "bond": {
      if (!row.enabled) return { linkUp: false, degraded: false };
      const members = strArr(cfg.members).map((n) => byName.get(n));
      const up = members.filter((m) => m?.enabled).length;
      return { linkUp: members.length > 0 && up === members.length, degraded: up > 0 && up < members.length };
    }
    case "gre":
    case "ipip": {
      const local = typeof cfg.local === "string" && cfg.local.length > 0;
      const remote = typeof cfg.remote === "string" && cfg.remote.length > 0;
      return { linkUp: row.enabled && local && remote, degraded: false };
    }
    default: // physical — up when enabled (M02 §5)
      return { linkUp: row.enabled, degraded: false };
  }
}

// ── shaping ─────────────────────────────────────────────────────────────────

export function shapeIface(
  row: IfaceRow,
  zoneName: string | null,
  live: IfaceLiveRates | undefined,
  allRows?: IfaceRow[],
): ShapedIface {
  const { linkUp, degraded } = linkStateOf(row, allRows ?? [row]);
  const cfg = parseIfaceConfig(row.config);
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    mode: row.mode,
    role: row.role,
    // effective parent — column first, config.parent fallback (seed-tolerant)
    parentName:
      row.parentName ?? (row.type === "vlan" && typeof cfg.parent === "string" && cfg.parent ? cfg.parent : null),
    vlanId: row.vlanId,
    mtu: row.mtu,
    mssClamp: row.mssClamp,
    enabled: row.enabled,
    config: cfg,
    description: row.description,
    zoneId: row.zoneId,
    zoneName,
    linkUp,
    degraded,
    rxKbps: live?.rxKbps ?? 0,
    txKbps: live?.txKbps ?? 0,
  };
}

/** Latest metrics ring tick → per-iface rx/tx map (M02 §6 — engine is the source). */
export function liveIfaceRates(): Map<string, IfaceLiveRates> {
  const ring = getEngine().metricsRing;
  const tick = ring.length ? ring[ring.length - 1] : undefined;
  return new Map((tick?.ifaces ?? []).map((i) => [i.name, { rxKbps: i.rxKbps, txKbps: i.txKbps }]));
}

/** Fetch + shape every tenant iface (zones joined once for names). */
export async function loadShapedIfaces(tenantId: number): Promise<ShapedIface[]> {
  const [rows, zones] = await Promise.all([
    db.networkInterface.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.zone.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  const zoneNames = new Map(zones.map((z) => [z.id, z.name]));
  const rates = liveIfaceRates();
  return rows.map((r) => shapeIface(r, r.zoneId ? (zoneNames.get(r.zoneId) ?? null) : null, rates.get(r.name), rows));
}

// ── shared reference checks (logical refs → 400 VALIDATION_ERROR, M02 §3) ──

export async function assertZoneExists(tenantId: number, zoneId: number): Promise<void> {
  const zone = await db.zone.findFirst({ where: { id: zoneId, tenantId } });
  if (!zone) throw ApiError.validation("Unknown zone");
}

export async function assertIfacesExist(tenantId: number, names: string[]): Promise<void> {
  const unique = [...new Set(names)];
  const rows = await db.networkInterface.findMany({ where: { tenantId, name: { in: unique } }, select: { name: true } });
  const known = new Set(rows.map((r) => r.name));
  for (const n of unique) {
    if (!known.has(n)) throw ApiError.validation(`Unknown interface ${n}`);
  }
}

// ── business-rule enforcement (iface-rules.ts — pure engine, unit-tested) ──

function rowToRuleView(row: IfaceRow): IfaceRuleView {
  const cfg = parseIfaceConfig(row.config);
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    mode: row.mode,
    role: row.role,
    mtu: row.mtu,
    mssClamp: row.mssClamp,
    enabled: row.enabled,
    parentName: row.parentName ?? (typeof cfg.parent === "string" ? cfg.parent : null),
    vlanId: row.vlanId,
    config: cfg,
  };
}

/** Convert lint issues into the API field-error shape (matches zodIssues). */
function throwIfErrors(issues: IfaceIssue[], action: string): void {
  const { errors, warnings } = groupIssues(issues);
  const keys = Object.keys(errors);
  if (keys.length > 0) {
    throw ApiError.validation(`Interface ${action} blocked by business rules`, {
      fieldErrors: errors,
      warnings,
    });
  }
}

/** Active config that would break when the interface goes admin-down. */
async function collectDisableRefs(tenantId: number, name: string): Promise<Array<{ kind: string; label: string }>> {
  const refs: Array<{ kind: string; label: string }> = [];
  const [routes, wanPolicies, dhcpSubnets, zones] = await Promise.all([
    db.staticRoute.findMany({ where: { tenantId, interfaceName: name, enabled: true }, select: { destinationCidr: true } }),
    db.wanPolicy.findMany({ where: { tenantId, interfaceName: name }, select: { id: true, mode: true } }),
    db.dhcpSubnet.findMany({ where: { tenantId, interfaceName: name, enabled: true }, select: { subnetCidr: true } }),
    db.zone.findMany({ where: { tenantId }, select: { name: true, interfaceNames: true } }),
  ]);
  for (const r of routes) refs.push({ kind: "static-route", label: r.destinationCidr });
  for (const w of wanPolicies) refs.push({ kind: "wan-policy", label: `#${w.id} (${w.mode})` });
  for (const s of dhcpSubnets) refs.push({ kind: "dhcp-subnet", label: s.subnetCidr });
  for (const z2 of zones) {
    const names = strArrJson(z2.interfaceNames);
    if (names.includes(name)) refs.push({ kind: "zone", label: z2.name });
  }
  return refs;
}

export interface IfaceRefItem {
  kind: string;
  label: string;
}

/**
 * Batched reference map for the whole tenant — the FortiGate "Ref." column
 * backing data (routes, WAN policies, DHCP subnets, zones, master memberships).
 */
export async function collectAllRefs(tenantId: number): Promise<Map<string, { count: number; items: IfaceRefItem[] }>> {
  const [routes, wanPolicies, dhcpSubnets, zones, masters] = await Promise.all([
    db.staticRoute.findMany({ where: { tenantId, enabled: true }, select: { interfaceName: true, destinationCidr: true } }),
    db.wanPolicy.findMany({ where: { tenantId }, select: { interfaceName: true, id: true, mode: true } }),
    db.dhcpSubnet.findMany({ where: { tenantId, enabled: true }, select: { interfaceName: true, subnetCidr: true } }),
    db.zone.findMany({ where: { tenantId }, select: { name: true, interfaceNames: true } }),
    db.networkInterface.findMany({ where: { tenantId, type: { in: ["bridge", "bond"] } }, select: { name: true, type: true, config: true } }),
  ]);
  const map = new Map<string, { count: number; items: IfaceRefItem[] }>();
  const push = (n: string | null | undefined, item: IfaceRefItem) => {
    if (!n) return;
    const e = map.get(n) ?? { count: 0, items: [] };
    e.count += 1;
    e.items.push(item);
    map.set(n, e);
  };
  for (const r of routes) push(r.interfaceName, { kind: "static-route", label: r.destinationCidr });
  for (const w of wanPolicies) push(w.interfaceName, { kind: "wan-policy", label: `#${w.id} (${w.mode})` });
  for (const s of dhcpSubnets) push(s.interfaceName, { kind: "dhcp-subnet", label: s.subnetCidr });
  for (const z2 of zones) {
    for (const n of strArrJson(z2.interfaceNames)) push(n, { kind: "zone", label: z2.name });
  }
  for (const m of masters) {
    const cfg = parseIfaceConfig(m.config);
    for (const member of strArr(cfg.members)) push(member, { kind: `${m.type}-member`, label: m.name });
  }
  return map;
}

/** Lint the tenant and throw 400 on errors (warnings returned for callers).
 *  forceOverride=true lets the caller bypass BR-MGMT-LOCKOUT specifically —
 *  an operator may consciously give up the last mgmt interface (recovery
 *  console access assumed), every other rule stays absolute. */
async function enforceRules(
  tenantId: number,
  candidate: IfaceRuleView,
  opts: { action?: "disable" | "delete"; roleFrom?: string | null; excludeId?: number; action_: string; forceOverride?: boolean },
): Promise<{ warnings: Record<string, string[]> }> {
  const rows = await db.networkInterface.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const views = rows.filter((r) => r.id !== opts.excludeId).map(rowToRuleView);
  const issues = lintIface({ self: candidate, others: views, action: opts.action, roleFrom: opts.roleFrom });
  const { warnings } = groupIssues(issues);
  const errors = issues.filter((i) => i.severity === "error");
  const lockoutOverridden =
    opts.forceOverride === true && errors.length > 0 && errors.every((i) => i.code === "BR-MGMT-LOCKOUT");
  if (!lockoutOverridden) throwIfErrors(issues, opts.action_);
  return { warnings };
}

// ── create ──────────────────────────────────────────────────────────────────

/** L3 addressing block shared by vlan/bridge/bond creates. */
function addrConfig(body: {
  ip?: string;
  cidrPrefix?: number;
  gateway?: string | null;
  dns?: string[];
  secondaryIps?: Array<{ ip: string; cidrPrefix: number }>;
}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (body.ip !== undefined && body.cidrPrefix != null) {
    out.ip = body.ip;
    out.cidrPrefix = body.cidrPrefix;
  }
  if (body.gateway != null) out.gateway = body.gateway;
  if (body.dns !== undefined) out.dns = body.dns;
  if (body.secondaryIps !== undefined) out.secondaryIps = body.secondaryIps;
  return out;
}

function buildCreateConfig(body: Exclude<IfaceCreateBody, { type: "physical" }>): Record<string, unknown> {
  switch (body.type) {
    case "vlan":
      return { parent: body.parent, ...addrConfig(body) };
    case "bridge":
      return {
        members: body.members,
        stp: body.stp ?? false,
        ...(body.stpMode ? { stpMode: body.stpMode } : {}),
        ...(body.stpPriority != null ? { stpPriority: body.stpPriority } : {}),
        ...(body.forwardDelay != null ? { forwardDelay: body.forwardDelay } : {}),
        igmpSnooping: body.igmpSnooping ?? false,
        ...addrConfig(body),
      };
    case "bond":
      return {
        members: body.members,
        mode: body.mode,
        ...(body.lacpRate ? { lacpRate: body.lacpRate } : {}),
        ...(body.miimon != null ? { miimon: body.miimon } : {}),
        ...addrConfig(body),
      };
    case "gre":
      return { local: body.local, remote: body.remote, ...(body.ttl != null ? { ttl: body.ttl } : {}) };
    case "ipip":
      return { local: body.local, remote: body.remote };
    case "loopback":
      return {
        ...(body.ip ? { ip: body.ip } : {}),
        ...(body.cidrPrefix != null ? { cidrPrefix: body.cidrPrefix } : {}),
      };
    default:
      return {};
  }
}

export async function createIface(
  tenantId: number,
  body: IfaceCreateBody,
): Promise<IfaceRow & { os: OsApplyOutcome }> {
  // zod already rejects physical via superRefine; this guard also narrows the union
  if (body.type === "physical") {
    throw ApiError.validation("Physical interfaces are provisioned by the appliance");
  }
  if (body.zoneId != null) await assertZoneExists(tenantId, body.zoneId);

  // logical member refs must resolve (same convention as zone saves, M02 §2)
  const refs: string[] = [];
  if (body.type === "vlan") refs.push(body.parent);
  if (body.type === "bridge" || body.type === "bond") refs.push(...body.members);
  if (refs.length) await assertIfacesExist(tenantId, refs);

  // enterprise business rules (subnet overlap, MTU chain, members, roles…)
  const candidate: IfaceRuleView = {
    name: body.name,
    type: body.type,
    mode: body.type === "bond" ? "l3" : body.mode,
    role: body.role,
    mtu: body.mtu,
    mssClamp: body.mssClamp ?? null,
    enabled: body.enabled,
    parentName: body.type === "vlan" ? body.parent : null,
    vlanId: body.type === "vlan" ? body.vlanId : null,
    config: buildCreateConfig(body),
  };
  await enforceRules(tenantId, candidate, { excludeId: undefined, action_: "create" });

  let created: IfaceRow;
  try {
    created = await db.networkInterface.create({
      data: {
        tenantId,
        name: body.name,
        type: body.type,
        // bond create payloads carry the aggregation mode under `mode` — the
        // DB l2|l3 column stays at its l3 default for bonds (see validators)
        mode: body.type === "bond" ? "l3" : body.mode,
        role: body.role,
        parentName: body.type === "vlan" ? body.parent : null,
        vlanId: body.type === "vlan" ? body.vlanId : null,
        mtu: body.mtu,
        mssClamp: body.mssClamp ?? null,
        enabled: body.enabled,
        config: JSON.stringify(buildCreateConfig(body)),
        description: body.description ?? null,
        zoneId: body.zoneId ?? null,
      },
    });
  } catch (err) {
    throw p2002ToConflict(err, `Interface '${body.name}' already exists`);
  }
  // appliance semantics: a created logical interface exists on the host
  const os = await convergeIfaceSafe(rowToRuleView(created));
  return { ...created, os };
}

// ── update ──────────────────────────────────────────────────────────────────

const L3_FIELDS = ["ip", "cidrPrefix", "gateway", "wanType", "dns"] as const;

/** wanType switch semantics on the physical config JSON (M02 §5 update flow). */
function mergePhysicalConfig(existing: IfaceRow, body: IfaceUpdateBody): Record<string, unknown> {
  const cfg = parseIfaceConfig(existing.config);
  if (body.lldp !== undefined) cfg.lldp = body.lldp;
  if (body.speed !== undefined) cfg.speed = body.speed;
  if (body.duplex !== undefined) cfg.duplex = body.duplex;
  if (body.secondaryIps !== undefined) cfg.secondaryIps = body.secondaryIps;

  const touchesWan =
    body.wanType !== undefined ||
    body.ip !== undefined ||
    body.cidrPrefix !== undefined ||
    body.gateway !== undefined ||
    body.dns !== undefined ||
    body.pppoe !== undefined;
  if (!touchesWan) return cfg;

  const wanType = body.wanType ?? (typeof cfg.wanType === "string" ? cfg.wanType : "static");
  if (wanType === "dhcp") {
    // dhcp clears the static address fields (hostname override only, M02 §2)
    delete cfg.ip;
    delete cfg.cidrPrefix;
    delete cfg.gateway;
    delete cfg.dns;
    delete cfg.pppoe;
  } else if (wanType === "pppoe") {
    if (body.pppoe) {
      const prev = cfg.pppoe && typeof cfg.pppoe === "object" ? (cfg.pppoe as Record<string, unknown>) : {};
      cfg.pppoe = {
        ...prev,
        user: body.pppoe.user,
        password: body.pppoe.password,
        ...(body.pppoe.service ? { service: body.pppoe.service } : {}),
      };
    }
    delete cfg.ip;
    delete cfg.cidrPrefix;
    delete cfg.gateway;
    delete cfg.dns;
  } else {
    // static keeps ip/cidrPrefix/gateway/dns
    if (body.ip !== undefined) cfg.ip = body.ip;
    if (body.cidrPrefix !== undefined) cfg.cidrPrefix = body.cidrPrefix;
    if (body.gateway !== undefined) cfg.gateway = body.gateway;
    if (body.dns !== undefined) cfg.dns = body.dns;
    delete cfg.pppoe;
  }
  cfg.wanType = wanType;
  return cfg;
}

/** Merge + validate the logical config passthrough against the row's type. */
async function mergeLogicalConfig(
  tenantId: number,
  existing: IfaceRow,
  body: IfaceUpdateBody,
): Promise<{ config: Record<string, unknown>; parentName?: string }> {
  const cfg = parseIfaceConfig(existing.config);
  if (!body.config) return { config: cfg };

  switch (existing.type) {
    case "vlan": {
      const parsed = vlanConfigPatch.safeParse(body.config);
      if (!parsed.success) throw ApiError.validation("Invalid vlan config", zodFieldErrors(parsed.error));
      Object.assign(cfg, parsed.data);
      if (parsed.data.parent) {
        await assertIfacesExist(tenantId, [parsed.data.parent]);
        return { config: cfg, parentName: parsed.data.parent };
      }
      break;
    }
    case "bridge": {
      const parsed = bridgeConfigPatch.safeParse(body.config);
      if (!parsed.success) throw ApiError.validation("Invalid bridge config", zodFieldErrors(parsed.error));
      if (parsed.data.members) await assertIfacesExist(tenantId, parsed.data.members);
      Object.assign(cfg, parsed.data);
      break;
    }
    case "bond": {
      const parsed = bondConfigPatch.safeParse(body.config);
      if (!parsed.success) throw ApiError.validation("Invalid bond config", zodFieldErrors(parsed.error));
      if (parsed.data.members) await assertIfacesExist(tenantId, parsed.data.members);
      Object.assign(cfg, parsed.data);
      break;
    }
    case "gre": {
      const parsed = greConfigPatch.safeParse(body.config);
      if (!parsed.success) throw ApiError.validation("Invalid gre config", zodFieldErrors(parsed.error));
      Object.assign(cfg, parsed.data);
      break;
    }
    case "ipip": {
      const parsed = ipipConfigPatch.safeParse(body.config);
      if (!parsed.success) throw ApiError.validation("Invalid ipip config", zodFieldErrors(parsed.error));
      Object.assign(cfg, parsed.data);
      break;
    }
    case "loopback": {
      const parsed = loopbackConfigPatch.safeParse(body.config);
      if (!parsed.success) throw ApiError.validation("Invalid loopback config", zodFieldErrors(parsed.error));
      Object.assign(cfg, parsed.data);
      break;
    }
    default:
      throw ApiError.validation(`Unsupported interface type '${existing.type}'`);
  }

  // tunnels: endpoints must differ after the merge (M02 §5)
  if (
    (existing.type === "gre" || existing.type === "ipip") &&
    typeof cfg.local === "string" &&
    typeof cfg.remote === "string" &&
    cfg.local.length > 0 &&
    cfg.local === cfg.remote
  ) {
    throw ApiError.validation("local and remote must differ");
  }
  return { config: cfg };
}

export async function updateIface(
  tenantId: number,
  id: number,
  body: IfaceUpdateBody,
  existing: IfaceRow,
): Promise<IfaceRow & { os: OsApplyOutcome }> {
  // L2/L3 mode semantics (M02 §5) — service-side check against the merged mode
  const nextMode = body.mode ?? existing.mode;
  if (nextMode === "l2") {
    for (const f of L3_FIELDS) {
      if (body[f] !== undefined && body[f] !== null) {
        throw ApiError.validation("L2 mode interfaces carry no L3 config", { field: f });
      }
    }
  }

  if (body.zoneId != null) await assertZoneExists(tenantId, body.zoneId);

  // physical identity is immutable (M02 §3 error table); logical names may change
  if (body.name && body.name !== existing.name) {
    if (existing.type === "physical") {
      throw ApiError.conflict("Physical interface identity is immutable");
    }
    const dup = await db.networkInterface.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Interface '${body.name}' already exists`);
  }

  // merged desired state FIRST — the rule engine lints the candidate, not the patch
  const merged =
    existing.type === "physical"
      ? { config: mergePhysicalConfig(existing, body) }
      : await mergeLogicalConfig(tenantId, existing, body);

  // physical L3→L2 switch — the row is scrubbed of ALL L3 config (BR-L2-L3
  // parity: an L2 port carries no addressing), and OS convergence strips the
  // kernel address. Only active REFERENCES still require an explicit force.
  if (existing.type === "physical" && nextMode === "l2" && existing.mode !== "l2") {
    for (const k of ["ip", "cidrPrefix", "gateway", "dns", "pppoe", "wanType", "secondaryIps"]) {
      delete merged.config[k];
    }
  }

  const nextEnabled = body.enabled ?? existing.enabled;
  const candidate: IfaceRuleView = {
    id: existing.id,
    name: body.name ?? existing.name,
    type: existing.type,
    mode: nextMode,
    role: body.role ?? existing.role,
    mtu: body.mtu ?? existing.mtu,
    mssClamp: body.mssClamp !== undefined ? (body.mssClamp ?? null) : existing.mssClamp,
    enabled: nextEnabled,
    parentName: merged.parentName ?? existing.parentName,
    vlanId: existing.vlanId,
    config: merged.config,
  };

  const disabling = existing.enabled && nextEnabled === false;
  const roleFrom = body.role !== undefined && body.role !== existing.role ? existing.role : null;

  // physical L2 switch — active references still need an explicit force
  if (existing.type === "physical" && nextMode === "l2" && existing.mode === "l3" && !body.force) {
    const refs = await collectDisableRefs(tenantId, existing.name);
    if (refs.length > 0) {
      throw ApiError.conflict(
        "Switching to L2 requires confirming active references",
        { refs },
      );
    }
  }

  // enterprise business rules (subnet overlap, MTU chain, mgmt lockout, members…)
  await enforceRules(tenantId, candidate, {
    excludeId: existing.id,
    action: disabling ? "disable" : undefined,
    roleFrom,
    action_: "update",
    forceOverride: body.force === true,
  });

  // disable with active references → 409 listing them, force overrides
  if (disabling && body.force !== true) {
    const refs = await collectDisableRefs(tenantId, existing.name);
    if (refs.length > 0) {
      throw ApiError.conflict(`Interface ${existing.name} is referenced by active configuration`, { refs });
    }
  }

  let updated: IfaceRow;
  try {
    // undefined fields stay untouched (patch semantics); explicit nulls clear
    updated = await db.networkInterface.update({
      where: { id },
      data: {
        name: body.name,
        mode: body.mode,
        role: body.role,
        mtu: body.mtu,
        mssClamp: body.mssClamp,
        enabled: body.enabled,
        description: body.description,
        zoneId: body.zoneId,
        parentName: merged.parentName,
        config: JSON.stringify(merged.config),
      },
    });
  } catch (err) {
    throw p2002ToConflict(err, `Interface '${body.name ?? existing.name}' already exists`);
  }
  // rename: the old kernel link must not linger (logical interfaces only)
  if (body.name && body.name !== existing.name && existing.type !== "physical") {
    await teardownIfaceSafe(rowToRuleView(existing));
  }
  // appliance semantics: every committed change converges the host
  const os = await convergeIfaceSafe(rowToRuleView(updated));
  return { ...updated, os };
}

// ── delete (cascade per M02 §2/§5) ──────────────────────────────────────────

export async function deleteIface(
  tenantId: number,
  row: IfaceRow,
): Promise<{ id: number; name: string; os: OsApplyOutcome }> {
  if (row.type === "physical") {
    throw ApiError.validation("Physical interfaces cannot be deleted — disable instead");
  }

  // last-mgmt lockout on delete — structural rules (members etc.) must not
  // block deletion (a bridge whose members were already scrubbed deletes fine)
  const rows = await db.networkInterface.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const others = rows.filter((r) => r.id !== row.id).map(rowToRuleView);
  const issues = lintIface({ self: rowToRuleView(row), others, action: "delete" });
  const lockout = issues.filter((i) => i.severity === "error" && i.code === "BR-MGMT-LOCKOUT");
  if (lockout.length > 0) throwIfErrors(lockout, "delete");

  await db.$transaction(async (tx) => {
    // hard FK by name — the WAN policy goes first (M02 §2 integrity rules)
    await tx.wanPolicy.deleteMany({ where: { tenantId, interfaceName: row.name } });
    // zones.interfaceNames is a logical ref — strip the deleted name (M02 §2)
    const zones = await tx.zone.findMany({ where: { tenantId } });
    for (const z of zones) {
      const names = strArrJson(z.interfaceNames);
      if (names.includes(row.name)) {
        await tx.zone.update({
          where: { id: z.id },
          data: { interfaceNames: JSON.stringify(names.filter((n) => n !== row.name)) },
        });
      }
    }
    // routes are cheap to re-point — null the soft ref, no 409 (M02 §3)
    await tx.staticRoute.updateMany({
      where: { tenantId, interfaceName: row.name },
      data: { interfaceName: null },
    });
    // bridges/bonds keep a dangling member otherwise — scrub membership refs
    const masters = await tx.networkInterface.findMany({ where: { tenantId, type: { in: ["bridge", "bond"] } } });
    for (const m of masters) {
      const cfg = parseIfaceConfig(m.config);
      const members = Array.isArray(cfg.members) ? strArr(cfg.members) : [];
      if (members.includes(row.name)) {
        await tx.networkInterface.update({
          where: { id: m.id },
          data: { config: JSON.stringify({ ...cfg, members: members.filter((n) => n !== row.name) }) },
        });
      }
    }
    await tx.networkInterface.delete({ where: { id: row.id } });
  });
  // appliance semantics: a deleted logical interface disappears from the host
  const os = await teardownIfaceSafe(rowToRuleView(row));
  return { id: row.id, name: row.name, os };
}

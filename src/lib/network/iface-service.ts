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
  bondConfigPatch,
  bridgeConfigPatch,
  greConfigPatch,
  ipipConfigPatch,
  loopbackConfigPatch,
  vlanConfigPatch,
  type IfaceCreateBody,
  type IfaceUpdateBody,
} from "@/lib/validators/network";

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

// ── create ──────────────────────────────────────────────────────────────────

function buildCreateConfig(body: Exclude<IfaceCreateBody, { type: "physical" }>): Record<string, unknown> {
  switch (body.type) {
    case "vlan":
      return { parent: body.parent };
    case "bridge":
      return {
        members: body.members,
        stp: body.stp ?? false,
        ...(body.stpMode ? { stpMode: body.stpMode } : {}),
        igmpSnooping: body.igmpSnooping ?? false,
      };
    case "bond":
      return { members: body.members, mode: body.mode };
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

export async function createIface(tenantId: number, body: IfaceCreateBody): Promise<IfaceRow> {
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

  try {
    return await db.networkInterface.create({
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
}

// ── update ──────────────────────────────────────────────────────────────────

const L3_FIELDS = ["ip", "cidrPrefix", "gateway", "wanType", "dns"] as const;

/** wanType switch semantics on the physical config JSON (M02 §5 update flow). */
function mergePhysicalConfig(existing: IfaceRow, body: IfaceUpdateBody): Record<string, unknown> {
  const cfg = parseIfaceConfig(existing.config);
  if (body.lldp !== undefined) cfg.lldp = body.lldp;

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
): Promise<IfaceRow> {
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

  const merged =
    existing.type === "physical"
      ? { config: mergePhysicalConfig(existing, body) }
      : await mergeLogicalConfig(tenantId, existing, body);

  try {
    // undefined fields stay untouched (patch semantics); explicit nulls clear
    return await db.networkInterface.update({
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
}

// ── delete (cascade per M02 §2/§5) ──────────────────────────────────────────

export async function deleteIface(tenantId: number, row: IfaceRow): Promise<{ id: number; name: string }> {
  if (row.type === "physical") {
    throw ApiError.validation("Physical interfaces cannot be deleted — disable instead");
  }
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
    await tx.networkInterface.delete({ where: { id: row.id } });
  });
  return { id: row.id, name: row.name };
}

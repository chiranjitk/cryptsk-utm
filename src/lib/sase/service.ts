/**
 * SASE service (spec §4.2) — DB-backed registry + plan rendering over the
 * SaseNode / SaseTunnel tables and the identity-aware routing stub:
 *
 *  • Node/tunnel CRUD with mesh-integrity guards: both tunnel endpoints must
 *    exist in the tenant (logical refs — SQLite has no FK on the ids), no
 *    self-tunnels, no duplicate pair in the same direction, nodes referenced
 *    by tunnels cannot be deleted.
 *  • renderForTenant loads the registry and hands the PURE renderer
 *    (lib/sase/mesh.ts) its shapes — the result is a plan/preview only; key
 *    material is redacted and NOTHING is applied to the host OS (cloud VM
 *    deployment is out of scope, §4.2 note).
 *  • Identity-aware routing stub: a user → region mapping stored as ONE JSON
 *    map under SystemSetting category "sase" key "identity_routing" — read
 *    and written through the EXISTING system-service settings helpers
 *    (getSetting / putSettingsBatch), never a parallel settings path.
 *    resolveNode maps a user to the nearest routable node via the pure
 *    pickNearestNode (same-region gateway first, else first active).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { getSetting, putSettingsBatch } from "@/lib/system/service";
import type { SettingsEntry } from "@/lib/validators/system";
import type {
  SaseCloud,
  SaseNodeCreate,
  SaseNodeUpdate,
  SaseResolve,
  SaseRole,
  SaseRoutingUpsert,
  SaseStatus,
  SaseTunnelCreate,
  SaseTunnelState,
  SaseTunnelUpdate,
} from "@/lib/validators/sase";
import {
  pickNearestNode,
  renderMeshConfig,
  type SaseMeshPlan,
  type SaseNodeShape,
  type SaseTunnelShape,
} from "@/lib/sase/mesh";

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface SaseNodeDTO {
  id: number;
  name: string;
  cloud: SaseCloud;
  region: string;
  role: SaseRole;
  tunnelEndpoint: string;
  publicSubnets: string[];
  status: SaseStatus;
  createdAt: string;
}

export interface SaseTunnelDTO {
  id: number;
  name: string;
  fromNodeId: number;
  toNodeId: number;
  /** resolved names for the view's from → to display */
  fromNodeName: string;
  toNodeName: string;
  state: SaseTunnelState;
  /** secret-store REFERENCE — never the PSK itself */
  pskRef: string;
  allowedSubnets: string[];
  createdAt: string;
}

// ── shaping helpers ─────────────────────────────────────────────────────────

type SaseNodeRow = {
  id: number;
  name: string;
  cloud: string;
  region: string;
  role: string;
  tunnelEndpoint: string;
  publicSubnets: string;
  status: string;
  createdAt: Date;
};

type SaseTunnelRow = {
  id: number;
  name: string;
  fromNodeId: number;
  toNodeId: number;
  state: string;
  pskRef: string;
  allowedSubnets: string;
  createdAt: Date;
};

function parseCidrList(raw: string): string[] {
  const v = parseJson<unknown>(raw, []);
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function toNodeDTO(row: SaseNodeRow): SaseNodeDTO {
  return {
    id: row.id,
    name: row.name,
    cloud: row.cloud as SaseCloud,
    region: row.region,
    role: row.role as SaseRole,
    tunnelEndpoint: row.tunnelEndpoint,
    publicSubnets: parseCidrList(row.publicSubnets),
    status: row.status as SaseStatus,
    createdAt: row.createdAt.toISOString(),
  };
}

function toTunnelDTO(row: SaseTunnelRow, nodeNames: Map<number, string>): SaseTunnelDTO {
  return {
    id: row.id,
    name: row.name,
    fromNodeId: row.fromNodeId,
    toNodeId: row.toNodeId,
    fromNodeName: nodeNames.get(row.fromNodeId) ?? `#${row.fromNodeId}`,
    toNodeName: nodeNames.get(row.toNodeId) ?? `#${row.toNodeId}`,
    state: row.state as SaseTunnelState,
    pskRef: row.pskRef,
    allowedSubnets: parseCidrList(row.allowedSubnets),
    createdAt: row.createdAt.toISOString(),
  };
}

function toNodeShape(row: SaseNodeRow): SaseNodeShape {
  return {
    id: row.id,
    name: row.name,
    cloud: row.cloud,
    region: row.region,
    role: row.role,
    tunnelEndpoint: row.tunnelEndpoint,
    publicSubnets: parseCidrList(row.publicSubnets),
    status: row.status,
  };
}

function toTunnelShape(row: SaseTunnelRow): SaseTunnelShape {
  return {
    id: row.id,
    name: row.name,
    fromNodeId: row.fromNodeId,
    toNodeId: row.toNodeId,
    state: row.state,
    pskRef: row.pskRef,
    allowedSubnets: parseCidrList(row.allowedSubnets),
  };
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "P2002";
}

async function requireNode(tenantId: number, id: number, label: string): Promise<SaseNodeRow> {
  const row = await db.saseNode.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`${label} not found`);
  return row;
}

// ── nodes (§4.2 cloud firewall node registry) ───────────────────────────────

export async function listNodes(tenantId: number): Promise<SaseNodeDTO[]> {
  const rows = await db.saseNode.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toNodeDTO);
}

export async function getNode(tenantId: number, id: number): Promise<SaseNodeDTO> {
  return toNodeDTO(await requireNode(tenantId, id, "SASE node"));
}

export async function createNode(tenantId: number, input: SaseNodeCreate): Promise<SaseNodeDTO> {
  try {
    const row = await db.saseNode.create({
      data: {
        tenantId,
        name: input.name.trim(),
        cloud: input.cloud,
        region: (input.region ?? "").trim(),
        role: input.role,
        tunnelEndpoint: (input.tunnelEndpoint ?? "").trim(),
        publicSubnets: stringifyJson(input.publicSubnets ?? []),
        status: input.status,
      },
    });
    return toNodeDTO(row);
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw ApiError.conflict(`SASE node name '${input.name.trim()}' already exists in this tenant`);
    }
    throw err;
  }
}

export async function updateNode(tenantId: number, id: number, input: SaseNodeUpdate): Promise<SaseNodeDTO> {
  await requireNode(tenantId, id, "SASE node");
  try {
    const row = await db.saseNode.update({
      where: { id },
      data: {
        ...(input.name !== undefined ? { name: input.name.trim() } : {}),
        ...(input.cloud !== undefined ? { cloud: input.cloud } : {}),
        ...(input.region !== undefined ? { region: input.region.trim() } : {}),
        ...(input.role !== undefined ? { role: input.role } : {}),
        ...(input.tunnelEndpoint !== undefined ? { tunnelEndpoint: input.tunnelEndpoint.trim() } : {}),
        ...(input.publicSubnets !== undefined ? { publicSubnets: stringifyJson(input.publicSubnets) } : {}),
        ...(input.status !== undefined ? { status: input.status } : {}),
      },
    });
    return toNodeDTO(row);
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw ApiError.conflict(`SASE node name '${input.name?.trim()}' already exists in this tenant`);
    }
    throw err;
  }
}

/**
 * Delete a node — rejected while any tunnel still references it: the mesh
 * renderer treats dangling refs as plan errors, so the registry must not
 * create them silently.
 */
export async function deleteNode(tenantId: number, id: number): Promise<{ ok: true }> {
  await requireNode(tenantId, id, "SASE node");
  const ref = await db.saseTunnel.findFirst({
    where: { tenantId, OR: [{ fromNodeId: id }, { toNodeId: id }] },
  });
  if (ref) {
    throw ApiError.conflict(
      `SASE node is still referenced by tunnel '${ref.name}' (id ${ref.id}) — delete the tunnel first`,
    );
  }
  await db.saseNode.delete({ where: { id } });
  return { ok: true };
}

// ── tunnels (§4.2 edge-to-cloud WireGuard mesh links) ───────────────────────

async function nodeNamesFor(tenantId: number, ids?: number[]): Promise<Map<number, string>> {
  const rows = await db.saseNode.findMany({
    where: { tenantId, ...(ids && ids.length > 0 ? { id: { in: ids } } : {}) },
    select: { id: true, name: true },
  });
  return new Map(rows.map((r) => [r.id, r.name]));
}

async function assertTunnelPair(tenantId: number, fromNodeId: number, toNodeId: number): Promise<void> {
  if (fromNodeId === toNodeId) {
    throw ApiError.validation("A tunnel cannot connect a node to itself");
  }
  const from = await db.saseNode.findFirst({ where: { id: fromNodeId, tenantId } });
  if (!from) throw ApiError.validation(`fromNodeId ${fromNodeId} does not reference an existing SASE node in this tenant`);
  const to = await db.saseNode.findFirst({ where: { id: toNodeId, tenantId } });
  if (!to) throw ApiError.validation(`toNodeId ${toNodeId} does not reference an existing SASE node in this tenant`);
}

async function assertNoDuplicatePair(
  tenantId: number,
  fromNodeId: number,
  toNodeId: number,
  excludeId?: number,
): Promise<void> {
  const dup = await db.saseTunnel.findFirst({
    where: {
      tenantId,
      fromNodeId,
      toNodeId,
      ...(excludeId !== undefined ? { id: { not: excludeId } } : {}),
    },
  });
  if (dup) {
    throw ApiError.conflict(
      `A tunnel in this direction already exists ('${dup.name}', id ${dup.id}) — same from → to pair`,
    );
  }
}

export async function listTunnels(tenantId: number): Promise<SaseTunnelDTO[]> {
  const rows = await db.saseTunnel.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const nodeIds = [...new Set(rows.flatMap((r) => [r.fromNodeId, r.toNodeId]))];
  const names = await nodeNamesFor(tenantId, nodeIds);
  return rows.map((r) => toTunnelDTO(r, names));
}

export async function createTunnel(tenantId: number, input: SaseTunnelCreate): Promise<SaseTunnelDTO> {
  await assertTunnelPair(tenantId, input.fromNodeId, input.toNodeId);
  await assertNoDuplicatePair(tenantId, input.fromNodeId, input.toNodeId);
  try {
    const row = await db.saseTunnel.create({
      data: {
        tenantId,
        name: input.name.trim(),
        fromNodeId: input.fromNodeId,
        toNodeId: input.toNodeId,
        state: input.state ?? "planned",
        pskRef: (input.pskRef ?? "").trim(),
        allowedSubnets: stringifyJson(input.allowedSubnets ?? []),
      },
    });
    const names = await nodeNamesFor(tenantId, [input.fromNodeId, input.toNodeId]);
    return toTunnelDTO(row, names);
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw ApiError.conflict(`SASE tunnel name '${input.name.trim()}' already exists in this tenant`);
    }
    throw err;
  }
}

export async function updateTunnel(
  tenantId: number,
  id: number,
  input: SaseTunnelUpdate,
): Promise<SaseTunnelDTO> {
  const row = await db.saseTunnel.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("SASE tunnel not found");

  const fromNodeId = input.fromNodeId ?? row.fromNodeId;
  const toNodeId = input.toNodeId ?? row.toNodeId;
  await assertTunnelPair(tenantId, fromNodeId, toNodeId);
  if (fromNodeId !== row.fromNodeId || toNodeId !== row.toNodeId) {
    await assertNoDuplicatePair(tenantId, fromNodeId, toNodeId, id);
  }

  const updated = await db.saseTunnel.update({
    where: { id: row.id },
    data: {
      ...(input.name !== undefined ? { name: input.name.trim() } : {}),
      ...(input.fromNodeId !== undefined ? { fromNodeId } : {}),
      ...(input.toNodeId !== undefined ? { toNodeId } : {}),
      ...(input.state !== undefined ? { state: input.state } : {}),
      ...(input.pskRef !== undefined ? { pskRef: input.pskRef.trim() } : {}),
      ...(input.allowedSubnets !== undefined ? { allowedSubnets: stringifyJson(input.allowedSubnets) } : {}),
    },
  });
  const names = await nodeNamesFor(tenantId, [updated.fromNodeId, updated.toNodeId]);
  return toTunnelDTO(updated, names);
}

export async function deleteTunnel(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.saseTunnel.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("SASE tunnel not found");
  await db.saseTunnel.delete({ where: { id: row.id } });
  return { ok: true };
}

// ── mesh config plan (§4.2 — preview only, keys redacted) ───────────────────

/**
 * Load the tenant registry and render the wg-quick mesh plan through the
 * PURE renderer. Plan-only: nothing is written to the host OS and all key
 * material renders `[REDACTED-SEE-SECRET-STORE]`.
 */
export async function renderForTenant(tenantId: number): Promise<SaseMeshPlan> {
  const [nodes, tunnels] = await Promise.all([
    db.saseNode.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.saseTunnel.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
  ]);
  return renderMeshConfig(nodes.map(toNodeShape), tunnels.map(toTunnelShape));
}

// ── identity-aware routing stub (§4.2 user → nearest node) ──────────────────

const SASE_SETTINGS_CATEGORY = "sase";
const IDENTITY_ROUTING_KEY = "identity_routing";

/** user email → { region, updatedAt } — one JSON map in a single setting row. */
type RoutingMap = Record<string, { region: string; updatedAt: string }>;

export interface SaseRoutingEntry {
  userEmail: string;
  region: string;
  updatedAt: string;
  /** nearest routable node for the entry's region (identity-aware routing stub) */
  resolvedNode: SaseNodeDTO | null;
}

export interface SaseResolveResult {
  userEmail: string;
  /** mapped region — null when the user has no routing entry */
  region: string | null;
  /** nearest node for the mapped region — null when unmapped or none is active */
  node: SaseNodeDTO | null;
}

function sanitizeRoutingMap(raw: RoutingMap): RoutingMap {
  const out: RoutingMap = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const [email, entry] of Object.entries(raw)) {
    if (entry && typeof entry === "object" && typeof (entry as RoutingMap[string])?.region === "string") {
      out[email] = { region: (entry as RoutingMap[string]).region, updatedAt: String((entry as RoutingMap[string]).updatedAt ?? "") };
    }
  }
  return out;
}

async function getRoutingMap(tenantId: number): Promise<RoutingMap> {
  const raw = await getSetting<RoutingMap>(tenantId, SASE_SETTINGS_CATEGORY, IDENTITY_ROUTING_KEY, {});
  return sanitizeRoutingMap(raw);
}

async function putRoutingMap(tenantId: number, map: RoutingMap): Promise<void> {
  await putSettingsBatch(tenantId, [
    // The M10 settings category enum predates the sase category (the DB
    // column is a plain string and putSettingsBatch applies no per-key
    // runtime schema) — this cast keeps ONE settings write path instead of
    // a parallel helper.
    { category: SASE_SETTINGS_CATEGORY, key: IDENTITY_ROUTING_KEY, value: map } as unknown as SettingsEntry,
  ]);
}

/** Active nodes as renderer shapes (pickNearestNode input). */
async function activeNodeShapes(tenantId: number): Promise<SaseNodeRow[]> {
  return db.saseNode.findMany({ where: { tenantId, status: "active" }, orderBy: { id: "asc" } });
}

function nodeDtoFor(rows: SaseNodeRow[], shape: SaseNodeShape | null): SaseNodeDTO | null {
  if (!shape) return null;
  const row = rows.find((r) => r.id === shape.id);
  return row ? toNodeDTO(row) : null;
}

/** Upsert one user → region mapping (email normalized lowercase). */
export async function identityRoutingUpsert(
  tenantId: number,
  input: SaseRoutingUpsert,
): Promise<SaseRoutingEntry> {
  const map = await getRoutingMap(tenantId);
  const email = input.userEmail.trim().toLowerCase();
  map[email] = { region: input.region.trim(), updatedAt: new Date().toISOString() };
  await putRoutingMap(tenantId, map);

  const rows = await activeNodeShapes(tenantId);
  const nearest = pickNearestNode(
    rows.map(toNodeShape),
    input.region,
  );
  return {
    userEmail: email,
    region: input.region.trim(),
    updatedAt: map[email].updatedAt,
    resolvedNode: nodeDtoFor(rows, nearest),
  };
}

/** The full map, sorted by email, each entry enriched with its resolved node. */
export async function identityRoutingList(tenantId: number): Promise<SaseRoutingEntry[]> {
  const [map, rows] = await Promise.all([getRoutingMap(tenantId), activeNodeShapes(tenantId)]);
  const shapes = rows.map(toNodeShape);
  return Object.entries(map)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([email, entry]) => ({
      userEmail: email,
      region: entry.region,
      updatedAt: entry.updatedAt,
      resolvedNode: nodeDtoFor(rows, pickNearestNode(shapes, entry.region)),
    }));
}

/**
 * Resolve one user to their nearest node (identity-aware routing stub):
 * mapped region → same-region gateway, else same-region active, else first
 * active anywhere, else null. Unknown users resolve to null (no mapping).
 */
export async function resolveNode(tenantId: number, input: SaseResolve): Promise<SaseResolveResult> {
  const email = input.userEmail.trim().toLowerCase();
  const [map, rows] = await Promise.all([getRoutingMap(tenantId), activeNodeShapes(tenantId)]);
  const entry = map[email];
  if (!entry) return { userEmail: email, region: null, node: null };
  const nearest = pickNearestNode(rows.map(toNodeShape), entry.region);
  return { userEmail: email, region: entry.region, node: nodeDtoFor(rows, nearest) };
}

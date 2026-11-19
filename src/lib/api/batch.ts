/**
 * Batch operations engine (spec §1.15) — executes a whitelisted sequence of
 * resource mutations IN-PROCESS by calling the same server-side service
 * functions the REST routes use (rule-service, nat-service, refs, positions,
 * shapes) — never an internal HTTP fetch.
 *
 * Contract:
 *   • whitelisted resource paths ONLY (unknown path → per-op error, no crash),
 *   • sequential execution, stop-on-first-error (later ops are not attempted
 *     and produce no result entry),
 *   • RBAC checked per operation via the path → capability-area map
 *     (batch POST/PUT/DELETE are all "write" operations),
 *   • per-op bodies validated against the SAME zod schemas the routes use.
 *
 * The route file (app/api/v1/batch/route.ts) owns auth/rate-limit/envelope and
 * the single `batch.execute` audit entry; this module never audits and never
 * snapshots config versions.
 */

import { z, type ZodType } from "zod";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { can, type AuthContext, type CapabilityArea } from "@/lib/auth/rbac";
import { BATCH_MAX_OPERATIONS, type BatchOperation } from "@/lib/validators/batch";
import { createRule, updateRule, type FirewallRuleBody } from "@/lib/firewall/rule-service";
import { createNatRule, updateNatRule, createOneToOnePair, type NatRuleBody } from "@/lib/firewall/nat-service";
import {
  addressObjectReferences,
  addressGroupReferences,
  assertNewIdsValid,
  findEmptyGroupReferences,
  scheduleReferences,
  serviceObjectReferences,
  serviceGroupReferences,
} from "@/lib/firewall/refs";
import { renumberFirewallRules, renumberNatRules } from "@/lib/firewall/positions";
import {
  shapeAddressObject,
  shapeNamedWithMembers,
  shapeScheduleObject,
  shapeServiceObject,
} from "@/lib/firewall/shapes";
import { shapeFirewallRule, shapeNatRule } from "@/lib/firewall/rule-shape";
import {
  addressGroupBodySchema,
  addressObjectBodySchema,
  firewallRuleBodySchema,
  idParamSchema,
  natPostBodySchema,
  natRuleBodySchema,
  scheduleObjectBodySchema,
  serviceGroupBodySchema,
  serviceObjectBodySchema,
} from "@/lib/validators/firewall";

// ── op result / outcome shapes (the batch response envelope data) ───────────

export interface BatchOpResult {
  index: number;
  path: string;
  method: string;
  ok: boolean;
  status: number;
  data?: unknown;
  error?: string;
}

export interface BatchOutcome {
  results: BatchOpResult[];
  ok: boolean;
  /** Operations that EXECUTED SUCCESSFULLY (denied/failed ops excluded —
   *  F-e #9: the route gates the config-version snapshot on executed > 0,
   *  and `denied` audit results key off executed === 0). */
  executed: number;
  failed: number;
}

// ── whitelisted resources + path → area mapping ─────────────────────────────

export type BatchResource =
  | "address-objects"
  | "service-objects"
  | "schedule-objects"
  | "firewall-rules"
  | "nat-rules"
  | "address-groups"
  | "service-groups";

/** RBAC map: every whitelisted resource family → its capability area. */
export const BATCH_RESOURCE_AREAS: Record<BatchResource, CapabilityArea> = {
  "address-objects": "firewall",
  "service-objects": "firewall",
  "schedule-objects": "firewall",
  "firewall-rules": "firewall",
  "nat-rules": "firewall",
  "address-groups": "firewall",
  "service-groups": "firewall",
};

const RESOURCE_NAMES = new Set<string>(Object.keys(BATCH_RESOURCE_AREAS));

/** Parse a whitelist path — "/resource" or "/resource/{numeric id}". Null ⇒ not whitelisted. */
export function parseBatchPath(path: string): { resource: BatchResource; id: number | null } | null {
  if (path.includes("?") || path.includes("#")) return null;
  const segs = path.split("/").filter(Boolean);
  if (segs.length === 1 && RESOURCE_NAMES.has(segs[0])) return { resource: segs[0] as BatchResource, id: null };
  if (segs.length === 2 && RESOURCE_NAMES.has(segs[0]) && /^\d+$/.test(segs[1])) {
    return { resource: segs[0] as BatchResource, id: Number(segs[1]) };
  }
  return null;
}

/** Path → RBAC capability area (null when the path is not batch-whitelisted). */
export function pathToArea(path: string): CapabilityArea | null {
  const parsed = parseBatchPath(path);
  return parsed ? BATCH_RESOURCE_AREAS[parsed.resource] : null;
}

// ── per-resource executors — mirror the route handlers 1:1 ──────────────────

type AddressObjectBody = z.infer<typeof addressObjectBodySchema>;
type ServiceObjectBody = z.infer<typeof serviceObjectBodySchema>;
type ScheduleObjectBody = z.infer<typeof scheduleObjectBodySchema>;
type AddressGroupBody = z.infer<typeof addressGroupBodySchema>;
type ServiceGroupBody = z.infer<typeof serviceGroupBodySchema>;
type NatPostBody = z.infer<typeof natPostBodySchema>;

async function createAddressObject(tenantId: number, body: AddressObjectBody): Promise<unknown> {
  const dup = await db.addressObject.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`Address object '${body.name}' already exists`);
  // duplicate-value awareness (non-blocking) — same semantics as the REST route
  const valueDup = await db.addressObject.findFirst({
    where: { tenantId, type: body.type, value: body.value.trim() },
    select: { id: true, name: true },
  });
  const row = await db.addressObject.create({
    data: {
      tenantId,
      name: body.name,
      type: body.type,
      value: body.value.trim(),
      description: body.description ?? null,
    },
  });
  return { ...shapeAddressObject(row), duplicateOf: valueDup };
}

async function updateAddressObject(tenantId: number, id: number, body: AddressObjectBody): Promise<unknown> {
  const row = await db.addressObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Address object ${id} not found`);
  if (body.name !== row.name) {
    const dup = await db.addressObject.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Address object '${body.name}' already exists`);
  }
  const valueDup = await db.addressObject.findFirst({
    where: { tenantId, type: body.type, value: body.value.trim(), id: { not: row.id } },
    select: { id: true, name: true },
  });
  const updated = await db.addressObject.update({
    where: { id: row.id },
    data: { name: body.name, type: body.type, value: body.value.trim(), description: body.description ?? null },
  });
  return { ...shapeAddressObject(updated), duplicateOf: valueDup };
}

async function deleteAddressObject(tenantId: number, id: number): Promise<unknown> {
  const row = await db.addressObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Address object ${id} not found`);
  const refs = await addressObjectReferences(tenantId, row.id);
  if (refs.length) {
    throw ApiError.conflict(`Address object '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.addressObject.delete({ where: { id: row.id } });
  return { ok: true };
}

async function createServiceObject(tenantId: number, body: ServiceObjectBody): Promise<unknown> {
  const dup = await db.serviceObject.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`Service object '${body.name}' already exists`);
  const row = await db.serviceObject.create({
    data: {
      tenantId,
      name: body.name,
      protocol: body.protocol,
      srcPort: body.srcPort ?? null,
      dstPort: body.dstPort ?? null,
      icmpType: body.icmpType ?? null,
      icmpCode: body.icmpCode ?? null,
      description: body.description ?? null,
    },
  });
  return shapeServiceObject(row);
}

async function updateServiceObject(tenantId: number, id: number, body: ServiceObjectBody): Promise<unknown> {
  const row = await db.serviceObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Service object ${id} not found`);
  if (body.name !== row.name) {
    const dup = await db.serviceObject.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Service object '${body.name}' already exists`);
  }
  const updated = await db.serviceObject.update({
    where: { id: row.id },
    data: {
      name: body.name,
      protocol: body.protocol,
      srcPort: body.srcPort ?? null,
      dstPort: body.dstPort ?? null,
      icmpType: body.icmpType ?? null,
      icmpCode: body.icmpCode ?? null,
      description: body.description ?? null,
    },
  });
  return shapeServiceObject(updated);
}

async function deleteServiceObject(tenantId: number, id: number): Promise<unknown> {
  const row = await db.serviceObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Service object ${id} not found`);
  const refs = await serviceObjectReferences(tenantId, row.id);
  if (refs.length) {
    throw ApiError.conflict(`Service object '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.serviceObject.delete({ where: { id: row.id } });
  return { ok: true };
}

async function createScheduleObject(tenantId: number, body: ScheduleObjectBody): Promise<unknown> {
  const dup = await db.scheduleObject.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`Schedule object '${body.name}' already exists`);
  const row = await db.scheduleObject.create({
    data: {
      tenantId,
      name: body.name,
      type: body.type,
      recurrence: body.recurrence ? JSON.stringify(body.recurrence) : null,
      startsAt: body.startsAt ? new Date(body.startsAt) : null,
      endsAt: body.endsAt ? new Date(body.endsAt) : null,
      timezone: body.timezone,
    },
  });
  return shapeScheduleObject(row);
}

async function updateScheduleObject(tenantId: number, id: number, body: ScheduleObjectBody): Promise<unknown> {
  const row = await db.scheduleObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Schedule object ${id} not found`);
  if (body.name !== row.name) {
    const dup = await db.scheduleObject.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Schedule object '${body.name}' already exists`);
  }
  const updated = await db.scheduleObject.update({
    where: { id: row.id },
    data: {
      name: body.name,
      type: body.type,
      recurrence: body.recurrence ? JSON.stringify(body.recurrence) : null,
      startsAt: body.startsAt ? new Date(body.startsAt) : null,
      endsAt: body.endsAt ? new Date(body.endsAt) : null,
      timezone: body.timezone,
    },
  });
  return shapeScheduleObject(updated);
}

async function deleteScheduleObject(tenantId: number, id: number): Promise<unknown> {
  const row = await db.scheduleObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Schedule object ${id} not found`);
  const refs = await scheduleReferences(tenantId, row.id);
  if (refs.length) {
    throw ApiError.conflict(`Schedule '${row.name}' is attached to ${refs.length} rule(s) — detach them first`, {
      referencedBy: refs,
    });
  }
  await db.scheduleObject.delete({ where: { id: row.id } });
  return { ok: true };
}

async function createAddressGroup(tenantId: number, body: AddressGroupBody): Promise<unknown> {
  const dup = await db.addressGroup.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`Address group '${body.name}' already exists`);
  if (body.memberIds.length) {
    const found = await db.addressObject.count({ where: { tenantId, id: { in: body.memberIds } } });
    if (found < body.memberIds.length) {
      const all = await db.addressObject.findMany({ where: { tenantId }, select: { id: true } });
      const known = new Set(all.map((a) => a.id));
      throw ApiError.validation("Unknown member id in memberIds", {
        offendingIds: body.memberIds.filter((m) => !known.has(m)),
      });
    }
  }
  const row = await db.addressGroup.create({
    data: { tenantId, name: body.name, memberIds: JSON.stringify(body.memberIds), description: body.description ?? null },
  });
  return shapeNamedWithMembers(row);
}

async function updateAddressGroup(tenantId: number, id: number, body: AddressGroupBody): Promise<unknown> {
  const row = await db.addressGroup.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Address group ${id} not found`);
  if (body.name !== row.name) {
    const dup = await db.addressGroup.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Address group '${body.name}' already exists`);
  }
  if (body.memberIds.length) {
    const found = await db.addressObject.count({ where: { tenantId, id: { in: body.memberIds } } });
    if (found < body.memberIds.length) {
      const all = await db.addressObject.findMany({ where: { tenantId }, select: { id: true } });
      const known = new Set(all.map((a) => a.id));
      throw ApiError.validation("Unknown member id in memberIds", {
        offendingIds: body.memberIds.filter((m) => !known.has(m)),
      });
    }
  }
  const updated = await db.addressGroup.update({
    where: { id: row.id },
    data: { name: body.name, memberIds: JSON.stringify(body.memberIds), description: body.description ?? null },
  });
  return shapeNamedWithMembers(updated);
}

async function deleteAddressGroup(tenantId: number, id: number): Promise<unknown> {
  const row = await db.addressGroup.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Address group ${id} not found`);
  const refs = await addressGroupReferences(tenantId, row.id);
  if (refs.length) {
    throw ApiError.conflict(`Address group '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.addressGroup.delete({ where: { id: row.id } });
  return { ok: true };
}

async function createServiceGroup(tenantId: number, body: ServiceGroupBody): Promise<unknown> {
  const dup = await db.serviceGroup.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`Service group '${body.name}' already exists`);
  await assertServiceGroupMembers(tenantId, body.memberIds);
  const row = await db.serviceGroup.create({
    data: { tenantId, name: body.name, memberIds: JSON.stringify(body.memberIds), description: body.description ?? null },
  });
  return shapeNamedWithMembers(row);
}

async function updateServiceGroup(tenantId: number, id: number, body: ServiceGroupBody): Promise<unknown> {
  const row = await db.serviceGroup.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Service group ${id} not found`);
  if (body.name !== row.name) {
    const dup = await db.serviceGroup.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Service group '${body.name}' already exists`);
  }
  await assertServiceGroupMembers(tenantId, body.memberIds);
  const updated = await db.serviceGroup.update({
    where: { id: row.id },
    data: { name: body.name, memberIds: JSON.stringify(body.memberIds), description: body.description ?? null },
  });
  return shapeNamedWithMembers(updated);
}

async function assertServiceGroupMembers(tenantId: number, memberIds: number[]): Promise<void> {
  if (!memberIds.length) return;
  const found = await db.serviceObject.count({ where: { tenantId, id: { in: memberIds } } });
  if (found < memberIds.length) {
    const all = await db.serviceObject.findMany({ where: { tenantId }, select: { id: true } });
    const known = new Set(all.map((s) => s.id));
    throw ApiError.validation("Unknown member id in memberIds", {
      offendingIds: memberIds.filter((m) => !known.has(m)),
    });
  }
}

async function deleteServiceGroup(tenantId: number, id: number): Promise<unknown> {
  const row = await db.serviceGroup.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Service group ${id} not found`);
  const refs = await serviceGroupReferences(tenantId, row.id);
  if (refs.length) {
    throw ApiError.conflict(`Service group '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.serviceGroup.delete({ where: { id: row.id } });
  return { ok: true };
}

async function createFirewallRule(tenantId: number, body: FirewallRuleBody): Promise<unknown> {
  const created = await createRule(tenantId, body);
  return shapeFirewallRule(await db.firewallRule.findUniqueOrThrow({ where: { id: created.id } }));
}

async function updateFirewallRule(tenantId: number, id: number, body: FirewallRuleBody): Promise<unknown> {
  const before = await db.firewallRule.findFirst({ where: { id, tenantId } });
  if (!before) throw ApiError.notFound(`Firewall rule ${id} not found`);
  await updateRule(tenantId, id, body);
  return shapeFirewallRule(await db.firewallRule.findUniqueOrThrow({ where: { id } }));
}

async function deleteFirewallRule(tenantId: number, id: number): Promise<unknown> {
  const row = await db.firewallRule.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Firewall rule ${id} not found`);
  await db.$transaction(async (tx) => {
    await tx.firewallRule.delete({ where: { id: row.id } });
    await renumberFirewallRules(tx as unknown as Parameters<typeof renumberFirewallRules>[0], tenantId);
  });
  return { ok: true };
}

async function createNat(tenantId: number, body: NatPostBody): Promise<unknown> {
  if ("oneToOne" in body) {
    const pair = await createOneToOnePair(tenantId, body.oneToOne);
    const [dnat, snat] = await Promise.all([
      db.natRule.findUniqueOrThrow({ where: { id: pair.dnatId } }),
      db.natRule.findUniqueOrThrow({ where: { id: pair.snatId } }),
    ]);
    return { dnat: shapeNatRule(dnat), snat: shapeNatRule(snat) };
  }
  const idCheck = await assertNewIdsValid(tenantId, {
    srcZoneIds: [],
    dstZoneIds: [],
    srcAddrIds: body.srcAddrIds,
    dstAddrIds: body.dstAddrIds,
    serviceIds: body.serviceIds,
    userIds: [],
    scheduleId: null,
    ipsPolicyId: null,
    qosPolicyId: null,
  });
  if (!idCheck.ok) throw ApiError.validation(idCheck.message, idCheck.details);
  const emptyGroups = await findEmptyGroupReferences(tenantId, body);
  if (emptyGroups.length > 0) {
    throw ApiError.validation(
      `NAT rule references empty group(s): ${emptyGroups.map((g) => `'${g.groupName}' (${g.kind})`).join(", ")} — add members first`,
      { emptyGroups },
    );
  }
  const created = await createNatRule(tenantId, body);
  return shapeNatRule(await db.natRule.findUniqueOrThrow({ where: { id: created.id } }));
}

async function updateNat(tenantId: number, id: number, body: NatRuleBody): Promise<unknown> {
  const before = await db.natRule.findFirst({ where: { id, tenantId } });
  if (!before) throw ApiError.notFound(`NAT rule ${id} not found`);
  const idCheck = await assertNewIdsValid(tenantId, {
    srcZoneIds: [],
    dstZoneIds: [],
    srcAddrIds: body.srcAddrIds,
    dstAddrIds: body.dstAddrIds,
    serviceIds: body.serviceIds,
    userIds: [],
    scheduleId: null,
    ipsPolicyId: null,
    qosPolicyId: null,
  });
  if (!idCheck.ok) throw ApiError.validation(idCheck.message, idCheck.details);
  const emptyGroups = await findEmptyGroupReferences(tenantId, body);
  if (emptyGroups.length > 0) {
    throw ApiError.validation(
      `NAT rule references empty group(s): ${emptyGroups.map((g) => `'${g.groupName}' (${g.kind})`).join(", ")} — add members first`,
      { emptyGroups },
    );
  }
  await updateNatRule(tenantId, id, body);
  return shapeNatRule(await db.natRule.findUniqueOrThrow({ where: { id } }));
}

async function deleteNat(tenantId: number, id: number): Promise<unknown> {
  const row = await db.natRule.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`NAT rule ${id} not found`);
  await db.$transaction(async (tx) => {
    await tx.natRule.delete({ where: { id: row.id } });
    await renumberNatRules(tx as unknown as Parameters<typeof renumberNatRules>[0], tenantId);
  });
  return { ok: true };
}

interface ResourceDef {
  area: CapabilityArea;
  postSchema?: ZodType;
  putSchema?: ZodType;
  post?: (tenantId: number, body: never) => Promise<unknown>;
  put?: (tenantId: number, id: number, body: never) => Promise<unknown>;
  del?: (tenantId: number, id: number) => Promise<unknown>;
}

const RESOURCES: Record<BatchResource, ResourceDef> = {
  "address-objects": {
    area: BATCH_RESOURCE_AREAS["address-objects"],
    postSchema: addressObjectBodySchema,
    putSchema: addressObjectBodySchema,
    post: createAddressObject,
    put: updateAddressObject,
    del: deleteAddressObject,
  },
  "service-objects": {
    area: BATCH_RESOURCE_AREAS["service-objects"],
    postSchema: serviceObjectBodySchema,
    putSchema: serviceObjectBodySchema,
    post: createServiceObject,
    put: updateServiceObject,
    del: deleteServiceObject,
  },
  "schedule-objects": {
    area: BATCH_RESOURCE_AREAS["schedule-objects"],
    postSchema: scheduleObjectBodySchema,
    putSchema: scheduleObjectBodySchema,
    post: createScheduleObject,
    put: updateScheduleObject,
    del: deleteScheduleObject,
  },
  "firewall-rules": {
    area: BATCH_RESOURCE_AREAS["firewall-rules"],
    postSchema: firewallRuleBodySchema,
    putSchema: firewallRuleBodySchema,
    post: createFirewallRule,
    put: updateFirewallRule,
    del: deleteFirewallRule,
  },
  "nat-rules": {
    area: BATCH_RESOURCE_AREAS["nat-rules"],
    postSchema: natPostBodySchema,
    putSchema: natRuleBodySchema,
    post: createNat,
    put: updateNat,
    del: deleteNat,
  },
  "address-groups": {
    area: BATCH_RESOURCE_AREAS["address-groups"],
    postSchema: addressGroupBodySchema,
    putSchema: addressGroupBodySchema,
    post: createAddressGroup,
    put: updateAddressGroup,
    del: deleteAddressGroup,
  },
  "service-groups": {
    area: BATCH_RESOURCE_AREAS["service-groups"],
    postSchema: serviceGroupBodySchema,
    putSchema: serviceGroupBodySchema,
    post: createServiceGroup,
    put: updateServiceGroup,
    del: deleteServiceGroup,
  },
};

// ── batch execution ─────────────────────────────────────────────────────────

/**
 * Run a validated batch: sequential, stop-on-first-error. Never throws —
 * failures surface as per-op results (ok=false + status + error). Unexpected
 * (non-ApiError/non-Zod) errors are MASKED in the per-op result (F-e #8) and
 * logged server-side with the requestId for correlation.
 */
export async function executeBatchOperations(
  auth: AuthContext,
  ops: BatchOperation[],
  requestId?: string,
): Promise<BatchOutcome> {
  if (ops.length > BATCH_MAX_OPERATIONS) {
    throw ApiError.validation(`Batch exceeds the ${BATCH_MAX_OPERATIONS}-operation cap`);
  }

  const results: BatchOpResult[] = [];
  for (let i = 0; i < ops.length; i++) {
    const op = ops[i];
    const entry: BatchOpResult = { index: i, path: op.path, method: op.method, ok: false, status: 500 };
    try {
      const parsed = parseBatchPath(op.path);
      if (!parsed) {
        throw ApiError.validation(
          `Path '${op.path}' is not batch-whitelisted — allowed: ${Object.keys(BATCH_RESOURCE_AREAS).join(", ")}`,
        );
      }
      const def = RESOURCES[parsed.resource];

      // RBAC — per-operation area; batch mutations are write operations
      if (!can(auth, def.area, "write")) {
        throw ApiError.forbidden(`Role '${auth.role}' may not write ${def.area.replace(/_/g, " ")}`);
      }

      if (op.method === "POST") {
        if (!def.post || !def.postSchema) throw ApiError.validation(`POST is not supported for ${parsed.resource}`);
        const body = def.postSchema.parse(op.body ?? {}) as never;
        entry.data = await def.post(auth.tenantId, body);
      } else if (op.method === "PUT") {
        if (parsed.id == null) throw ApiError.validation(`PUT ${op.path} requires a resource id`);
        if (!def.put || !def.putSchema) throw ApiError.validation(`PUT is not supported for ${parsed.resource}`);
        const id = idParamSchema.parse({ id: parsed.id }).id;
        const body = def.putSchema.parse(op.body ?? {}) as never;
        entry.data = await def.put(auth.tenantId, id, body);
      } else {
        if (parsed.id == null) throw ApiError.validation(`DELETE ${op.path} requires a resource id`);
        if (!def.del) throw ApiError.validation(`DELETE is not supported for ${parsed.resource}`);
        const id = idParamSchema.parse({ id: parsed.id }).id;
        entry.data = await def.del(auth.tenantId, id);
      }

      entry.ok = true;
      entry.status = 200;
    } catch (err) {
      if (err instanceof ApiError) {
        entry.status = err.status;
        entry.error = err.message;
      } else if (err instanceof z.ZodError) {
        entry.status = 400;
        entry.error = "Operation body failed validation";
      } else {
        // F-e #8: unexpected errors never leak internals into the API response
        entry.status = 500;
        entry.error = "Internal error during batch operation";
        console.error(
          `[batch] ${requestId ?? "-"} op ${i} (${op.method} ${op.path}) unexpected error:`,
          err instanceof Error ? err.stack ?? err.message : err,
        );
      }
      results.push(entry);
      break; // stop-on-first-error
    }
    results.push(entry);
  }

  const failed = results.filter((r) => !r.ok).length;
  // F-e #9: `executed` counts SUCCESSFUL operations only — a batch whose ops
  // were denied/failed has executed === 0 so the route skips the config-version
  // snapshot + config:updated broadcast.
  return { results, ok: failed === 0, executed: results.length - failed, failed };
}

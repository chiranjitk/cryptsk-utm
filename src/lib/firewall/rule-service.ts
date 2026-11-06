/**
 * Rule service — create/update/reorder/import logic shared by the
 * firewall-rules routes (keeps route files thin; API_STANDARDS §3).
 */

import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { canonicalAppLabel } from "./app-catalog";
import { assertNewIdsValid } from "./refs";
import { renumberFirewallRules } from "./positions";

export type FirewallRuleBody = {
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
  action: string;
  logging: string;
  connLimit?: number | null;
  rateLimit?: number | null;
  synProtection: boolean;
  synThreshold?: number | null;
  ipsPolicyId?: number | null;
  qosPolicyId?: number | null;
  tags: string[];
  comment?: string | null;
};

export function normalizeAppLabels(labels: string[]): string[] {
  const out: string[] = [];
  for (const label of labels) {
    const canonical = canonicalAppLabel(label);
    if (!canonical) throw ApiError.validation(`Unknown application label '${label}'`, { offendingLabels: [label] });
    if (!out.includes(canonical)) out.push(canonical);
  }
  return out;
}

async function assertRuleIdsValid(tenantId: number, body: FirewallRuleBody): Promise<void> {
  const check = await assertNewIdsValid(tenantId, body);
  if (!check.ok) throw ApiError.validation(check.message, check.details);
  const normalized = normalizeAppLabels(body.applicationIds);
  body.applicationIds = normalized;
}

export async function createRule(tenantId: number, body: FirewallRuleBody): Promise<{ id: number; name: string; position: number }> {
  await assertRuleIdsValid(tenantId, body);

  const dup = await db.firewallRule.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`Firewall rule '${body.name}' already exists`);

  const max = await db.firewallRule.aggregate({ where: { tenantId }, _max: { position: true } });
  const appendPos = (max._max.position ?? 0) + 1;
  const desired = body.position ? Math.min(body.position, appendPos) : appendPos;

  const created = await db.$transaction(async (tx) => {
    if (desired < appendPos) {
      await tx.firewallRule.updateMany({
        where: { tenantId, position: { gte: desired } },
        data: { position: { increment: 1 } },
      });
    }
    return tx.firewallRule.create({
      data: {
        tenantId,
        name: body.name,
        description: body.description ?? null,
        enabled: body.enabled,
        position: desired,
        srcZoneIds: JSON.stringify(body.srcZoneIds),
        dstZoneIds: JSON.stringify(body.dstZoneIds),
        srcAddrIds: JSON.stringify(body.srcAddrIds),
        dstAddrIds: JSON.stringify(body.dstAddrIds),
        serviceIds: JSON.stringify(body.serviceIds),
        applicationIds: JSON.stringify(body.applicationIds),
        userIds: JSON.stringify(body.userIds),
        srcMacs: JSON.stringify(body.srcMacs),
        scheduleId: body.scheduleId ?? null,
        action: body.action,
        logging: body.logging,
        connLimit: body.connLimit ?? null,
        rateLimit: body.rateLimit ?? null,
        synProtection: body.synProtection,
        synThreshold: body.synThreshold ?? null,
        ipsPolicyId: body.ipsPolicyId ?? null,
        qosPolicyId: body.qosPolicyId ?? null,
        tags: JSON.stringify(body.tags),
        comment: body.comment ?? null,
      },
      select: { id: true, name: true, position: true },
    });
  });
  return created;
}

export async function updateRule(tenantId: number, id: number, body: FirewallRuleBody): Promise<{ id: number; name: string }> {
  await assertRuleIdsValid(tenantId, body);

  const existing = await db.firewallRule.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound(`Firewall rule ${id} not found`);

  if (body.name !== existing.name) {
    const dup = await db.firewallRule.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Firewall rule '${body.name}' already exists`);
  }

  // explicit placement goes through /reorder — PUT keeps the rule in place
  const desired = existing.position;

  await db.$transaction(async (tx) => {
    await tx.firewallRule.update({
      where: { id: existing.id },
      data: {
        name: body.name,
        description: body.description ?? null,
        enabled: body.enabled,
        position: desired,
        srcZoneIds: JSON.stringify(body.srcZoneIds),
        dstZoneIds: JSON.stringify(body.dstZoneIds),
        srcAddrIds: JSON.stringify(body.srcAddrIds),
        dstAddrIds: JSON.stringify(body.dstAddrIds),
        serviceIds: JSON.stringify(body.serviceIds),
        applicationIds: JSON.stringify(body.applicationIds),
        userIds: JSON.stringify(body.userIds),
        srcMacs: JSON.stringify(body.srcMacs),
        scheduleId: body.scheduleId ?? null,
        action: body.action,
        logging: body.logging,
        connLimit: body.connLimit ?? null,
        rateLimit: body.rateLimit ?? null,
        synProtection: body.synProtection,
        synThreshold: body.synThreshold ?? null,
        ipsPolicyId: body.ipsPolicyId ?? null,
        qosPolicyId: body.qosPolicyId ?? null,
        tags: JSON.stringify(body.tags),
        comment: body.comment ?? null,
      },
    });
    await renumberFirewallRules(tx as unknown as Parameters<typeof renumberFirewallRules>[0], tenantId);
  });
  return { id: existing.id, name: body.name };
}

export async function reorderRules(tenantId: number, orderedIds: number[]): Promise<void> {
  const all = await db.firewallRule.findMany({ where: { tenantId }, select: { id: true } });
  const known = new Set(all.map((r) => r.id));
  const seen = new Set<number>();
  for (const id of orderedIds) {
    if (!known.has(id)) {
      throw ApiError.validation(`orderedIds contains unknown rule id ${id}`, { offendingIds: [id] });
    }
    if (seen.has(id)) {
      throw ApiError.validation(`orderedIds contains duplicate id ${id}`, { duplicateIds: [id] });
    }
    seen.add(id);
  }
  const missing = all.filter((r) => !seen.has(r.id)).map((r) => r.id);
  if (missing.length) {
    throw ApiError.validation("orderedIds must be a permutation of all tenant rule ids", { missingIds: missing });
  }
  await db.$transaction(async (tx) => {
    await renumberFirewallRules(tx as unknown as Parameters<typeof renumberFirewallRules>[0], tenantId, orderedIds);
  });
}

/** Import — all-or-nothing; row errors abort the whole batch. */
export async function importRules(
  tenantId: number,
  bodies: FirewallRuleBody[],
): Promise<Array<{ id: number; name: string; position: number }>> {
  const names = new Set<string>();
  for (const b of bodies) {
    if (names.has(b.name)) throw ApiError.validation(`Duplicate rule name '${b.name}' inside the import batch`);
    names.add(b.name);
    const dup = await db.firewallRule.findFirst({ where: { tenantId, name: b.name } });
    if (dup) throw ApiError.validation(`Firewall rule '${b.name}' already exists`);
  }

  const created = await db.$transaction(async (tx) => {
    const out: Array<{ id: number; name: string; position: number; desired: number | null }> = [];
    for (const body of bodies) {
      await assertRuleIdsValid(tenantId, body);
      const row = await tx.firewallRule.create({
        data: {
          tenantId,
          name: body.name,
          description: body.description ?? null,
          enabled: body.enabled,
          position: 0,
          srcZoneIds: JSON.stringify(body.srcZoneIds),
          dstZoneIds: JSON.stringify(body.dstZoneIds),
          srcAddrIds: JSON.stringify(body.srcAddrIds),
          dstAddrIds: JSON.stringify(body.dstAddrIds),
          serviceIds: JSON.stringify(body.serviceIds),
          applicationIds: JSON.stringify(body.applicationIds),
          userIds: JSON.stringify(body.userIds),
          srcMacs: JSON.stringify(body.srcMacs),
          scheduleId: body.scheduleId ?? null,
          action: body.action,
          logging: body.logging,
          connLimit: body.connLimit ?? null,
          rateLimit: body.rateLimit ?? null,
          synProtection: body.synProtection,
          synThreshold: body.synThreshold ?? null,
          ipsPolicyId: body.ipsPolicyId ?? null,
          qosPolicyId: body.qosPolicyId ?? null,
          tags: JSON.stringify(body.tags),
          comment: body.comment ?? null,
        },
        select: { id: true, name: true, position: true },
      });
      out.push({ ...row, desired: body.position ?? null });
    }
    // dense renumber honoring requested positions (stable by import order)
    const sorted = [...out].sort((a, b) => (a.desired ?? Number.MAX_SAFE_INTEGER) - (b.desired ?? Number.MAX_SAFE_INTEGER));
    let p = 1;
    for (const r of sorted) {
      await tx.firewallRule.update({ where: { id: r.id }, data: { position: p++ } });
    }
    return out.map(({ id, name }) => ({ id, name }));
  });
  return created;
}

/**
 * QoS service (M08) — shaper policies + per-policy rules.
 * Per M08-QOS.md §2/§3/§5 and SCHEMA.md §3. Policies carry the total
 * bandwidthKbps budget and an optional ifaceName attachment (logical ref into
 * interfaces.name); rules classify traffic into priority classes with
 * guaranteed/max rates, DSCP marks and app/user/address matchers (JSON-string
 * columns parsed per column — PROJECT_MEMORY §13).
 *
 * Business checks (M08 §5): guaranteed ≤ max, sum(guaranteed) ≤ budget,
 * bandwidthKbps ≥ 1000, matcher ids exist in-tenant, one catch-all rule per
 * policy, one enabled policy per iface, delete RESTRICT-ed by firewall rules.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { canonicalAppLabel } from "@/lib/firewall/app-catalog";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { QOS_TEMPLATES, type QosTemplateName } from "./templates";
import type {
  QosPolicyCreate,
  QosPolicyUpdate,
  QosRuleCreate,
  QosRuleUpdate,
} from "@/lib/validators/qos";

// ── DTOs ────────────────────────────────────────────────────────────────────

export type QosPolicyDTO = {
  id: number;
  name: string;
  enabled: boolean;
  template: string | null;
  bandwidthKbps: number;
  ifaceName: string | null;
  /** per-policy rule count (M08 §3 list contract) */
  ruleCount: number;
  /** attachment state: iface exists in-tenant + its enabled flag (null when detached) */
  ifaceAttached: boolean;
  ifaceEnabled: boolean | null;
  /** sum of guaranteedKbps across the policy's rules — budget usage for the UI */
  guaranteedSumKbps: number;
};

export type QosRuleDTO = {
  id: number;
  policyId: number;
  name: string;
  priority: number;
  guaranteedKbps: number | null;
  maxKbps: number | null;
  dscpMark: number | null;
  matchApps: string[];
  matchUsers: string[];
  matchAddresses: string[];
  /** per-user/per-app hard limit class (M08 §5.2 / spec §1.11) */
  hardLimit: boolean;
};

const fieldErr = (field: string, message: string) =>
  ApiError.validation(message, { fieldErrors: { [field]: [message] } });

function isHardLimit(
  matchApps: string[],
  matchUsers: string[],
  matchAddresses: string[],
  guaranteedKbps: number | null,
  maxKbps: number | null,
): boolean {
  if (matchAddresses.length > 0) return false;
  if (guaranteedKbps != null || maxKbps == null) return false;
  const dims = (matchUsers.length > 0 ? 1 : 0) + (matchApps.length > 0 ? 1 : 0);
  return dims === 1;
}

function toRuleDTO(row: {
  id: number;
  policyId: number;
  name: string;
  priority: number;
  guaranteedKbps: number | null;
  maxKbps: number | null;
  dscpMark: number | null;
  matchApps: string;
  matchUsers: string;
  matchAddresses: string;
}): QosRuleDTO {
  // parse each JSON column separately (PROJECT_MEMORY §13)
  const matchApps = parseJson<string[]>(row.matchApps, []).filter((a) => typeof a === "string");
  const matchUsers = parseJson<string[]>(row.matchUsers, []).filter((a) => typeof a === "string");
  const matchAddresses = parseJson<string[]>(row.matchAddresses, []).filter((a) => typeof a === "string");
  return {
    id: row.id,
    policyId: row.policyId,
    name: row.name,
    priority: row.priority,
    guaranteedKbps: row.guaranteedKbps,
    maxKbps: row.maxKbps,
    dscpMark: row.dscpMark,
    matchApps,
    matchUsers,
    matchAddresses,
    hardLimit: isHardLimit(matchApps, matchUsers, matchAddresses, row.guaranteedKbps, row.maxKbps),
  };
}

// ── policies ────────────────────────────────────────────────────────────────

function policyDTO(
  row: { id: number; name: string; enabled: boolean; template: string | null; bandwidthKbps: number; ifaceName: string | null },
  ifaces: Array<{ name: string; enabled: boolean }>,
  ruleCount: number,
  guaranteedSumKbps: number,
): QosPolicyDTO {
  const iface = row.ifaceName ? ifaces.find((i) => i.name === row.ifaceName) : undefined;
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    template: row.template,
    bandwidthKbps: row.bandwidthKbps,
    ifaceName: row.ifaceName,
    ruleCount,
    ifaceAttached: Boolean(iface),
    ifaceEnabled: iface ? iface.enabled : null,
    guaranteedSumKbps,
  };
}

async function policyExtras(tenantId: number, policyIds: number[]) {
  const [rules, ifaces] = await Promise.all([
    db.qosRule.findMany({
      where: { tenantId, policyId: { in: policyIds } },
      select: { policyId: true, guaranteedKbps: true },
    }),
    db.networkInterface.findMany({ where: { tenantId }, select: { name: true, enabled: true } }),
  ]);
  const counts = new Map<number, number>();
  const sums = new Map<number, number>();
  for (const r of rules) {
    counts.set(r.policyId, (counts.get(r.policyId) ?? 0) + 1);
    sums.set(r.policyId, (sums.get(r.policyId) ?? 0) + (r.guaranteedKbps ?? 0));
  }
  return { counts, sums, ifaces };
}

export async function listPolicies(tenantId: number): Promise<QosPolicyDTO[]> {
  const rows = await db.qosPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const { counts, sums, ifaces } = await policyExtras(tenantId, rows.map((r) => r.id));
  return rows.map((r) =>
    policyDTO(r, ifaces, counts.get(r.id) ?? 0, sums.get(r.id) ?? 0),
  );
}

/** One ENABLED policy per ifaceName (M08 §5.3) — 409 naming the claimant. */
async function assertIfaceFree(
  tenantId: number,
  ifaceName: string,
  excludeId?: number,
): Promise<void> {
  const claimant = await db.qosPolicy.findFirst({
    where: {
      tenantId,
      ifaceName,
      enabled: true,
      ...(excludeId ? { NOT: { id: excludeId } } : {}),
    },
    select: { id: true, name: true },
    orderBy: { id: "asc" },
  });
  if (claimant) {
    throw ApiError.conflict(
      `Interface ${ifaceName} is already shaped by enabled policy "${claimant.name}" (id ${claimant.id}) — disable it first or detach`,
      { conflicting: { id: claimant.id, name: claimant.name, ifaceName } },
    );
  }
}

async function assertIfaceExists(tenantId: number, ifaceName: string): Promise<void> {
  await assertIfacesExist(tenantId, [ifaceName]).catch(() => {
    throw fieldErr("ifaceName", `Interface "${ifaceName}" does not exist`);
  });
}

function seedRulesFor(template: string | null | undefined, bandwidthKbps: number) {
  const def = template ? QOS_TEMPLATES[template as QosTemplateName] : undefined;
  if (!def) return [];
  return def.rules.map((r) => ({
    name: r.name,
    priority: r.priority,
    guaranteedKbps: r.guaranteedPct == null ? null : Math.round((bandwidthKbps * r.guaranteedPct) / 100),
    maxKbps: r.maxPct == null ? null : Math.round((bandwidthKbps * r.maxPct) / 100),
    dscpMark: r.dscpMark,
    matchApps: r.matchApps,
  }));
}

export async function createPolicy(tenantId: number, body: QosPolicyCreate): Promise<QosPolicyDTO> {
  if (body.ifaceName) {
    await assertIfaceExists(tenantId, body.ifaceName);
    if (body.enabled) await assertIfaceFree(tenantId, body.ifaceName);
  }
  const dup = await db.qosPolicy.findFirst({ where: { tenantId, name: body.name }, select: { id: true } });
  if (dup) throw ApiError.conflict(`QoS policy '${body.name}' already exists`);

  const seeds = seedRulesFor(body.template, body.bandwidthKbps);
  const ifaces = await db.networkInterface.findMany({ where: { tenantId }, select: { name: true, enabled: true } });
  const row = await db.$transaction(async (tx) => {
    const created = await tx.qosPolicy.create({
      data: {
        tenantId,
        name: body.name,
        enabled: body.enabled,
        template: body.template ?? null,
        bandwidthKbps: body.bandwidthKbps,
        ifaceName: body.ifaceName || null,
      },
    });
    if (seeds.length > 0) {
      await tx.qosRule.createMany({
        data: seeds.map((s) => ({
          tenantId,
          policyId: created.id,
          name: s.name,
          priority: s.priority,
          guaranteedKbps: s.guaranteedKbps,
          maxKbps: s.maxKbps,
          dscpMark: s.dscpMark,
          matchApps: stringifyJson(s.matchApps),
          matchUsers: "[]",
          matchAddresses: "[]",
        })),
      });
    }
    return created;
  });
  return policyDTO(row, ifaces, seeds.length, seeds.reduce((s, r) => s + (r.guaranteedKbps ?? 0), 0));
}

export async function updatePolicy(tenantId: number, id: number, body: QosPolicyUpdate): Promise<QosPolicyDTO> {
  const existing = await db.qosPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("QoS policy not found");

  const merged = {
    name: body.name ?? existing.name,
    enabled: body.enabled ?? existing.enabled,
    template: body.template !== undefined ? (body.template ?? null) : existing.template,
    bandwidthKbps: body.bandwidthKbps ?? existing.bandwidthKbps,
    ifaceName: body.ifaceName !== undefined ? (body.ifaceName || null) : existing.ifaceName,
  };

  if (merged.ifaceName) {
    await assertIfaceExists(tenantId, merged.ifaceName);
    if (merged.enabled) await assertIfaceFree(tenantId, merged.ifaceName, id);
  }
  if (merged.name !== existing.name) {
    const dup = await db.qosPolicy.findFirst({ where: { tenantId, name: merged.name }, select: { id: true } });
    if (dup) throw ApiError.conflict(`QoS policy '${merged.name}' already exists`);
  }

  // guaranteed-sum vs budget — also fires when the budget shrinks (M08 §5.2)
  const rules = await db.qosRule.findMany({
    where: { tenantId, policyId: id },
    select: { guaranteedKbps: true },
  });
  const sum = rules.reduce((s, r) => s + (r.guaranteedKbps ?? 0), 0);
  if (sum > merged.bandwidthKbps) throw guaranteedSumError(sum, merged.bandwidthKbps);

  const row = await db.qosPolicy.update({
    where: { id },
    data: {
      name: body.name !== undefined ? merged.name : undefined,
      enabled: body.enabled ?? undefined,
      template: body.template !== undefined ? merged.template : undefined,
      bandwidthKbps: body.bandwidthKbps ?? undefined,
      ifaceName: body.ifaceName !== undefined ? merged.ifaceName : undefined,
    },
  });
  const { counts, sums, ifaces } = await policyExtras(tenantId, [id]);
  return policyDTO(row, ifaces, counts.get(id) ?? 0, sums.get(id) ?? 0);
}

/**
 * Deleting a policy is RESTRICT-ed while any FirewallRule.qosPolicyId points
 * at it (SCHEMA.md §3 / ER_DIAGRAM §2) — 409 lists the referencing rule names.
 */
export async function deletePolicy(tenantId: number, id: number): Promise<{ cascadedRules: number }> {
  const existing = await db.qosPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("QoS policy not found");
  const refs = await db.firewallRule.findMany({
    where: { tenantId, qosPolicyId: id },
    select: { name: true },
    orderBy: { id: "asc" },
  });
  if (refs.length > 0) {
    throw ApiError.conflict(
      `QoS policy "${existing.name}" is referenced by ${refs.length} firewall rule(s): ${refs.map((r) => r.name).join(", ")}`,
      { referencedBy: refs.map((r) => ({ ruleName: r.name, ruleType: "firewall" })) },
    );
  }
  const ruleCount = await db.qosRule.count({ where: { tenantId, policyId: id } });
  await db.qosPolicy.delete({ where: { id } }); // cascades QosRule rows (schema onDelete: Cascade)
  return { cascadedRules: ruleCount };
}

// ── rules ───────────────────────────────────────────────────────────────────

export async function listRules(tenantId: number, policyId?: number): Promise<QosRuleDTO[]> {
  const rows = await db.qosRule.findMany({
    where: { tenantId, ...(policyId ? { policyId } : {}) },
    orderBy: [{ priority: "asc" }, { id: "asc" }], // no position column — priority IS the order (M08 §5.3)
  });
  return rows.map(toRuleDTO);
}

async function assertPolicyExists(tenantId: number, policyId: number) {
  const policy = await db.qosPolicy.findFirst({ where: { tenantId, id: policyId } });
  if (!policy) throw fieldErr("policyId", "QoS policy not found");
  return policy;
}

/** Normalize + validate matcher ids in-tenant; canonicalizes app labels in place. */
async function assertMatchersValid(
  tenantId: number,
  matchers: { matchApps: string[]; matchUsers: string[]; matchAddresses: string[] },
): Promise<void> {
  const apps: string[] = [];
  const unknownApps: string[] = [];
  for (const raw of matchers.matchApps) {
    const canonical = canonicalAppLabel(raw);
    if (!canonical) unknownApps.push(raw);
    else if (!apps.includes(canonical)) apps.push(canonical);
  }
  matchers.matchApps = apps;
  if (unknownApps.length > 0) {
    throw fieldErr("matchApps", `Unknown application label(s): ${unknownApps.join(", ")}`);
  }

  const userIds = matchers.matchUsers.map((v) => Number(v));
  if (userIds.some((n) => !Number.isInteger(n) || n <= 0)) {
    const bad = matchers.matchUsers.filter((_, i) => !Number.isInteger(userIds[i]) || userIds[i] <= 0);
    throw fieldErr("matchUsers", `User ids must be integers: ${bad.join(", ")}`);
  }
  if (matchers.matchUsers.length === 0) return;
  const uniqueUserIds = [...new Set(matchers.matchUsers.map((v) => Number(v)))];
  const foundUsers = await db.user.findMany({ where: { tenantId, id: { in: uniqueUserIds } }, select: { id: true } });
  const knownUsers = new Set(foundUsers.map((u) => u.id));
  const unknownUsers = uniqueUserIds.filter((id) => !knownUsers.has(id));
  if (unknownUsers.length > 0) {
    throw fieldErr("matchUsers", `Unknown user id(s): ${unknownUsers.join(", ")}`);
  }

  if (matchers.matchAddresses.length === 0) return;
  const uniqueAddrIds = [...new Set(matchers.matchAddresses.map((v) => Number(v)))].filter(
    (n) => Number.isInteger(n) && n > 0,
  );
  const foundAddrs = await db.addressObject.findMany({ where: { tenantId, id: { in: uniqueAddrIds } }, select: { id: true } });
  const knownAddrs = new Set(foundAddrs.map((a) => a.id));
  const unknownAddrs = uniqueAddrIds.filter((id) => !knownAddrs.has(id));
  if (unknownAddrs.length > 0) {
    throw fieldErr("matchAddresses", `Unknown address object id(s): ${unknownAddrs.join(", ")}`);
  }
}

function guaranteedSumError(sum: number, budget: number): ApiError {
  const message = `Guaranteed rates sum to ${sum} kbps, exceeding the policy budget of ${budget} kbps`;
  return ApiError.validation(message, {
    fieldErrors: { guaranteedKbps: [`Sum of guaranteed rates (${sum} kbps) exceeds the ${budget} kbps budget`] },
    guaranteedSumKbps: sum,
    budgetKbps: budget,
  });
}

/** M08 §5.2: sum(guaranteedKbps) of the policy's rules must fit the budget. */
async function assertGuaranteedSumFits(
  tenantId: number,
  policy: { id: number; bandwidthKbps: number },
  extra: { guaranteedKbps?: number | null } | null,
  excludeId?: number,
): Promise<void> {
  const rules = await db.qosRule.findMany({
    where: { tenantId, policyId: policy.id, ...(excludeId ? { NOT: { id: excludeId } } : {}) },
    select: { guaranteedKbps: true },
  });
  const sum = rules.reduce((s, r) => s + (r.guaranteedKbps ?? 0), 0) + (extra?.guaranteedKbps ?? 0);
  if (sum > policy.bandwidthKbps) throw guaranteedSumError(sum, policy.bandwidthKbps);
}

const isCatchAll = (m: { matchApps: string[]; matchUsers: string[]; matchAddresses: string[] }) =>
  m.matchApps.length === 0 && m.matchUsers.length === 0 && m.matchAddresses.length === 0;

async function assertCatchAllFree(tenantId: number, policyId: number, excludeId?: number): Promise<void> {
  const rules = await db.qosRule.findMany({
    where: { tenantId, policyId, ...(excludeId ? { NOT: { id: excludeId } } : {}) },
    select: { matchApps: true, matchUsers: true, matchAddresses: true },
  });
  const existing = rules.some((r) =>
    isCatchAll({
      matchApps: parseJson<string[]>(r.matchApps, []),
      matchUsers: parseJson<string[]>(r.matchUsers, []),
      matchAddresses: parseJson<string[]>(r.matchAddresses, []),
    }),
  );
  if (existing) {
    throw ApiError.conflict(
      "This policy already has a catch-all rule (no matchers) — only one is allowed per policy",
    );
  }
}

function assertGuaranteedMax(guaranteedKbps: number | null | undefined, maxKbps: number | null | undefined): void {
  if (guaranteedKbps != null && maxKbps != null && guaranteedKbps > maxKbps) {
    const message = `guaranteedKbps (${guaranteedKbps}) must be ≤ maxKbps (${maxKbps})`;
    throw ApiError.validation(message, {
      fieldErrors: {
        guaranteedKbps: [message],
        maxKbps: [`Must be ≥ guaranteedKbps (${guaranteedKbps})`],
      },
    });
  }
}

export async function createRule(tenantId: number, body: QosRuleCreate): Promise<QosRuleDTO> {
  const policy = await assertPolicyExists(tenantId, body.policyId);
  assertGuaranteedMax(body.guaranteedKbps ?? null, body.maxKbps ?? null);
  await assertMatchersValid(tenantId, body);
  if (isCatchAll(body)) await assertCatchAllFree(tenantId, policy.id);
  await assertGuaranteedSumFits(tenantId, { id: policy.id, bandwidthKbps: policy.bandwidthKbps }, body);

  const row = await db.qosRule.create({
    data: {
      tenantId,
      policyId: policy.id,
      name: body.name,
      priority: body.priority,
      guaranteedKbps: body.guaranteedKbps ?? null,
      maxKbps: body.maxKbps ?? null,
      dscpMark: body.dscpMark ?? null,
      matchApps: stringifyJson(body.matchApps),
      matchUsers: stringifyJson(body.matchUsers),
      matchAddresses: stringifyJson(body.matchAddresses),
    },
  });
  return toRuleDTO(row);
}

export async function updateRule(tenantId: number, id: number, body: QosRuleUpdate): Promise<QosRuleDTO> {
  const existing = await db.qosRule.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("QoS rule not found");
  const policy = await assertPolicyExists(tenantId, existing.policyId);

  const merged = {
    name: body.name ?? existing.name,
    priority: body.priority ?? existing.priority,
    guaranteedKbps: body.guaranteedKbps !== undefined ? (body.guaranteedKbps ?? null) : existing.guaranteedKbps,
    maxKbps: body.maxKbps !== undefined ? (body.maxKbps ?? null) : existing.maxKbps,
    dscpMark: body.dscpMark !== undefined ? (body.dscpMark ?? null) : existing.dscpMark,
    matchApps: body.matchApps ?? parseJson<string[]>(existing.matchApps, []),
    matchUsers: body.matchUsers ?? parseJson<string[]>(existing.matchUsers, []),
    matchAddresses: body.matchAddresses ?? parseJson<string[]>(existing.matchAddresses, []),
  };

  assertGuaranteedMax(merged.guaranteedKbps, merged.maxKbps);
  await assertMatchersValid(tenantId, merged);
  if (isCatchAll(merged)) await assertCatchAllFree(tenantId, policy.id, id);
  await assertGuaranteedSumFits(tenantId, { id: policy.id, bandwidthKbps: policy.bandwidthKbps }, merged, id);

  const row = await db.qosRule.update({
    where: { id },
    data: {
      name: body.name !== undefined ? merged.name : undefined,
      priority: body.priority ?? undefined,
      guaranteedKbps: body.guaranteedKbps !== undefined ? merged.guaranteedKbps : undefined,
      maxKbps: body.maxKbps !== undefined ? merged.maxKbps : undefined,
      dscpMark: body.dscpMark !== undefined ? merged.dscpMark : undefined,
      matchApps: body.matchApps !== undefined ? stringifyJson(merged.matchApps) : undefined,
      matchUsers: body.matchUsers !== undefined ? stringifyJson(merged.matchUsers) : undefined,
      matchAddresses: body.matchAddresses !== undefined ? stringifyJson(merged.matchAddresses) : undefined,
    },
  });
  return toRuleDTO(row);
}

export async function deleteRule(tenantId: number, id: number): Promise<void> {
  const existing = await db.qosRule.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("QoS rule not found");
  await db.qosRule.delete({ where: { id } });
}

/**
 * GET/PUT/DELETE /api/v1/nat-rules/{id}
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, natRuleBodySchema } from "@/lib/validators/firewall";
import { shapeNatRule } from "@/lib/firewall/rule-shape";
import { updateNatRule } from "@/lib/firewall/nat-service";
import { assertNewIdsValid, findEmptyGroupReferences } from "@/lib/firewall/refs";
import { renumberNatRules } from "@/lib/firewall/positions";

export const dynamic = "force-dynamic";

async function findRow(tenantId: number, id: number) {
  const row = await db.natRule.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`NAT rule ${id} not found`);
  return row;
}

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  return { data: shapeNatRule(await findRow(auth.tenantId, id)) };
});

export const PUT = route(
  { area: "firewall", bodySchema: natRuleBodySchema, section: "nat" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const before = await findRow(auth.tenantId, id);
    const idCheck = await assertNewIdsValid(auth.tenantId, {
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
    const emptyGroups = await findEmptyGroupReferences(auth.tenantId, body);
    if (emptyGroups.length > 0) {
      throw ApiError.validation(
        `NAT rule references empty group(s): ${emptyGroups.map((g) => `'${g.groupName}' (${g.kind})`).join(", ")} — add members first`,
        { emptyGroups },
      );
    }
    await updateNatRule(auth.tenantId, id, body);
    const after = await db.natRule.findUniqueOrThrow({ where: { id } });
    return {
      data: shapeNatRule(after),
      audit: {
        action: "nat_rule.update",
        objectType: "nat_rule",
        objectId: id,
        objectName: before.name ?? `#${id}`,
        before: shapeNatRule(before),
        after: shapeNatRule(after),
      },
    };
  },
);

export const DELETE = route({ area: "firewall", section: "nat" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await findRow(auth.tenantId, id);

  await db.$transaction(async (tx) => {
    await tx.natRule.delete({ where: { id: row.id } });
    await renumberNatRules(tx as unknown as Parameters<typeof renumberNatRules>[0], auth.tenantId);
  });

  return {
    data: { ok: true },
    audit: {
      action: "nat_rule.delete",
      objectType: "nat_rule",
      objectId: row.id,
      objectName: row.name ?? `#${row.id}`,
      before: shapeNatRule(row),
    },
  };
});

/**
 * GET  /api/v1/nat-rules — ordered NAT list (?q=&page=&limit=)
 * POST /api/v1/nat-rules — create a NAT rule, OR the 1:1 (static NAT) helper:
 *   body {oneToOne: {publicIp, internalHost, iface?, name?, comment?}} emits
 *   the paired dnat (no port) + snat rows atomically with a single audit entry
 *   (M03 §4) — both rows share the `1:1:<uuid>` comment marker.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { fwListQuery, natPostBodySchema } from "@/lib/validators/firewall";
import { shapeNatRule } from "@/lib/firewall/rule-shape";
import { assertNewIdsValid } from "@/lib/firewall/refs";
import { createNatRule, createOneToOnePair } from "@/lib/firewall/nat-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = {
    tenantId: auth.tenantId,
    ...(q ? { OR: [{ name: { contains: q } }, { comment: { contains: q } }] } : {}),
  };
  const [total, rows] = await Promise.all([
    db.natRule.count({ where }),
    db.natRule.findMany({ where, orderBy: { position: "asc" }, skip: (query.page - 1) * query.limit, take: query.limit }),
  ]);
  return {
    data: rows.map(shapeNatRule),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "firewall", bodySchema: natPostBodySchema, section: "nat" },
  async ({ auth, body }) => {
    if ("oneToOne" in body) {
      const pair = await createOneToOnePair(auth.tenantId, body.oneToOne);
      const [dnat, snat] = await Promise.all([
        db.natRule.findUniqueOrThrow({ where: { id: pair.dnatId } }),
        db.natRule.findUniqueOrThrow({ where: { id: pair.snatId } }),
      ]);
      return {
        data: { dnat: shapeNatRule(dnat), snat: shapeNatRule(snat) },
        audit: {
          action: "nat_rule.create_1to1",
          objectType: "nat_rule",
          objectName: `1:1 pair ${body.oneToOne.publicIp} ↔ ${body.oneToOne.internalHost}`,
          after: { dnatId: pair.dnatId, snatId: pair.snatId, marker: pair.marker },
        },
      };
    }

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

    const created = await createNatRule(auth.tenantId, body);
    const row = await db.natRule.findUniqueOrThrow({ where: { id: created.id } });
    return {
      data: shapeNatRule(row),
      audit: {
        action: "nat_rule.create",
        objectType: "nat_rule",
        objectId: created.id,
        objectName: created.name ?? `#${created.id}`,
      },
    };
  },
);

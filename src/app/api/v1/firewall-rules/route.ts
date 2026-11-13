/**
 * GET  /api/v1/firewall-rules — ordered list (position asc; ?zone=&q=&page=&limit=)
 * POST /api/v1/firewall-rules — create (appends at max(position)+1 unless an
 * explicit position is provided; unknown ids in any JSON array → 400).
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { firewallRuleBodySchema, fwListQuery } from "@/lib/validators/firewall";
import { shapeFirewallRule } from "@/lib/firewall/rule-shape";
import { createRule } from "@/lib/firewall/rule-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = {
    tenantId: auth.tenantId,
    ...(q ? { OR: [{ name: { contains: q } }, { comment: { contains: q } }] } : {}),
    ...(query.enabled ? { enabled: query.enabled === "true" } : {}),
  };

  let rows = await db.firewallRule.findMany({ where, orderBy: { position: "asc" } });

  if (query.zone) {
    // zone is a logical (JSON-array) ref — resolve name→id and filter in memory
    let zoneId: number | null = null;
    if (/^\d+$/.test(query.zone)) zoneId = Number(query.zone);
    else {
      const z = await db.zone.findFirst({ where: { tenantId: auth.tenantId, name: query.zone } });
      if (z) zoneId = z.id;
    }
    rows = zoneId
      ? rows.filter((r) => {
          const ids = (raw: string): number[] => {
            try {
              const v = JSON.parse(raw);
              return Array.isArray(v) ? v : [];
            } catch {
              return [];
            }
          };
          return ids(r.srcZoneIds).includes(zoneId) || ids(r.dstZoneIds).includes(zoneId);
        })
      : [];
  }

  const total = rows.length;
  const page = rows.slice((query.page - 1) * query.limit, query.page * query.limit);
  return {
    data: page.map(shapeFirewallRule),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "firewall", bodySchema: firewallRuleBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const created = await createRule(auth.tenantId, body);
    return {
      data: shapeFirewallRule(await db.firewallRule.findUniqueOrThrow({ where: { id: created.id } })),
      audit: { action: "rule.create", objectType: "firewall_rule", objectId: created.id, objectName: created.name },
    };
  },
);

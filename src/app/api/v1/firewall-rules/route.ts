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

  type FwRow = Awaited<ReturnType<typeof db.firewallRule.findMany>>;
  let rows: FwRow;
  let total: number;

  if (!query.zone) {
    // no zone filter → pagination is pushed down to the DB (take/skip)
    [rows, total] = await Promise.all([
      db.firewallRule.findMany({
        where,
        orderBy: { position: "asc" },
        skip: (query.page - 1) * query.limit,
        take: query.limit,
      }),
      db.firewallRule.count({ where }),
    ]);
  } else {
    // zone is a logical (JSON-array) ref — SQLite cannot filter inside a JSON
    // column, so a position-ordered page*limit window is fetched and filtered
    // in memory. CAVEAT: `total` counts the filtered window only (a deep page
    // under a zone filter can under-report; acceptable for the GUI pager).
    let zoneId: number | null = null;
    if (/^\d+$/.test(query.zone)) zoneId = Number(query.zone);
    else {
      const z = await db.zone.findFirst({ where: { tenantId: auth.tenantId, name: query.zone } });
      if (z) zoneId = z.id;
    }
    const window = zoneId
      ? await db.firewallRule.findMany({ where, orderBy: { position: "asc" }, take: query.page * query.limit })
      : [];
    const filtered = window.filter((r) => {
      const ids = (raw: string): number[] => {
        try {
          const v = JSON.parse(raw);
          return Array.isArray(v) ? v : [];
        } catch {
          return [];
        }
      };
      return ids(r.srcZoneIds).includes(zoneId) || ids(r.dstZoneIds).includes(zoneId);
    });
    total = filtered.length;
    rows = filtered.slice((query.page - 1) * query.limit, query.page * query.limit);
  }

  return {
    data: rows.map(shapeFirewallRule),
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

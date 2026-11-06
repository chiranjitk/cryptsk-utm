/**
 * GET  /api/v1/zones — list zones with member interface names (+ ?q= search,
 * ?page=&limit= pagination). Also feeds the RuleEditor zone pickers.
 * POST /api/v1/zones — create zone (409 duplicate name, 400 unknown ifaces).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { fwListQuery, zoneBodySchema } from "@/lib/validators/firewall";
import { syncZoneMembers } from "@/lib/firewall/zone-service";

export const dynamic = "force-dynamic";

function parseNames(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function shapeZone(z: { id: number; name: string; type: string; interfaceNames: string; description: string | null }) {
  return {
    id: z.id,
    name: z.name,
    type: z.type,
    interfaceNames: parseNames(z.interfaceNames),
    description: z.description,
  };
}

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = { tenantId: auth.tenantId, ...(q ? { name: { contains: q } } : {}) };
  const [total, zones] = await Promise.all([
    db.zone.count({ where }),
    db.zone.findMany({
      where,
      orderBy: { id: "asc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: zones.map(shapeZone),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "firewall", bodySchema: zoneBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const existing = await db.zone.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (existing) throw ApiError.conflict(`Zone '${body.name}' already exists`);

    // validate member iface names before creating
    if (body.interfaceNames.length) {
      const all = await db.networkInterface.findMany({ where: { tenantId: auth.tenantId }, select: { name: true } });
      const names = new Set(all.map((i) => i.name));
      const missing = body.interfaceNames.filter((n) => !names.has(n));
      if (missing.length) throw ApiError.validation("Unknown interface name", { offendingNames: missing });
    }

    const zone = await db.$transaction(async (tx) => {
      const created = await tx.zone.create({
        data: {
          tenantId: auth.tenantId,
          name: body.name,
          type: body.type,
          interfaceNames: JSON.stringify(body.interfaceNames),
          description: body.description ?? null,
        },
      });
      await syncZoneMembers(created.id, auth.tenantId, body.interfaceNames);
      return created;
    });

    return {
      data: shapeZone(zone),
      audit: {
        action: "zone.create",
        objectType: "zone",
        objectId: zone.id,
        objectName: zone.name,
        after: shapeZone(zone),
      },
    };
  },
);

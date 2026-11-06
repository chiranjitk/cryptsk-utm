/**
 * GET/PUT/DELETE /api/v1/zones/{id} — zone detail, update (WAN/LAN keep
 * name/type), delete (409 protected zones or zones referenced by rules;
 * member interface zoneId stays consistent on both paths).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, zonePutSchema } from "@/lib/validators/firewall";
import { assertZoneNotProtected, detachZoneMembers, syncZoneMembers } from "@/lib/firewall/zone-service";
import { zoneReferences } from "@/lib/firewall/refs";

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

async function findZone(tenantId: number, id: number) {
  const zone = await db.zone.findFirst({ where: { id, tenantId } });
  if (!zone) throw ApiError.notFound(`Zone ${id} not found`);
  return zone;
}

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const zone = await findZone(auth.tenantId, id);
  return { data: shapeZone(zone) };
});

export const PUT = route(
  { area: "firewall", bodySchema: zonePutSchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const zone = await findZone(auth.tenantId, id);

    if (body.name !== zone.name || body.type !== zone.type) {
      assertZoneNotProtected(zone.name, "renamed or retyped");
    }
    if (body.name !== zone.name) {
      const dup = await db.zone.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
      if (dup) throw ApiError.conflict(`Zone '${body.name}' already exists`);
    }

    const updated = await db.$transaction(async (tx) => {
      const row = await tx.zone.update({
        where: { id: zone.id },
        data: {
          name: body.name,
          type: body.type,
          interfaceNames: JSON.stringify(body.interfaceNames),
          description: body.description ?? null,
        },
      });
      await syncZoneMembers(zone.id, auth.tenantId, body.interfaceNames);
      return row;
    });

    return {
      data: shapeZone(updated),
      audit: {
        action: "zone.update",
        objectType: "zone",
        objectId: zone.id,
        objectName: zone.name,
        before: shapeZone(zone),
        after: shapeZone(updated),
      },
    };
  },
);

export const DELETE = route({ area: "firewall", section: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const zone = await findZone(auth.tenantId, id);
  assertZoneNotProtected(zone.name, "deleted");

  const refs = await zoneReferences(zone.id);
  if (refs.length) {
    throw ApiError.conflict(`Zone '${zone.name}' is referenced by ${refs.length} rule(s)`, { referencedBy: refs });
  }

  await db.$transaction(async (tx) => {
    await detachZoneMembers(zone.id);
    await tx.zone.delete({ where: { id: zone.id } });
  });

  return {
    data: { ok: true },
    audit: {
      action: "zone.delete",
      objectType: "zone",
      objectId: zone.id,
      objectName: zone.name,
      before: shapeZone(zone),
    },
  };
});

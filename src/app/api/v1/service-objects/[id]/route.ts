/**
 * GET/PUT/DELETE /api/v1/service-objects/{id}
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, serviceObjectBodySchema } from "@/lib/validators/firewall";
import { shapeServiceObject } from "@/lib/firewall/shapes";
import { serviceObjectReferences } from "@/lib/firewall/refs";

export const dynamic = "force-dynamic";

async function findRow(tenantId: number, id: number) {
  const row = await db.serviceObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Service object ${id} not found`);
  return row;
}

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  return { data: shapeServiceObject(await findRow(auth.tenantId, id)) };
});

export const PUT = route(
  { area: "firewall", bodySchema: serviceObjectBodySchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await findRow(auth.tenantId, id);
    if (body.name !== row.name) {
      const dup = await db.serviceObject.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
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
    return {
      data: shapeServiceObject(updated),
      audit: {
        action: "service_object.update",
        objectType: "service_object",
        objectId: row.id,
        objectName: row.name,
        before: { ...row },
        after: { ...updated },
      },
    };
  },
);

export const DELETE = route({ area: "firewall", section: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await findRow(auth.tenantId, id);
  const refs = await serviceObjectReferences(auth.tenantId, row.id);
  if (refs.length) {
    throw ApiError.conflict(`Service object '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.serviceObject.delete({ where: { id: row.id } });
  return {
    data: { ok: true },
    audit: {
      action: "service_object.delete",
      objectType: "service_object",
      objectId: row.id,
      objectName: row.name,
      before: { ...row },
    },
  };
});

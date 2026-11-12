/**
 * BFD profile item (M19 §2.6) — update / delete, audit
 * `bfd_profile.update|delete`. Delete is guarded: 409 while a BGP neighbor
 * references the profile.
 */

import { route, numericId } from "@/lib/api/handler";
import { bfdProfileUpdateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { assertNotReferencedByNeighbor } from "../../internal";

export const dynamic = "force-dynamic";

async function findProfile(tenantId: number, id: number) {
  const row = await db.bfdProfile.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("BFD profile not found");
  return row;
}

export const PUT = route(
  { area: "dynamic_routing", bodySchema: bfdProfileUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await findProfile(auth.tenantId, id);
    const updated = await db.bfdProfile.update({ where: { id }, data: body });
    return {
      data: updated,
      audit: {
        action: "bfd_profile.update",
        objectType: "bfd_profile",
        objectId: id,
        objectName: updated.name,
        before: existing,
        after: updated,
      },
    };
  },
);

export const DELETE = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const existing = await findProfile(auth.tenantId, id);
    await assertNotReferencedByNeighbor(auth.tenantId, "bfdProfileId", id, existing.name);
    await db.bfdProfile.delete({ where: { id } });
    return {
      data: { ok: true },
      audit: {
        action: "bfd_profile.delete",
        objectType: "bfd_profile",
        objectId: id,
        objectName: existing.name,
        before: existing,
      },
    };
  },
);

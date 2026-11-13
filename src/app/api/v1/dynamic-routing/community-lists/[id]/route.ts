/**
 * Community list item (M19 §2.6) — update / delete, audit
 * `community_list.update|delete`.
 */

import { route, numericId } from "@/lib/api/handler";
import { communityListUpdateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { toCommunityListDTO } from "../../internal";

export const dynamic = "force-dynamic";

async function findList(tenantId: number, id: number) {
  const row = await db.communityList.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Community list not found");
  return row;
}

export const PUT = route(
  { area: "dynamic_routing", bodySchema: communityListUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await findList(auth.tenantId, id);
    const updated = await db.communityList.update({
      where: { id },
      data: {
        ...(body.name === undefined ? {} : { name: body.name }),
        ...(body.type === undefined ? {} : { type: body.type }),
        ...(body.entries === undefined ? {} : { entries: JSON.stringify(body.entries) }),
      },
    });
    return {
      data: toCommunityListDTO(updated),
      audit: {
        action: "community_list.update",
        objectType: "community_list",
        objectId: id,
        objectName: updated.name,
        before: toCommunityListDTO(existing),
        after: toCommunityListDTO(updated),
      },
    };
  },
);

export const DELETE = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const existing = await findList(auth.tenantId, id);
    await db.communityList.delete({ where: { id } });
    return {
      data: { ok: true },
      audit: {
        action: "community_list.delete",
        objectType: "community_list",
        objectId: id,
        objectName: existing.name,
        before: toCommunityListDTO(existing),
      },
    };
  },
);

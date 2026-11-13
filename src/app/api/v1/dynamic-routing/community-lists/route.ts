/**
 * Community lists (M19 §2.6 policy objects) — GET list + POST create. Standard
 * entries are "AS:NN" tags, expanded entries are regex strings (validated by
 * the zod schema); stored as JSON array of strings.
 */

import { route } from "@/lib/api/handler";
import { communityListCreateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { toCommunityListDTO } from "@/app/api/v1/dynamic-routing/internal";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  const rows = await db.communityList.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ name: "asc" }],
  });
  return { data: rows.map(toCommunityListDTO) };
});

export const POST = route(
  { area: "dynamic_routing", bodySchema: communityListCreateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    const created = await db.communityList.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        type: body.type,
        entries: JSON.stringify(body.entries),
      },
    });
    return {
      data: toCommunityListDTO(created),
      audit: {
        action: "community_list.create",
        objectType: "community_list",
        objectId: created.id,
        objectName: created.name,
        after: toCommunityListDTO(created),
      },
    };
  },
);

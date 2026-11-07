/**
 * Prefix lists (M19 §2.6 policy objects) — GET list + POST create. Entries are
 * stored as JSON; CIDR family and unique seq are enforced by the zod schema.
 * Deleting a list still referenced by a BGP neighbor → 409.
 */

import { route } from "@/lib/api/handler";
import { prefixListCreateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { toPrefixListDTO } from "@/app/api/v1/dynamic-routing/internal";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  const rows = await db.prefixList.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ name: "asc" }],
  });
  return { data: rows.map(toPrefixListDTO) };
});

export const POST = route(
  { area: "dynamic_routing", bodySchema: prefixListCreateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    const created = await db.prefixList.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        family: body.family,
        entries: JSON.stringify(body.entries),
      },
    });
    return {
      data: toPrefixListDTO(created),
      audit: {
        action: "prefix_list.create",
        objectType: "prefix_list",
        objectId: created.id,
        objectName: created.name,
        after: toPrefixListDTO(created),
      },
    };
  },
);

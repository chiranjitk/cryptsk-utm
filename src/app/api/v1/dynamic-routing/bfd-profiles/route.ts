/**
 * BFD profiles (M19 §2.6) — GET list + POST create. Intervals 50-60000 ms,
 * detect multiplier 2-50. Deleting a profile still referenced by a BGP
 * neighbor → 409.
 */

import { route } from "@/lib/api/handler";
import { bfdProfileCreateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  const rows = await db.bfdProfile.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ name: "asc" }],
  });
  return { data: rows };
});

export const POST = route(
  { area: "dynamic_routing", bodySchema: bfdProfileCreateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    const created = await db.bfdProfile.create({
      data: { tenantId: auth.tenantId, ...body },
    });
    return {
      data: created,
      audit: {
        action: "bfd_profile.create",
        objectType: "bfd_profile",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

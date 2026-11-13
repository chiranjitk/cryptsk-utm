/**
 * OSPF interfaces (M19 §2.6) — GET list + POST create. interfaceName is unique
 * per tenant (P2002 → 409). deadSec ≥ 2×hello enforced by the zod schema.
 */

import { route } from "@/lib/api/handler";
import { ospfInterfaceCreateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  const rows = await db.ospfInterface.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ interfaceName: "asc" }],
  });
  return { data: rows };
});

export const POST = route(
  { area: "dynamic_routing", bodySchema: ospfInterfaceCreateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    const created = await db.ospfInterface.create({
      data: { tenantId: auth.tenantId, ...body },
    });
    return {
      data: created,
      audit: {
        action: "ospf_interface.create",
        objectType: "ospf_interface",
        objectId: created.id,
        objectName: created.interfaceName,
        after: created,
      },
    };
  },
);

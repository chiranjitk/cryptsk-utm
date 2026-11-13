/** User groups (M07 §3) — list incl. member ids, create. */

import { route } from "@/lib/api/handler";
import { userGroupCreateSchema } from "@/lib/validators/identity";
import { createGroup, listGroups } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  return { data: await listGroups(auth.tenantId) };
});

export const POST = route(
  { area: "identity", bodySchema: userGroupCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    const created = await createGroup(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "user_group.create", objectType: "user_group", objectId: created.id, objectName: created.name, after: created },
    };
  },
);

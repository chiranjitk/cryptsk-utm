/**
 * /api/v1/ztna/apps — ZTNA-protected resource list + creation (Phase 4 §4.4,
 * identity-based access user-to-resource). RBAC area "ztna".
 */

import { route } from "@/lib/api/handler";
import { ztnaAppCreateSchema } from "@/lib/validators/ztna";
import { createApp, listApps } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ztna" }, async ({ auth }) => {
  return { data: await listApps(auth.tenantId) };
});

export const POST = route(
  { area: "ztna", bodySchema: ztnaAppCreateSchema, section: "ztna" },
  async ({ auth, body }) => {
    const created = await createApp(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "ztna.app.create",
        objectType: "ztna_application",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

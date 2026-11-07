/**
 * SD-WAN overlays (M20 §2.5) — GET list + POST create.
 * Mutations audit `overlay.create` and snapshot section `sdwan`.
 */

import { route } from "@/lib/api/handler";
import { overlayCreateSchema } from "@/lib/validators/sdwan";
import { createOverlay, listOverlays } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sdwan" }, async ({ auth }) => {
  return { data: await listOverlays(auth.tenantId) };
});

export const POST = route(
  { area: "sdwan", bodySchema: overlayCreateSchema, section: "sdwan" },
  async ({ auth, body }) => {
    const created = await createOverlay(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "overlay.create",
        objectType: "sdwan_overlay",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

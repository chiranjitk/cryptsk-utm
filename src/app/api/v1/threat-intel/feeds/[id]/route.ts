/** Threat feed item (M13 §2.11) — update / delete, audit `threat_feed.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { feedUpdateSchema } from "@/lib/validators/threat-intel";
import { deleteFeed, updateFeed } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "threat_intel", bodySchema: feedUpdateSchema, section: "threat_intel" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateFeed(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "threat_feed.update",
        objectType: "threat_feed",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "threat_intel", section: "threat_intel" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteFeed(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "threat_feed.delete", objectType: "threat_feed", objectId: id } };
});

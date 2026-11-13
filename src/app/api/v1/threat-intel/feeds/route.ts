/**
 * Threat feeds (M13 §2.11 tab 1) — GET list + POST create.
 * Mutations audit `threat_feed.create` and snapshot section `threat_intel`.
 */

import { route } from "@/lib/api/handler";
import { feedCreateSchema } from "@/lib/validators/threat-intel";
import { createFeed, listFeeds } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "threat_intel" }, async ({ auth }) => {
  return { data: await listFeeds(auth.tenantId) };
});

export const POST = route(
  { area: "threat_intel", bodySchema: feedCreateSchema, section: "threat_intel" },
  async ({ auth, body }) => {
    const created = await createFeed(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "threat_feed.create",
        objectType: "threat_feed",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

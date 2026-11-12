/**
 * POST /api/v1/threat-intel/feeds/[id]/sync — SIMULATED ingestion (M13 §2.11,
 * sandbox mode; the appliance does the real fetch). Replays the built-in
 * per-provider corpus, upserts IOCs, optionally auto-blocks new critical
 * IOCs, mints sample hits and stamps the feed's sync state.
 * Audits `threat_feed.sync`.
 */

import { route, numericId } from "@/lib/api/handler";
import { syncFeed } from "@/lib/threat-intel/corpus";

export const dynamic = "force-dynamic";

export const POST = route({ area: "threat_intel", section: "threat_intel" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const result = await syncFeed(auth.tenantId, id);
  return {
    data: result,
    audit: {
      action: "threat_feed.sync",
      objectType: "threat_feed",
      objectId: id,
      objectName: result.feedName,
      after: result,
    },
  };
});

/**
 * /api/v1/sase/routing — identity-aware routing map (spec §4.2 stub).
 * GET returns the user → region entries with each resolved nearest node;
 * POST upserts one {userEmail, region} mapping (stored as a single JSON map
 * in SystemSetting category "sase" key "identity_routing" via the EXISTING
 * system-service settings helpers — no parallel settings path).
 */

import { route } from "@/lib/api/handler";
import { saseRoutingUpsertSchema } from "@/lib/validators/sase";
import { identityRoutingList, identityRoutingUpsert } from "@/lib/sase/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sase" }, async ({ auth }) => {
  return { data: await identityRoutingList(auth.tenantId) };
});

export const POST = route(
  { area: "sase", bodySchema: saseRoutingUpsertSchema, section: "sase" },
  async ({ auth, body }) => {
    const entry = await identityRoutingUpsert(auth.tenantId, body);
    return {
      data: entry,
      audit: {
        action: "sase.routing.upsert",
        objectType: "sase_identity_routing",
        objectId: entry.userEmail,
        objectName: `${entry.userEmail} → ${entry.region}`,
        after: entry,
      },
    };
  },
);

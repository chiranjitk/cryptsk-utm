/** Terminate one portal session (spec §7, T1-d) — audited admin action. */

import { route, numericId } from "@/lib/api/handler";
import { terminatePortalSession } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const session = await terminatePortalSession(auth.tenantId, id);
  return {
    data: session,
    audit: {
      action: "captive_portal.session.terminate",
      objectType: "captive_portal_session",
      objectId: id,
      objectName: session.userName ?? undefined,
      after: session,
    },
  };
});

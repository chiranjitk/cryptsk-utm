/**
 * NAT66 rule hit simulator (M21 §2.7) — POST with no body bumps the rule's
 * hitCount by a deterministic +1..5 and returns the row (audit `nat66.simulate`),
 * so the demo counters move like live traffic.
 */

import { route, numericId } from "@/lib/api/handler";
import { simulateNat66Hit } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const POST = route({ area: "ipv6", section: "ipv6" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const updated = await simulateNat66Hit(auth.tenantId, id);
  return {
    data: updated,
    audit: {
      action: "nat66.simulate",
      objectType: "nat66_rule",
      objectId: id,
      objectName: updated.name,
      after: { hitCount: updated.hitCount },
    },
  };
});

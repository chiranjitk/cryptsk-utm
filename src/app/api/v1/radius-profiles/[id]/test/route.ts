/**
 * RADIUS profile test (M07 §3/§5.3) — simulated client-side connectivity
 * probe wired to the existing testRadiusProfile service (TEST-NET addresses
 * fail in the sandbox, everything else answers). OS-side work never uses
 * radtest; this endpoint is a console-level probe only.
 */

import { route, numericId } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { testRadiusProfile } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const row = await db.radiusProfile.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!row) throw ApiError.notFound("RADIUS profile not found");

  const result = await testRadiusProfile(auth.tenantId, id);
  return {
    data: result,
    audit: {
      action: "radius_profile.test",
      objectType: "radius_profile",
      objectId: id,
      objectName: row.name,
      after: result,
    },
  };
});

/**
 * RADIUS sharedSecret reveal (M07 §3/§5.3) — STRICT:
 * super_admin/tenant_admin ONLY (matrix identity.write also allows
 * security_admin — this endpoint is narrower), audited with sourceIp.
 * Never part of any list/detail response.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity" }, async ({ auth, params, ip }) => {
  if (!["super_admin", "tenant_admin"].includes(auth.role)) {
    throw ApiError.forbidden("Revealing the RADIUS shared secret requires super_admin or tenant_admin");
  }
  const id = numericId(params, "id");
  const row = await db.radiusProfile.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!row) throw ApiError.notFound("RADIUS profile not found");
  return {
    data: { id: row.id, name: row.name, sharedSecret: row.sharedSecret },
    audit: {
      action: "radius_profile.reveal",
      objectType: "radius_profile",
      objectId: id,
      objectName: row.name,
      result: "success",
      details: { sourceIp: ip },
    },
  };
});

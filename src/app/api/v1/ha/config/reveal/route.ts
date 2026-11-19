/**
 * VRRP authPass reveal (M10 §5.1) — STRICT: super_admin/tenant_admin ONLY
 * (admin matrix column + explicit role gate, mirroring the RADIUS reveal
 * endpoint), audited with sourceIp. The DTO never carries the secret;
 * GET responses expose hasAuthPass only.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { getHaConfigRow } from "@/lib/ha/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "ha", admin: true }, async ({ auth, ip }) => {
  if (!["super_admin", "tenant_admin"].includes(auth.role)) {
    throw ApiError.forbidden("Revealing the VRRP auth password requires super_admin or tenant_admin");
  }
  const row = await getHaConfigRow(auth.tenantId);
  if (!row.authPass) {
    throw ApiError.validation("No VRRP auth password is configured");
  }
  return {
    data: { id: row.id, authPass: row.authPass },
    audit: {
      action: "ha_config.reveal",
      objectType: "ha_config",
      objectId: row.id,
      objectName: "ha",
      result: "success",
      details: { sourceIp: ip },
    },
  };
});

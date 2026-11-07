/**
 * BYOD enrollment revoke (M23, spec 2.9) — DELETE → status "revoked" when the
 * enrollment is still pending; already-revoked rows are idempotent no-ops;
 * anything else conflicts. Audit `byod.revoke`.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { toByodDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const row = await db.byodEnrollment.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound("Enrollment not found");

  if (row.status === "revoked") {
    return {
      data: { ok: true, ...toByodDTO(row) },
      audit: { action: "byod.revoke", objectType: "byod_enrollment", objectId: id, objectName: row.userName },
    };
  }
  if (row.status !== "pending") {
    throw ApiError.conflict(`Enrollment is ${row.status} — only pending enrollments can be revoked`);
  }

  const updated = await db.byodEnrollment.update({ where: { id: row.id }, data: { status: "revoked" } });
  return {
    data: { ok: true, ...toByodDTO(updated) },
    audit: { action: "byod.revoke", objectType: "byod_enrollment", objectId: id, objectName: row.userName },
  };
});

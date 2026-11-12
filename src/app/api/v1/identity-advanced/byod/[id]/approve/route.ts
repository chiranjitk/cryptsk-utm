/**
 * BYOD enrollment approve (M23, spec 2.9) — POST → status "approved" from
 * pending (idempotent when already approved, conflict once expired/revoked/
 * enrolled). Audit `byod.approve`.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { toByodDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const row = await db.byodEnrollment.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound("Enrollment not found");

  if (row.status === "approved") {
    return {
      data: toByodDTO(row),
      audit: { action: "byod.approve", objectType: "byod_enrollment", objectId: id, objectName: row.userName },
    };
  }
  if (row.status !== "pending") {
    throw ApiError.conflict(`Enrollment is ${row.status} — only pending enrollments can be approved`);
  }
  if (row.expiresAt.getTime() < Date.now()) {
    throw ApiError.conflict("Enrollment token expired — issue a new one");
  }

  const updated = await db.byodEnrollment.update({ where: { id: row.id }, data: { status: "approved" } });
  return {
    data: toByodDTO(updated),
    audit: { action: "byod.approve", objectType: "byod_enrollment", objectId: id, objectName: row.userName },
  };
});

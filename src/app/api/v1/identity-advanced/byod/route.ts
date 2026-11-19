/**
 * BYOD enrollments (M23, spec 2.9) — GET list + POST enroll.
 * One-time secret rule: the enrollment token (16 hex uppercase, crypto
 * random) is returned ONCE in the POST response and NEVER on GET (lists
 * carry hasToken: true). Expired pending/approved rows read as "expired".
 *
 * AT-REST NOTE (audit fix #25 — documented, no crypto this pass): the
 * enrollment token is stored PLAINTEXT by design (schema locked). The
 * exposure is controlled in the response layer instead — the raw token
 * never serializes into any DTO/GET (hasToken flag only) and leaves the
 * server exactly once on create; only device-approving admins can mint one.
 */

import { randomBytes } from "node:crypto";
import { route } from "@/lib/api/handler";
import { byodCreateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { assertNacDeviceExists, toByodDTO, type ByodDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  const rows = await db.byodEnrollment.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: { createdAt: "desc" },
  });
  return { data: rows.map(toByodDTO) satisfies ByodDTO[] };
});

export const POST = route(
  { area: "identity", bodySchema: byodCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    await assertNacDeviceExists(auth.tenantId, body.deviceId);
    const token = randomBytes(8).toString("hex").toUpperCase(); // 16 hex chars
    const created = await db.byodEnrollment.create({
      data: {
        tenantId: auth.tenantId,
        userName: body.userName,
        deviceId: body.deviceId ?? null,
        token,
        status: "pending",
        expiresAt: new Date(Date.now() + body.ttlHours * 3_600_000),
      },
    });
    return {
      // One-time secret: the raw token leaves the server exactly once.
      data: { ...toByodDTO(created), token },
      audit: { action: "byod.create", objectType: "byod_enrollment", objectId: created.id, objectName: created.userName },
    };
  },
);

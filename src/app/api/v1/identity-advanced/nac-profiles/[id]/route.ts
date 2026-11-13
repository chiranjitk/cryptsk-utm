/**
 * NAC profile item (M23, spec 2.9) — update / delete, audit
 * `nac_profile.update|delete`. Deleting a profile leaves its devices with a
 * dangling logical ref (nacProfileId kept — the view renders "—").
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { nacProfileUpdateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { toNacProfileDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "identity", bodySchema: nacProfileUpdateSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await db.nacProfile.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!existing) throw ApiError.notFound("NAC profile not found");

    const updated = await db.nacProfile.update({
      where: { id: existing.id },
      data: {
        name: body.name ?? existing.name,
        method: body.method ?? existing.method,
        eapType: body.eapType ?? existing.eapType,
        dynamicVlan: body.dynamicVlan ?? existing.dynamicVlan,
        guestVlan: body.guestVlan !== undefined ? body.guestVlan : existing.guestVlan,
        authFailVlan: body.authFailVlan !== undefined ? body.authFailVlan : existing.authFailVlan,
        profiling: body.profiling ?? existing.profiling,
        byodOnboarding: body.byodOnboarding ?? existing.byodOnboarding,
        enabled: body.enabled ?? existing.enabled,
      },
    });
    const deviceCount = await db.nacDevice.count({ where: { tenantId: auth.tenantId, nacProfileId: id } });
    const dto = toNacProfileDTO(updated, deviceCount);
    return {
      data: dto,
      audit: {
        action: "nac_profile.update",
        objectType: "nac_profile",
        objectId: id,
        objectName: updated.name,
        before: toNacProfileDTO(existing, deviceCount),
        after: dto,
      },
    };
  },
);

export const DELETE = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const existing = await db.nacProfile.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!existing) throw ApiError.notFound("NAC profile not found");
  await db.nacProfile.delete({ where: { id: existing.id } });
  return {
    data: { ok: true },
    audit: { action: "nac_profile.delete", objectType: "nac_profile", objectId: id, objectName: existing.name },
  };
});

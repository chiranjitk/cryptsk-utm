/**
 * RADIUS CoA profile item (M23, spec 2.10) — update / delete, audit
 * `coa_profile.update|delete`. Partial update; VLAN pool rules are re-checked
 * by the schema refines over the merged-able fields.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { coaProfileUpdateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { assertRadiusProfileExists, toCoaProfileDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "identity", bodySchema: coaProfileUpdateSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await db.radiusCoaProfile.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!existing) throw ApiError.notFound("CoA profile not found");

    const merged = {
      radiusProfileId: body.radiusProfileId !== undefined ? body.radiusProfileId : existing.radiusProfileId,
    };
    await assertRadiusProfileExists(auth.tenantId, merged.radiusProfileId);

    const updated = await db.radiusCoaProfile.update({
      where: { id: existing.id },
      data: {
        name: body.name ?? existing.name,
        radiusProfileId: merged.radiusProfileId,
        coaEnabled: body.coaEnabled ?? existing.coaEnabled,
        dynamicVlan: body.dynamicVlan ?? existing.dynamicVlan,
        vlanPoolStart: body.vlanPoolStart !== undefined ? body.vlanPoolStart : existing.vlanPoolStart,
        vlanPoolEnd: body.vlanPoolEnd !== undefined ? body.vlanPoolEnd : existing.vlanPoolEnd,
        sessionTimeoutMin: body.sessionTimeoutMin ?? existing.sessionTimeoutMin,
        enabled: body.enabled ?? existing.enabled,
      },
    });

    const radiusName = merged.radiusProfileId
      ? (
          await db.radiusProfile.findFirst({
            where: { id: merged.radiusProfileId, tenantId: auth.tenantId },
            select: { name: true },
          })
        )?.name ?? null
      : null;
    const dto = toCoaProfileDTO(updated, radiusName);
    return {
      data: dto,
      audit: {
        action: "coa_profile.update",
        objectType: "radius_coa_profile",
        objectId: id,
        objectName: updated.name,
        before: toCoaProfileDTO(existing, existing.radiusProfileId ? `#${existing.radiusProfileId}` : null),
        after: dto,
      },
    };
  },
);

export const DELETE = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const existing = await db.radiusCoaProfile.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!existing) throw ApiError.notFound("CoA profile not found");
  await db.radiusCoaProfile.delete({ where: { id: existing.id } });
  return {
    data: { ok: true },
    audit: { action: "coa_profile.delete", objectType: "radius_coa_profile", objectId: id, objectName: existing.name },
  };
});

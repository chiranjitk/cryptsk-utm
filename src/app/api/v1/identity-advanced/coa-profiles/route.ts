/**
 * RADIUS CoA profiles (M23, spec 2.10) — GET list + POST create.
 * Area `identity`; mutations audit `coa_profile.create` and snapshot
 * section `identity`. radiusProfileId is validated against radius_profiles.
 */

import { route } from "@/lib/api/handler";
import { coaProfileCreateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { assertRadiusProfileExists, toCoaProfileDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  const [rows, radiusProfiles] = await Promise.all([
    db.radiusCoaProfile.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } }),
    db.radiusProfile.findMany({ where: { tenantId: auth.tenantId }, select: { id: true, name: true } }),
  ]);
  const names = new Map(radiusProfiles.map((r) => [r.id, r.name]));
  return { data: rows.map((row) => toCoaProfileDTO(row, names.get(row.radiusProfileId ?? -1) ?? null)) };
});

export const POST = route(
  { area: "identity", bodySchema: coaProfileCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    await assertRadiusProfileExists(auth.tenantId, body.radiusProfileId);
    const created = await db.radiusCoaProfile.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        radiusProfileId: body.radiusProfileId ?? null,
        coaEnabled: body.coaEnabled,
        dynamicVlan: body.dynamicVlan,
        vlanPoolStart: body.vlanPoolStart ?? null,
        vlanPoolEnd: body.vlanPoolEnd ?? null,
        sessionTimeoutMin: body.sessionTimeoutMin,
        enabled: body.enabled,
      },
    });
    const dto = toCoaProfileDTO(created, null);
    return {
      data: dto,
      audit: { action: "coa_profile.create", objectType: "radius_coa_profile", objectId: created.id, objectName: created.name, after: dto },
    };
  },
);

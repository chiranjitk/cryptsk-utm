/**
 * NAC profiles (M23, spec 2.9) — GET list + POST create. Area `identity`;
 * mutations audit `nac_profile.create` and snapshot section `identity`.
 * The list carries a deviceCount per profile for the view cards.
 */

import { route } from "@/lib/api/handler";
import { nacProfileCreateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { toNacProfileDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  const rows = await db.nacProfile.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } });
  const devices = await db.nacDevice.groupBy({
    by: ["nacProfileId"],
    where: { tenantId: auth.tenantId, nacProfileId: { not: null } },
    _count: { _all: true },
  });
  const counts = new Map(devices.map((d) => [d.nacProfileId, d._count._all]));
  return { data: rows.map((row) => toNacProfileDTO(row, counts.get(row.id) ?? 0)) };
});

export const POST = route(
  { area: "identity", bodySchema: nacProfileCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    const created = await db.nacProfile.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        method: body.method,
        eapType: body.eapType,
        dynamicVlan: body.dynamicVlan,
        guestVlan: body.guestVlan ?? null,
        authFailVlan: body.authFailVlan ?? null,
        profiling: body.profiling,
        byodOnboarding: body.byodOnboarding,
        enabled: body.enabled,
      },
    });
    const dto = toNacProfileDTO(created, 0);
    return {
      data: dto,
      audit: { action: "nac_profile.create", objectType: "nac_profile", objectId: created.id, objectName: created.name, after: dto },
    };
  },
);

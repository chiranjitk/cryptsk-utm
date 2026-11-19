/**
 * NAC profiles (M23, spec 2.9) — GET list + POST create. Guard area `nac`
 * (audit fix #11 — was `identity`): the RBAC matrix gives nac.read to
 * super_admin/tenant_admin/security_admin/network_admin and nac.write to
 * super_admin/tenant_admin/network_admin. Mutations audit `nac_profile.create`
 * and snapshot section `identity`. The list carries a deviceCount per profile
 * for the view cards. Duplicate names 409 (audit fix #25 — missing pre-check).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { nacProfileCreateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { toNacProfileDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const GET = route({ area: "nac" }, async ({ auth }) => {
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
  { area: "nac", bodySchema: nacProfileCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    // audit fix — duplicate-name pre-check (409) before the create
    const dup = await db.nacProfile.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A NAC profile named "${body.name}" already exists`);
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

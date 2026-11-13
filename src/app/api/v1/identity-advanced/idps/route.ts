/**
 * Federated identity providers (M23, spec 2.9) — GET list + POST create.
 * Area `federation`; mutations snapshot section `identity` and audit
 * `idp.create`. clientSecret is write-only (never returned — hasSecret).
 */

import { route } from "@/lib/api/handler";
import { idpCreateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { assertIdpCertUsable, toIdpDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const GET = route({ area: "federation" }, async ({ auth }) => {
  const [rows, certs] = await Promise.all([
    db.federatedIdp.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } }),
    db.certificate.findMany({ where: { tenantId: auth.tenantId }, select: { id: true, name: true } }),
  ]);
  const certNames = new Map(certs.map((c) => [c.id, c.name]));
  return { data: rows.map((row) => toIdpDTO(row, certNames.get(row.idpCertId ?? -1) ?? null)) };
});

export const POST = route(
  { area: "federation", bodySchema: idpCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    await assertIdpCertUsable(auth.tenantId, body.idpCertId);
    const created = await db.federatedIdp.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        protocol: body.protocol,
        entityId: body.entityId ?? null,
        metadataUrl: body.metadataUrl ?? null,
        ssoUrl: body.ssoUrl ?? null,
        clientId: body.clientId ?? null,
        clientSecret: body.clientSecret ?? null,
        idpCertId: body.idpCertId ?? null,
        redirectUri: body.redirectUri ?? null,
        status: "untested",
        enabled: body.enabled,
      },
    });
    const dto = toIdpDTO(created);
    return {
      data: dto,
      audit: { action: "idp.create", objectType: "federated_idp", objectId: created.id, objectName: created.name, after: dto },
    };
  },
);

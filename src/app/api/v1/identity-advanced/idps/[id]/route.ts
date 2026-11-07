/**
 * Federated IdP item (M23, spec 2.9) — update / delete, audit
 * `idp.update|delete`. clientSecret: null or omitted keeps the stored secret;
 * a non-null string replaces it. Cross-field SAML2/OIDC rules are re-checked
 * against the merged record.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { idpSemanticError, idpUpdateSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { assertIdpCertUsable, toIdpDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "federation", bodySchema: idpUpdateSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const existing = await db.federatedIdp.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!existing) throw ApiError.notFound("IdP not found");
    await assertIdpCertUsable(auth.tenantId, body.idpCertId);

    const merged = {
      name: body.name ?? existing.name,
      protocol: body.protocol ?? existing.protocol,
      entityId: body.entityId !== undefined ? body.entityId : existing.entityId,
      metadataUrl: body.metadataUrl !== undefined ? body.metadataUrl : existing.metadataUrl,
      ssoUrl: body.ssoUrl !== undefined ? body.ssoUrl : existing.ssoUrl,
      clientId: body.clientId !== undefined ? body.clientId : existing.clientId,
      // null / omitted → keep the stored secret (write-only secret rule)
      clientSecret: body.clientSecret != null && body.clientSecret !== "" ? body.clientSecret : existing.clientSecret,
      idpCertId: body.idpCertId !== undefined ? body.idpCertId : existing.idpCertId,
      redirectUri: body.redirectUri !== undefined ? body.redirectUri : existing.redirectUri,
      enabled: body.enabled ?? existing.enabled,
    };
    const semantic = idpSemanticError(merged);
    if (semantic) throw ApiError.validation(semantic);

    const updated = await db.federatedIdp.update({
      where: { id: existing.id },
      data: {
        name: merged.name,
        protocol: merged.protocol,
        entityId: merged.entityId,
        metadataUrl: merged.metadataUrl,
        ssoUrl: merged.ssoUrl,
        clientId: merged.clientId,
        clientSecret: merged.clientSecret,
        idpCertId: merged.idpCertId,
        redirectUri: merged.redirectUri,
        enabled: merged.enabled,
      },
    });
    const dto = toIdpDTO(updated);
    return {
      data: dto,
      audit: { action: "idp.update", objectType: "federated_idp", objectId: id, objectName: updated.name, before: toIdpDTO(existing), after: dto },
    };
  },
);

export const DELETE = route({ area: "federation", section: "identity" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const existing = await db.federatedIdp.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!existing) throw ApiError.notFound("IdP not found");
  await db.federatedIdp.delete({ where: { id: existing.id } });
  return {
    data: { ok: true },
    audit: { action: "idp.delete", objectType: "federated_idp", objectId: id, objectName: existing.name, before: toIdpDTO(existing) },
  };
});

/**
 * CA detail (M14) — GET one (sanitized), PUT name/crlUrl/ocspUrl/autoRenew,
 * DELETE only while the CA has issued no certificates and no subordinates
 * (409 CONFLICT otherwise). Key material never appears in JSON responses.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { caUpdateSchema } from "@/lib/validators/pki";
import { sanitizeCa } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

function parseId(raw: string): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.notFound("CA not found");
  return id;
}

export const GET = route({ area: "pki" }, async ({ auth, params }) => {
  const id = parseId(params.id ?? "");
  const ca = await db.certificateAuthority.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!ca) throw ApiError.notFound("CA not found");
  const [issuedCount, parent] = await Promise.all([
    db.certificate.count({ where: { caId: id } }),
    ca.parentCaId
      ? db.certificateAuthority.findFirst({ where: { id: ca.parentCaId, tenantId: auth.tenantId }, select: { name: true } })
      : Promise.resolve(null),
  ]);
  return { data: sanitizeCa(ca, issuedCount, parent?.name ?? null) };
});

export const PUT = route(
  { area: "pki", bodySchema: caUpdateSchema, section: "pki" },
  async ({ auth, params, body }) => {
    const id = parseId(params.id ?? "");
    const ca = await db.certificateAuthority.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!ca) throw ApiError.notFound("CA not found");

    const updated = await db.certificateAuthority.update({
      where: { id: ca.id },
      data: {
        ...(body.name !== undefined ? { name: body.name } : {}),
        ...(body.crlUrl !== undefined ? { crlUrl: body.crlUrl ?? null } : {}),
        ...(body.ocspUrl !== undefined ? { ocspUrl: body.ocspUrl ?? null } : {}),
        ...(body.autoRenew !== undefined ? { autoRenew: body.autoRenew } : {}),
      },
    });

    const before = sanitizeCa(ca);
    const after = sanitizeCa(updated);
    return {
      data: after,
      audit: { action: "pki_ca.update", objectType: "pki_ca", objectId: id, objectName: updated.name, before, after },
    };
  },
);

export const DELETE = route({ area: "pki", section: "pki" }, async ({ auth, params }) => {
  const id = parseId(params.id ?? "");
  const ca = await db.certificateAuthority.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!ca) throw ApiError.notFound("CA not found");

  const issued = await db.certificate.count({ where: { caId: id } });
  if (issued > 0) {
    throw ApiError.conflict(`CA has issued ${issued} certificate(s) — revoke and delete them first`, {
      issued,
    });
  }
  const subordinates = await db.certificateAuthority.count({ where: { parentCaId: id, tenantId: auth.tenantId } });
  if (subordinates > 0) {
    throw ApiError.conflict(`CA has ${subordinates} subordinate CA(s) — delete them first`, {
      subordinates,
    });
  }

  const before = sanitizeCa(ca);
  await db.certificateAuthority.delete({ where: { id: ca.id } });
  return {
    data: { ok: true },
    audit: { action: "pki_ca.delete", objectType: "pki_ca", objectId: id, objectName: ca.name, before },
  };
});

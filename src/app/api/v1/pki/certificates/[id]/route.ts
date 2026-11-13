/**
 * Certificate detail (M14) — GET one (incl. public certPem, NEVER keyPem) and
 * DELETE with the soft rule: only revoked or expired certificates may be
 * deleted; active ones answer 409 CONFLICT. Deleting also clears the
 * certificate's CertRevocation ledger rows.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { statusOf } from "@/lib/pki/x509";
import { sanitizeCert } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

function parseId(raw: string): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.notFound("Certificate not found");
  return id;
}

export const GET = route({ area: "pki" }, async ({ auth, params }) => {
  const id = parseId(params.id ?? "");
  const cert = await db.certificate.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!cert) throw ApiError.notFound("Certificate not found");
  const ca = await db.certificateAuthority.findFirst({
    where: { id: cert.caId, tenantId: auth.tenantId },
    select: { name: true },
  });
  return { data: sanitizeCert(cert, ca?.name ?? null) };
});

export const DELETE = route({ area: "pki", section: "pki" }, async ({ auth, params }) => {
  const id = parseId(params.id ?? "");
  const cert = await db.certificate.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!cert) throw ApiError.notFound("Certificate not found");

  const status = statusOf(cert.notAfter, cert.status === "revoked");
  if (status === "active") {
    throw ApiError.conflict("Only revoked or expired certificates can be deleted — revoke it first");
  }

  const before = sanitizeCert(cert);
  await db.$transaction([
    db.certRevocation.deleteMany({ where: { certId: cert.id } }),
    db.certificate.delete({ where: { id: cert.id } }),
  ]);

  return {
    data: { ok: true },
    audit: { action: "pki_certificate.delete", objectType: "pki_certificate", objectId: id, objectName: cert.name, before },
  };
});

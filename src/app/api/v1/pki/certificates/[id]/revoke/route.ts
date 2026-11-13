/**
 * POST /api/v1/pki/certificates/[id]/revoke (M14) — flips status to revoked,
 * stores the reason and appends a CertRevocation ledger row (which feeds the
 * CA's real signed CRL via /api/v1/pki/cas/[id]/crl).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { certRevokeSchema } from "@/lib/validators/pki";
import { sanitizeCert } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "pki", bodySchema: certRevokeSchema, section: "pki" },
  async ({ auth, params, body }) => {
    const id = Number.parseInt(params.id ?? "", 10);
    if (!Number.isInteger(id) || id <= 0) throw ApiError.notFound("Certificate not found");
    const cert = await db.certificate.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!cert) throw ApiError.notFound("Certificate not found");
    if (cert.status === "revoked") throw ApiError.conflict("Certificate is already revoked");

    const updated = await db.certificate.update({
      where: { id: cert.id },
      data: { status: "revoked", revocationReason: body.reason },
    });
    await db.certRevocation.create({
      data: { tenantId: auth.tenantId, certId: cert.id, caId: cert.caId, serial: cert.serial, reason: body.reason },
    });

    return {
      data: sanitizeCert(updated),
      audit: {
        action: "pki_certificate.revoke",
        objectType: "pki_certificate",
        objectId: id,
        objectName: cert.name,
        before: { status: cert.status },
        after: { status: "revoked", reason: body.reason },
      },
    };
  },
);

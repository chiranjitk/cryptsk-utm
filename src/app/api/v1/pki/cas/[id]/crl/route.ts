/**
 * GET /api/v1/pki/cas/[id]/crl (M14) — real signed CRL for the CA, built from
 * the CertRevocation ledger via buildCrl() (RFC 5280 CertificateList, signed
 * with the CA key; see lib/pki/x509 — forge has no CRL API, the DER is
 * assembled and signed by hand). `nextUpdateDays` tunes the window.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { buildCrl, crlReasonCode } from "@/lib/pki/x509";
import { crlQuerySchema } from "@/lib/validators/pki";
import { pemResponse, slugFilename } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "pki", querySchema: crlQuerySchema }, async ({ auth, params, query }) => {
  const id = Number.parseInt(params.id ?? "", 10);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.notFound("CA not found");
  const ca = await db.certificateAuthority.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!ca) throw ApiError.notFound("CA not found");
  if (!ca.keyPem) throw ApiError.conflict("CA has no signing key material");

  const revoked = await db.certRevocation.findMany({ where: { caId: id }, orderBy: { revokedAt: "asc" } });
  const crlPem = buildCrl(
    { certPem: ca.certPem, keyPem: ca.keyPem },
    revoked.map((r) => ({ serial: r.serial, date: r.revokedAt, reasonCode: crlReasonCode(r.reason) })),
    query.nextUpdateDays,
    revoked.length + 1, // crlNumber advances with ledger size
  );

  return { data: pemResponse(crlPem, `${slugFilename(ca.name)}.crl`, "application/pkix-crl") };
});

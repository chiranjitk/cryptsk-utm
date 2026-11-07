/**
 * POST /api/v1/pki/cas/[id]/revoke (M14) — marks the CA revoked (stored status
 * column). Recomputation on read keeps the status badge authoritative even
 * after expiry. Revoking a CA does not touch already-issued certificates.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { sanitizeCa } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

export const POST = route({ area: "pki", section: "pki" }, async ({ auth, params }) => {
  const id = Number.parseInt(params.id ?? "", 10);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.notFound("CA not found");
  const ca = await db.certificateAuthority.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!ca) throw ApiError.notFound("CA not found");
  if (ca.status === "revoked") throw ApiError.conflict("CA is already revoked");

  const updated = await db.certificateAuthority.update({ where: { id: ca.id }, data: { status: "revoked" } });
  const issued = await db.certificate.count({ where: { caId: id } });

  return {
    data: sanitizeCa(updated, issued),
    audit: {
      action: "pki_ca.revoke",
      objectType: "pki_ca",
      objectId: id,
      objectName: ca.name,
      before: { status: ca.status },
      after: { status: "revoked" },
    },
  };
});

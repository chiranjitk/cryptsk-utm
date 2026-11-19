/**
 * GET /api/v1/pki/cas/[id]/export?part=cert|key|chain (M14) — PEM download.
 * SECURITY: part=key carries the CA private key and is admin-class
 * (super_admin/tenant_admin only — enforced in-handler; `admin: true` marks
 * the route admin-class per the RBAC matrix). part=chain concatenates the CA
 * with its parent chain up to the root.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { writeAudit } from "@/lib/api/audit";
import { db } from "@/lib/db";
import { pkiPartQuerySchema } from "@/lib/validators/pki";
import { caChainPems, pemResponse, requireKeyAdmin, slugFilename } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "pki", querySchema: pkiPartQuerySchema, admin: true },
  async ({ auth, params, query, ip }) => {
    const id = Number.parseInt(params.id ?? "", 10);
    if (!Number.isInteger(id) || id <= 0) throw ApiError.notFound("CA not found");
    const ca = await db.certificateAuthority.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!ca) throw ApiError.notFound("CA not found");

    const slug = slugFilename(ca.name);
    if (query.part === "key") {
      requireKeyAdmin(auth.role);
      if (!ca.keyPem) throw ApiError.conflict("CA has no private key material");
      // audit fix M7 — private-key export is the single most sensitive action
      // in the PKI module and MUST leave an audit trail. This is a GET, so
      // the shared handler's isMutation audit never fires (matching the
      // radius/ha reveal convention, which are POSTs for the same reason):
      // write the audit row explicitly, before the PEM leaves the server.
      await writeAudit({
        tenantId: auth.tenantId,
        userId: auth.userId,
        username: auth.username,
        sourceIp: ip,
        info: {
          action: "pki_ca.key_export",
          objectType: "certificate_authority",
          objectId: ca.id,
          objectName: ca.name,
          result: "success",
        },
      }).catch((err: unknown) =>
        console.error(`[pki] CA key export audit write failed (ca ${ca.id}):`, err instanceof Error ? err.message : err),
      );
      return { data: pemResponse(ca.keyPem, `${slug}.key`) };
    }

    if (query.part === "chain") {
      const chain = await caChainPems(auth.tenantId, id);
      if (chain.length === 0) throw ApiError.conflict("CA has no certificate material");
      return { data: pemResponse(chain.join("\n"), `${slug}-chain.pem`) };
    }

    if (!ca.certPem) throw ApiError.conflict("CA has no certificate material");
    return { data: pemResponse(ca.certPem, `${slug}.crt`) };
  },
);

/**
 * WAF virtual hosts (M17 §2.4.1) — GET list + POST create.
 * Mutations audit `waf.vhost.create` and snapshot section `waf`.
 * certId is validated server-side: the certificate must exist, be active
 * (status + not expired) and be issuedFor `waf` | `general`.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { vhostCreateSchema } from "@/lib/validators/waf";
import { assertCertUsable, listVhosts } from "@/app/api/v1/waf/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "waf" }, async ({ auth }) => {
  return { data: await listVhosts(auth.tenantId) };
});

export const POST = route(
  { area: "waf", bodySchema: vhostCreateSchema, section: "waf" },
  async ({ auth, body }) => {
    // FQDN uniqueness is a business rule (tenantId, hostname) — P2002 also
    // maps to 409 via the handler, but a friendly message reads better.
    const dup = await db.wafVhost.findFirst({
      where: { tenantId: auth.tenantId, hostname: body.hostname },
      select: { id: true },
    });
    if (dup) throw ApiError.conflict(`A vhost for "${body.hostname}" already exists`);

    const certId = await assertCertUsable(auth.tenantId, body.certId ?? null, body.tls);

    const created = await db.wafVhost.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        hostname: body.hostname,
        backendHost: body.backendHost,
        backendPort: body.backendPort,
        listenPort: body.listenPort,
        tls: body.tls,
        certId,
        mode: body.mode,
        enabled: body.enabled,
      },
    });
    return {
      data: created,
      audit: {
        action: "waf.vhost.create",
        objectType: "waf_vhost",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

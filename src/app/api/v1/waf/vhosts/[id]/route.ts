/**
 * WAF vhost item (M17 §2.4.1) — update / delete, audit `waf.vhost.update|delete`.
 * DELETE is blocked with 409 while a WafPolicy references the vhost.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { vhostUpdateSchema } from "@/lib/validators/waf";
import { assertCertUsable } from "@/app/api/v1/waf/shared";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "waf", bodySchema: vhostUpdateSchema, section: "waf" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await db.wafVhost.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!existing) throw ApiError.notFound("Vhost not found");

    if (body.hostname !== undefined && body.hostname !== existing.hostname) {
      const dup = await db.wafVhost.findFirst({
        where: { tenantId: auth.tenantId, hostname: body.hostname },
        select: { id: true },
      });
      if (dup) throw ApiError.conflict(`A vhost for "${body.hostname}" already exists`);
    }

    // tls / certId resolution: a newly provided certId is (re-)validated; when
    // tls flips off the binding is dropped; otherwise the binding persists.
    const tls = body.tls ?? existing.tls;
    let certId = existing.certId;
    if (body.certId !== undefined) {
      certId = await assertCertUsable(auth.tenantId, body.certId ?? null, tls);
    } else if (!tls) {
      certId = null;
    }

    const updated = await db.wafVhost.update({
      where: { id },
      data: {
        ...(body.name !== undefined ? { name: body.name } : {}),
        ...(body.hostname !== undefined ? { hostname: body.hostname } : {}),
        ...(body.backendHost !== undefined ? { backendHost: body.backendHost } : {}),
        ...(body.backendPort !== undefined ? { backendPort: body.backendPort } : {}),
        ...(body.listenPort !== undefined ? { listenPort: body.listenPort } : {}),
        tls,
        certId,
        ...(body.mode !== undefined ? { mode: body.mode } : {}),
        ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      },
    });
    return {
      data: updated,
      audit: {
        action: "waf.vhost.update",
        objectType: "waf_vhost",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "waf", section: "waf" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const existing = await db.wafVhost.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!existing) throw ApiError.notFound("Vhost not found");

  const referencing = await db.wafPolicy.findFirst({
    where: { tenantId: auth.tenantId, vhostId: id },
    select: { id: true, name: true },
  });
  if (referencing) {
    throw ApiError.conflict("Vhost is protected by a WAF policy — delete the policy first", {
      referencedBy: [{ type: "policy", name: referencing.name }],
    });
  }

  await db.wafVhost.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "waf.vhost.delete",
      objectType: "waf_vhost",
      objectId: id,
      objectName: existing.name,
    },
  };
});

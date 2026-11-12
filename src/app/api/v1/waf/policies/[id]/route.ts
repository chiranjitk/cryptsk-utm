/**
 * WAF policy item (M17 §2.4.2) — update / delete, audit `waf.policy.update|delete`.
 * DELETE cascades the policy's exclusions. Moving a policy to another vhost
 * re-checks the one-policy-per-vhost rule (excluding itself).
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { policyUpdateSchema } from "@/lib/validators/waf";
import { policyOr404, shapePolicy } from "@/app/api/v1/waf/shared";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "waf", bodySchema: policyUpdateSchema, section: "waf" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await policyOr404(auth.tenantId, id);
    if (body.vhostId !== undefined && body.vhostId !== existing.vhostId) {
      const vhost = await db.wafVhost.findFirst({
        where: { id: body.vhostId, tenantId: auth.tenantId },
        select: { id: true, name: true },
      });
      if (!vhost) throw ApiError.notFound("Vhost not found for this tenant");
      const dup = await db.wafPolicy.findFirst({
        where: { tenantId: auth.tenantId, vhostId: body.vhostId, id: { not: id } },
        select: { id: true },
      });
      if (dup) throw ApiError.conflict("Vhost already has a WAF policy (one policy per vhost)");
    }

    const updated = await db.wafPolicy.update({
      where: { id },
      data: {
        ...(body.name !== undefined ? { name: body.name } : {}),
        ...(body.vhostId !== undefined ? { vhostId: body.vhostId } : {}),
        ...(body.owaspCrsEnabled !== undefined ? { owaspCrsEnabled: body.owaspCrsEnabled } : {}),
        ...(body.crsVersion !== undefined ? { crsVersion: body.crsVersion } : {}),
        ...(body.paranoiaLevel !== undefined ? { paranoiaLevel: body.paranoiaLevel } : {}),
        ...(body.anomalyInThreshold !== undefined ? { anomalyInThreshold: body.anomalyInThreshold } : {}),
        ...(body.anomalyOutThreshold !== undefined ? { anomalyOutThreshold: body.anomalyOutThreshold } : {}),
        ...(body.learningMode !== undefined ? { learningMode: body.learningMode } : {}),
        ...(body.geoBlockCountries !== undefined
          ? { geoBlockCountries: JSON.stringify(body.geoBlockCountries) }
          : {}),
        ...(body.rateLimitRpm !== undefined ? { rateLimitRpm: body.rateLimitRpm ?? null } : {}),
        ...(body.rateLimitBurst !== undefined ? { rateLimitBurst: body.rateLimitBurst ?? null } : {}),
        ...(body.apiProtection !== undefined ? { apiProtection: body.apiProtection } : {}),
        ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      },
    });
    return {
      data: shapePolicy(updated),
      audit: {
        action: "waf.policy.update",
        objectType: "waf_policy",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "waf", section: "waf" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const existing = await policyOr404(auth.tenantId, id);

  await db.wafExclusion.deleteMany({ where: { tenantId: auth.tenantId, policyId: id } });
  await db.wafPolicy.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "waf.policy.delete",
      objectType: "waf_policy",
      objectId: id,
      objectName: existing.name,
    },
  };
});

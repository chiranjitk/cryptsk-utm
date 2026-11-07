/**
 * WAF policies (M17 §2.4.2) — GET list + POST create.
 * One policy per vhost (unique tenantId+vhostId as a business rule → 409 on
 * duplicates). Mutations audit `waf.policy.create` and snapshot section `waf`.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { policyCreateSchema } from "@/lib/validators/waf";
import { listPolicies, shapePolicy } from "@/app/api/v1/waf/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "waf" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "waf", bodySchema: policyCreateSchema, section: "waf" },
  async ({ auth, body }) => {
    const vhost = await db.wafVhost.findFirst({
      where: { id: body.vhostId, tenantId: auth.tenantId },
      select: { id: true, name: true, hostname: true },
    });
    if (!vhost) throw ApiError.notFound("Vhost not found for this tenant");

    const dup = await db.wafPolicy.findFirst({
      where: { tenantId: auth.tenantId, vhostId: body.vhostId },
      select: { id: true },
    });
    if (dup) {
      throw ApiError.conflict(`Vhost already has a WAF policy (one policy per vhost)`, {
        referencedBy: [{ type: "policy", name: String(dup.id) }],
      });
    }

    const created = await db.wafPolicy.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        vhostId: body.vhostId,
        owaspCrsEnabled: body.owaspCrsEnabled,
        crsVersion: body.crsVersion,
        paranoiaLevel: body.paranoiaLevel,
        anomalyInThreshold: body.anomalyInThreshold,
        anomalyOutThreshold: body.anomalyOutThreshold,
        learningMode: body.learningMode,
        geoBlockCountries: JSON.stringify(body.geoBlockCountries),
        rateLimitRpm: body.rateLimitRpm ?? null,
        rateLimitBurst: body.rateLimitBurst ?? null,
        apiProtection: body.apiProtection,
        enabled: body.enabled,
      },
    });
    return {
      data: shapePolicy(created, vhost),
      audit: {
        action: "waf.policy.create",
        objectType: "waf_policy",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

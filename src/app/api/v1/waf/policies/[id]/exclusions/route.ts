/**
 * WAF policy exclusions (M17 §2.4.3) — GET list + POST create under
 * /policies/[id]. Mutations audit `waf.exclusion.create`, section `waf`.
 */

import { route, numericId } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { exclusionCreateSchema } from "@/lib/validators/waf";
import { policyOr404, shapeExclusion } from "../../../shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "waf" }, async ({ auth, params }) => {
  const policyId = numericId(params, "id");
  await policyOr404(auth.tenantId, policyId);
  const rows = await db.wafExclusion.findMany({
    where: { tenantId: auth.tenantId, policyId },
    orderBy: { id: "asc" },
  });
  return { data: rows.map(shapeExclusion) };
});

export const POST = route(
  { area: "waf", bodySchema: exclusionCreateSchema, section: "waf" },
  async ({ auth, body, params }) => {
    const policyId = numericId(params, "id");
    await policyOr404(auth.tenantId, policyId);
    const created = await db.wafExclusion.create({
      data: {
        tenantId: auth.tenantId,
        policyId,
        scope: body.scope,
        matchValue: body.matchValue,
        ruleId: body.ruleId ?? null,
        note: body.note ?? null,
        enabled: body.enabled,
      },
    });
    return {
      data: shapeExclusion(created),
      audit: {
        action: "waf.exclusion.create",
        objectType: "waf_exclusion",
        objectId: created.id,
        objectName: created.matchValue,
        after: created,
      },
    };
  },
);

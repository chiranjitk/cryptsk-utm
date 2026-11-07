/**
 * WAF policy exclusion item (M17 §2.4.3) — update / delete under
 * /policies/[id]/exclusions/[exclusionId], audit `waf.exclusion.update|delete`.
 * The exclusion must belong to the given policy (and tenant) → 404 otherwise.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { exclusionUpdateSchema } from "@/lib/validators/waf";
import { policyOr404, shapeExclusion } from "../../../../shared";

export const dynamic = "force-dynamic";

/** Resolve the exclusion scoped to (tenant, policy, exclusionId) or 404. */
async function exclusionOr404(tenantId: number, policyId: number, exclusionId: number) {
  const row = await db.wafExclusion.findFirst({
    where: { id: exclusionId, tenantId, policyId },
  });
  if (!row) throw ApiError.notFound("Exclusion not found for this policy");
  return row;
}

export const PUT = route(
  { area: "waf", bodySchema: exclusionUpdateSchema, section: "waf" },
  async ({ auth, body, params }) => {
    const policyId = Number(params.id);
    const exclusionId = Number(params.exclusionId);
    await policyOr404(auth.tenantId, policyId);
    await exclusionOr404(auth.tenantId, policyId, exclusionId);

    const updated = await db.wafExclusion.update({
      where: { id: exclusionId },
      data: {
        ...(body.scope !== undefined ? { scope: body.scope } : {}),
        ...(body.matchValue !== undefined ? { matchValue: body.matchValue } : {}),
        ...(body.ruleId !== undefined ? { ruleId: body.ruleId ?? null } : {}),
        ...(body.note !== undefined ? { note: body.note ?? null } : {}),
        ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      },
    });
    return {
      data: shapeExclusion(updated),
      audit: {
        action: "waf.exclusion.update",
        objectType: "waf_exclusion",
        objectId: exclusionId,
        objectName: updated.matchValue,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "waf", section: "waf" }, async ({ auth, params }) => {
  const policyId = Number(params.id);
  const exclusionId = Number(params.exclusionId);
  await policyOr404(auth.tenantId, policyId);
  const existing = await exclusionOr404(auth.tenantId, policyId, exclusionId);

  await db.wafExclusion.delete({ where: { id: exclusionId } });
  return {
    data: { ok: true },
    audit: {
      action: "waf.exclusion.delete",
      objectType: "waf_exclusion",
      objectId: exclusionId,
      objectName: existing.matchValue,
    },
  };
});

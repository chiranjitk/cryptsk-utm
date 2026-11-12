/**
 * Per-policy web category rules (M16 §2.3.2) — GET returns the joined 13-row
 * view (stored rules merged over the locked category enum; implicit rows are
 * flagged `configured: false`). PUT replaces the full rule set in one
 * transaction (delete-then-create upsert semantics; unique tenant+policy+
 * category). Audit `url_filter.category_rules.replace`.
 */

import { route, numericId } from "@/lib/api/handler";
import { categoryRulesPutSchema } from "@/lib/validators/url-filter";
import { listCategoryRules, replaceCategoryRules } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "url_filter" }, async ({ auth, params }) => {
  const policyId = numericId(params, "id");
  return { data: await listCategoryRules(auth.tenantId, policyId) };
});

export const PUT = route(
  { area: "url_filter", bodySchema: categoryRulesPutSchema, section: "url_filter" },
  async ({ auth, body, params }) => {
    const policyId = numericId(params, "id");
    const rules = await replaceCategoryRules(auth.tenantId, policyId, body.rules);
    return {
      data: rules,
      audit: {
        action: "url_filter.category_rules.replace",
        objectType: "url_category_rule",
        objectId: policyId,
        after: { policyId, count: rules.filter((r) => r.configured).length },
      },
    };
  },
);

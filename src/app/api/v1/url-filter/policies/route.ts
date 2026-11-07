/**
 * URL filter policies (M16 §2.3.1) — GET list + POST create.
 * Mutations audit `url_filter.policy.create` and snapshot section `url_filter`.
 */

import { route } from "@/lib/api/handler";
import { policyCreateSchema } from "@/lib/validators/url-filter";
import { createPolicy, listPolicies } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "url_filter" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "url_filter", bodySchema: policyCreateSchema, section: "url_filter" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "url_filter.policy.create",
        objectType: "url_filter_policy",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

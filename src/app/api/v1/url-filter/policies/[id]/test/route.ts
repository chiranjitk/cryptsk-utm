/**
 * POST /api/v1/url-filter/policies/[id]/test — simulated decision engine
 * (M16 §2.3.4). MISSING-ROUTE FIX: the UI's "Test URL" card already called
 * this endpoint; the route itself never existed (404). Wires the existing
 * service testUrl with urlTestSchema; the decision is recorded in
 * url_filter_logs. Audit `url_filter.policy.test`, section `url_filter`.
 */

import { route, numericId } from "@/lib/api/handler";
import { urlTestSchema } from "@/lib/validators/url-filter";
import { testUrl } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "url_filter", bodySchema: urlTestSchema, section: "url_filter" },
  async ({ auth, body, params, ip }) => {
    const id = numericId(params, "id");
    const result = await testUrl(auth.tenantId, id, body.url, ip);
    return {
      data: result,
      audit: {
        action: "url_filter.policy.test",
        objectType: "url_filter_policy",
        objectId: id,
        objectName: body.url.slice(0, 128),
        after: result,
      },
    };
  },
);

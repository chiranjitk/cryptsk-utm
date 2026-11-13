/**
 * Import-by-paste for custom lists (M16 §2.3.3) — newline-separated values;
 * blanks/comments/invalids/duplicates are skipped, matchType inferred per
 * line, ≤500 rows created per call. Returns { created, skipped }. Audit
 * `url_filter.custom_list.import`.
 */

import { route } from "@/lib/api/handler";
import { customListImportSchema } from "@/lib/validators/url-filter";
import { importCustomLists } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "url_filter", bodySchema: customListImportSchema, section: "url_filter" },
  async ({ auth, body }) => {
    const result = await importCustomLists(auth.tenantId, body);
    return {
      data: result,
      audit: {
        action: "url_filter.custom_list.import",
        objectType: "url_custom_list",
        objectId: body.policyId,
        after: { policyId: body.policyId, listType: body.listType, ...result },
      },
    };
  },
);

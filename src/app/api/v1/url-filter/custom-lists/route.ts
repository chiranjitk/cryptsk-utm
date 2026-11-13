/**
 * Custom block/allow lists (M16 §2.3.3) — GET list (?policyId&listType
 * filters) + POST single entry. Mutations audit `url_filter.custom_list.create`
 * and snapshot section `url_filter`.
 */

import { route } from "@/lib/api/handler";
import { customListCreateSchema, customListQuerySchema } from "@/lib/validators/url-filter";
import { createCustomList, listCustomLists } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "url_filter", querySchema: customListQuerySchema },
  async ({ auth, query }) => {
    return { data: await listCustomLists(auth.tenantId, query) };
  },
);

export const POST = route(
  { area: "url_filter", bodySchema: customListCreateSchema, section: "url_filter" },
  async ({ auth, body }) => {
    const created = await createCustomList(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "url_filter.custom_list.create",
        objectType: "url_custom_list",
        objectId: created.id,
        objectName: created.value,
        after: created,
      },
    };
  },
);

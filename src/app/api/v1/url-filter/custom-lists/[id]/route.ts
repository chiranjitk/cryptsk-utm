/** Custom list entry (M16 §2.3.3) — delete, audit `url_filter.custom_list.delete`. */

import { route, numericId } from "@/lib/api/handler";
import { deleteCustomList } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "url_filter", section: "url_filter" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteCustomList(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "url_filter.custom_list.delete", objectType: "url_custom_list", objectId: id },
  };
});

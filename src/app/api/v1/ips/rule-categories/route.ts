/**
 * /api/v1/ips/rule-categories — ET category list for the editor matrix
 * (M04 §4). Static catalog; enabled state lives on each policy's
 * ruleCategories map.
 */

import { route } from "@/lib/api/handler";
import { CATEGORY_CATALOG } from "@/lib/ips/catalog";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ips_policies" }, async () => {
  return {
    data: {
      categories: CATEGORY_CATALOG.map((c) => ({
        name: c.name,
        label: c.label,
        baseSeverity: c.baseSeverity,
        family: c.family,
        sidRange: `${c.sidBase + 1}–${c.sidBase + 9999}`,
        description: c.description,
      })),
      total: CATEGORY_CATALOG.length,
    },
  };
});

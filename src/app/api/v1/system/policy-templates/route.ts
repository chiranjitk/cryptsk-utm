/** GET /api/v1/system/policy-templates — static per-vertical catalog (M10 §5.8). */

import { route } from "@/lib/api/handler";
import { POLICY_TEMPLATES } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "system" }, async () => {
  return { data: POLICY_TEMPLATES };
});

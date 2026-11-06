/** GET /api/v1/ha/status — simulated local + peer state (M10 §3/§4). */

import { route } from "@/lib/api/handler";
import { getHaStatus } from "@/lib/ha/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ha" }, async ({ auth }) => {
  return { data: await getHaStatus(auth.tenantId) };
});

/** GET /api/v1/system/status — appliance health strip payload (M10 §3). */

import { route } from "@/lib/api/handler";
import { getSystemStatus } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "system" }, async ({ auth }) => {
  return { data: await getSystemStatus(auth.tenantId) };
});

/** GET /api/v1/system/firmware — firmware state (M10 §5.6). */

import { route } from "@/lib/api/handler";
import { getFirmware } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firmware" }, async ({ auth }) => {
  return { data: await getFirmware(auth.tenantId) };
});

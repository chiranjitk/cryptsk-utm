/** POST /api/v1/system/firmware/check — simulated update check (M10 §5.6). */

import { route } from "@/lib/api/handler";
import { firmwareCheckSchema } from "@/lib/validators/system";
import { checkFirmware } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "firmware", bodySchema: firmwareCheckSchema, section: "system" },
  async ({ auth }) => {
    const firmware = await checkFirmware(auth.tenantId);
    return {
      data: firmware,
      audit: {
        action: "firmware.check",
        objectType: "firmware",
        after: { available: firmware.available, lastCheckAt: firmware.lastCheckAt },
      },
    };
  },
);

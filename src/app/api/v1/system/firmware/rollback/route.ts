/** POST /api/v1/system/firmware/rollback — 409 when history < 2 (M10 §5.6). */

import { route } from "@/lib/api/handler";
import { firmwareRollbackSchema } from "@/lib/validators/system";
import { rollbackFirmware } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "firmware", bodySchema: firmwareRollbackSchema, section: "system" },
  async ({ auth }) => {
    const firmware = await rollbackFirmware(auth.tenantId);
    return {
      data: firmware,
      audit: {
        action: "firmware.rollback",
        objectType: "firmware",
        after: { current: firmware.current },
      },
    };
  },
);

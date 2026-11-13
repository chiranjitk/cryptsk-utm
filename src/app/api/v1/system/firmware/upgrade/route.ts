/**
 * POST /api/v1/system/firmware/upgrade — staged upgrade, simulated (M10 §5.6):
 * safety backup first, then version bump + history entry; audited.
 */

import { route } from "@/lib/api/handler";
import { firmwareUpgradeSchema } from "@/lib/validators/system";
import { upgradeFirmware } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "firmware", bodySchema: firmwareUpgradeSchema, section: "system" },
  async ({ auth }) => {
    const { firmware, safetyBackupId } = await upgradeFirmware(auth.tenantId);
    return {
      data: firmware,
      audit: {
        action: "firmware.upgrade",
        objectType: "firmware",
        after: { current: firmware.current, safetyBackupId },
      },
    };
  },
);

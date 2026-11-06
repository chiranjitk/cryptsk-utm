/**
 * POST /api/v1/system/setup/complete — mark the first-time-setup wizard done
 * (M10 §4 `#/setup`): sets SystemSetting system/setup {completed: true};
 * section system → `config:updated {section:"system"}` re-evaluates the gate.
 */

import { route } from "@/lib/api/handler";
import { setupCompleteSchema } from "@/lib/validators/system";
import { completeSetup } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "system", admin: true, bodySchema: setupCompleteSchema, section: "system" },
  async ({ auth }) => {
    const completed = await completeSetup(auth.tenantId);
    return {
      data: { completed },
      audit: {
        action: "setup.complete",
        objectType: "system_setup",
        after: { completed: true },
      },
    };
  },
);

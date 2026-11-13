/**
 * /api/v1/ips/update-settings — ET rule auto-update scheduler (M04 §4,
 * "Rule Updates" card). Persists to the `ips/auto_update` SystemSetting;
 * GET simulates the update cycle when the next-run window has passed.
 */

import { route } from "@/lib/api/handler";
import { ipsUpdateSettingsBodySchema } from "@/lib/validators/ips";
import { getUpdateSettings, putUpdateSettings, runUpdateNow } from "@/lib/ips/service";
import { z } from "zod";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ips_policies" }, async ({ auth }) => {
  return { data: await getUpdateSettings(auth.tenantId) };
});

export const PUT = route(
  { area: "ips_policies", bodySchema: ipsUpdateSettingsBodySchema, section: "ips" },
  async ({ auth, body }) => {
    const next = await putUpdateSettings(auth.tenantId, body);
    return {
      data: next,
      audit: {
        action: "ips_update_settings.save",
        objectType: "ips_update_settings",
        objectName: "auto_update",
        after: { enabled: next.enabled, interval: next.interval, time: next.time },
      },
    };
  },
);

/** "Run update now" — simulated refresh: bumps lastUpdateAt, recomputes next. */
export const POST = route(
  { area: "ips_policies", bodySchema: z.object({}).default({}), section: "ips" },
  async ({ auth }) => {
    const next = await runUpdateNow(auth.tenantId);
    return {
      data: next,
      audit: {
        action: "ips_update_settings.run_now",
        objectType: "ips_update_settings",
        objectName: "auto_update",
      },
    };
  },
);

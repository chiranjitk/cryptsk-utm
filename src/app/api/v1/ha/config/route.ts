/** GET/PUT /api/v1/ha/config — HA singleton (M10 §3); PUT snapshots section ha. */

import { route } from "@/lib/api/handler";
import { haConfigSchema } from "@/lib/validators/system";
import { getHaConfig, putHaConfig } from "@/lib/ha/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ha" }, async ({ auth }) => {
  return { data: await getHaConfig(auth.tenantId) };
});

export const PUT = route(
  { area: "ha", bodySchema: haConfigSchema, section: "ha" },
  async ({ auth, body }) => {
    const before = await getHaConfig(auth.tenantId);
    const after = await putHaConfig(auth.tenantId, body);
    return {
      data: after,
      audit: {
        action: "ha_config.update",
        objectType: "ha_config",
        objectId: after.id,
        objectName: "ha",
        before,
        after,
      },
    };
  },
);

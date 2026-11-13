/**
 * GET/PUT /api/v1/system/settings — grouped settings read + batch upsert
 * (M10 §5.2). PUT is admin-class (matrix system column), audited and
 * snapshotted as section system. Write-only masking: the "••••••••" literal
 * on advanced/snmp.community keeps the stored value.
 */

import { route } from "@/lib/api/handler";
import { settingsBatchSchema } from "@/lib/validators/system";
import { getSettingsGrouped, putSettingsBatch } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "system" }, async ({ auth }) => {
  return { data: await getSettingsGrouped(auth.tenantId) };
});

export const PUT = route(
  { area: "system", admin: true, bodySchema: settingsBatchSchema, section: "system" },
  async ({ auth, body }) => {
    const before = await getSettingsGrouped(auth.tenantId);
    await putSettingsBatch(auth.tenantId, body);
    const touched = Object.fromEntries(
      body.map((e) => [`${e.category}/${e.key}`, before[e.category]?.[e.key] ?? null]),
    );
    return {
      data: { updated: body.length },
      audit: {
        action: "system_settings.update",
        objectType: "system_settings",
        objectName: body.map((e) => `${e.category}/${e.key}`).join(", ").slice(0, 200),
        before: touched,
        after: Object.fromEntries(body.map((e) => [`${e.category}/${e.key}`, e.value])),
      },
    };
  },
);

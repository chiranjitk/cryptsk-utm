/**
 * GET/PUT /api/v1/system/settings — grouped settings read + batch upsert
 * (M10 §5.2). PUT is admin-class (matrix system column), audited and
 * snapshotted as section system. Write-only masking: the "••••••••" literal
 * on advanced/snmp.community keeps the stored value.
 *
 * Audit redaction (F-e #5): SNMP community is masked in BOTH the before and
 * after audit snapshots — the secret never reaches audit_log.
 */

import { route } from "@/lib/api/handler";
import { settingsBatchSchema } from "@/lib/validators/system";
import { getSettingsGrouped, putSettingsBatch, maskSnmpValue } from "@/lib/system/service";
import type { AuditInfo } from "@/lib/api/audit";

export const dynamic = "force-dynamic";

export const GET = route({ area: "system" }, async ({ auth }) => {
  return { data: await getSettingsGrouped(auth.tenantId) };
});

/** Mask the SNMP community in an audit snapshot (defense in depth — the read
 *  path already masks, but the after-payload comes straight from the request). */
function redactAuditEntry(category: string, key: string, value: unknown): unknown {
  if (category === "advanced" && key === "snmp") return maskSnmpValue(value);
  return value;
}

export const PUT = route(
  { area: "system", admin: true, bodySchema: settingsBatchSchema, section: "system" },
  async ({ auth, body }) => {
    const before = await getSettingsGrouped(auth.tenantId);
    await putSettingsBatch(auth.tenantId, body);
    const touched = Object.fromEntries(
      body.map((e) => [`${e.category}/${e.key}`, redactAuditEntry(e.category, e.key, before[e.category]?.[e.key] ?? null)]),
    );
    const audit: AuditInfo = {
      action: "system_settings.update",
      objectType: "system_settings",
      objectName: body.map((e) => `${e.category}/${e.key}`).join(", ").slice(0, 200),
      before: touched,
      after: Object.fromEntries(body.map((e) => [`${e.category}/${e.key}`, redactAuditEntry(e.category, e.key, e.value)])),
    };
    return {
      data: { updated: body.length },
      audit,
    };
  },
);

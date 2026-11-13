/**
 * IPv6 settings singleton (M21 §2.7) — GET auto-creates the tenant row with
 * spec defaults; PUT fully validates and audits `ipv6.settings`.
 */

import { route } from "@/lib/api/handler";
import { ipv6SettingsUpdateSchema } from "@/lib/validators/ipv6";
import { getOrCreateSettings, toSettingsDTO, updateSettings } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ipv6" }, async ({ auth }) => {
  return { data: toSettingsDTO(await getOrCreateSettings(auth.tenantId)) };
});

export const PUT = route(
  { area: "ipv6", bodySchema: ipv6SettingsUpdateSchema, section: "ipv6" },
  async ({ auth, body }) => {
    const updated = await updateSettings(auth.tenantId, body);
    return {
      data: toSettingsDTO(updated),
      audit: { action: "ipv6.settings", objectType: "ipv6_settings", objectId: updated.id, after: toSettingsDTO(updated) },
    };
  },
);

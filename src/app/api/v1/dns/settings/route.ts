/**
 * DNS resolver settings (M06 §3) — SystemSetting ("dns","resolver") JSON.
 * DoT/DoH toggles are display-only in sandbox (M06 §5.4) but persist.
 */

import { route } from "@/lib/api/handler";
import { resolverSettingsSchema } from "@/lib/validators/dns-dhcp";
import { getResolverSettings, putResolverSettings } from "@/lib/dns/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp" }, async ({ auth }) => {
  return { data: await getResolverSettings(auth.tenantId) };
});

export const PUT = route(
  { area: "dns_dhcp", bodySchema: resolverSettingsSchema, section: "dns" },
  async ({ auth, body }) => {
    const saved = await putResolverSettings(auth.tenantId, body);
    return {
      data: saved,
      audit: { action: "dns_resolver.update", objectType: "dns_resolver", objectName: "resolver", after: saved },
    };
  },
);

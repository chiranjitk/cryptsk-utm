/** DHCP relay / ip-helper singleton config (M06 §3/§5.4) — SystemSetting ("dhcp","relay"). */

import { route } from "@/lib/api/handler";
import { dhcpRelaySchema } from "@/lib/validators/dns-dhcp";
import { getRelay, putRelay } from "@/lib/dhcp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp" }, async ({ auth }) => {
  return { data: await getRelay(auth.tenantId) };
});

export const PUT = route(
  { area: "dns_dhcp", bodySchema: dhcpRelaySchema, section: "dhcp" },
  async ({ auth, body }) => {
    const saved = await putRelay(auth.tenantId, body);
    return {
      data: saved,
      audit: { action: "dhcp_relay.update", objectType: "dhcp_relay", objectName: "relay", after: saved },
    };
  },
);

/**
 * OSPF global settings (M19 §2.6) — GET returns the single per-tenant row,
 * creating the default (routerId 10.10.0.1, reference bandwidth 100 Mbps,
 * disabled) when missing. PUT updates it. Section `dynamic_routing`,
 * audit `ospf_settings.update`.
 */

import { route } from "@/lib/api/handler";
import { ospfSettingsUpdateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

async function getOrCreateSettings(tenantId: number) {
  const existing = await db.ospfSettings.findFirst({ where: { tenantId } });
  if (existing) return existing;
  return db.ospfSettings.create({
    data: {
      tenantId,
      routerId: "10.10.0.1",
      referenceBandwidth: 100,
      gracefulRestart: false,
      enabled: false,
    },
  });
}

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  return { data: await getOrCreateSettings(auth.tenantId) };
});

export const PUT = route(
  { area: "dynamic_routing", bodySchema: ospfSettingsUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    await getOrCreateSettings(auth.tenantId); // guarantees exactly one row per tenant
    const existing = await db.ospfSettings.findFirst({ where: { tenantId: auth.tenantId } });
    const updated = await db.ospfSettings.update({ where: { id: existing!.id }, data: body });
    return {
      data: updated,
      audit: {
        action: "ospf_settings.update",
        objectType: "ospf_settings",
        objectId: updated.id,
        objectName: updated.routerId,
        before: existing,
        after: updated,
      },
    };
  },
);

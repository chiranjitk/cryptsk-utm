/**
 * BGP global settings (M19 §2.6 OS extension) — GET returns the single
 * per-tenant BgpSettings row, creating the default (localAs 65000,
 * routerId 10.10.0.1, graceful restart off, disabled) when missing. PUT
 * updates it (zod: localAs 1-4294967295, routerId valid IPv4, gracefulRestart,
 * enabled — every field optional so toggles can PUT a single key; provided
 * fields are merged onto the row). Section `dynamic_routing`, audit
 * `bgp_settings.update`.
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { isIpv4 } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { getOrCreateBgpSettings } from "@/lib/dynamic-routing/os-service";

export const dynamic = "force-dynamic";

export const bgpSettingsUpdateSchema = z
  .object({
    localAs: z.coerce.number().int().min(1).max(4294967295).optional(),
    routerId: z.string().trim().refine(isIpv4, "must be a valid IPv4 address").optional(),
    gracefulRestart: z.boolean().optional(),
    enabled: z.boolean().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export const GET = route({ area: "dynamic_routing", section: "dynamic_routing" }, async ({ auth }) => {
  return { data: await getOrCreateBgpSettings(auth.tenantId) };
});

export const PUT = route(
  { area: "dynamic_routing", bodySchema: bgpSettingsUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    const existing = await getOrCreateBgpSettings(auth.tenantId); // exactly one row per tenant
    const updated = await db.bgpSettings.update({
      where: { id: existing.id },
      data: Object.fromEntries(Object.entries(body).filter(([, v]) => v !== undefined)),
    });
    return {
      data: updated,
      audit: {
        action: "bgp_settings.update",
        objectType: "bgp_settings",
        objectId: updated.id,
        objectName: `AS${updated.localAs}`,
        before: existing,
        after: updated,
      },
    };
  },
);

/** Captive portal profile (M07 §3) — singleton read / upsert. */

import { route } from "@/lib/api/handler";
import { captivePortalUpdateSchema } from "@/lib/validators/identity";
import { getCaptivePortal, putCaptivePortal } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  return { data: await getCaptivePortal(auth.tenantId) };
});

export const PUT = route(
  { area: "identity", bodySchema: captivePortalUpdateSchema, section: "identity" },
  async ({ auth, body }) => {
    const saved = await putCaptivePortal(auth.tenantId, body);
    return {
      data: saved,
      audit: { action: "captive_portal.update", objectType: "captive_portal", objectId: saved.id || undefined, objectName: saved.name, after: saved },
    };
  },
);

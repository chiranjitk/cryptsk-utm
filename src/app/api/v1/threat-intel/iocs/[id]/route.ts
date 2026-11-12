/** IOC item (M13 §2.11) — delete, audit `threat_ioc.delete`. */

import { route, numericId } from "@/lib/api/handler";
import { deleteIoc } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "threat_intel", section: "threat_intel" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteIoc(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "threat_ioc.delete", objectType: "ioc", objectId: id } };
});

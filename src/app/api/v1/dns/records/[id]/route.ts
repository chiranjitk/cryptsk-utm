/** DNS record item (M06 §3) — update / delete. */

import { route, numericId } from "@/lib/api/handler";
import { dnsRecordUpdateSchema } from "@/lib/validators/dns-dhcp";
import { deleteRecord, updateRecord } from "@/lib/dns/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "dns_dhcp", bodySchema: dnsRecordUpdateSchema, section: "dns" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateRecord(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "dns_record.update", objectType: "dns_record", objectId: id, objectName: `${updated.name}.${updated.zone}`, after: updated },
    };
  },
);

export const DELETE = route({ area: "dns_dhcp", section: "dns" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteRecord(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "dns_record.delete", objectType: "dns_record", objectId: id } };
});

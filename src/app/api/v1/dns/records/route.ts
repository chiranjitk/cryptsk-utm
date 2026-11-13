/** Local DNS records (M06 §3) — paginated list + create. */

import { route } from "@/lib/api/handler";
import { dnsRecordCreateSchema, dnsRecordQuerySchema } from "@/lib/validators/dns-dhcp";
import { createRecord, listRecords } from "@/lib/dns/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp", querySchema: dnsRecordQuerySchema }, async ({ auth, query }) => {
  const { data, meta } = await listRecords(auth.tenantId, query);
  return { data, meta };
});

export const POST = route(
  { area: "dns_dhcp", bodySchema: dnsRecordCreateSchema, section: "dns" },
  async ({ auth, body }) => {
    const created = await createRecord(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "dns_record.create", objectType: "dns_record", objectId: created.id, objectName: `${created.name}.${created.zone}`, after: created },
    };
  },
);

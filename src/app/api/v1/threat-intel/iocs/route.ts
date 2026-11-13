/**
 * IOCs (M13 §2.11 tab 2) — GET server-paged list (severity/category/type/q/
 * feedId filters, ordered lastSeen desc) + POST manual IOC creation.
 * Mutations audit `threat_ioc.create` and snapshot section `threat_intel`.
 */

import { route } from "@/lib/api/handler";
import { iocCreateSchema, iocQuerySchema } from "@/lib/validators/threat-intel";
import { createIoc, listIocs } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "threat_intel", querySchema: iocQuerySchema }, async ({ auth, query }) => {
  const { data, meta } = await listIocs(auth.tenantId, query);
  return { data, meta };
});

export const POST = route(
  { area: "threat_intel", bodySchema: iocCreateSchema, section: "threat_intel" },
  async ({ auth, body }) => {
    const created = await createIoc(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "threat_ioc.create",
        objectType: "ioc",
        objectId: created.id,
        objectName: `${created.type}:${created.value}`,
        after: created,
      },
    };
  },
);

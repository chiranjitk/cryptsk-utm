/**
 * NAT66 rules (M21 §2.7) — GET list + POST create. Mutations audit
 * `nat66.create` and snapshot section `ipv6`.
 */

import { route } from "@/lib/api/handler";
import { nat66CreateSchema } from "@/lib/validators/ipv6";
import { createNat66Rule, listNat66Rules } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ipv6" }, async ({ auth }) => {
  return { data: await listNat66Rules(auth.tenantId) };
});

export const POST = route(
  { area: "ipv6", bodySchema: nat66CreateSchema, section: "ipv6" },
  async ({ auth, body }) => {
    const created = await createNat66Rule(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "nat66.create", objectType: "nat66_rule", objectId: created.id, objectName: created.name, after: created },
    };
  },
);

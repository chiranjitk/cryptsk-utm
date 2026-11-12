/**
 * Lease release — LOCKED endpoint (PROJECT_MEMORY §7.2 + ENDPOINTS §5):
 * POST /api/v1/dhcp/leases/{id}/release. Sets state=released, freeing the IP
 * (stale non-active rows are pruned before re-use by the churn engine).
 * Role floor network_admin comes from the dns_dhcp write tier (rbac.ts).
 */

import { route, numericId } from "@/lib/api/handler";
import { z } from "zod";
import { releaseLease } from "@/lib/dhcp/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "dns_dhcp", bodySchema: z.object({}).default({}), section: "dhcp" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const released = await releaseLease(auth.tenantId, id);
    return {
      data: released,
      audit: {
        action: "dhcp_lease.release",
        objectType: "dhcp_lease",
        objectId: id,
        objectName: released.ip,
        before: { state: "active", ip: released.ip, mac: released.mac },
        after: { state: "released", ip: released.ip, mac: released.mac },
      },
    };
  },
);

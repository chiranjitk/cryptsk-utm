/**
 * Guest vouchers (M07 §3/§5.4) — MockEngine in-memory store.
 * GET returns masked codes (`…last4`); POST is the ONLY response that ever
 * carries the full codes (one-time reveal, M07 §4).
 */

import { route } from "@/lib/api/handler";
import { voucherGenerateSchema } from "@/lib/validators/identity";
import { getCaptivePortal } from "@/lib/identity/service";
import { generateVouchers, listVouchers, toVoucherDTO } from "@/lib/identity/vouchers";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async () => {
  return { data: listVouchers().map(toVoucherDTO) };
});

export const POST = route(
  { area: "identity", bodySchema: voucherGenerateSchema, section: "identity" },
  async ({ auth, body }) => {
    const portal = await getCaptivePortal(auth.tenantId);
    const ttlHours = body.ttlHours ?? portal.voucherTtlHours;
    const created = generateVouchers(body.count, ttlHours, body.bandwidthKbps);
    return {
      // full codes, exactly once — the client shows the reveal dialog
      data: created.map((v) => ({ id: v.id, code: v.code, expiresAt: v.expiresAt })),
      audit: {
        action: "voucher.generate",
        objectType: "voucher",
        objectName: `${created.length} vouchers`,
        after: { count: created.length, ttlHours },
      },
    };
  },
);

/** Revoke one voucher (M07 §3) — persistent store, audited. */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { revokeVoucher } from "@/lib/identity/vouchers";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  // only UNUSED vouchers revoke — redeemed/expired codes are terminal already
  if (!(await revokeVoucher(id, auth.tenantId))) {
    throw ApiError.notFound("Voucher not found (or it is already redeemed, expired or revoked)");
  }
  return {
    data: { ok: true },
    audit: { action: "voucher.revoke", objectType: "voucher", objectId: id },
  };
});

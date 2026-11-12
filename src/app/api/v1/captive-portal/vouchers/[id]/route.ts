/** Revoke one voucher (M07 §3) — in-memory store, audited. */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { revokeVoucher } from "@/lib/identity/vouchers";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "identity" }, async ({ params }) => {
  const id = numericId(params, "id");
  if (!revokeVoucher(id)) throw ApiError.notFound("Voucher not found (or the store was restarted — vouchers are volatile in sandbox)");
  return {
    data: { ok: true },
    audit: { action: "voucher.revoke", objectType: "voucher", objectId: id },
  };
});

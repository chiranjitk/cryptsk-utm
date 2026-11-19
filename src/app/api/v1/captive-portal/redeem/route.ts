/**
 * POST /api/v1/captive-portal/redeem — PUBLIC voucher redemption (spec §1.10,
 * audit fix #12: redeem() was dead code with no endpoint). No console sign-in:
 * the portal splash page posts {code, portalId?} directly.
 *
 * 5 redemptions/min per source IP (register-route limiter convention). The
 * voucher claim + CaptivePortalSession open run in ONE transaction inside
 * vouchers.redeem (double-redeem race-safe). The response mirrors /register's
 * guest subset — the hashed sessionId NEVER leaves the server. Anonymous
 * caller → deliberately NO audit write (keep it public-clean; the opened
 * CaptivePortalSession row is itself the auditable record).
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { ok, fail } from "@/lib/api/envelope";
import { hit } from "@/lib/api/rate-limit";
import { redeem } from "@/lib/identity/vouchers";
import { ulid } from "@/lib/ulid";

export const dynamic = "force-dynamic";

const redeemBody = z.object({
  /** optional portal pin — must match a tenant-1 portal profile when present */
  portalId: z.coerce.number().int().positive().optional(),
  /** normalized in redeem(): trimmed + uppercased (codes render uppercase) */
  code: z.string().trim().min(4, "Voucher code is required").max(32, "Voucher code is up to 32 chars"),
});

export const POST = route(
  { isPublic: true, bodySchema: redeemBody },
  async ({ body, ip }) => {
    const requestId = ulid();

    // guest-facing throttle: 5 redemptions/min per source IP
    const throttle = hit(`portal-redeem:${ip}`, 5);
    if (!throttle.allowed) {
      return fail(
        "RATE_LIMITED",
        `Too many redemption attempts from this address, retry after ${throttle.retryAfterSec} seconds`,
        { requestId, retryAfter: throttle.retryAfterSec },
      );
    }

    const result = await redeem(body.code, ip, undefined, 1, body.portalId);
    if (!result) {
      // uniform failure — unknown / expired / revoked / already redeemed
      return fail("VALIDATION_ERROR", "Invalid, expired or already-redeemed voucher code", {
        requestId,
        details: { fieldErrors: { code: ["Invalid, expired or already-redeemed voucher code"] } },
      });
    }

    // guest-facing subset only — mirrors /register, no hashed sessionId
    return ok(
      {
        token: result.session.token,
        kind: result.session.kind,
        clientIp: result.session.clientIp,
        state: result.session.state,
        startedAt: result.session.startedAt,
        expiresAt: result.session.expiresAt,
        voucherId: result.voucher.id,
      },
      undefined,
      requestId,
    );
  },
);

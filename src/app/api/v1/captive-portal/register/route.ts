/**
 * POST /api/v1/captive-portal/register — PUBLIC guest self-registration
 * (spec §1.10, T1-d). No console sign-in: the portal splash page posts
 * {name, agree, clientMac?} directly. 5 registrations/min per source IP
 * (auth/login throttle convention); the session token is returned ONCE —
 * only sha256(token) is persisted. Audited with the request source IP.
 */

import { route } from "@/lib/api/handler";
import { ok, fail } from "@/lib/api/envelope";
import { hit } from "@/lib/api/rate-limit";
import { writeAudit } from "@/lib/api/audit";
import { ulid } from "@/lib/ulid";
import { portalSelfRegisterSchema } from "@/lib/validators/identity";
import { selfRegister } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { isPublic: true, bodySchema: portalSelfRegisterSchema },
  async ({ auth, body, ip }) => {
    const requestId = ulid();

    // guest-facing throttle: 5 registrations/min per source IP
    const throttle = hit(`portal-register:${ip}`, 5);
    if (!throttle.allowed) {
      return fail(
        "RATE_LIMITED",
        `Too many registrations from this address, retry after ${throttle.retryAfterSec} seconds`,
        { requestId, retryAfter: throttle.retryAfterSec },
      );
    }

    const { session, token } = await selfRegister(auth.tenantId, {
      name: body.name,
      phone: body.phone,
      agree: body.agree,
      clientIp: ip,
      clientMac: body.clientMac,
    });

    await writeAudit({
      tenantId: auth.tenantId,
      username: auth.username,
      sourceIp: ip,
      info: {
        action: "captive_portal.register",
        objectType: "captive_portal_session",
        objectId: session.id,
        objectName: body.name,
        after: { kind: session.kind, userName: body.name, clientIp: session.clientIp, sourceIp: ip },
      },
    }).catch(() => {});

    // guest-facing subset only — the hashed sessionId never leaves the server
    return ok(
      {
        token,
        kind: session.kind,
        userName: session.userName,
        clientIp: session.clientIp,
        state: session.state,
        startedAt: session.startedAt,
        expiresAt: session.expiresAt,
      },
      undefined,
      requestId,
    );
  },
);

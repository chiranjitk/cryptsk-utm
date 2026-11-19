/**
 * POST /api/v1/auth/logout — clears the session cookie (audited).
 *
 * Deliberately NO capability `area`: sign-out is self-service for EVERY
 * authenticated principal (all roles, auditor and api keys included).
 * Gating it as a mutation on an area would 403 everyone — dashboard.write
 * is empty by design (read-only area). authenticate() still runs since the
 * route is not public, so anonymous callers get 401 (handler.ts contract).
 *
 * Audit fix #1 — the presented token's session is REVOKED in the AuthSession
 * registry (server-side JWT revocation): the cookie is verified by signature
 * first (decode-without-trust — a forged/expired token revokes nothing).
 */

import { route } from "@/lib/api/handler";
import { ok } from "@/lib/api/envelope";
import { SESSION_COOKIE, verifySession } from "@/lib/auth/jwt";
import { revokeSessionByJti } from "@/lib/auth/session-store";
import { getCookie } from "@/lib/auth/session";

export const POST = route({}, async ({ req }) => {
  const token = getCookie(req, SESSION_COOKIE);
  if (token) {
    const claims = await verifySession(token); // null for forged/expired tokens
    if (claims) await revokeSessionByJti(claims.jti).catch(() => {});
  }
  const res = ok({ success: true });
  res.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return { data: res, audit: { action: "auth.logout", objectType: "user" } };
});

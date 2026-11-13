/**
 * POST /api/v1/auth/logout — clears the session cookie (audited).
 *
 * Deliberately NO capability `area`: sign-out is self-service for EVERY
 * authenticated principal (all roles, auditor and api keys included).
 * Gating it as a mutation on an area would 403 everyone — dashboard.write
 * is empty by design (read-only area). authenticate() still runs since the
 * route is not public, so anonymous callers get 401 (handler.ts contract).
 */

import { route } from "@/lib/api/handler";
import { ok } from "@/lib/api/envelope";
import { SESSION_COOKIE } from "@/lib/auth/jwt";

export const POST = route({}, async () => {
  const res = ok({ success: true });
  res.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return { data: res, audit: { action: "auth.logout", objectType: "user" } };
});

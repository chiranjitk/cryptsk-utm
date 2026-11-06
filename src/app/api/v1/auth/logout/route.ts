/**
 * POST /api/v1/auth/logout — clears the session cookie (audited).
 */

import { route } from "@/lib/api/handler";
import { ok } from "@/lib/api/envelope";
import { SESSION_COOKIE } from "@/lib/auth/jwt";

export const POST = route({ area: "dashboard" }, async () => {
  const res = ok({ success: true });
  res.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return { data: res, audit: { action: "auth.logout", objectType: "user" } };
});

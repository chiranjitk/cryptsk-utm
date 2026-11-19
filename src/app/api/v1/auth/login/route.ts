/**
 * POST /api/v1/auth/login — docs/07-SECURITY/AUTH_AND_RBAC.md §2.
 * {username, password, totpCode?} → bcrypt check → JWT in httpOnly
 * SameSite=Lax cookie `cryptsk_token`; the JWT carries a `jti` registered as
 * an AuthSession row (revocation registry — ./lib/auth/session-store.ts).
 * 5 attempts/min per (username, ip) throttle + audited.
 *
 * Audit fixes (F-c):
 *  - #4 tenant resolved FROM THE USER (findFirst by username, lowest id wins
 *    across tenants) — no hardcoded tenant 1 for the token/audit trail.
 *  - #5 lockout enforcement: auth policy lockout.maxAttempts/windowMin drives
 *    an in-memory per-username failed-attempt counter. Failures only; cleared
 *    on success. CAVEAT (documented): the counter is per-process memory — a
 *    restart clears lockouts and counts (durable lockout needs a schema
 *    change, out of scope).
 *  - #7 no MFA/user enumeration: every pre-auth failure (unknown user, bad
 *    password, enrolled-but-missing code) runs a DUMMY bcrypt+TOTP verify and
 *    returns the SAME generic message. `details.totpRequired` is NOT sent —
 *    the login UI renders only error.message (no TOTP field), so the client
 *    flow is unchanged.
 *  - #8 policy totp.required=true + un-enrolled user → 403 "MFA enrollment
 *    required" (machine code in details.code = "mfa_required"; envelope code
 *    stays FORBIDDEN — the error taxonomy is LOCKED).
 *  - #9 concurrent-session cap (sessionLimits.maxConcurrentPerUser, default 4):
 *    oldest active sessions revoked beyond cap − 1 before the new AuthSession.
 *  - #10 session TTL from auth policy sessionLifetimeHours (clamped 1–24 h,
 *    default 8 h) — JWT exp, cookie maxAge and AuthSession.expiresAt agree.
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { route } from "@/lib/api/handler";
import { ok, fail } from "@/lib/api/envelope";
import { hit, publicClientKey } from "@/lib/api/rate-limit";
import { writeAudit } from "@/lib/api/audit";
import { db } from "@/lib/db";
import { verifyPassword } from "@/lib/auth/password";
import { SESSION_COOKIE, clampSessionTtl, signSession } from "@/lib/auth/jwt";
import { createAuthSession, enforceConcurrentSessionCap } from "@/lib/auth/session-store";
import { can, ROLES, type CapabilityArea } from "@/lib/auth/rbac";
import { verifyTotp } from "@/lib/auth/totp";
import { DEFAULT_AUTH_SETTINGS, getAuthSettings } from "@/lib/identity/service";
import { ulid } from "@/lib/ulid";

const loginBody = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(128),
  totpCode: z.string().regex(/^\d{6}$/).optional(),
});

/** Generic failure message — identical for every pre-auth failure (#7). */
const GENERIC_FAILURE = "Invalid username or password";

/** bcrypt hash of an unguessable random string — keeps failure timing flat. */
const DUMMY_HASH = "$2a$12$BgO1Vo1VZ7UjgTjNwKHdZeLq3EPye//u/KdC82dKojonVedxsXVma";
const DUMMY_TOTP_SECRET = "JBSWY3DPEHPK3PXP"; // classic base32 test vector

/** Same-cost work as a real failed credential path (bcrypt + TOTP loop). */
async function dummyVerify(): Promise<void> {
  await verifyPassword("cryptsk-dummy-verify-password", DUMMY_HASH);
  await verifyTotp(DUMMY_TOTP_SECRET, "000000");
}

// ── in-memory lockout (#5) — per-username failed-attempt counter ─────────────

interface LockoutState {
  failures: number;
  windowStartedAt: number;
  lockedUntil: number;
}
const lockouts = new Map<string, LockoutState>();
const LOCKOUT_MAP_MAX = 5_000;

function pruneLockouts(): void {
  if (lockouts.size <= LOCKOUT_MAP_MAX) return;
  const now = Date.now();
  for (const [k, v] of lockouts) {
    if (v.lockedUntil < now && now - v.windowStartedAt > 3_600_000) lockouts.delete(k);
  }
}

/** Count one failed attempt; flip to "locked" once maxAttempts is reached. */
function recordLoginFailure(usernameKey: string, maxAttempts: number, windowMin: number): void {
  const now = Date.now();
  const windowMs = Math.max(1, windowMin) * 60_000;
  const state = lockouts.get(usernameKey);
  if (!state || now - state.windowStartedAt > windowMs) {
    lockouts.set(usernameKey, { failures: 1, windowStartedAt: now, lockedUntil: 0 });
    return;
  }
  state.failures += 1;
  if (state.failures >= Math.max(1, maxAttempts)) {
    state.lockedUntil = now + windowMs;
    state.failures = 0;
    state.windowStartedAt = now;
  }
}

function isLocked(usernameKey: string): { locked: boolean; retryAfterSec: number } {
  const state = lockouts.get(usernameKey);
  if (!state || state.lockedUntil <= Date.now()) return { locked: false, retryAfterSec: 0 };
  return { locked: true, retryAfterSec: Math.ceil((state.lockedUntil - Date.now()) / 1000) };
}

/** Effective permission summary for UI gating (mirrors the matrix — never trusted alone). */
export function permissionsFor(role: string, scopes?: string[]): Record<string, string[]> {
  const areas: CapabilityArea[] = [
    "dashboard", "network", "firewall", "ips_policies", "ips_events", "vpn_config",
    "vpn_sessions", "dns_dhcp", "identity", "qos", "logs", "log_forwarding", "reports",
    "webhooks", "firmware", "audit", "ha", "system", "backups", "api_keys", "notifications",
  ];
  const out: Record<string, string[]> = { read: [], write: [], admin: [] };
  const knownRole = (ROLES as readonly string[]).includes(role) ? (role as (typeof ROLES)[number]) : "helpdesk";
  const auth = { kind: "user" as const, role: knownRole, tenantId: 1, scopes };
  for (const area of areas) {
    for (const op of ["read", "write", "admin"] as const) {
      if (can(auth, area, op)) out[op].push(area);
    }
  }
  return out;
}

export const POST = route(
  {
    isPublic: true,
    bodySchema: loginBody,
  },
  async ({ body, ip, req }) => {
    const requestId = ulid();
    const { username, password, totpCode } = body;
    const usernameKey = username.toLowerCase();

    // #5 — policy-driven lockout check FIRST (a locked account stays locked
    // even for correct credentials; the 5/min throttle below still applies)
    // audit fix L10 — a settings read failure must be OBSERVABLE: silently
    // running on defaults would drop an operator-tightened lockout policy.
    const policy = await getAuthSettings().catch((err: unknown) => {
      console.error(`[api] ${requestId} auth settings read failed, using defaults:`, err instanceof Error ? err.message : err);
      return DEFAULT_AUTH_SETTINGS;
    });
    const lock = isLocked(usernameKey);
    if (lock.locked) {
      await writeAudit({
        tenantId: 1, // principal unresolved — audit under the default tenant
        username,
        sourceIp: ip,
        info: { action: "auth.login", objectType: "user", objectName: username, result: "denied" },
      }).catch((err: unknown) => {
        console.error(`[api] ${requestId} audit write failed:`, err instanceof Error ? err.message : err);
      });
      return fail("RATE_LIMITED", "Account temporarily locked due to failed login attempts", {
        requestId,
        retryAfter: lock.retryAfterSec,
        details: { locked: true },
      });
    }

    // login throttle: 5 attempts/min per (username-lowercased, best-effort
    // client key) — audit fix M9: the bucket key uses the case-folded username
    // so `Admin`/`ADMIN`/`aDmin` share one budget; audit fix M8: the IP
    // dimension uses publicClientKey() so callers behind no proxy are not all
    // collapsed into one bucket. The policy lockout (usernameKey, above) is
    // the hard failure cap; this minute-bucket is defense-in-depth.
    const throttle = hit(`login:${usernameKey}:${publicClientKey(req)}`, 5);
    if (!throttle.allowed) {
      return fail("RATE_LIMITED", `Too many login attempts, retry after ${throttle.retryAfterSec} seconds`, {
        requestId,
        retryAfter: throttle.retryAfterSec,
      });
    }

    const deny = async (result: "failure" | "denied", message: string, userId?: number, tenantId?: number) => {
      await writeAudit({
        tenantId: tenantId ?? 1, // principal unresolved → default tenant (#4)
        userId,
        username,
        sourceIp: ip,
        info: { action: "auth.login", objectType: "user", objectName: username, result },
      }).catch((err: unknown) => {
        console.error(`[api] ${requestId} audit write failed:`, err instanceof Error ? err.message : err);
      });
      return fail("UNAUTHORIZED", message, { requestId });
    };

    // #4 — resolve the tenant from the user, not a hardcoded tenant 1.
    // usernames are unique per tenant (@@unique([tenantId, username])), so a
    // username CAN exist in several tenants; the lowest id (oldest account)
    // wins and isActive is verified below. Kept deliberately simple per the
    // audit fix — multi-tenant username disambiguation is a future concern.
    const user = await db.user.findFirst({ where: { username }, orderBy: { id: "asc" } });

    // #7 — identical failure shape + dummy work for every pre-auth outcome
    if (!user) {
      await dummyVerify();
      return deny("failure", GENERIC_FAILURE);
    }
    if (!user.isActive) {
      await dummyVerify();
      return deny("failure", GENERIC_FAILURE, user.id, user.tenantId);
    }

    const passwordOk = await verifyPassword(password, user.passwordHash);
    if (!passwordOk) {
      recordLoginFailure(usernameKey, policy.lockout.maxAttempts, policy.lockout.windowMin);
      return deny("failure", GENERIC_FAILURE, user.id, user.tenantId);
    }

    // #8 — policy demands MFA but the account is not enrolled → dedicated
    // error AFTER a successful password check (machine code in details;
    // envelope code stays FORBIDDEN/403 — taxonomy is LOCKED)
    if (policy.totp.required && !user.totpSecret) {
      return fail("FORBIDDEN", "MFA enrollment required — enroll a TOTP authenticator before signing in", {
        requestId,
        details: { code: "mfa_required" },
      });
    }

    // #7 — enrolled users must present a code; the missing-code branch runs
    // the dummy path and returns the GENERIC failure (no totpRequired leak;
    // the login UI has no TOTP field and only renders error.message)
    if (user.totpSecret) {
      if (!totpCode) {
        await dummyVerify();
        return deny("failure", GENERIC_FAILURE, user.id, user.tenantId);
      }
      const totpOk = await verifyTotp(user.totpSecret, totpCode, user.id);
      if (!totpOk) {
        recordLoginFailure(usernameKey, policy.lockout.maxAttempts, policy.lockout.windowMin);
        // audit fix M10 — a wrong TOTP code must return the SAME generic
        // message as a wrong password: a distinct message would confirm to a
        // caller that the presented password was correct (password-validity
        // oracle + account enumeration). The failure distinction lives
        // server-side only, in the audit trail.
        return deny("failure", GENERIC_FAILURE, user.id, user.tenantId);
      }
    }

    // #10 — policy session lifetime (clamped 1–24 h, default 8 h)
    const ttlSec = clampSessionTtl(policy.sessionLifetimeHours * 3600);
    const { token, jti, expiresAt } = await signSession(
      {
        sub: String(user.id),
        username: user.username,
        role: user.role as (typeof ROLES)[number],
        tenantId: user.tenantId,
      },
      ttlSec,
    );

    // #9 — concurrent-session cap, THEN register the new session (#1).
    // Registration is load-bearing (revocation registry): a login that cannot
    // register its jti must FAIL CLOSED (500), never hand out an
    // unrevocable/401-ing cookie.
    await enforceConcurrentSessionCap(user.id, policy.sessionLimits?.maxConcurrentPerUser ?? 4).catch((err: unknown) => {
      // audit fix L11 — cap enforcement must not silently vanish on DB error
      console.error(`[api] ${requestId} concurrent session cap enforcement failed:`, err instanceof Error ? err.message : err);
    });
    await createAuthSession({
      jti,
      userId: user.id,
      tenantId: user.tenantId,
      ip,
      userAgent: req.headers.get("user-agent") ?? "",
      expiresAt,
    });

    lockouts.delete(usernameKey); // success clears the failure counter (#5)
    pruneLockouts();

    await db.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } }).catch(() => {});
    await writeAudit({
      tenantId: user.tenantId,
      userId: user.id,
      username: user.username,
      sourceIp: ip,
      info: { action: "auth.login", objectType: "user", objectId: user.id, objectName: user.username, result: "success" },
    }).catch((err: unknown) => {
      console.error(`[api] ${requestId} audit write failed:`, err instanceof Error ? err.message : err);
    });

    const res = ok(
      {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          email: user.email,
          tenantId: user.tenantId,
        },
        permissions: permissionsFor(user.role),
      },
      undefined,
      requestId,
    );
    // Mark the cookie Secure only when the request actually arrived over HTTPS
    // (directly or via a TLS-terminating proxy). Gating on NODE_ENV breaks
    // plain-HTTP deployments: browsers silently drop Secure cookies on non-https
    // origins, so the session never sticks and login appears to do nothing.
    // audit fix L14 — x-forwarded-proto is spoofable, so it is honored only
    // under the same CONSOLE_TRUST_PROXY opt-in that gates x-forwarded-for in
    // handler.ts clientIp(); without it only the real request URL decides.
    const xfProto = req.headers.get("x-forwarded-proto")?.split(",")[0]?.trim();
    const trustProto = process.env.CONSOLE_TRUST_PROXY === "1" && xfProto;
    const isHttps = trustProto ? trustProto === "https" : new URL(req.url).protocol === "https:";
    res.cookies.set(SESSION_COOKIE, token, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: ttlSec,
      secure: isHttps,
    });
    return res;
  },
);

export type LoginRouteRequest = NextRequest;

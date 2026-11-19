/**
 * JWT (jose HS256) — ADR-007 + docs/07-SECURITY/AUTH_AND_RBAC.md §2.
 * Claims: { sub, username, role, tenantId, jti, iat, exp }.
 *   exp   = iat + ttlSec (caller-supplied; clamped 1–24 h — the login route
 *           derives it from the auth policy `sessionLifetimeHours`, default 8h).
 *   jti   = crypto.randomUUID(), generated at sign time and REGISTERED in the
 *           AuthSession table (schema §7 — server-side revocation registry,
 *           see ./session-store.ts). verifySession() rejects tokens without a
 *           jti, so pre-registry tokens fail closed.
 * Transport: httpOnly cookie `cryptsk_token`.
 */

import { randomUUID } from "crypto";
import { SignJWT, jwtVerify } from "jose";
import type { Role } from "./rbac";

export const SESSION_COOKIE = "cryptsk_token";
export const SESSION_TTL_SEC = 8 * 60 * 60; // 8h default (auth policy sessionLifetimeHours)
/** Auth policy `sessionLifetimeHours` is validated 1–24 — mirror the clamp here. */
export const SESSION_TTL_MIN_SEC = 1 * 60 * 60;
export const SESSION_TTL_MAX_SEC = 24 * 60 * 60;

const DEV_SECRET = "cryptsk-sandbox-dev-secret-do-not-use-in-prod";
let devSecretWarned = false;

function secretKey(): Uint8Array {
  const secret = process.env.AUTH_SECRET ?? DEV_SECRET;
  if (process.env.NODE_ENV === "production" && (secret.length === 0 || secret === DEV_SECRET)) {
    // Fail closed (audit fix): the known dev literal must never sign or verify
    // production tokens. Deployments set a real AUTH_SECRET (.env).
    throw new Error("AUTH_SECRET is missing or equals the dev literal — refusing to sign/verify in production");
  }
  if (secret === DEV_SECRET && !devSecretWarned) {
    devSecretWarned = true; // warn once per process, not per request
    console.warn("[auth] AUTH_SECRET falls back to the sandbox dev literal — never use in production");
  }
  return new TextEncoder().encode(secret);
}

export interface SessionClaims {
  sub: string;
  username: string;
  role: Role;
  tenantId: number;
  /** JWT ID — registered in AuthSession; REQUIRED for a token to authenticate. */
  jti: string;
}

export type SessionClaimsInput = Omit<SessionClaims, "jti">;

export interface SignedSession {
  token: string;
  /** jti stamped into the token — pass to createAuthSession() at login. */
  jti: string;
  /** Absolute expiry mirroring the `exp` claim (AuthSession.expiresAt). */
  expiresAt: Date;
  ttlSec: number;
}

/** Clamp a session lifetime to the 1–24 h policy window (invalid → 8 h default). */
export function clampSessionTtl(ttlSec: number | undefined | null): number {
  if (ttlSec === undefined || ttlSec === null || !Number.isFinite(ttlSec)) return SESSION_TTL_SEC;
  return Math.min(SESSION_TTL_MAX_SEC, Math.max(SESSION_TTL_MIN_SEC, Math.round(ttlSec)));
}

export async function signSession(claims: SessionClaimsInput, ttlSec: number = SESSION_TTL_SEC): Promise<SignedSession> {
  const now = Math.floor(Date.now() / 1000);
  const jti = randomUUID();
  const ttl = clampSessionTtl(ttlSec);
  const token = await new SignJWT({
    username: claims.username,
    role: claims.role,
    tenantId: claims.tenantId,
    jti,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(claims.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(secretKey());
  return { token, jti, expiresAt: new Date((now + ttl) * 1000), ttlSec: ttl };
}

export async function verifySession(token: string): Promise<SessionClaims | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey(), { algorithms: ["HS256"] });
    if (!payload.sub || typeof payload.username !== "string") return null;
    if (typeof payload.role !== "string" || typeof payload.tenantId !== "number") return null;
    if (typeof payload.jti !== "string" || payload.jti.length === 0) return null; // pre-registry token → fail closed
    return {
      sub: payload.sub,
      username: payload.username,
      role: payload.role as Role,
      tenantId: payload.tenantId,
      jti: payload.jti,
    };
  } catch {
    return null;
  }
}

/**
 * JWT (jose HS256) — ADR-007 + docs/07-SECURITY/AUTH_AND_RBAC.md §2.
 * Claims: { sub, username, role, tenantId, iat, exp }; exp = iat + 8h.
 * Transport: httpOnly cookie `cryptsk_token`.
 */

import { SignJWT, jwtVerify } from "jose";
import type { Role } from "./rbac";

export const SESSION_COOKIE = "cryptsk_token";
export const SESSION_TTL_SEC = 8 * 60 * 60; // 8h

function secretKey(): Uint8Array {
  const secret = process.env.AUTH_SECRET ?? "cryptsk-sandbox-dev-secret-do-not-use-in-prod";
  return new TextEncoder().encode(secret);
}

export interface SessionClaims {
  sub: string;
  username: string;
  role: Role;
  tenantId: number;
}

export async function signSession(claims: SessionClaims): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    username: claims.username,
    role: claims.role,
    tenantId: claims.tenantId,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(claims.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + SESSION_TTL_SEC)
    .sign(secretKey());
}

export async function verifySession(token: string): Promise<SessionClaims | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey(), { algorithms: ["HS256"] });
    if (!payload.sub || typeof payload.username !== "string") return null;
    if (typeof payload.role !== "string" || typeof payload.tenantId !== "number") return null;
    return {
      sub: payload.sub,
      username: payload.username,
      role: payload.role as Role,
      tenantId: payload.tenantId,
    };
  } catch {
    return null;
  }
}

/**
 * POST /api/v1/auth/login — docs/07-SECURITY/AUTH_AND_RBAC.md §2.
 * {username, password, totpCode?} → bcrypt check → JWT 8h in httpOnly
 * SameSite=Lax cookie `cryptsk_token`. 5 attempts/min per (username, ip).
 * Failures are indistinguishable (no user enumeration) + audited.
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { route } from "@/lib/api/handler";
import { ok, fail } from "@/lib/api/envelope";
import { hit } from "@/lib/api/rate-limit";
import { writeAudit } from "@/lib/api/audit";
import { db } from "@/lib/db";
import { verifyPassword } from "@/lib/auth/password";
import { SESSION_COOKIE, SESSION_TTL_SEC, signSession } from "@/lib/auth/jwt";
import { can, ROLES, type CapabilityArea } from "@/lib/auth/rbac";
import { verifyTotp } from "@/lib/auth/totp";
import { ulid } from "@/lib/ulid";

const loginBody = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(128),
  totpCode: z.string().regex(/^\d{6}$/).optional(),
});

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
  async ({ body, ip }) => {
    const requestId = ulid();
    const { username, password, totpCode } = body;

    // login throttle: 5 failed attempts/min per (username, source ip)
    const throttle = hit(`login:${username}:${ip}`, 5);
    if (!throttle.allowed) {
      return fail("RATE_LIMITED", `Too many login attempts, retry after ${throttle.retryAfterSec} seconds`, {
        requestId,
        retryAfter: throttle.retryAfterSec,
      });
    }

    const deny = async (result: "failure" | "denied", message: string, userId?: number) => {
      await writeAudit({
        tenantId: 1,
        userId,
        username,
        sourceIp: ip,
        info: { action: "auth.login", objectType: "user", objectName: username, result },
      }).catch(() => {});
      return fail("UNAUTHORIZED", message, { requestId });
    };

    const user = await db.user.findUnique({
      where: { tenantId_username: { tenantId: 1, username } },
    });
    if (!user || !user.isActive) return deny("failure", "Invalid username or password");

    const passwordOk = await verifyPassword(password, user.passwordHash);
    if (!passwordOk) return deny("failure", "Invalid username or password", user.id);

    // TOTP gate (Phase 1: enrolled users must present a code; seeded users have none)
    if (user.totpSecret) {
      if (!totpCode) {
        return fail("UNAUTHORIZED", "TOTP code required", { requestId, details: { totpRequired: true } });
      }
      const totpOk = await verifyTotp(user.totpSecret, totpCode);
      if (!totpOk) return deny("failure", "Invalid TOTP code", user.id);
    }

    const token = await signSession({
      sub: String(user.id),
      username: user.username,
      role: user.role as (typeof ROLES)[number],
      tenantId: user.tenantId,
    });

    await db.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } }).catch(() => {});
    await writeAudit({
      tenantId: user.tenantId,
      userId: user.id,
      username: user.username,
      sourceIp: ip,
      info: { action: "auth.login", objectType: "user", objectId: user.id, objectName: user.username, result: "success" },
    }).catch(() => {});

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
    res.cookies.set(SESSION_COOKIE, token, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: SESSION_TTL_SEC,
      secure: process.env.NODE_ENV === "production",
    });
    return res;
  },
);

export type LoginRouteRequest = NextRequest;

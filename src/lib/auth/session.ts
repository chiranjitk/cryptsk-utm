/**
 * Session extraction — resolves the caller (JWT cookie or Bearer API key)
 * into an AuthContext. docs/07-SECURITY/AUTH_AND_RBAC.md §1–§3.
 */

import type { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import { SESSION_COOKIE, verifySession } from "./jwt";
import { ApiError } from "@/lib/api/errors";
import { createHash } from "crypto";
import type { AuthContext } from "./rbac";

function cookieFromHeader(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

export function getCookie(req: NextRequest, name: string): string | undefined {
  // NextRequest.cookies is the sanctioned accessor; header fallback keeps this
  // testable from plain Requests.
  try {
    const c = req.cookies.get(name)?.value;
    if (c) return c;
  } catch {
    /* fall through to header */
  }
  return cookieFromHeader(req.headers.get("cookie"), name);
}

/** sha256 of the presented key — ApiKey.hashedKey stores the same digest. */
function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Authenticate the request. Throws UNAUTHORIZED (401) when no valid principal.
 * Successful API-key auth touches `lastUsedAt` (max once per minute per key).
 */
export async function authenticate(req: NextRequest): Promise<AuthContext> {
  // 1) Browser session (httpOnly cookie)
  const token = getCookie(req, SESSION_COOKIE);
  if (token) {
    const claims = await verifySession(token);
    if (claims) {
      return {
        kind: "user",
        userId: Number(claims.sub),
        username: claims.username,
        role: claims.role,
        tenantId: claims.tenantId,
      };
    }
  }

  // 2) Machine access (Authorization: Bearer ck_<prefix8>_<secret32>)
  const authz = req.headers.get("authorization");
  if (authz?.startsWith("Bearer ck_")) {
    const presented = authz.slice("Bearer ".length).trim();
    // full key shape: ck_ + 8-char prefix + "_" + 32-char secret
    if (presented.length > 12 && presented[11] === "_") {
      const prefix = presented.slice(0, 11); // "ck_" + 8 chars — matches ApiKey.prefix
      const key = await db.apiKey.findUnique({ where: { prefix } });
      if (key && !key.revoked && !(key.expiresAt && key.expiresAt.getTime() < Date.now())) {
        if (key.hashedKey === sha256(presented)) {
          const last = key.lastUsedAt?.getTime() ?? 0;
          if (Date.now() - last > 60_000) {
            await db.apiKey.update({ where: { id: key.id }, data: { lastUsedAt: new Date() } }).catch(() => {});
          }
          return {
            kind: "key",
            role: "api_service",
            tenantId: key.tenantId,
            userId: undefined,
            username: key.name,
            scopes: parseJson<string[]>(key.scopes, ["read"]),
          };
        }
      }
    }
    throw ApiError.unauthorized("Invalid API key");
  }

  throw ApiError.unauthorized();
}

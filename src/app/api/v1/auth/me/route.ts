/**
 * GET /api/v1/auth/me — current user + effective permissions (UI gating).
 * The API is the only RBAC authority; hidden UI is never trusted.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { permissionsFor } from "../login/route";

export const GET = route({}, async ({ auth }) => {
  if (auth.kind === "key") {
    return {
      data: {
        kind: "key" as const,
        username: auth.username,
        tenantId: auth.tenantId,
        scopes: auth.scopes ?? [],
        permissions: permissionsFor("api_service", auth.scopes),
      },
    };
  }
  const user = await db.user.findUnique({
    where: { id: auth.userId },
    select: { id: true, username: true, role: true, email: true, tenantId: true, lastLoginAt: true, isActive: true },
  });
  if (!user || !user.isActive) throw ApiError.unauthorized("Session user no longer active");
  return {
    data: {
      kind: "user" as const,
      ...user,
      permissions: permissionsFor(user.role),
    },
  };
});

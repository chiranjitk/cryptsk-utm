/**
 * GET /api/v1/openapi.json (M11 §4.2) — serves the OpenAPI 3.1 artifact built
 * ONCE at module load by lib/api/openapi.ts from the LOCKED §7.2 ROUTE_MANIFEST.
 * Authenticated principals only (helpdesk floor — ENDPOINTS §14): `area` is
 * omitted here so the RBAC matrix is skipped while auth is still enforced,
 * letting read-scope machine keys fetch the artifact (M11 §7).
 */

import { NextResponse } from "next/server";
import { route } from "@/lib/api/handler";
import { openApiSpec } from "@/lib/api/openapi";

export const dynamic = "force-dynamic";

export const GET = route({}, async () => {
  // Handler pass-through: returning a NextResponse shapes its own envelope —
  // the raw OpenAPI document IS the body (application/json, cached object).
  return { data: NextResponse.json(openApiSpec, { headers: { "Content-Type": "application/json" } }) };
});

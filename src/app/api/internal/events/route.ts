/**
 * GET /api/internal/events?cursor=N — NON-PUBLISHED internal route polled by
 * the realtime mini-service every 1 s (single-writer to SQLite;
 * SIMULATION_LAYER §7). Guarded by a shared token; never used by the UI.
 *
 * Token handling (F-e #4):
 *   • INTERNAL_TOKEN unset → 503 immediately — the internal event bus is not
 *     configured and must fail closed (no default-token fallback);
 *   • INTERNAL_TOKEN set → constant-time comparison (crypto.timingSafeEqual,
 *     length-guarded) so the token cannot be probed byte-by-byte.
 */

import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";
import { fail, ok } from "@/lib/api/envelope";
import { eventsSince } from "@/lib/engine/events";
import { getEngine } from "@/lib/engine";

export const dynamic = "force-dynamic";

/** Length-guarded constant-time token comparison (F-e #4). */
function tokenMatches(provided: string | null, expected: string): boolean {
  if (!provided) return false;
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export async function GET(req: NextRequest) {
  const expected = process.env.INTERNAL_TOKEN;
  if (!expected) {
    return NextResponse.json(
      { error: { code: "INTERNAL", message: "internal event bus not configured" } },
      { status: 503 },
    );
  }
  const token = req.headers.get("x-internal-token");
  if (!tokenMatches(token, expected)) {
    return fail("UNAUTHORIZED", "Internal endpoint");
  }
  await getEngine().start().catch(() => {});
  const cursor = Number(req.nextUrl.searchParams.get("cursor") ?? "0");
  const { events, cursor: next } = eventsSince(Number.isFinite(cursor) ? cursor : 0);
  return ok({ events, cursor: next });
}

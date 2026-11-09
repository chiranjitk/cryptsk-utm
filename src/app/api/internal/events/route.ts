/**
 * GET /api/internal/events?cursor=N — NON-PUBLISHED internal route polled by
 * the realtime mini-service every 1 s (single-writer to SQLite;
 * SIMULATION_LAYER §7). Guarded by a shared token; never used by the UI.
 */

import { NextRequest } from "next/server";
import { fail, ok } from "@/lib/api/envelope";
import { eventsSince } from "@/lib/engine/events";
import { getEngine } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const token = req.headers.get("x-internal-token");
  const expected = process.env.INTERNAL_TOKEN ?? "cryptsk-internal";
  if (token !== expected) {
    return fail("UNAUTHORIZED", "Internal endpoint");
  }
  await getEngine().start().catch(() => {});
  const cursor = Number(req.nextUrl.searchParams.get("cursor") ?? "0");
  const { events, cursor: next } = eventsSince(Number.isFinite(cursor) ? cursor : 0);
  return ok({ events, cursor: next });
}

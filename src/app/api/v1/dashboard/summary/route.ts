/**
 * GET /api/v1/dashboard/summary — first vertical slice (M01).
 * Payload contract: docs/04-API/ENDPOINTS.md §2 (+ additive
 * throughputHistory / recentThreats fields for chart backfill + threat feed).
 * Wired to SimulatedAdapter → MockEngine ring buffers + SQLite aggregates.
 */

import { route } from "@/lib/api/handler";
import { getAdapter } from "@/lib/adapters";
import { getMockEngine } from "@/lib/engine/mock-engine";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dashboard" }, async ({ auth }) => {
  // lazily boot the engine in whichever process serves the first request
  await getMockEngine().start().catch(() => {});
  const adapter = getAdapter();
  const summary = await adapter.getDashboardSummary(auth.tenantId);
  return { data: summary };
});

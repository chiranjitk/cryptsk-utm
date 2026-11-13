/**
 * GET /api/v1/wan-policies/os — multi-WAN GUI↔kernel visibility.
 *
 * Returns the REAL kernel state of the multi-WAN integration: gate, planner
 * input (config plane), managed-band `ip rule` entries, live contents of the
 * managed tables (240 egress + 260..271 per-WAN source routing), an
 * idempotent preview of what the next converge pass would do, and the real
 * failover event log. Read-only — never executes a step.
 */

import { route } from "@/lib/api/handler";
import { getEngine } from "@/lib/engine";
import { wanOsStatus } from "@/lib/network/wan-os";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async () => {
  const status = await wanOsStatus();
  return {
    data: {
      ...status,
      events: getEngine().wanTransitionEvents ?? [],
    },
  };
});

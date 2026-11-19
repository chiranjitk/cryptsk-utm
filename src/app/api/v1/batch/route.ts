/**
 * POST /api/v1/batch — generic batch operations endpoint (spec §1.15).
 * Body: { operations: [{ method: "POST"|"PUT"|"DELETE", path, body? }, …] } —
 * max 20 ops, executed sequentially in-process against the SAME service
 * functions the REST routes use (lib/api/batch.ts), stop-on-first-error.
 * RBAC is checked per operation's resource (path → capability-area map).
 *
 * Exactly ONE audit entry is written per batch (`batch.execute`) with the
 * summary counts; firewall-family mutations converge the nftables policy via
 * the hook below (same behavior as the individual routes).
 *
 * Config-version gating (F-e #9): the section snapshot + `config:updated`
 * broadcast only fire when at least one operation EXECUTED (executed > 0) —
 * denied/failed batches must not bump the config version.
 */

import { route } from "@/lib/api/handler";
import { batchRequestSchema } from "@/lib/validators/batch";
import { executeBatchOperations } from "@/lib/api/batch";
import { snapshotConfigVersion } from "@/lib/api/audit";
import { scheduleFirewallConverge } from "@/lib/firewall/firewall-converge";

export const dynamic = "force-dynamic";

export const POST = route(
  // no route-level `area` — RBAC is enforced per operation inside the executor;
  // no route-level `section` — the snapshot is gated on executed > 0 below.
  { bodySchema: batchRequestSchema },
  async ({ auth, body, requestId }) => {
    const outcome = await executeBatchOperations(auth, body.operations, requestId);

    // F-e #9: only executed operations snapshot the firewall config version +
    // broadcast config:updated + schedule nftables convergence.
    if (outcome.executed > 0) {
      const changeSummary = `batch.execute: batch ${outcome.executed}/${body.operations.length}`;
      await snapshotConfigVersion({
        tenantId: auth.tenantId,
        section: "firewall",
        changeSummary,
        userId: auth.userId,
        // audit fix L23 — snapshot failures are OBSERVABLE (matches handler.ts)
      }).catch((err: unknown) =>
        console.error(`[batch] ${requestId} config snapshot failed:`, err instanceof Error ? err.message : err),
      );
      scheduleFirewallConverge(auth.tenantId);
    }

    return {
      data: outcome,
      audit: {
        action: "batch.execute",
        objectType: "batch",
        objectName: `batch ${outcome.executed}/${body.operations.length}`,
        after: {
          total: body.operations.length,
          executed: outcome.executed,
          failed: outcome.failed,
          ok: outcome.ok,
          paths: body.operations.map((op) => `${op.method} ${op.path}`),
        },
        ...(outcome.executed === 0 && outcome.failed > 0 ? { result: "denied" as const } : {}),
        ...(outcome.failed > 0 && outcome.executed > 0 ? { result: "failure" as const } : {}),
      },
    };
  },
);

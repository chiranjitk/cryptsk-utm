/**
 * POST /api/v1/batch — generic batch operations endpoint (spec §1.15).
 * Body: { operations: [{ method: "POST"|"PUT"|"DELETE", path, body? }, …] } —
 * max 20 ops, executed sequentially in-process against the SAME service
 * functions the REST routes use (lib/api/batch.ts), stop-on-first-error.
 * RBAC is checked per operation's resource (path → capability-area map).
 *
 * Exactly ONE audit entry is written per batch (`batch.execute`) with the
 * summary counts; firewall-family mutations converge the nftables policy via
 * the shared section hook below (same behavior as the individual routes).
 */

import { route } from "@/lib/api/handler";
import { batchRequestSchema } from "@/lib/validators/batch";
import { executeBatchOperations } from "@/lib/api/batch";

export const dynamic = "force-dynamic";

export const POST = route(
  // no route-level `area` — RBAC is enforced per operation inside the executor
  { bodySchema: batchRequestSchema, section: "firewall" },
  async ({ auth, body }) => {
    const outcome = await executeBatchOperations(auth, body.operations);
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

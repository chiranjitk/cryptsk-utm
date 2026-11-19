/**
 * /api/v1/sase/mesh — PLAN-ONLY WireGuard mesh config preview (spec §4.2).
 *
 * plan-only, keys redacted: GET loads the tenant's SASE registry and returns
 * the PURE renderMeshConfig plan — per-node wg-quick configs with
 * `[REDACTED-SEE-SECRET-STORE]` for PrivateKey/PublicKey/PresharedKey and
 * validation errors collected per mesh rule. NOTHING is applied to the host
 * OS and no cloud VM is deployed — this endpoint never mutates anything.
 */

import { route } from "@/lib/api/handler";
import { renderForTenant } from "@/lib/sase/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sase" }, async ({ auth }) => {
  const plan = await renderForTenant(auth.tenantId);
  return { data: plan };
});

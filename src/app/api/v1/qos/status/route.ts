/**
 * GET /api/v1/qos/status — live kernel shaping state per enabled policy:
 * expected classes/filters from the deterministic renderer vs parsed
 * `tc -j` output, drift reasons, state-file info, tc availability and
 * data-plane mode. Read-only.
 */

import { route } from "@/lib/api/handler";
import { readQosKernelStatus } from "@/lib/qos/os-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "qos" }, async ({ auth }) => {
  return { data: await readQosKernelStatus(auth.tenantId) };
});

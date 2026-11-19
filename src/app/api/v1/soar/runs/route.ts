/**
 * /api/v1/soar/runs — paginated playbook-run ledger, filterable by playbook
 * and status. Run rows carry a logical playbookId ref; playbook names are
 * joined in the service.
 */

import { route } from "@/lib/api/handler";
import { soarRunsQuerySchema } from "@/lib/validators/soar";
import { listRuns } from "@/lib/soar/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "soar", querySchema: soarRunsQuerySchema }, async ({ auth, query }) => {
  return listRuns(auth.tenantId, query);
});

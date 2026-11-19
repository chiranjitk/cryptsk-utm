/**
 * GET /api/v1/config-anomaly/findings — persisted ConfigAnomalyFinding rows
 * (spec §4.5 rule-based pass). Filters: kind, severity, status; newest
 * detection first, server-paginated envelope.
 */

import { route } from "@/lib/api/handler";
import { configAnomalyFindingsQuerySchema } from "@/lib/validators/config-anomaly";
import { listFindings } from "@/lib/firewall/anomaly-service";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "config_anomaly", querySchema: configAnomalyFindingsQuerySchema },
  async ({ auth, query }) => {
    return listFindings(auth.tenantId, query);
  },
);

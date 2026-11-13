/**
 * GET /api/v1/logs/audit — server-paginated audit trail (M09 §3, area "audit").
 * `?facets=objectTypes` swaps the payload for `{ objectTypes }` (distinct via
 * groupBy) — additive param feeding the audit view's filter Select.
 */

import { route, type HandlerResult } from "@/lib/api/handler";
import { auditLogQuerySchema, type AuditLogQuery } from "@/lib/validators/logs";
import { distinctAuditObjectTypes, listAuditLogs, type AuditLogDTO } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

type AuditData = AuditLogDTO[] | { objectTypes: string[] };

export const GET = route<undefined, AuditLogQuery, AuditData>(
  { area: "audit", querySchema: auditLogQuerySchema },
  async ({ auth, query }): Promise<HandlerResult<AuditData>> => {
    if (query.facets === "objectTypes") {
      return { data: { objectTypes: await distinctAuditObjectTypes(auth.tenantId) } };
    }
    const { rows, meta } = await listAuditLogs(auth.tenantId, query);
    return { data: rows, meta };
  },
);

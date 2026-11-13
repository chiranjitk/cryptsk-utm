/**
 * GET /api/v1/logs/firewall/export — CSV of the current filter (M09 §3,
 * locked surface). Same params as the list endpoint minus `page`; capped at
 * 10 000 rows most-recent-first; `X-Row-Cap` reports the cap. Shaped as a raw
 * NextResponse (handler passes it through with x-request-id).
 */

import { NextResponse } from "next/server";
import { route } from "@/lib/api/handler";
import { firewallExportQuerySchema } from "@/lib/validators/logs";
import { exportFirewallLogsCsv } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "logs", querySchema: firewallExportQuerySchema }, async ({ auth, query }) => {
  const csv = await exportFirewallLogsCsv(auth.tenantId, query);
  const res = new NextResponse(csv, {
    status: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": 'attachment; filename="firewall-logs.csv"',
      "X-Row-Cap": "10000",
    },
  });
  return { data: res };
});

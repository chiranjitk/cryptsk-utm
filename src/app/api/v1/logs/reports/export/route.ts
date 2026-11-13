/**
 * GET /api/v1/logs/reports/export?range=&format=csv|json — report export
 * (M09 §3): CSV of the bucket series or JSON of the LOCKED stats payload.
 */

import { NextResponse } from "next/server";
import { route } from "@/lib/api/handler";
import { reportExportQuerySchema } from "@/lib/validators/logs";
import { getLogStats } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "reports", querySchema: reportExportQuerySchema }, async ({ auth, query }) => {
  const stats = await getLogStats(auth.tenantId, query.range);

  if (query.format === "json") {
    const res = new NextResponse(JSON.stringify(stats, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="traffic-report-${query.range}.json"`,
      },
    });
    return { data: res };
  }

  const actions = stats.series.map((s) => s.key);
  const byTs = new Map<string, Record<string, number | string>>();
  for (const s of stats.series) {
    for (const p of s.points) {
      const row = byTs.get(p.ts) ?? { bucket: p.ts };
      row[s.key] = p.count;
      byTs.set(p.ts, row);
    }
  }
  const header = ["bucket", ...actions].join(",");
  const lines = [...byTs.values()].map((row) => [row.bucket, ...actions.map((a) => row[a] ?? 0)].join(","));
  const csv = [header, ...lines].join("\n");

  const res = new NextResponse(csv, {
    status: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="traffic-report-${query.range}.csv"`,
    },
  });
  return { data: res };
});

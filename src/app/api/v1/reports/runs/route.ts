/**
 * M12 report runs (spec 2.13 §3) — GET paged list + POST render-now.
 * POST computes the requested section rollups from the real tables, renders
 * a print-friendly HTML document (engine.ts) and stores it in contentHtml
 * with status `done`. format "pdf" produces identical HTML plus the
 * `pdfViaPrint: true` summary hint (the view opens the print dialog).
 */

import { route } from "@/lib/api/handler";
import { reportRunCreateSchema, reportRunListQuerySchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";
import {
  buildReportHtml,
  computeSectionSummary,
  pageMetaOf,
  rangeWindow,
  toRunListItem,
  type ReportSummary,
} from "@/app/api/v1/reports/engine";

export const dynamic = "force-dynamic";

export const GET = route({ area: "reports", querySchema: reportRunListQuerySchema }, async ({ auth, query }) => {
  const where = {
    tenantId: auth.tenantId,
    ...(query.source ? { source: query.source } : {}),
    ...(query.status ? { status: query.status } : {}),
  };
  const [rows, total] = await Promise.all([
    db.reportRun.findMany({
      where,
      orderBy: { id: "desc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.reportRun.count({ where }),
  ]);
  return { data: rows.map(toRunListItem), meta: pageMetaOf(query.page, query.limit, total) };
});

export const POST = route(
  { area: "reports", bodySchema: reportRunCreateSchema, section: "reports" },
  async ({ auth, body }) => {
    const { since, until } = rangeWindow(body.range);
    const sectionSummary = await computeSectionSummary(auth.tenantId, body.sections, since, until);
    const summary: ReportSummary = {
      meta: {
        generatedAt: until.toISOString(),
        range: body.range,
        since: since.toISOString(),
        until: until.toISOString(),
        pdfViaPrint: body.format === "pdf",
      },
      ...sectionSummary,
    };
    const tenant = await db.tenant.findUnique({ where: { id: auth.tenantId }, select: { name: true } });
    const contentHtml = buildReportHtml({
      title: body.name,
      tenantName: tenant?.name ?? `tenant ${auth.tenantId}`,
      range: body.range,
      generatedAt: until,
      summary,
    });
    const created = await db.reportRun.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        source: "ad-hoc",
        range: body.range,
        format: body.format,
        sections: JSON.stringify(body.sections),
        status: "done",
        summary: JSON.stringify(summary),
        contentHtml,
        startedAt: until,
        finishedAt: new Date(),
      },
    });
    return {
      data: toRunListItem(created),
      audit: {
        action: "report.run",
        objectType: "report_run",
        objectId: created.id,
        objectName: created.name,
        after: { id: created.id, name: created.name, range: created.range, format: created.format, status: created.status },
      },
    };
  },
);

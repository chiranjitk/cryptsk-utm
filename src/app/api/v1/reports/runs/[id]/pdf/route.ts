/**
 * GET /api/v1/reports/runs/{id}/pdf — true server-side PDF download (spec
 * §1.12 report formats). Loads the ReportRun and rebuilds the document
 * sections from the run's structured summary via the SAME engine helper the
 * HTML renderer uses (buildReportSections — no duplicated rollup logic), then
 * renders it with the dependency-free writer (src/lib/reports/pdf.ts).
 *
 * Runs WITHOUT structured content (failed/legacy rows) respond 409 CONFLICT —
 * the view falls back to the pdfViaPrint hint (print dialog over contentHtml).
 */

import { NextResponse } from "next/server";
import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import { renderPdf } from "@/lib/reports/pdf";
import { buildReportSections, type ReportSummary } from "@/app/api/v1/reports/engine";

export const dynamic = "force-dynamic";

export const GET = route({ area: "reports" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const row = await db.reportRun.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!row) throw ApiError.notFound("Report run not found");

  const summary = parseJson<ReportSummary | null>(row.summary, null);
  const sections = summary ? buildReportSections(summary) : [];
  if (sections.length === 0) {
    throw ApiError.conflict(
      "Report run has no structured content to render as PDF — use the HTML view (pdfViaPrint fallback)",
    );
  }

  const tenant = await db.tenant.findUnique({ where: { id: auth.tenantId }, select: { name: true } });
  const generated = (row.finishedAt ?? row.createdAt).toISOString().replace("T", " ").slice(0, 19);
  const pdf = renderPdf({
    title: row.name,
    subtitle: `Tenant: ${tenant?.name ?? `tenant ${auth.tenantId}`} · Range: ${row.range} · Generated: ${generated} UTC`,
    sections,
  });

  return {
    data: new NextResponse(new Uint8Array(pdf), {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="report-${id}.pdf"`,
        "Content-Length": String(pdf.byteLength),
      },
    }),
  };
});

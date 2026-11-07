/**
 * M12 compliance run (spec 2.13 §5) — POST { templateId } renders the
 * per-framework checklist against real data and stores it as a ReportRun
 * (source "compliance") with a checklist table in the HTML, plus the
 * template's selected section rollups. Bumps template.lastRunAt.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { complianceRunSchema, type ReportSection } from "@/lib/validators/reporting";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import {
  buildChecklist,
  buildReportHtml,
  computeSectionSummary,
  rangeWindow,
  toRunListItem,
  type ReportSummary,
} from "@/app/api/v1/reports/engine";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "reports", bodySchema: complianceRunSchema, section: "reports" },
  async ({ auth, body }) => {
    const template = await db.complianceTemplate.findFirst({
      where: { tenantId: auth.tenantId, id: body.templateId },
    });
    if (!template) throw ApiError.notFound("Compliance template not found");

    const checklist = await buildChecklist(auth.tenantId, template.framework);
    const passed = checklist.filter((r) => r.pass).length;
    const passRate = checklist.length > 0 ? Math.round((passed / checklist.length) * 100) : 0;

    const sections = parseJson<ReportSection[]>(template.sections, []);
    const { since, until } = rangeWindow(template.range);
    const sectionSummary =
      sections.length > 0 ? await computeSectionSummary(auth.tenantId, sections, since, until) : {};

    const summary: ReportSummary = {
      meta: {
        generatedAt: until.toISOString(),
        range: template.range,
        since: since.toISOString(),
        until: until.toISOString(),
        pdfViaPrint: false,
      },
      framework: template.framework,
      checklist,
      passRate,
      ...sectionSummary,
    };
    const tenant = await db.tenant.findUnique({ where: { id: auth.tenantId }, select: { name: true } });
    const contentHtml = buildReportHtml({
      title: `${template.name} — ${template.framework} compliance`,
      tenantName: tenant?.name ?? `tenant ${auth.tenantId}`,
      range: template.range,
      generatedAt: until,
      summary,
    });
    const now = new Date();
    const run = await db.reportRun.create({
      data: {
        tenantId: auth.tenantId,
        name: `${template.name} — ${template.framework} check`,
        source: "compliance",
        templateId: template.id,
        range: template.range,
        format: "html",
        sections: JSON.stringify(sections),
        status: "done",
        summary: JSON.stringify(summary),
        contentHtml,
        startedAt: now,
        finishedAt: now,
      },
    });
    await db.complianceTemplate.update({ where: { id: template.id }, data: { lastRunAt: now } });

    return {
      data: toRunListItem(run),
      audit: {
        action: "compliance.run",
        objectType: "report_run",
        objectId: run.id,
        objectName: run.name,
        after: {
          id: run.id,
          name: run.name,
          framework: template.framework,
          passRate,
          status: run.status,
        },
      },
    };
  },
);

/**
 * M12 compliance templates (spec 2.13 §4) — GET list + POST create.
 * Framework enum: PCI | HIPAA | GDPR | ISO27001 | SOC2. Name unique per tenant.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { complianceTemplateCreateSchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";

export const dynamic = "force-dynamic";

export type ComplianceTemplateDTO = {
  id: number;
  name: string;
  framework: string;
  sections: string[];
  range: string;
  enabled: boolean;
  lastRunAt: string | null;
  createdAt: string;
};

export function toTemplateDto(row: {
  id: number;
  name: string;
  framework: string;
  sections: string;
  range: string;
  enabled: boolean;
  lastRunAt: Date | null;
  createdAt: Date;
}): ComplianceTemplateDTO {
  return {
    id: row.id,
    name: row.name,
    framework: row.framework,
    sections: parseJson<string[]>(row.sections, []),
    range: row.range,
    enabled: row.enabled,
    lastRunAt: row.lastRunAt ? row.lastRunAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

export const GET = route({ area: "reports" }, async ({ auth }) => {
  const rows = await db.complianceTemplate.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } });
  return { data: rows.map(toTemplateDto) };
});

export const POST = route(
  { area: "reports", bodySchema: complianceTemplateCreateSchema, section: "reports" },
  async ({ auth, body }) => {
    const dup = await db.complianceTemplate.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A template named "${body.name}" already exists`);
    const created = await db.complianceTemplate.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        framework: body.framework,
        sections: JSON.stringify(body.sections),
        range: body.range,
        enabled: body.enabled,
      },
    });
    return {
      data: toTemplateDto(created),
      audit: {
        action: "compliance_template.create",
        objectType: "compliance_template",
        objectId: created.id,
        objectName: created.name,
        after: { id: created.id, name: created.name, framework: created.framework },
      },
    };
  },
);

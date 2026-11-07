/**
 * M12 compliance templates — PUT update + DELETE by id (spec 2.13 §4).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { complianceTemplateUpdateSchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import type { ComplianceTemplateDTO } from "../route";

export const dynamic = "force-dynamic";

function toDto(row: {
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

export const PUT = route(
  { area: "reports", bodySchema: complianceTemplateUpdateSchema, section: "reports" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    if (!Number.isInteger(id) || id <= 0) throw ApiError.validation("Invalid template id");
    const existing = await db.complianceTemplate.findFirst({ where: { tenantId: auth.tenantId, id } });
    if (!existing) throw ApiError.notFound("Compliance template not found");
    if (body.name && body.name !== existing.name) {
      const dup = await db.complianceTemplate.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
      if (dup) throw ApiError.conflict(`A template named "${body.name}" already exists`);
    }
    const { sections, ...rest } = body;
    const updated = await db.complianceTemplate.update({
      where: { id },
      data: {
        ...rest,
        ...(sections ? { sections: JSON.stringify(sections) } : {}),
      },
    });
    return {
      data: toDto(updated),
      audit: {
        action: "compliance_template.update",
        objectType: "compliance_template",
        objectId: updated.id,
        objectName: updated.name,
        after: { id: updated.id, name: updated.name, framework: updated.framework, enabled: updated.enabled },
      },
    };
  },
);

export const DELETE = route({ area: "reports", section: "reports" }, async ({ auth, params }) => {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.validation("Invalid template id");
  const existing = await db.complianceTemplate.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!existing) throw ApiError.notFound("Compliance template not found");
  await db.complianceTemplate.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "compliance_template.delete",
      objectType: "compliance_template",
      objectId: existing.id,
      objectName: existing.name,
      after: { id: existing.id, name: existing.name },
    },
  };
});

/**
 * M12 anonymization rules — PUT update + DELETE by id (spec 2.13 §6).
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { anonymizationRuleUpdateSchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";
import type { AnonymizationRuleDTO } from "../route";

export const dynamic = "force-dynamic";

function toDto(row: {
  id: number;
  name: string;
  dataset: string;
  field: string;
  strategy: string;
  enabled: boolean;
  createdAt: Date;
}): AnonymizationRuleDTO {
  return {
    id: row.id,
    name: row.name,
    dataset: row.dataset,
    field: row.field,
    strategy: row.strategy,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

export const PUT = route(
  { area: "reports", bodySchema: anonymizationRuleUpdateSchema, section: "reports" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    if (!Number.isInteger(id) || id <= 0) throw ApiError.validation("Invalid rule id");
    const existing = await db.anonymizationRule.findFirst({ where: { tenantId: auth.tenantId, id } });
    if (!existing) throw ApiError.notFound("Anonymization rule not found");
    if (body.name && body.name !== existing.name) {
      const dup = await db.anonymizationRule.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
      if (dup) throw ApiError.conflict(`A rule named "${body.name}" already exists`);
    }
    const updated = await db.anonymizationRule.update({ where: { id }, data: body });
    return {
      data: toDto(updated),
      audit: {
        action: "anonymization_rule.update",
        objectType: "anonymization_rule",
        objectId: updated.id,
        objectName: updated.name,
        after: { id: updated.id, name: updated.name, strategy: updated.strategy, enabled: updated.enabled },
      },
    };
  },
);

export const DELETE = route({ area: "reports", section: "reports" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  if (!Number.isInteger(id) || id <= 0) throw ApiError.validation("Invalid rule id");
  const existing = await db.anonymizationRule.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!existing) throw ApiError.notFound("Anonymization rule not found");
  await db.anonymizationRule.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "anonymization_rule.delete",
      objectType: "anonymization_rule",
      objectId: existing.id,
      objectName: existing.name,
      after: { id: existing.id, name: existing.name },
    },
  };
});

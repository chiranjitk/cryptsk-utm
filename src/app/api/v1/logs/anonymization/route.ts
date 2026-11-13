/**
 * M12 anonymization rules (spec 2.13 §6) — GET list + POST create.
 * Strategy enum: hash | mask | pseudonymize. No plaintext secrets echoed —
 * rules carry only strategy metadata, never sample values.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { anonymizationRuleCreateSchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export type AnonymizationRuleDTO = {
  id: number;
  name: string;
  dataset: string;
  field: string;
  strategy: string;
  enabled: boolean;
  createdAt: string;
};

export function toRuleDto(row: {
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

export const GET = route({ area: "reports" }, async ({ auth }) => {
  const rows = await db.anonymizationRule.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } });
  return { data: rows.map(toRuleDto) };
});

export const POST = route(
  { area: "reports", bodySchema: anonymizationRuleCreateSchema, section: "reports" },
  async ({ auth, body }) => {
    const dup = await db.anonymizationRule.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A rule named "${body.name}" already exists`);
    const created = await db.anonymizationRule.create({ data: { tenantId: auth.tenantId, ...body } });
    return {
      data: toRuleDto(created),
      audit: {
        action: "anonymization_rule.create",
        objectType: "anonymization_rule",
        objectId: created.id,
        objectName: created.name,
        after: { id: created.id, name: created.name, dataset: created.dataset, strategy: created.strategy },
      },
    };
  },
);

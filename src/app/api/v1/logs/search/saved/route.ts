/**
 * M12 saved log searches (spec 2.13 §2) — GET list + POST create.
 * Name is unique per tenant (@@unique([tenantId, name])); duplicate creates
 * return 409 CONFLICT. Reads are area `logs`; writes use area `reports`
 * because the `logs` capability matrix has no write column.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { savedSearchCreateSchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";

export const dynamic = "force-dynamic";

export type SavedSearchDTO = {
  id: number;
  name: string;
  dataset: string;
  queryText: string;
  filters: Record<string, string>;
  createdAt: string;
};

function toDto(row: {
  id: number;
  name: string;
  dataset: string;
  queryText: string;
  filters: string;
  createdAt: Date;
}): SavedSearchDTO {
  return {
    id: row.id,
    name: row.name,
    dataset: row.dataset,
    queryText: row.queryText,
    filters: parseJson<Record<string, string>>(row.filters, {}),
    createdAt: row.createdAt.toISOString(),
  };
}

export const GET = route({ area: "logs" }, async ({ auth }) => {
  const rows = await db.savedLogSearch.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: { id: "asc" },
  });
  return { data: rows.map(toDto) };
});

export const POST = route(
  { area: "reports", bodySchema: savedSearchCreateSchema, section: "reports" },
  async ({ auth, body }) => {
    const dup = await db.savedLogSearch.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A saved search named "${body.name}" already exists`);
    const created = await db.savedLogSearch.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        dataset: body.dataset,
        queryText: body.queryText,
        filters: JSON.stringify(body.filters),
      },
    });
    return {
      data: toDto(created),
      audit: {
        action: "saved_search.create",
        objectType: "saved_search",
        objectId: created.id,
        objectName: created.name,
        after: { id: created.id, name: created.name, dataset: created.dataset },
      },
    };
  },
);

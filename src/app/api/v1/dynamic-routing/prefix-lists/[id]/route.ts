/**
 * Prefix list item (M19 §2.6) — update / delete, audit `prefix_list.update|delete`.
 * Delete is guarded: 409 while a BGP neighbor references the list.
 * Partial updates merge with the stored row and re-run refinePrefixList
 * (CIDR-family / unique-seq / ge ≤ le) on the merged result.
 */

import { route, numericId } from "@/lib/api/handler";
import { prefixListUpdateSchema, refinePrefixList } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { assertNotReferencedByNeighbor, toPrefixListDTO } from "../../internal";

export const dynamic = "force-dynamic";

async function findList(tenantId: number, id: number) {
  const row = await db.prefixList.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Prefix list not found");
  return row;
}

export const PUT = route(
  { area: "dynamic_routing", bodySchema: prefixListUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await findList(auth.tenantId, id);
    // merge-then-revalidate (mirrors ipv6/shared.ts updateNat66Rule): a patch
    // that changes family OR entries alone must still satisfy the pair rule
    const mergedFamily = body.family ?? existing.family;
    let storedEntries: Array<{ seq: number; prefix: string; ge?: number | null; le?: number | null }> | null = null;
    if (body.entries === undefined) {
      try {
        storedEntries = JSON.parse(existing.entries);
      } catch {
        storedEntries = null; // corrupt stored JSON — nothing sane to merge
      }
    }
    if (body.entries !== undefined) {
      if (!refinePrefixList({ family: mergedFamily, entries: body.entries })) {
        throw ApiError.validation("Prefix list update failed validation", {
          fieldErrors: {
            entries: ["entries must have unique seq, valid CIDR for the list family and ge ≤ le"],
          },
        });
      }
    } else if (storedEntries && !refinePrefixList({ family: mergedFamily, entries: storedEntries })) {
      // e.g. a family-only switch that strands ipv4 CIDRs on an ipv6 list
      throw ApiError.validation("Prefix list update failed validation", {
        fieldErrors: {
          entries: ["entries must have unique seq, valid CIDR for the list family and ge ≤ le"],
        },
      });
    }
    const updated = await db.prefixList.update({
      where: { id },
      data: {
        ...(body.name === undefined ? {} : { name: body.name }),
        ...(body.family === undefined ? {} : { family: body.family }),
        ...(body.entries === undefined ? {} : { entries: JSON.stringify(body.entries) }),
      },
    });
    return {
      data: toPrefixListDTO(updated),
      audit: {
        action: "prefix_list.update",
        objectType: "prefix_list",
        objectId: id,
        objectName: updated.name,
        before: toPrefixListDTO(existing),
        after: toPrefixListDTO(updated),
      },
    };
  },
);

export const DELETE = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const existing = await findList(auth.tenantId, id);
    await assertNotReferencedByNeighbor(auth.tenantId, "prefixListInId", id, existing.name);
    await assertNotReferencedByNeighbor(auth.tenantId, "prefixListOutId", id, existing.name);
    await db.prefixList.delete({ where: { id } });
    return {
      data: { ok: true },
      audit: {
        action: "prefix_list.delete",
        objectType: "prefix_list",
        objectId: id,
        objectName: existing.name,
        before: toPrefixListDTO(existing),
      },
    };
  },
);

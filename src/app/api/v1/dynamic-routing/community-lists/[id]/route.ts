/**
 * Community list item (M19 §2.6) — update / delete, audit
 * `community_list.update|delete`. Partial updates merge with the stored row
 * and re-run refineCommunityEntries (AS:NN grammar / regex) on the merged
 * type+entries pair.
 */

import { route, numericId } from "@/lib/api/handler";
import { communityListUpdateSchema, refineCommunityEntries } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { toCommunityListDTO } from "../../internal";

export const dynamic = "force-dynamic";

async function findList(tenantId: number, id: number) {
  const row = await db.communityList.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Community list not found");
  return row;
}

const ENTRIES_MESSAGE = 'standard entries must be "AS:NN"; expanded entries must be valid regex';

export const PUT = route(
  { area: "dynamic_routing", bodySchema: communityListUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await findList(auth.tenantId, id);
    // merge-then-revalidate (mirrors ipv6/shared.ts updateNat66Rule): a patch
    // that changes type OR entries alone must still satisfy the pair rule
    const mergedType = body.type ?? (existing.type as "standard" | "expanded");
    let storedEntries: string[] | null = null;
    if (body.entries === undefined) {
      try {
        const parsed: unknown = JSON.parse(existing.entries);
        storedEntries = Array.isArray(parsed) ? parsed.filter((e): e is string => typeof e === "string") : null;
      } catch {
        storedEntries = null; // corrupt stored JSON — nothing sane to merge
      }
    }
    if (body.entries !== undefined) {
      if (!refineCommunityEntries(mergedType, body.entries)) {
        throw ApiError.validation("Community list update failed validation", {
          fieldErrors: { entries: [ENTRIES_MESSAGE] },
        });
      }
    } else if (storedEntries && !refineCommunityEntries(mergedType, storedEntries)) {
      // e.g. a type-only switch from expanded to standard stranding regexes
      throw ApiError.validation("Community list update failed validation", {
        fieldErrors: { entries: [ENTRIES_MESSAGE] },
      });
    }
    const updated = await db.communityList.update({
      where: { id },
      data: {
        ...(body.name === undefined ? {} : { name: body.name }),
        ...(body.type === undefined ? {} : { type: body.type }),
        ...(body.entries === undefined ? {} : { entries: JSON.stringify(body.entries) }),
      },
    });
    return {
      data: toCommunityListDTO(updated),
      audit: {
        action: "community_list.update",
        objectType: "community_list",
        objectId: id,
        objectName: updated.name,
        before: toCommunityListDTO(existing),
        after: toCommunityListDTO(updated),
      },
    };
  },
);

export const DELETE = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const existing = await findList(auth.tenantId, id);
    await db.communityList.delete({ where: { id } });
    return {
      data: { ok: true },
      audit: {
        action: "community_list.delete",
        objectType: "community_list",
        objectId: id,
        objectName: existing.name,
        before: toCommunityListDTO(existing),
      },
    };
  },
);

/**
 * DLP patterns (Phase 3 §3.3) — GET list + POST create. Mutations audit
 * `dlp.pattern.create` and snapshot section `dlp`.
 */

import { route } from "@/lib/api/handler";
import { dlpPatternCreateSchema } from "@/lib/validators/dlp";
import { createPattern, listPatterns } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dlp" }, async ({ auth }) => {
  return { data: await listPatterns(auth.tenantId) };
});

export const POST = route(
  { area: "dlp", bodySchema: dlpPatternCreateSchema, section: "dlp" },
  async ({ auth, body }) => {
    const created = await createPattern(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "dlp.pattern.create",
        objectType: "dlp_pattern",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

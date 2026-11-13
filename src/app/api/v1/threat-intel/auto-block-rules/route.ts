/**
 * Auto-block rules (M13 §2.11 tab 3) — GET list + POST create (manual rules;
 * `auto-feed` rules are engine-owned and created by feed sync). Mutations
 * audit `threat_autoblock.create` and snapshot section `threat_intel`.
 */

import { route } from "@/lib/api/handler";
import { autoBlockCreateSchema } from "@/lib/validators/threat-intel";
import { createAutoBlockRule, listAutoBlockRules } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "threat_intel" }, async ({ auth }) => {
  return { data: await listAutoBlockRules(auth.tenantId) };
});

export const POST = route(
  { area: "threat_intel", bodySchema: autoBlockCreateSchema, section: "threat_intel" },
  async ({ auth, body }) => {
    const created = await createAutoBlockRule(auth.tenantId, body, auth.username ?? "admin");
    return {
      data: created,
      audit: {
        action: "threat_autoblock.create",
        objectType: "auto_block_rule",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

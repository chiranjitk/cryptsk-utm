/**
 * /api/v1/sites/templates — reusable site config bundles ("deploy new site
 * from template", Phase 4 §4.1). GET lists the tenant templates; POST creates
 * one with a JSON payload object ({firewallRules[], natRules[], …}) that the
 * validator enforces as a real object (never a string).
 */

import { route } from "@/lib/api/handler";
import { templateCreateSchema } from "@/lib/validators/sites";
import { createTemplate, listTemplates } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sites" }, async ({ auth }) => {
  return { data: await listTemplates(auth.tenantId) };
});

export const POST = route(
  { area: "sites", bodySchema: templateCreateSchema },
  async ({ auth, body }) => {
    const created = await createTemplate(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "site_template.create",
        objectType: "site_template",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);

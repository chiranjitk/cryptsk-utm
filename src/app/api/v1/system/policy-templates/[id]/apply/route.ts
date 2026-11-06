/**
 * POST /api/v1/system/policy-templates/{id}/apply — apply a starter bundle
 * (M10 §5.8): idempotent-by-replace for named seed rows, ONE config_versions
 * snapshot with section "all" (sentinel → every view refetches), audited.
 */

import { route } from "@/lib/api/handler";
import { templateApplySchema } from "@/lib/validators/system";
import { applyTemplate } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "system", admin: true, bodySchema: templateApplySchema, section: "all" },
  async ({ auth, params }) => {
    const result = await applyTemplate(auth.tenantId, params.id);
    return {
      data: result,
      audit: {
        action: "template.apply",
        objectType: "policy_template",
        objectName: result.template.id,
        after: result.summary,
      },
    };
  },
);

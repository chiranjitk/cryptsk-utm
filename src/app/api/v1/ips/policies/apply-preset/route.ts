/**
 * POST /api/v1/ips/policies/apply-preset — one-click Conservative/Balanced/
 * Aggressive bundles (DATA_PLANE §3.1). Creates a new policy (default name =
 * preset key uppercased) or replaces the selected policy's category map +
 * mode via replacePolicyId.
 */

import { route } from "@/lib/api/handler";
import { ipsPresetBodySchema } from "@/lib/validators/ips";
import { applyPreset } from "@/lib/ips/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "ips_policies", bodySchema: ipsPresetBodySchema, section: "ips" },
  async ({ auth, body }) => {
    const policy = await applyPreset(auth.tenantId, body.preset, body.name, body.replacePolicyId);
    return {
      data: policy,
      audit: {
        action: "ips_policy.apply_preset",
        objectType: "ips_policy",
        objectId: policy.id,
        objectName: policy.name,
        after: { preset: body.preset, mode: policy.mode, replaced: Boolean(body.replacePolicyId) },
      },
    };
  },
);

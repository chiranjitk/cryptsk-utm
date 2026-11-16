/**
 * App control simulated test (M18 §2.2.4) — resolves the decision for one app
 * against one policy (rule → unknown_app → default), persists an AppControlLog
 * row and bumps the matched rule's hitCount. This route was MISSING (the UI
 * test card pointed at a 404) — it wires the existing testApp service with the
 * appTestSchema validator. Audit `app_control.policy.test`, section
 * `app_control` (numericId() guards the path param).
 */

import { route, numericId } from "@/lib/api/handler";
import { appTestSchema } from "@/lib/validators/app-control";
import { testApp } from "@/app/api/v1/app-control/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "app_control", bodySchema: appTestSchema, section: "app_control" },
  async ({ auth, body, params, ip }) => {
    const policyId = numericId(params, "id");
    const result = await testApp(auth.tenantId, policyId, body, ip);
    return {
      data: result,
      audit: {
        action: "app_control.policy.test",
        objectType: "app_control_policy",
        objectId: policyId,
        objectName: result.appName,
        after: result,
      },
    };
  },
);

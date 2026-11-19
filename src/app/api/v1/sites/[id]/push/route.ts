/**
 * /api/v1/sites/[id]/push — central push to a remote site (Phase 4 §4.1).
 * Body: {kind: policy|template|firmware, templateId?, firmwareVersion?,
 * payload?}. The service validates the site (and the referenced template /
 * catalog firmware release), records a SiteDeployment in `pushing`, then
 * resolves the SIMULATED transport immediately: status "applied" (with
 * pushedAt/appliedAt) unless the site has never connected — "failed" with
 * result.errors ["site has never connected"]. The real remote push transport
 * (API + WebSocket to the site agent) is out of scope for the console; this
 * route comment is the documented contract for that seam.
 */

import { route, numericId } from "@/lib/api/handler";
import { sitePushSchema } from "@/lib/validators/sites";
import { pushToSite } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "sites", bodySchema: sitePushSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const deployment = await pushToSite(auth.tenantId, id, body, auth.username ?? "system");
    return {
      data: deployment,
      audit: {
        action: "site.push",
        objectType: "site_deployment",
        objectId: deployment.id,
        objectName: `${deployment.siteName ?? `site#${id}`} ${deployment.kind} push`,
        after: { kind: deployment.kind, status: deployment.status, result: deployment.result },
      },
    };
  },
);

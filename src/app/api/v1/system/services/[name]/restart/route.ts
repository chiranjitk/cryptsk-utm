/** POST /api/v1/system/services/{name}/restart — simulated restart (M10 §3). */

import { route } from "@/lib/api/handler";
import { serviceRestartSchema } from "@/lib/validators/system";
import { restartService } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "system", admin: true, bodySchema: serviceRestartSchema, section: "system" },
  async ({ auth, params }) => {
    const service = await restartService(auth.tenantId, params.name);
    return {
      data: service,
      audit: {
        action: "service.restart",
        objectType: "service",
        objectName: service.name,
        after: service,
      },
    };
  },
);

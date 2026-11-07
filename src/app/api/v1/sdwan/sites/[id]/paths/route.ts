/** Path create under a site (M20 §2.5) — POST /sites/[id]/paths, audit `path.create`. */

import { route } from "@/lib/api/handler";
import { pathCreateSchema } from "@/lib/validators/sdwan";
import { createPath } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "sdwan", bodySchema: pathCreateSchema, section: "sdwan" },
  async ({ auth, body, params }) => {
    const siteId = Number(params.id);
    const created = await createPath(auth.tenantId, siteId, body);
    return {
      data: created,
      audit: {
        action: "path.create",
        objectType: "sdwan_path",
        objectId: created.id,
        objectName: `${created.siteName}/${created.wanInterface}`,
        after: created,
      },
    };
  },
);

/** GET /api/v1/config-versions — paginated version list (?section=&page=). */

import { route } from "@/lib/api/handler";
import { configVersionListQuery } from "@/lib/validators/system";
import { listConfigVersions } from "@/lib/config-versions/service";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "system", querySchema: configVersionListQuery },
  async ({ auth, query }) => {
    const { data, meta } = await listConfigVersions(auth.tenantId, query);
    return { data, meta };
  },
);

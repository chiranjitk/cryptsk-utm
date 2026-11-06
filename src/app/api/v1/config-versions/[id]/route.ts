/** GET /api/v1/config-versions/{id} — one version incl. configSnapshot JSON. */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { getConfigVersion } from "@/lib/config-versions/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "system" }, async ({ auth, params }) => {
  const id = Number(params.id);
  if (!Number.isInteger(id)) throw ApiError.notFound("Config version not found");
  return { data: await getConfigVersion(auth.tenantId, id) };
});

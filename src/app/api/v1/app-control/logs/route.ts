/**
 * App control decision log (M18 §2.2.5) — paged-lite, newest first, optional
 * appName/action filters (limit defaults 100, max 500).
 */

import { route } from "@/lib/api/handler";
import { appControlLogQuerySchema } from "@/lib/validators/app-control";
import { listLogs } from "@/app/api/v1/app-control/service";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "app_control", querySchema: appControlLogQuerySchema },
  async ({ auth, query }) => {
    const { data, meta } = await listLogs(auth.tenantId, query);
    return { data, meta };
  },
);

/**
 * POST /api/v1/routes/apply — converge static routes onto the kernel FIB
 * (route-os planner → route-apply executor, gated by CONSOLE_OS_APPLY).
 * Body: { id? } — one route, or all routes (enabled rows install, disabled
 * rows withdraw stale entries). Sibling-aware plans keep ECMP members intact.
 * GET — plan preview (no exec) for the UI confirm dialog.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { z } from "zod";
import { readKernelRoutes, buildRouteApplyPlan, kernelRouteState, type KernelRoute } from "@/lib/network/route-os";
import { convergeRouteSafe } from "@/lib/network/route-apply";
import type { RouteRuleView } from "@/lib/network/route-rules";

export const dynamic = "force-dynamic";

const applyBody = z.object({ id: z.number().int().min(1).optional() });

async function convergeOne(view: RouteRuleView, siblings: RouteRuleView[]) {
  const kernel = (await readKernelRoutes().catch(() => null)) as KernelRoute[] | null;
  const os = await convergeRouteSafe(async () => buildRouteApplyPlan(view, kernel, siblings));
  const fresh = await readKernelRoutes().catch(() => null);
  return {
    id: view.id,
    name: view.name ?? null,
    destinationCidr: view.destinationCidr,
    osState: kernelRouteState(view, fresh),
    os: { gate: os.gate, applied: os.applied, reason: os.reason, plan: os.plan, results: os.results },
  };
}

export const POST = route({ area: "network", bodySchema: applyBody, section: "routing" }, async ({ auth, body }) => {
  const rows = await db.staticRoute.findMany({ where: { tenantId: auth.tenantId } });
  const views = rows as unknown as RouteRuleView[];
  if (body.id) {
    const view = views.find((r) => r.id === body.id);
    if (!view) throw ApiError.notFound(`Route ${body.id} not found`);
    return {
      data: [await convergeOne(view, views)],
      audit: { action: "route.os-apply", objectType: "static_route", objectId: view.id, objectName: view.name ?? view.destinationCidr },
    };
  }
  const outcomes = [];
  for (const view of views) outcomes.push(await convergeOne(view, views));
  return {
    data: outcomes,
    audit: { action: "route.os-apply", objectType: "static_route", objectId: null, objectName: "all" },
  };
});

export const GET = route({ area: "network" }, async ({ auth }) => {
  const rows = await db.staticRoute.findMany({ where: { tenantId: auth.tenantId } });
  const kernel = await readKernelRoutes().catch(() => null);
  const views = rows as unknown as RouteRuleView[];
  return {
    data: views.map((v) => ({
      id: v.id,
      destinationCidr: v.destinationCidr,
      enabled: v.enabled,
      osState: kernelRouteState(v, kernel),
      plan: buildRouteApplyPlan(v, kernel, views).steps,
    })),
  };
});

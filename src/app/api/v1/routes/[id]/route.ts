/**
 * GET/PUT/DELETE /api/v1/routes/{id} — static route detail, replace, delete.
 * PUT re-validates business rules (409 + force) and re-checks the interface
 * ref. DELETE withdraws the row's kernel entries (best effort, gated) before
 * the DB delete.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, routeCreateSchema } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeStaticRoute } from "@/lib/network/shapes";
import { readKernelRoutes, kernelRouteState, buildRouteDeletePlan, buildRouteApplyPlan, type KernelRoute } from "@/lib/network/route-os";
import { convergeRouteSafe } from "@/lib/network/route-apply";
import { conflictRouteIssues, hardRouteIssues, validateRouteMutation, type RouteRuleView } from "@/lib/network/route-rules";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.staticRoute.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Route ${id} not found`);
  const kernel = await readKernelRoutes().catch(() => null);
  return { data: { ...shapeStaticRoute(row), osState: kernelRouteState(row as unknown as RouteRuleView, kernel) } };
});

export const PUT = route(
  { area: "network", bodySchema: routeCreateSchema, section: "routing" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const before = await db.staticRoute.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!before) throw ApiError.notFound(`Route ${id} not found`);
    if (body.interfaceName) await assertIfacesExist(auth.tenantId, [body.interfaceName]);

    const siblings = await db.staticRoute.findMany({ where: { tenantId: auth.tenantId } });
    const candidate: RouteRuleView = {
      id,
      destinationCidr: body.destinationCidr,
      gateway: body.gateway ?? null,
      interfaceName: body.interfaceName ?? null,
      distance: body.distance,
      blackhole: body.blackhole,
      enabled: body.enabled,
    };
    const issues = validateRouteMutation(candidate, siblings as unknown as RouteRuleView[], { excludeId: id });
    const hard = hardRouteIssues(issues);
    if (hard.length > 0) throw ApiError.validation(hard.map((i) => i.message).join("; "));
    const conflicts = conflictRouteIssues(issues);
    if (conflicts.length > 0 && !body.force) {
      throw ApiError.conflict("Route conflicts with existing configuration", { issues: conflicts });
    }

    const updated = await db.staticRoute.update({
      where: { id },
      data: {
        name: body.name ?? null,
        destinationCidr: body.destinationCidr,
        gateway: body.gateway ?? null,
        interfaceName: body.interfaceName ?? null,
        distance: body.distance,
        bfd: body.bfd,
        blackhole: body.blackhole,
        enabled: body.enabled,
        description: body.description ?? null,
      },
    });

    // auto-converge (gated, best-effort — same contract as interface writes):
    // previous-aware plan withdraws the pre-edit footprint, installs the new one
    const kernel = (await readKernelRoutes().catch(() => null)) as KernelRoute[] | null;
    const siblings = (await db.staticRoute.findMany({ where: { tenantId: auth.tenantId } })) as unknown as RouteRuleView[];
    const os = await convergeRouteSafe(async () =>
      buildRouteApplyPlan(updated as unknown as RouteRuleView, kernel, siblings, before as unknown as RouteRuleView),
    );

    return {
      data: shapeStaticRoute(updated),
      osState: kernelRouteState(updated as unknown as RouteRuleView, await readKernelRoutes().catch(() => null)),
      os,
      info: issues.filter((i) => i.kind === "info"),
      audit: {
        action: "route.update",
        objectType: "static_route",
        objectId: id,
        objectName: before.name ?? before.destinationCidr,
        before: shapeStaticRoute(before),
        after: shapeStaticRoute(updated),
        ...(body.force ? { info: { forced: true } } : {}),
      },
    };
  },
);

export const DELETE = route({ area: "network", section: "routing" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.staticRoute.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Route ${id} not found`);

  // withdraw kernel entries first (gated; DB delete never rolls back on host errors)
  const kernel = await readKernelRoutes().catch(() => null);
  const os = await convergeRouteSafe(async () => buildRouteDeletePlan(row as unknown as RouteRuleView, kernel));

  await db.staticRoute.delete({ where: { id } });
  return {
    data: { ok: true },
    os,
    audit: {
      action: "route.delete",
      objectType: "static_route",
      objectId: row.id,
      objectName: row.name ?? row.destinationCidr,
      before: shapeStaticRoute(row),
    },
  };
});

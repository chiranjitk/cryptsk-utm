/**
 * GET  /api/v1/routes — static routes with LIVE kernel state (osState) and
 * REAL next-hop probe state (bfd) — vendor Status-column parity.
 *   osState:  in-kernel | drifted | missing | disabled | null (unknown host)
 *   bfdState: up | down | unknown (ping-based next-hop reachability, 30 s cache)
 * POST /api/v1/routes — create; business rules from route-rules.ts:
 *   hard issues → 400; conflicts (duplicate / primary-default shadow) → 409
 *   with `issues[]` unless body.force=true.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { netListQuery, routeCreateSchema } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeStaticRoute } from "@/lib/network/shapes";
import { readKernelRoutes, kernelRouteState } from "@/lib/network/route-os";
import { probeNextHops } from "@/lib/network/nh-probe";
import { conflictRouteIssues, hardRouteIssues, validateRouteMutation, type RouteRuleView } from "@/lib/network/route-rules";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  let rows = await db.staticRoute.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ destinationCidr: "asc" }, { distance: "asc" }],
  });
  const shaped = rows.map(shapeStaticRoute);

  // live kernel state + real next-hop probes (best-effort, never block the list)
  const [kernel, nhMap] = await Promise.all([
    readKernelRoutes().catch(() => null),
    probeNextHops(
      shaped.filter((r) => r.bfd && r.enabled && !r.blackhole && r.gateway).map((r) => r.gateway as string),
    ).catch(() => new Map()),
  ]);
  const withOs = shaped.map((r) => {
    const osState = kernelRouteState(r as unknown as RouteRuleView, kernel);
    const nh = r.gateway && r.bfd && r.enabled && !r.blackhole ? nhMap.get(r.gateway) : undefined;
    return {
      ...r,
      osState,
      bfdState: nh ? nh.state : (r.bfdState ?? null),
      nhLatencyMs: nh?.latencyMs ?? null,
    };
  });

  if (query.iface) return { data: withOs.filter((r) => r.interfaceName === query.iface) };
  if (query.enabled) return { data: withOs.filter((r) => r.enabled === (query.enabled === "true")) };
  const q = (query.q ?? "").trim().toLowerCase();
  if (q) {
    return {
      data: withOs.filter(
        (r) =>
          r.destinationCidr.toLowerCase().includes(q) ||
          (r.name ?? "").toLowerCase().includes(q) ||
          (r.gateway ?? "").toLowerCase().includes(q),
      ),
    };
  }
  return { data: withOs };
});

export const POST = route(
  { area: "network", bodySchema: routeCreateSchema, section: "routing" },
  async ({ auth, body }) => {
    if (body.interfaceName) await assertIfacesExist(auth.tenantId, [body.interfaceName]);

    const siblings = await db.staticRoute.findMany({ where: { tenantId: auth.tenantId } });
    const candidate: RouteRuleView = {
      destinationCidr: body.destinationCidr,
      gateway: body.gateway ?? null,
      interfaceName: body.interfaceName ?? null,
      distance: body.distance,
      blackhole: body.blackhole,
      enabled: body.enabled,
    };
    const issues = validateRouteMutation(candidate, siblings as unknown as RouteRuleView[]);
    const hard = hardRouteIssues(issues);
    if (hard.length > 0) throw ApiError.validation(hard.map((i) => i.message).join("; "));
    const conflicts = conflictRouteIssues(issues);
    if (conflicts.length > 0 && !body.force) {
      throw ApiError.conflict("Route conflicts with existing configuration", { issues: conflicts });
    }

    const created = await db.staticRoute.create({
      data: {
        tenantId: auth.tenantId,
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
    return {
      data: shapeStaticRoute(created),
      osState: kernelRouteState(created as unknown as RouteRuleView, await readKernelRoutes().catch(() => null)),
      info: issues.filter((i) => i.kind === "info"),
      audit: {
        action: "route.create",
        objectType: "static_route",
        objectId: created.id,
        objectName: created.name ?? created.destinationCidr,
        ...(body.force ? { info: { forced: true } } : {}),
      },
    };
  },
);

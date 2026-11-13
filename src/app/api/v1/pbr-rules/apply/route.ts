/**
 * POST /api/v1/pbr-rules/apply — converge policy-based routing rules onto the
 * kernel (pbr-os planner → route-apply executor, gated by CONSOLE_OS_APPLY).
 * Body: { id? } — one rule, or all rules: enabled → replace (teardown then
 * apply), disabled → withdraw. Service-matched rules report config-only
 * honestly (fwmark datapath is a planned dataplane change).
 * GET — plan preview (no exec) for the UI confirm dialog.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { z } from "zod";
import { shapePbrRule } from "@/lib/network/shapes";
import {
  buildPbrApplyPlan,
  buildPbrTeardownPlan,
  readKernelPbrRules,
  resolvePbrCidrs,
  resolveServiceSelectors,
  pbrKernelState,
  type PbrKernelState,
  type PbrOsPlanStep,
  type PbrRuleView,
} from "@/lib/network/pbr-os";
import { convergeRouteSafe } from "@/lib/network/route-apply";

export const dynamic = "force-dynamic";

const applyBody = z.object({ id: z.number().int().min(1).optional() });

function viewOf(row: { id: number; name: string; position: number; enabled: boolean; srcAddrIds: string; dstAddrIds: string; serviceIds: string; outgoingIface: string | null; gateway: string | null; description?: string | null; createdAt?: Date }): PbrRuleView {
  const s = shapePbrRule(row);
  return {
    id: s.id,
    name: s.name,
    position: s.position,
    enabled: s.enabled,
    srcAddrIds: s.srcAddrIds,
    dstAddrIds: s.dstAddrIds,
    serviceIds: s.serviceIds,
    outgoingIface: s.outgoingIface,
    gateway: s.gateway,
  };
}

async function convergeOne(view: PbrRuleView) {
  const [src, dst, svc] = await Promise.all([
    resolvePbrCidrs(1, view.srcAddrIds),
    resolvePbrCidrs(1, view.dstAddrIds),
    resolveServiceSelectors(1, view.serviceIds),
  ]);
  const applyPlan = buildPbrApplyPlan(view, src, dst, svc);

  if (!view.enabled) {
    const teardown = buildPbrTeardownPlan(
      view,
      src.filter((s) => s.cidr).length,
      dst.filter((d) => d.cidr).length,
      Math.max(1, applyPlan.steps.length - 1),
    );
    const os = await convergeRouteSafe(async () => ({ name: teardown.name, osName: null, steps: teardown.steps }));
    const fresh = await readKernelPbrRules().catch(() => null);
    return {
      id: view.id,
      name: view.name,
      position: view.position,
      state: pbrKernelState(view, fresh, { configOnly: applyPlan.configOnly }),
      configOnly: applyPlan.configOnly,
      os: { gate: os.gate, applied: os.applied, reason: os.reason, plan: os.plan, results: os.results },
    };
  }

  // replace semantics: withdraw old policy first, then install fresh
  const teardown = buildPbrTeardownPlan(
    view,
    src.filter((s) => s.cidr).length,
    dst.filter((d) => d.cidr).length,
    Math.max(1, applyPlan.steps.length - 1),
  );
  const t0 = await convergeRouteSafe(async () => ({ name: teardown.name, osName: null, steps: teardown.steps }));
  const os = await convergeRouteSafe(async () => ({ name: applyPlan.name, osName: view.outgoingIface, steps: applyPlan.steps }));
  const fresh = await readKernelPbrRules().catch(() => null);
  return {
    id: view.id,
    name: view.name,
    position: view.position,
    state: pbrKernelState(view, fresh, { configOnly: applyPlan.configOnly }),
    configOnly: applyPlan.configOnly,
    os: {
      gate: os.gate,
      applied: os.applied,
      reason: os.applied ? os.reason : t0.applied ? os.reason : `${t0.reason} → ${os.reason}`,
      plan: { name: applyPlan.name, osName: view.outgoingIface, steps: [...teardown.steps, ...applyPlan.steps] },
      results: [...(t0.results ?? []), ...(os.results ?? [])],
    },
  };
}

export const POST = route({ area: "network", bodySchema: applyBody, section: "routing" }, async ({ auth, body }) => {
  const rows = await db.pbrRule.findMany({ where: { tenantId: auth.tenantId }, orderBy: { position: "asc" } });
  const views = rows.map(viewOf);
  const outcomes: Array<Awaited<ReturnType<typeof convergeOne>>> = [];
  if (body.id) {
    const view = views.find((v) => v.id === body.id);
    if (!view) throw ApiError.notFound(`PBR rule ${body.id} not found`);
    outcomes.push(await convergeOne(view));
  } else {
    for (const view of views) outcomes.push(await convergeOne(view));
  }
  return {
    data: outcomes,
    audit: {
      action: "pbr.os-apply",
      objectType: "pbr_rule",
      objectId: body.id,
      objectName: body.id ? (views.find((v) => v.id === body.id)?.name ?? "?") : "all",
    },
  };
});

export const GET = route({ area: "network" }, async ({ auth }) => {
  const rows = await db.pbrRule.findMany({ where: { tenantId: auth.tenantId }, orderBy: { position: "asc" } });
  const kernel = await readKernelPbrRules().catch(() => null);
  const data: Array<{
    id: number;
    name: string;
    position: number;
    enabled: boolean;
    state: PbrKernelState | null;
    configOnly: boolean;
    reason: string;
    plan: PbrOsPlanStep[];
  }> = [];
  for (const row of rows) {
    const view = viewOf(row);
    const [src, dst, svc] = await Promise.all([
      resolvePbrCidrs(auth.tenantId, view.srcAddrIds),
      resolvePbrCidrs(auth.tenantId, view.dstAddrIds),
      resolveServiceSelectors(auth.tenantId, view.serviceIds),
    ]);
    const plan = buildPbrApplyPlan(view, src, dst, svc);
    data.push({
      id: view.id,
      name: view.name,
      position: view.position,
      enabled: view.enabled,
      state: pbrKernelState(view, kernel, { configOnly: plan.configOnly }),
      configOnly: plan.configOnly,
      reason: plan.reason,
      plan: plan.steps,
    });
  }
  return { data };
});

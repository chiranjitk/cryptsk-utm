/**
 * GET  /api/v1/network/port-mirrors/apply — plan preview (no exec) + live
 *      kernel state per SPAN session.
 * POST /api/v1/network/port-mirrors/apply — converge sessions onto the
 *      kernel (mirror-os planner → mirror-apply executor, gated by
 *      CONSOLE_OS_APPLY). Body: { id? } — one session or all: enabled →
 *      replace (teardown then install clsact + matchall/mirred filters),
 *      disabled → withdraw.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { z } from "zod";
import {
  buildMirrorApplyPlan,
  buildMirrorTeardownPlan,
  mirrorKernelState,
  readKernelMirrorFilters,
  type MirrorKernelState,
  type MirrorOsView,
} from "@/lib/network/mirror-os";
import { convergeMirrorSafe } from "@/lib/network/mirror-apply";

export const dynamic = "force-dynamic";

const applyBody = z.object({ id: z.number().int().min(1).optional() });

function viewOf(row: { id: number; name: string; srcIface: string; dstIface: string; direction: string; enabled: boolean }): MirrorOsView {
  return {
    id: row.id,
    name: row.name,
    srcIface: row.srcIface,
    dstIface: row.dstIface,
    direction: (["ingress", "egress", "both"].includes(row.direction) ? row.direction : "both") as MirrorOsView["direction"],
    enabled: row.enabled,
  };
}

async function convergeOne(view: MirrorOsView) {
  // replace semantics: withdraw stale filters first, then install fresh
  const os = await convergeMirrorSafe(() =>
    view.enabled ? buildMirrorApplyPlan(view) : buildMirrorTeardownPlan(view),
  );
  const kernel = await readKernelMirrorFilters(view.srcIface).catch(() => null);
  const state = mirrorKernelState(view, kernel);
  return {
    id: view.id,
    name: view.name,
    srcIface: view.srcIface,
    dstIface: view.dstIface,
    state,
    os: {
      gate: os.gate,
      applied: os.applied,
      reason: os.reason,
      plan: os.plan,
      results: os.results,
    },
  };
}

export const POST = route({ area: "network", bodySchema: applyBody, section: "interfaces" }, async ({ auth, body }) => {
  const rows = await db.portMirror.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } });
  const views = rows.map(viewOf);
  const outcomes: Array<Awaited<ReturnType<typeof convergeOne>>> = [];
  if (body.id) {
    const view = views.find((v) => v.id === body.id);
    if (!view) throw ApiError.notFound(`Port mirror ${body.id} not found`);
    outcomes.push(await convergeOne(view));
  } else {
    for (const view of views) outcomes.push(await convergeOne(view));
  }
  return {
    data: outcomes,
    audit: {
      action: "mirror.os-apply",
      objectType: "port_mirror",
      objectId: body.id,
      objectName: body.id ? (views.find((v) => v.id === body.id)?.name ?? "?") : "all",
    },
  };
});

export const GET = route({ area: "network" }, async ({ auth }) => {
  const rows = await db.portMirror.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } });
  const data: Array<{ id: number; name: string; enabled: boolean; state: MirrorKernelState; reason: string; plan: Array<{ cmd: string; summary: string }> }> = [];
  for (const row of rows) {
    const view = viewOf(row);
    const plan = buildMirrorApplyPlan(view);
    const kernel = await readKernelMirrorFilters(view.srcIface).catch(() => null);
    data.push({
      id: view.id,
      name: view.name,
      enabled: view.enabled,
      state: mirrorKernelState(view, kernel),
      reason: plan.reason,
      plan: plan.steps.map((s) => ({ cmd: s.cmd, summary: s.summary })),
    });
  }
  return { data };
});

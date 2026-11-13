/**
 * POST /api/v1/pbr-rules/apply — converge policy-based routing rules onto the
 * kernel (pbr-os planner → route-apply executor, gated by CONSOLE_OS_APPLY).
 *
 * Body: { id?, confirmMatchAll? } — one rule, or all rules: enabled → replace
 * (teardown then apply), disabled → withdraw.
 *
 * Enterprise safety (2026-11-14 WAN-outage class fix):
 *   • match-all rules (no src/dst/service match → selector-less ip rule that
 *     captures every flow, management egress included) require an explicit
 *     confirmMatchAll — unconfirmed applies are rejected with 422
 *   • iface-only egress resolves its next-hop from the interface's live
 *     default route; device-only policy defaults are never installed
 *   • commit-confirm: WAN health (gateway + public ICMP probe) is snapshotted
 *     before and after the apply; a measured regression triggers an automatic
 *     rollback of everything this request installed, then re-verification —
 *     the response carries the full health report per outcome
 *
 * GET — plan preview (no exec) for the UI confirm dialog; plans are compiled
 * as-if-confirmed (the UI dialog carries the match-all warning).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { z } from "zod";
import { shapePbrRule } from "@/lib/network/shapes";
import {
  buildPbrApplyPlan,
  buildPbrTeardownPlan,
  pbrHealthRegressed,
  pbrKernelState,
  preparePbrRules,
  probeWanHealth,
  readKernelPbrRules,
  type PbrKernelState,
  type PbrOsPlanStep,
  type PbrRuleView,
  type PbrWanHealth,
  type PreparedPbrRule,
} from "@/lib/network/pbr-os";
import { convergeRouteSafe } from "@/lib/network/route-apply";

export const dynamic = "force-dynamic";

const applyBody = z.object({
  id: z.number().int().min(1).optional(),
  confirmMatchAll: z.boolean().optional(),
});

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

interface ConvergeOutcome {
  id: number;
  name: string;
  position: number;
  state: PbrKernelState | null;
  configOnly: boolean;
  os: {
    gate: "on" | "off";
    applied: boolean;
    reason: string;
    plan: { name: string; osName: string | null; steps: PbrOsPlanStep[] };
    results?: Array<{ cmd: string; ok: boolean; stderr?: string; soft?: boolean }>;
  };
  installed: boolean;
}

/** Teardown + apply one prepared rule. installed=true when kernel steps ran. */
async function convergeOne(p: PreparedPbrRule): Promise<ConvergeOutcome> {
  const view = p.view;
  const applyPlan = buildPbrApplyPlan(view, p.src, p.dst, p.svc, {
    confirmMatchAll: true,
    egressGateway: p.egress?.gateway ?? null,
    egressDev: p.egress?.dev ?? null,
  });

  const srcCidrCount = p.src.filter((s) => s.cidr).length;
  const dstCidrCount = p.dst.filter((d) => d.cidr).length;
  const teardown = buildPbrTeardownPlan(view, srcCidrCount, dstCidrCount, Math.max(1, p.svcSelectors));

  if (!view.enabled) {
    const os = await convergeRouteSafe(async () => ({ name: teardown.name, osName: null, steps: teardown.steps }));
    const fresh = await readKernelPbrRules().catch(() => null);
    return {
      id: view.id,
      name: view.name,
      position: view.position,
      state: pbrKernelState(view, fresh),
      configOnly: false,
      installed: false,
      os: { gate: os.gate, applied: os.applied, reason: os.reason, plan: { name: teardown.name, osName: null, steps: teardown.steps }, results: os.results },
    };
  }

  const configOnly = applyPlan.configOnly;
  // replace semantics: withdraw old policy first, then install fresh
  const t0 = await convergeRouteSafe(async () => ({ name: teardown.name, osName: null, steps: teardown.steps }));
  const os = await convergeRouteSafe(async () => ({ name: applyPlan.name, osName: view.outgoingIface, steps: applyPlan.steps }));
  const fresh = await readKernelPbrRules().catch(() => null);
  return {
    id: view.id,
    name: view.name,
    position: view.position,
    state: pbrKernelState(view, fresh, { configOnly }),
    configOnly,
    installed: !configOnly && os.applied === true,
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

  const prepared = await preparePbrRules(views, auth.tenantId);

  // match-all hard gate: selector-less ip rules capture every flow (the
  // 2026-11-14 outage class) — install only behind an explicit confirmation
  if (body.confirmMatchAll !== true) {
    const offenders = prepared.filter((p) => p.matchAll);
    if (offenders.length > 0) {
      throw ApiError.validation(
        `match-all policy route${offenders.length === 1 ? "" : "s"} ${offenders
          .map((o) => `'${o.view.name}'`)
          .join(", ")} would steer ALL traffic (including the appliance's own management egress) into ${
          offenders.length === 1 ? "its" : "their"
        } policy table — add a source/destination/service match, or re-send the apply with confirmMatchAll: true`,
      );
    }
  }

  // commit-confirm: baseline WAN health before any kernel mutation
  const baseline = await probeWanHealth();

  const outcomes: ConvergeOutcome[] = [];
  if (body.id) {
    const p = prepared.find((x) => x.view.id === body.id);
    if (!p) throw ApiError.notFound(`PBR rule ${body.id} not found`);
    outcomes.push(await convergeOne(p));
  } else {
    for (const p of prepared) outcomes.push(await convergeOne(p));
  }

  // post-apply verification + automatic rollback (FortiGate commit-confirm)
  const after = await probeWanHealth();
  let rolledBack = false;
  let rollbackReason: string | null = null;
  let postRollback: PbrWanHealth | null = null;
  if (pbrHealthRegressed(baseline, after)) {
    rolledBack = true;
    rollbackReason = `WAN health regressed after apply (gateway ${
      after.gatewayOk === false ? "unreachable" : "ok"
    } / public probe ${after.internetOk === false ? "unreachable" : after.internetOk === null ? "unknown" : "ok"} vs healthy baseline) — policy rules were withdrawn automatically to restore the forwarding path`;
    for (const p of prepared) {
      if (!p.view.enabled) continue;
      const teardown = buildPbrTeardownPlan(
        p.view,
        p.src.filter((s) => s.cidr).length,
        p.dst.filter((d) => d.cidr).length,
        Math.max(1, p.svcSelectors),
      );
      await convergeRouteSafe(async () => ({ name: teardown.name, osName: null, steps: teardown.steps }));
    }
    postRollback = await probeWanHealth();
    // re-read kernel so the reported states reflect the rolled-back reality
    const fresh = await readKernelPbrRules().catch(() => null);
    for (const o of outcomes) {
      const p = prepared.find((x) => x.view.id === o.id);
      if (p) o.state = pbrKernelState(p.view, fresh, { configOnly: o.configOnly });
      o.installed = false;
    }
  }

  const health = { baseline, after, rolledBack, rollbackReason, postRollback };
  return {
    data: outcomes.map((o) => ({ ...o, health })),
    audit: {
      action: rolledBack ? "pbr.os-apply-rollback" : "pbr.os-apply",
      objectType: "pbr_rule",
      objectId: body.id,
      objectName: body.id ? (views.find((v) => v.id === body.id)?.name ?? "?") : "all",
    },
  };
});

export const GET = route({ area: "network" }, async ({ auth }) => {
  const rows = await db.pbrRule.findMany({ where: { tenantId: auth.tenantId }, orderBy: { position: "asc" } });
  const kernel = await readKernelPbrRules().catch(() => null);
  const views = rows.map(viewOf);
  const prepared = await preparePbrRules(views, auth.tenantId);
  const data: Array<{
    id: number;
    name: string;
    position: number;
    enabled: boolean;
    state: PbrKernelState | null;
    configOnly: boolean;
    matchAll: boolean;
    reason: string;
    plan: PbrOsPlanStep[];
  }> = [];
  for (const p of prepared) {
    data.push({
      id: p.view.id,
      name: p.view.name,
      position: p.view.position,
      enabled: p.view.enabled,
      state: pbrKernelState(p.view, kernel, { configOnly: p.confirmedPlan.configOnly }),
      configOnly: p.confirmedPlan.configOnly,
      matchAll: p.matchAll,
      reason: p.confirmedPlan.reason,
      plan: p.confirmedPlan.steps,
    });
  }
  return { data };
});

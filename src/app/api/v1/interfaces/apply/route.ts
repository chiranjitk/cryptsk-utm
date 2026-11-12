/**
 * POST /api/v1/interfaces/apply — converge the host OS onto the console DB.
 *
 * Two-phase by design (enterprise commit semantics):
 *   1. plan  — pure buildApplyPlan() output per interface (always returned)
 *   2. exec  — only when CONSOLE_OS_APPLY=1 AND `ip` exists on the host;
 *              otherwise the response carries the plan + an honest reason.
 *
 * Body { name?: string } narrows the run to a single interface.
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { loadShapedIfaces, parseIfaceConfig } from "@/lib/network/iface-service";
import { buildApplyPlan, osRowFor, type OsPlan } from "@/lib/network/iface-os";
import { readInterfaces } from "@/lib/host/proc";
import { hasTool, runTool } from "@/lib/host/tools";
import type { IfaceRuleView } from "@/lib/network/iface-rules";

export const dynamic = "force-dynamic";

const applyBodySchema = z.object({ name: z.string().max(64).optional() });

export const POST = route(
  { area: "network", bodySchema: applyBodySchema, section: "interfaces" },
  async ({ auth, body }) => {
    const [shaped, osIfaces] = await Promise.all([loadShapedIfaces(auth.tenantId), readInterfaces()]);

    const views: IfaceRuleView[] = shaped
      .filter((i) => (body.name ? i.name === body.name : true))
      .map((i) => ({
        id: i.id,
        name: i.name,
        type: i.type,
        mode: i.mode,
        role: i.role,
        mtu: i.mtu,
        mssClamp: i.mssClamp,
        enabled: i.enabled,
        parentName: i.parentName,
        vlanId: i.vlanId,
        config: parseIfaceConfig(JSON.stringify(i.config)),
      }));

    const plans: OsPlan[] = views.map((v) => buildApplyPlan(v, osRowFor(osIfaces, v.name)));
    const applyEnabled = process.env.CONSOLE_OS_APPLY === "1";

    if (!applyEnabled) {
      return {
        data: {
          applied: false,
          reason: "OS apply is gated off on this installation (CONSOLE_OS_APPLY!=1) — plan preview only",
          plans,
        },
        audit: {
          action: "iface.os-apply.plan",
          objectType: "interface",
          objectName: body.name ?? "all",
        },
      };
    }

    const toolPresent = await hasTool("ip");
    if (!toolPresent) {
      return {
        data: {
          applied: false,
          reason: "'ip' (iproute2) not found on the host — cannot execute the plan",
          plans,
        },
        audit: {
          action: "iface.os-apply.plan",
          objectType: "interface",
          objectName: body.name ?? "all",
        },
      };
    }

    const results: Array<{ cmd: string; ok: boolean; stderr?: string }> = [];
    for (const plan of plans) {
      for (const step of plan.steps) {
        const r = await runTool(step.cmd);
        results.push({ cmd: step.cmd, ok: r.ok, stderr: r.ok ? undefined : r.stderr });
      }
    }
    const failed = results.filter((r) => !r.ok);

    return {
      data: {
        applied: failed.length === 0,
        reason: failed.length === 0 ? "plan executed" : `${failed.length} step(s) failed`,
        results,
        plans,
      },
      audit: {
        action: "iface.os-apply.exec",
        objectType: "interface",
        objectName: body.name ?? "all",
      },
    };
  },
);

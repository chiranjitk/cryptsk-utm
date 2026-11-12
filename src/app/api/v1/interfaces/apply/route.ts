/**
 * POST /api/v1/interfaces/apply — converge ONE host interface onto the
 * console DB (single-interface by design — no bulk exec path).
 *
 * The guards (gate / tool / whitelist / protection / default-route ownership)
 * live in iface-apply.ts and are IDENTICAL to the ones that run automatically
 * after every create/update/delete — this endpoint is the manual repair path
 * ("Apply to Host") when the host has drifted from the console.
 *
 * Body { name } — required, narrows the run to one interface.
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { loadShapedIfaces, parseIfaceConfig } from "@/lib/network/iface-service";
import { convergeIface } from "@/lib/network/iface-apply";
import type { IfaceRuleView } from "@/lib/network/iface-rules";

export const dynamic = "force-dynamic";

const applyBodySchema = z.object({ name: z.string().min(1).max(64) });

export const POST = route(
  { area: "network", bodySchema: applyBodySchema, section: "interfaces" },
  async ({ auth, body }) => {
    const shaped = await loadShapedIfaces(auth.tenantId);

    const shapedRow = shaped.find((i) => i.name === body.name);
    if (!shapedRow) {
      return {
        data: {
          applied: false,
          reason: `Interface '${body.name}' not found`,
          plans: [],
        },
      };
    }
    const view: IfaceRuleView = {
      id: shapedRow.id,
      name: shapedRow.name,
      type: shapedRow.type,
      mode: shapedRow.mode,
      role: shapedRow.role,
      mtu: shapedRow.mtu,
      mssClamp: shapedRow.mssClamp,
      enabled: shapedRow.enabled,
      parentName: shapedRow.parentName,
      vlanId: shapedRow.vlanId,
      config: parseIfaceConfig(JSON.stringify(shapedRow.config)),
    };

    const outcome = await convergeIface(view);

    return {
      data: {
        applied: outcome.applied,
        reason: outcome.reason,
        results: outcome.results,
        plans: [outcome.plan],
      },
      audit: {
        action: outcome.gate === "on" ? "iface.os-apply.exec" : "iface.os-apply.plan",
        objectType: "interface",
        objectName: body.name,
      },
    };
  },
);

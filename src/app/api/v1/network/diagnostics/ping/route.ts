/**
 * POST /api/v1/network/diagnostics/ping — scoped ping tool (pfSense parity).
 * Body { host, iface?, count?, size?, df? } — count hard-capped at 4,
 * size capped at 1472 with DF (path-MTU discovery), 9 s ceiling,
 * `ping` binary gated, action audited.
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { runDiagPing } from "@/lib/host/diagnostics";

export const dynamic = "force-dynamic";

const pingBodySchema = z.object({
  host: z.string().min(1).max(253),
  iface: z.string().max(15).optional(),
  count: z.number().int().min(1).max(4).default(3),
  /** payload bytes — with df=true enables ping -M do -s N (MTU discovery) */
  size: z.number().int().min(0).max(1472).optional(),
  df: z.boolean().optional(),
});

export const POST = route(
  { area: "network", bodySchema: pingBodySchema },
  async ({ body, auth }) => {
    const result = await runDiagPing(body.host, body.iface, body.count, body.size, body.df);
    return {
      data: result,
      audit: {
        action: "network.diagnostics.ping",
        objectType: "diagnostic",
        objectName: body.host,
        result: result.ok ? "success" : "failure",
      },
    };
  },
);

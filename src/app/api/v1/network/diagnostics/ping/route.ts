/**
 * POST /api/v1/network/diagnostics/ping — scoped ping tool (pfSense parity).
 * Body { host, iface?, count? } — count hard-capped at 4, 9 s ceiling,
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
});

export const POST = route(
  { area: "network", bodySchema: pingBodySchema },
  async ({ body, auth }) => {
    const result = await runDiagPing(body.host, body.iface, body.count);
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

/**
 * POST /api/v1/network/diagnostics/traceroute — bounded path trace
 * (pfSense parity). Body { host, iface?, maxHops? } — maxHops capped at 15,
 * `traceroute` binary gated (tracepath fallback), action audited.
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { runDiagTraceroute } from "@/lib/host/diagnostics";

export const dynamic = "force-dynamic";

const tracerouteBodySchema = z.object({
  host: z.string().min(1).max(253),
  iface: z.string().max(15).optional(),
  maxHops: z.number().int().min(1).max(15).default(10),
});

export const POST = route(
  { area: "network", bodySchema: tracerouteBodySchema },
  async ({ body }) => {
    const result = await runDiagTraceroute(body.host, body.iface, body.maxHops);
    return {
      data: result,
      audit: {
        action: "network.diagnostics.traceroute",
        objectType: "diagnostic",
        objectName: body.host,
        result: result.ok ? "success" : "failure",
      },
    };
  },
);

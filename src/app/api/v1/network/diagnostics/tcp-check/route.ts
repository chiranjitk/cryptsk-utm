/**
 * POST /api/v1/network/diagnostics/tcp-check — TCP connect test from the
 * appliance (pfSense Diagnostics > Test Port parity). Body { host, port,
 * iface? } — optional source-interface bind, 3 s ceiling, action audited.
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { runDiagTcpCheck } from "@/lib/host/diagnostics";

export const dynamic = "force-dynamic";

const tcpCheckBodySchema = z.object({
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535),
  iface: z.string().max(15).optional(),
});

export const POST = route(
  { area: "network", bodySchema: tcpCheckBodySchema },
  async ({ body }) => {
    const result = await runDiagTcpCheck(body.host, body.port, body.iface);
    return {
      data: result,
      audit: {
        action: "network.diagnostics.tcp-check",
        objectType: "diagnostic",
        objectName: `${body.host}:${body.port}`,
        result: result.ok ? "success" : "failure",
      },
    };
  },
);

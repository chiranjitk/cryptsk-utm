/**
 * POST /api/v1/network/diagnostics/dns-lookup — resolve a name (pfSense
 * Diagnostics > DNS Lookup parity). Body { name, server? } — dig → host →
 * nslookup fallback chain, action audited.
 */

import { z } from "zod";
import { route } from "@/lib/api/handler";
import { runDiagDnsLookup } from "@/lib/host/diagnostics";

export const dynamic = "force-dynamic";

const dnsLookupBodySchema = z.object({
  name: z.string().min(1).max(253),
  server: z.string().max(15).optional(),
});

export const POST = route(
  { area: "network", bodySchema: dnsLookupBodySchema },
  async ({ body }) => {
    const result = await runDiagDnsLookup(body.name, body.server);
    return {
      data: result,
      audit: {
        action: "network.diagnostics.dns-lookup",
        objectType: "diagnostic",
        objectName: body.name,
        result: result.ok ? "success" : "failure",
      },
    };
  },
);

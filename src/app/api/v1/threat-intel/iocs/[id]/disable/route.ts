/**
 * POST /api/v1/threat-intel/iocs/[id]/disable — soft-disable an IOC
 * (enabled=false by default; body { enabled: true } re-enables — used by the
 * console switch). Provenance and hit history are kept. Audits
 * `threat_ioc.disable` / `threat_ioc.enable`.
 */

import { route } from "@/lib/api/handler";
import { iocDisableSchema } from "@/lib/validators/threat-intel";
import { disableIoc } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "threat_intel", bodySchema: iocDisableSchema, section: "threat_intel" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await disableIoc(auth.tenantId, id, body.enabled);
    return {
      data: updated,
      audit: {
        action: updated.enabled ? "threat_ioc.enable" : "threat_ioc.disable",
        objectType: "ioc",
        objectId: id,
        objectName: `${updated.type}:${updated.value}`,
        after: updated,
      },
    };
  },
);

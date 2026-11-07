/**
 * BGP session control (M19 §2.6) — POST { action: "start" | "stop" } on the
 * neighbor's SIMULATED session state machine: start walks idle→connect then
 * connect→established (uptimeSec 0, prefixesReceived deterministic 2-30 from
 * the peerIp+remoteAs hash); stop returns to idle with 0 prefixes. Persisted
 * on the row. Audit `bgp.session`.
 */

import { route } from "@/lib/api/handler";
import { bgpSessionActionSchema, hashIpv4To } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { toNeighborDTO } from "../../../../internal";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "dynamic_routing", bodySchema: bgpSessionActionSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const neighbor = await db.bgpNeighbor.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!neighbor) throw ApiError.notFound("BGP neighbor not found");

    let updated;
    if (body.action === "start") {
      if (!neighbor.enabled) {
        throw ApiError.validation("BGP neighbor is disabled", {
          fieldErrors: { enabled: ["enable the neighbor before starting a session"] },
        });
      }
      // simulated handshake: connect → established
      await db.bgpNeighbor.update({ where: { id }, data: { state: "connect" } });
      updated = await db.bgpNeighbor.update({
        where: { id },
        data: {
          state: "established",
          uptimeSec: 0,
          prefixesReceived: hashIpv4To(`${neighbor.peerIp}:${neighbor.remoteAs}`, 30, 2),
        },
      });
    } else {
      updated = await db.bgpNeighbor.update({
        where: { id },
        data: { state: "idle", uptimeSec: 0, prefixesReceived: 0 },
      });
    }

    return {
      data: toNeighborDTO(updated),
      audit: {
        action: "bgp.session",
        objectType: "bgp_neighbor",
        objectId: id,
        objectName: neighbor.name,
        after: { action: body.action, state: updated.state, prefixesReceived: updated.prefixesReceived },
      },
    };
  },
);

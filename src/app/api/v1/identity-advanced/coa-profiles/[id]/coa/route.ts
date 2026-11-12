/**
 * RADIUS CoA packet send (M23, spec 2.10) — SIMULATED (the appliance sends the
 * real CoA/Disconnect packet to the NAS). Validates the userName exists,
 * persists an IdentityActivityEvent (`coa`) and audits `radius.coa`.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { coaSendSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "identity", bodySchema: coaSendSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const profile = await db.radiusCoaProfile.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!profile) throw ApiError.notFound("CoA profile not found");
    if (!profile.enabled || !profile.coaEnabled) {
      throw ApiError.conflict("CoA is disabled on this profile — enable it first");
    }

    const user = await db.user.findFirst({
      where: { tenantId: auth.tenantId, username: body.userName },
      select: { id: true },
    });
    if (!user) throw ApiError.validation(`userName '${body.userName}' not found`);

    // Realistic RADIUS CoA attribute set per action (simulated packet).
    const attributes: Record<string, string | number> = {
      "User-Name": body.userName,
      "NAS-IP-Address": "10.0.0.1",
    };
    if (body.action === "vlan" && body.vlanId !== undefined) {
      attributes["Tunnel-Type"] = "VLAN";
      attributes["Tunnel-Medium-Type"] = "IEEE-802";
      attributes["Tunnel-Private-Group-Id"] = body.vlanId;
    } else if (body.action === "disconnect") {
      attributes["Acct-Terminate-Cause"] = "Admin-Reset";
    } else {
      attributes["Filter-Id"] = "reauth-required";
    }
    attributes["Message-Authenticator"] = "0x" + (fnvStub(body.userName) * 7919 % 0xffffffff).toString(16).padStart(8, "0");

    await db.identityActivityEvent.create({
      data: {
        tenantId: auth.tenantId,
        userName: body.userName,
        event: "coa",
        detail: JSON.stringify({ action: body.action, vlanId: body.vlanId ?? null, profile: profile.name }),
      },
    });

    return {
      data: { sent: true, packet: { code: "CoA-Request", attributes } },
      audit: {
        action: "radius.coa",
        objectType: "radius_coa_profile",
        objectId: profile.id,
        objectName: profile.name,
      },
    };
  },
);

/** Local FNV-1a for the fake Message-Authenticator octets (kept deterministic). */
function fnvStub(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

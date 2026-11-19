/**
 * PPPoE password reveal (M02 §2) — STRICT: super_admin/tenant_admin ONLY
 * (admin matrix column + explicit role gate, mirroring the RADIUS reveal
 * endpoint), only when PPPoE is configured on the interface, audited with
 * sourceIp. Never part of any list/detail response.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { parseIfaceConfig } from "@/lib/network/iface-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "network", admin: true }, async ({ auth, params, ip }) => {
  if (!["super_admin", "tenant_admin"].includes(auth.role)) {
    throw ApiError.forbidden("Revealing the PPPoE password requires super_admin or tenant_admin");
  }
  const id = numericId(params, "id");
  const row = await db.networkInterface.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Interface ${id} not found`);

  const cfg = parseIfaceConfig(row.config);
  const pppoe = cfg.pppoe;
  const pppoeCfg =
    pppoe && typeof pppoe === "object" && !Array.isArray(pppoe)
      ? (pppoe as Record<string, unknown>)
      : null;
  const password = typeof pppoeCfg?.password === "string" ? pppoeCfg.password : undefined;
  if (!password) {
    throw ApiError.validation("Interface has no PPPoE configuration");
  }

  return {
    data: {
      id: row.id,
      name: row.name,
      pppoeUser: typeof pppoeCfg?.user === "string" ? pppoeCfg.user : null,
      password,
    },
    audit: {
      action: "iface.pppoe_reveal",
      objectType: "interface",
      objectId: id,
      objectName: row.name,
      result: "success",
      details: { sourceIp: ip },
    },
  };
});

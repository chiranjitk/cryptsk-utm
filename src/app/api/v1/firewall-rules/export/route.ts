/**
 * GET /api/v1/firewall-rules/export?format=json|csv — download the ruleset.
 * CSV columns: position,name,enabled,action,srcZones,dstZones,srcAddrs,
 * dstAddrs,services,logging,tags,comment (M03 §8 — schema pinned here).
 */

import { NextResponse } from "next/server";
import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { exportQuerySchema } from "@/lib/validators/firewall";
import { shapeFirewallRule } from "@/lib/firewall/rule-shape";
import { CSV_COLUMNS, csvRow } from "@/lib/firewall/csv";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall", querySchema: exportQuerySchema }, async ({ auth, query }) => {
  const tenantId = auth.tenantId;
  const [rules, zones, addrObjs, addrGroups, svcObjs, svcGroups] = await Promise.all([
    db.firewallRule.findMany({ where: { tenantId }, orderBy: { position: "asc" } }),
    db.zone.findMany({ where: { tenantId }, select: { id: true, name: true } }),
    db.addressObject.findMany({ where: { tenantId }, select: { id: true, name: true } }),
    db.addressGroup.findMany({ where: { tenantId }, select: { id: true, name: true } }),
    db.serviceObject.findMany({ where: { tenantId }, select: { id: true, name: true } }),
    db.serviceGroup.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);

  const zoneName = new Map(zones.map((z) => [z.id, z.name]));
  const addrName = new Map([...addrObjs, ...addrGroups].map((a) => [a.id, a.name]));
  const svcName = new Map([...svcObjs, ...svcGroups].map((s) => [s.id, s.name]));

  const names = (raw: string, map: Map<number, string>): string => {
    try {
      const v = JSON.parse(raw);
      if (!Array.isArray(v)) return "";
      return v.map((id) => map.get(id) ?? String(id)).join(",");
    } catch {
      return "";
    }
  };

  if (query.format === "csv") {
    const lines = [csvRow([...CSV_COLUMNS])];
    for (const r of rules) {
      const s = shapeFirewallRule(r);
      lines.push(
        csvRow([
          String(s.position),
          s.name,
          s.enabled ? "true" : "false",
          s.action,
          names(r.srcZoneIds, zoneName),
          names(r.dstZoneIds, zoneName),
          names(r.srcAddrIds, addrName),
          names(r.dstAddrIds, addrName),
          names(r.serviceIds, svcName),
          s.logging,
          s.tags.join(","),
          s.comment ?? "",
        ]),
      );
    }
    return new NextResponse(lines.join("\n") + "\n", {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": `attachment; filename="firewall-rules.csv"`,
      },
    });
  }

  const payload = rules.map(shapeFirewallRule);
  return new NextResponse(JSON.stringify(payload, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="firewall-rules.json"`,
    },
  });
});

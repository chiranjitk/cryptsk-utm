/**
 * POST /api/v1/firewall-rules/import — {format: "json"|"csv", payload}.
 * All-or-nothing: any invalid row aborts the whole batch (400 with per-row
 * errors in details.rows) — M03 §3/§5. The same validation as manual create
 * applies to every row (zod + id existence + app catalog).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { importBodySchema } from "@/lib/validators/firewall";
import { csvToDrafts, type CsvRuleDraft } from "@/lib/firewall/csv";
import { importRules, type FirewallRuleBody } from "@/lib/firewall/rule-service";
import { firewallRuleBodySchema } from "@/lib/validators/firewall";
import { z } from "zod";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "firewall", bodySchema: importBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const tenantId = auth.tenantId;
    const rowErrors: Array<{ row: number; message: string }> = [];
    let bodies: FirewallRuleBody[] = [];

    if (body.format === "json") {
      let parsed: unknown;
      try {
        parsed = JSON.parse(body.payload);
      } catch {
        throw ApiError.validation("payload is not valid JSON");
      }
      const items = Array.isArray(parsed) ? parsed : [parsed];
      bodies = [];
      items.forEach((item, idx) => {
        const r = firewallRuleBodySchema.safeParse(item);
        if (!r.success) {
          const msg = r.error.issues.map((i) => `${i.path.join(".") || "_"}: ${i.message}`).join("; ");
          rowErrors.push({ row: idx + 1, message: msg });
          return;
        }
        bodies.push(r.data);
      });
    } else {
      // CSV — resolve names via the tenant's zone/object/group tables
      const [zones, addrObjs, addrGroups, svcObjs, svcGroups] = await Promise.all([
        db.zone.findMany({ where: { tenantId }, select: { id: true, name: true } }),
        db.addressObject.findMany({ where: { tenantId }, select: { id: true, name: true } }),
        db.addressGroup.findMany({ where: { tenantId }, select: { id: true, name: true } }),
        db.serviceObject.findMany({ where: { tenantId }, select: { id: true, name: true } }),
        db.serviceGroup.findMany({ where: { tenantId }, select: { id: true, name: true } }),
      ]);
      const drafts = csvToDrafts(body.payload, {
        zone: new Map(zones.map((z) => [z.name.toLowerCase(), z.id])),
        addr: new Map([...addrObjs, ...addrGroups].map((a) => [a.name.toLowerCase(), a.id])),
        service: new Map([...svcObjs, ...svcGroups].map((s) => [s.name.toLowerCase(), s.id])),
      });
      rowErrors.push(...drafts.errors);

      bodies = [];
      drafts.drafts.forEach((d: CsvRuleDraft, idx) => {
        const r = z
          .object({
            name: z.string().min(1),
            enabled: z.boolean(),
            action: z.enum(["allow", "deny", "drop", "reject"]),
            logging: z.enum(["none", "summary", "detail"]),
          })
          .safeParse(d);
        if (!r.success) {
          rowErrors.push({ row: idx + 1, message: "invalid draft row" });
          return;
        }
        bodies.push({
          name: d.name,
          enabled: d.enabled,
          position: d.position,
          srcZoneIds: d.srcZoneIds,
          dstZoneIds: d.dstZoneIds,
          srcAddrIds: d.srcAddrIds,
          dstAddrIds: d.dstAddrIds,
          serviceIds: d.serviceIds,
          applicationIds: [],
          userIds: [],
          srcMacs: [],
          action: d.action,
          logging: d.logging,
          synProtection: false,
          tags: d.tags,
          comment: d.comment,
        });
      });
    }

    if (rowErrors.length) {
      throw ApiError.validation("Import payload has invalid rows — nothing was persisted", { rows: rowErrors });
    }
    if (!bodies.length) {
      throw ApiError.validation("Import payload contains no rules");
    }

    const created = await importRules(tenantId, bodies);
    return {
      data: { imported: created.length, rules: created },
      audit: {
        action: "rule.import",
        objectType: "firewall_rule",
        objectName: `${created.length} imported rules`,
      },
    };
  },
);

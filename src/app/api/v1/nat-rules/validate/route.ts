/**
 * POST /api/v1/nat-rules/validate — NAT shadow/conflict detection +
 * generator-faithful advisories (mirrors /firewall-rules/validate, M03 §5).
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { natRuleBodySchema, validateBodySchema } from "@/lib/validators/firewall";
import { parseIds } from "@/lib/firewall/refs";
import { loadExpansionContext } from "@/lib/firewall/rule-loader";
import { detectNatConflicts, natAdvisories, type NatCandidate } from "@/lib/firewall/nat-validate";

export const dynamic = "force-dynamic";

export const POST = route({ area: "firewall", bodySchema: validateBodySchema.extend({ rule: natRuleBodySchema }) }, async ({ auth, body }) => {
  const [rows, ctx] = await Promise.all([
    db.natRule.findMany({ where: { tenantId: auth.tenantId }, orderBy: { position: "asc" } }),
    loadExpansionContext(auth.tenantId),
  ]);

  const toCandidate = (r: {
    id: number | null;
    name: string | null;
    position: number;
    enabled: boolean;
    type: string;
    srcAddrIds: number[];
    dstAddrIds: number[];
    serviceIds: number[];
    outgoingIface: string | null;
    translatedSrc: string | null;
    translatedSrcPool: string[];
    translatedDst: string | null;
    translatedPort: number | null;
    translatedPortRange: string | null;
    logging: string;
  }): NatCandidate => ({
    id: r.id,
    name: r.name,
    position: r.position,
    enabled: r.enabled,
    type: r.type,
    srcAddrs: ctx.expandAddr(r.srcAddrIds),
    dstAddrs: ctx.expandAddr(r.dstAddrIds),
    services: ctx.expandSvc(r.serviceIds),
    outgoingIface: r.outgoingIface,
    translatedSrc: r.translatedSrc,
    translatedSrcPool: r.translatedSrcPool,
    translatedDst: r.translatedDst,
    translatedPort: r.translatedPort,
    translatedPortRange: r.translatedPortRange,
    logging: r.logging,
  });

  const candidate = toCandidate({
    id: body.excludeRuleId ?? null,
    name: body.rule.name ?? null,
    position: Number.MAX_SAFE_INTEGER, // appended at the end (create semantics)
    enabled: body.rule.enabled,
    type: body.rule.type,
    srcAddrIds: body.rule.srcAddrIds,
    dstAddrIds: body.rule.dstAddrIds,
    serviceIds: body.rule.serviceIds,
    outgoingIface: body.rule.outgoingIface ?? null,
    translatedSrc: body.rule.translatedSrc ?? null,
    translatedSrcPool: body.rule.translatedSrcPool ?? [],
    translatedDst: body.rule.translatedDst ?? null,
    translatedPort: body.rule.translatedPort ?? null,
    translatedPortRange: body.rule.translatedPortRange ?? null,
    logging: body.rule.logging,
  });

  const existing = rows
    .filter((r) => r.id !== body.excludeRuleId)
    .map((r) =>
      toCandidate({
        id: r.id,
        name: r.name,
        position: r.position,
        enabled: r.enabled,
        type: r.type,
        srcAddrIds: parseIds(r.srcAddrIds),
        dstAddrIds: parseIds(r.dstAddrIds),
        serviceIds: parseIds(r.serviceIds),
        outgoingIface: r.outgoingIface,
        translatedSrc: r.translatedSrc,
        translatedSrcPool: (() => {
          try {
            const v = JSON.parse(r.translatedSrcPool);
            return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
          } catch {
            return [];
          }
        })(),
        translatedDst: r.translatedDst,
        translatedPort: r.translatedPort,
        translatedPortRange: r.translatedPortRange,
        logging: r.logging,
      }),
    );

  const conflicts = detectNatConflicts(candidate, existing);
  const warnings = natAdvisories(candidate);
  return {
    data: {
      ok: conflicts.filter((c) => c.reason !== "redundant").length === 0,
      conflicts,
      warnings,
    },
  };
});

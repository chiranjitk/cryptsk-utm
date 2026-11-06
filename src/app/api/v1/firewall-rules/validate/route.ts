/**
 * POST /api/v1/firewall-rules/validate — shadow/conflict detection (M03 §5,
 * pure function, no persist). Body: {rule, excludeRuleId?}.
 */

import { route } from "@/lib/api/handler";
import { validateBodySchema } from "@/lib/validators/firewall";
import { loadExpansionContext, loadEvalRules } from "@/lib/firewall/rule-loader";
import { detectConflicts, type CandidateRule } from "@/lib/firewall/rule-match";
import { normalizeAppLabels } from "@/lib/firewall/rule-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "firewall", bodySchema: validateBodySchema }, async ({ auth, body }) => {
  const tenantId = auth.tenantId;
  const [existing, ctx] = await Promise.all([loadEvalRules(tenantId), loadExpansionContext(tenantId)]);

  const candidate: CandidateRule = {
    name: body.rule.name,
    action: body.rule.action,
    srcZoneIds: body.rule.srcZoneIds,
    dstZoneIds: body.rule.dstZoneIds,
    srcAddrs: ctx.expandAddr(body.rule.srcAddrIds),
    dstAddrs: ctx.expandAddr(body.rule.dstAddrIds),
    services: ctx.expandSvc(body.rule.serviceIds),
    applicationIds: normalizeAppLabels(body.rule.applicationIds),
    userNames: ctx.userNames(body.rule.userIds),
    schedule: ctx.toSchedule(body.rule.scheduleId ?? null),
  };

  const conflicts = detectConflicts(candidate, existing.rules, body.excludeRuleId);
  return { data: { ok: conflicts.length === 0, conflicts } };
});

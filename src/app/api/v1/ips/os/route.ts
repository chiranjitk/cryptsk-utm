/**
 * /api/v1/ips/os — the GUI↔Suricata integration endpoint (mirrors
 * /api/v1/firewall-rules/os for the IPS engine).
 *
 * GET   — live OS status: facts (service state, version, running-mode, rule
 *         files, updater), the generated plan (managed rules, threshold
 *         block, warnings), drift (applied/in-sync), last apply state, gate.
 *
 * POST  — { action }:
 *           "apply"        — backup → write managed rules + threshold block +
 *                            yaml rule-files/threshold-file → `suricata -T`
 *                            validation → automatic rollback on failure →
 *                            live reload (suricatasc ruleset-reload)
 *           "rollback"     — restore the newest backup and reload
 *           "update-rules" — real `suricata-update` ET refresh + live reload
 *                            (requires the binary + OS apply gate)
 */

import { route } from "@/lib/api/handler";
import { z } from "zod";
import {
  buildIpsApplyPlan,
  readIpsApplyState,
  applyIpsOs,
  rollbackIpsOs,
  runOsRuleUpdate,
} from "@/lib/ips/ips-os";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["apply", "rollback", "update-rules"]),
});

export const GET = route({ area: "ips_policies" }, async ({ auth }) => {
  const [plan, state] = await Promise.all([buildIpsApplyPlan(auth.tenantId), readIpsApplyState()]);
  return {
    data: {
      gate: process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off",
      facts: plan.facts,
      plan: {
        defaultPolicy: plan.defaultPolicy,
        enabledPolicyCount: plan.enabledPolicyCount,
        managedRuleCount: plan.managedRuleCount,
        thresholdEntryCount: plan.thresholdEntryCount,
        yamlNeedsManagedFile: plan.yamlNeedsManagedFile,
        yamlNeedsThresholdFile: plan.yamlNeedsThresholdFile,
        warnings: plan.warnings,
        managedRules: plan.managedRules,
        thresholdBlock: plan.thresholdBlock,
      },
      drift: plan.drift,
      lastApply: state,
    },
  };
});

export const POST = route({ area: "ips_policies", bodySchema, section: "ips" }, async ({ auth, body }) => {
  switch (body.action) {
    case "apply": {
      const outcome = await applyIpsOs(auth.tenantId);
      return {
        data: outcome,
        audit: {
          action: outcome.rolledBack ? "ips.os-apply-rollback" : "ips.os-apply",
          objectType: "ips_policy",
          objectId: outcome.policyId ?? undefined,
          objectName: outcome.policyName ?? undefined,
          result: outcome.applied ? "success" : "failure",
        },
      };
    }
    case "rollback": {
      const r = await rollbackIpsOs();
      return {
        data: r,
        audit: {
          action: "ips.os-rollback",
          objectType: "ips_policy",
          objectName: r.backupDir ?? undefined,
          result: r.rolledBack ? "success" : "failure",
        },
      };
    }
    case "update-rules": {
      const r = await runOsRuleUpdate();
      return {
        data: r,
        audit: {
          action: "ips.os-update-rules",
          objectType: "ips_policy",
          result: r.ranOnOs ? "success" : "failure",
        },
      };
    }
  }
});

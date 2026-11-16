/**
 * POST /api/v1/waf/policies/[id]/test — simulated CRS test request (M17 §2.4.4):
 * body per wafTestSchema { method, url, payload? } → evaluateCrs() engine
 * (src/lib/waf/rules.ts — sandbox stand-in for the appliance's ModSecurity 3 +
 * OWASP CRS 3.3.7 evaluation: pattern-scored anomaly scoring, geo sentinel,
 * 60s rate-limit window) → verdict JSON + a summary WafLog row so the 24h
 * feed / stats counters reflect simulated traffic like the appliance would.
 *
 * Audit: waf.policy.test (objectType waf_policy).
 */

import { route, numericId } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { wafTestSchema } from "@/lib/validators/waf";
import { policyOr404, safeCountries } from "@/app/api/v1/waf/shared";
import { evaluateCrs } from "@/lib/waf/rules";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "waf", bodySchema: wafTestSchema, section: "waf" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const policy = await policyOr404(auth.tenantId, id);

    const verdict = evaluateCrs(
      {
        owaspCrsEnabled: policy.owaspCrsEnabled,
        paranoiaLevel: policy.paranoiaLevel,
        anomalyInThreshold: policy.anomalyInThreshold,
        anomalyOutThreshold: policy.anomalyOutThreshold,
        learningMode: policy.learningMode,
        geoBlockCountries: safeCountries(policy.geoBlockCountries),
        rateLimitRpm: policy.rateLimitRpm,
        rateLimitBurst: policy.rateLimitBurst,
        enabled: policy.enabled,
      },
      policy.id,
      { method: body.method, url: body.url, payload: body.payload ?? "" },
    );

    // Top-scoring match feeds the summary log row (stats topRules groups by
    // ruleId; rows without a match stay ruleId-null summary entries).
    const top = [...verdict.matched].sort((a, b) => b.score - a.score)[0] ?? null;
    await db.wafLog.create({
      data: {
        tenantId: auth.tenantId,
        vhostId: policy.vhostId,
        clientIp: "127.0.0.1", // simulated traffic originates from the console
        method: body.method,
        url: body.url,
        ruleId: top?.id ?? null,
        ruleMsg: top?.msg ?? verdict.summary,
        anomalyScore: verdict.anomalyScore,
        action: verdict.action,
        payloadSnippet: body.payload ? body.payload.slice(0, 200) : null,
      },
    });

    return {
      data: {
        action: verdict.action,
        reason: verdict.reason,
        anomalyScore: verdict.anomalyScore,
        threshold: verdict.threshold,
        matched: verdict.matched,
        learningMode: policy.learningMode,
        summary: verdict.summary,
      },
      audit: {
        action: "waf.policy.test",
        objectType: "waf_policy",
        objectId: id,
        objectName: policy.name,
        after: {
          method: body.method,
          url: body.url,
          action: verdict.action,
          reason: verdict.reason,
          anomalyScore: verdict.anomalyScore,
          threshold: verdict.threshold,
          matched: verdict.matched.length,
        },
      },
    };
  },
);

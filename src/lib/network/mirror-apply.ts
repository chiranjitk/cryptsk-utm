/**
 * OS convergence executor for PORT MIRRORING (tc/mirred SPAN sessions).
 *
 * Mirrors route-apply.ts guard structure with tc-specific safety:
 *   gate        CONSOLE_OS_APPLY=1            off → plan preview, no exec
 *   tool        `tc` (iproute2) on the host
 *   whitelist   only `tc qdisc replace` + `tc filter add|del` on clsact blocks
 *   protect     `lo` and CONSOLE_PROTECTED_IFACES (default ens32) are never
 *               touched — the executor refuses any plan step that targets them
 */

import { hasTool, runTool } from "@/lib/host/tools";
import { isProtectedMirrorIface, type MirrorOsPlan, type MirrorPlanStep } from "./mirror-os";
import type { OsApplyOutcome } from "./route-apply";

const MIRROR_EXEC_WHITELIST =
  /^tc (qdisc replace dev [a-z0-9][a-z0-9._-]* clsact|filter (add|del) dev [a-z0-9][a-z0-9._-]* (ingress|egress).*)$/;

function stepGuarded(step: MirrorPlanStep): string | null {
  const dev = /^(?:tc (?:qdisc replace|filter (?:add|del)) dev) ([a-z0-9][a-z0-9._-]*)/.exec(step.cmd)?.[1];
  if (!dev) return "refused: step does not name a valid target device";
  if (isProtectedMirrorIface(dev)) {
    return `refused: dev ${dev} is a protected interface (CONSOLE_PROTECTED_IFACES) — mirroring never touches it`;
  }
  if (!MIRROR_EXEC_WHITELIST.test(step.cmd)) {
    return "refused: plan step failed the tc whitelist — execution aborted";
  }
  return null;
}

function execGuard(plan: MirrorOsPlan): Pick<OsApplyOutcome, "gate" | "applied" | "reason"> | null {
  if (process.env.CONSOLE_OS_APPLY !== "1") {
    return {
      gate: "off",
      applied: false,
      reason: "OS convergence is disabled by platform policy on this installation — the plan above is a preview only",
    };
  }
  return null;
}

async function execPlan(plan: MirrorOsPlan): Promise<OsApplyOutcome> {
  const asPlan = { name: plan.name, osName: plan.srcIface, steps: plan.steps.map((s) => ({ cmd: s.cmd, summary: s.summary })) };
  const guarded = execGuard(plan);
  if (guarded) return { ...guarded, plan: asPlan };
  if (!(await hasTool("tc"))) {
    return { gate: "on", applied: false, reason: "'tc' (iproute2) not found on the host — cannot execute the plan", plan: asPlan };
  }

  const results: Array<{ cmd: string; ok: boolean; stderr?: string }> = [];
  for (const step of plan.steps) {
    const guardMsg = stepGuarded(step);
    if (guardMsg) {
      return { gate: "on", applied: false, reason: guardMsg, plan: asPlan, results };
    }
    const r = await runTool(step.cmd);
    const ok = r.ok || Boolean(step.soft); // soft cleanup failures are non-fatal
    results.push({ cmd: step.cmd, ok, stderr: ok ? undefined : r.stderr || r.error });
    if (!r.ok && !step.soft) break; // transactional: stop at first hard failure
  }
  const hardFailed = results.filter((r) => !r.ok);
  return {
    gate: "on",
    applied: hardFailed.length === 0,
    reason: hardFailed.length === 0 ? "applied to host" : `${hardFailed.length} step(s) failed`,
    plan: asPlan,
    results,
  };
}

/** Never throws — convergence errors surface as an honest failed outcome. */
export async function convergeMirrorSafe(build: () => MirrorOsPlan): Promise<OsApplyOutcome> {
  try {
    return await execPlan(build());
  } catch (err) {
    return {
      gate: process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      plan: { name: "?", osName: null, steps: [] },
    };
  }
}

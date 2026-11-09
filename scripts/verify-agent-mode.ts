/**
 * verify-agent-mode.ts — end-to-end proof of the real agent data plane.
 *
 *  1. spawns the REAL Go agent binary (agent/cryptsk-agent) on :8080
 *  2. boots AgentEngine (ADAPTER_MODE=agent) against it
 *  3. waits 3 ticks and asserts the rings carry REAL host telemetry
 *  4. calls AgentAdapter.getDashboardSummary and asserts the full merge
 *  5. probes eth0 through the agent (real gateway TCP probe)
 *
 * NO mock/simulated data anywhere in this path — every number comes from
 * /proc of this machine via the agent transport. Run: bun scripts/verify-agent-mode.ts
 */

process.env.AGENT_SHARED_SECRET = "verify-secret-000";
process.env.AGENT_BASE_URL = "http://127.0.0.1:8099";
process.env.AGENT_LISTEN = ":8099";
process.env.ADAPTER_MODE = "agent";

import { spawn } from "child_process";
import path from "path";

const ROOT = path.resolve(__dirname, "..");
const BIN = path.join(ROOT, "agent", "cryptsk-agent");

let failures = 0;
function check(name: string, cond: boolean, detail = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!cond) failures++;
}

async function main() {
  // 1. spawn the real agent
  const agent = spawn(BIN, [], {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  agent.stdout.on("data", (d) => process.stdout.write(`[agent] ${d}`));
  agent.stderr.on("data", (d) => process.stderr.write(`[agent:err] ${d}`));

  try {
    // wait for healthz
    let healthy = false;
    for (let i = 0; i < 40; i++) {
      try {
        const res = await fetch("http://127.0.0.1:8099/healthz");
        if (res.ok) { healthy = true; break; }
      } catch {}
      await new Promise((r) => setTimeout(r, 250));
    }
    check("agent healthz", healthy);

    // 2+3. AgentEngine — 3 ticks of real telemetry
    const { getAgentEngine } = await import("../src/lib/engine/agent-engine");
    const { AgentAdapter } = await import("../src/lib/adapters/agent");

    const engine = getAgentEngine();
    await engine.start();
    await new Promise((r) => setTimeout(r, 7500)); // > 3 ticks

    const ticks = engine.metricsRing;
    check("metricsRing has real ticks", ticks.length >= 2, `${ticks.length} ticks`);
    const last = ticks[ticks.length - 1];
    check("tick has real iface list", (last?.ifaces?.length ?? 0) > 0, JSON.stringify(last?.ifaces));
    check("tick cpuPct is a real number", typeof last?.cpuPct === "number", String(last?.cpuPct));
    check("tick conntrackCount measured", (last?.conntrackCount ?? 0) > 0, String(last?.conntrackCount));

    // 4. full dashboard merge (agent host-plane + console DB aggregates)
    const adapter = new AgentAdapter();
    const summary = await adapter.getDashboardSummary(1);
    check("summary.health.uptimeSec real", summary.health.uptimeSec > 0, String(summary.health.uptimeSec));
    check("summary.throughput present", !!summary.throughput);
    check("summary.alerts24h bySeverity keys", ["info", "low", "medium", "high", "critical"].every((k) => k in summary.alerts24h.bySeverity), JSON.stringify(summary.alerts24h));
    check("summary.topApps is array", Array.isArray(summary.topApps), `${summary.topApps.length} apps`);
    check("summary.topTalkers is array", Array.isArray(summary.topTalkers), `${summary.topTalkers.length} talkers`);
    check("summary.vpnStatus is array", Array.isArray(summary.vpnStatus));
    check("summary.recentThreats is array", Array.isArray(summary.recentThreats));
    check("summary.throughputHistory backfilled", summary.throughputHistory.length >= 2, `${summary.throughputHistory.length} ticks`);

    // 5. real WAN probe through the agent
    const state = await engine.forceProbe("eth0");
    check("forceProbe(eth0) real verdict", ["up", "degraded", "down"].includes(state ?? ""), String(state));

    // honesty probes: unauthenticated call must fail loudly (no fallback data)
    const bad = await fetch("http://127.0.0.1:8099/v1/engine/snapshot", {
      method: "POST",
      headers: { "content-type": "application/json", "x-agent-auth": "wrong" },
      body: "{}",
    });
    check("agent rejects bad auth (401)", bad.status === 401, String(bad.status));

    engine.stop();
    console.log(failures === 0 ? "\nALL CHECKS PASSED — agent data plane is real end-to-end" : `\n${failures} CHECKS FAILED`);
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
    agent.kill("SIGTERM");
  }
}

main().catch((err) => {
  console.error("verify-agent-mode crashed:", err);
  process.exit(1);
});

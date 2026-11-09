/**
 * Next.js instrumentation hook — boots the data-plane engine with the server
 * process. ADAPTER_MODE=host (default, ADR-021) starts the HostCollector:
 * real /proc telemetry, gateway probes, and appliance source tails.
 * ADAPTER_MODE=agent starts the AgentEngine: the same locked 2 s tick, fed by
 * the remote Go sensor agent (AGENT_BASE_URL :8080 snapshot transport).
 * ADAPTER_MODE=simulated boots the legacy MockEngine demo plane (dev only).
 */

export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  try {
    const { getEngine, getDataPlaneMode } = await import("@/lib/engine");
    console.log(`[instrumentation] data plane: ${getDataPlaneMode()}`);
    await getEngine().start();
  } catch (err) {
    console.error("[instrumentation] engine boot deferred:", err instanceof Error ? err.message : err);
  }
}

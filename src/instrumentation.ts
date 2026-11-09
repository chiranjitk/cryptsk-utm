/**
 * Next.js instrumentation hook — boots the data-plane engine with the server
 * process. ADAPTER_MODE=host (default, ADR-021) starts the HostCollector:
 * real /proc telemetry, gateway probes, and appliance source tails.
 * ADAPTER_MODE=simulated boots the legacy MockEngine demo plane.
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

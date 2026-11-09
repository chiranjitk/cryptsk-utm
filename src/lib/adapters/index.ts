/**
 * Adapter factory (ADR-004 + ADR-021) — ADAPTER_MODE:
 *   • "host"      (default) → HostAdapter  : real host data plane (HostCollector)
 *   • "simulated"           → SimulatedAdapter : MockEngine demo plane
 *   • "agent"               → HostAdapter for now; the HTTP transport to the
 *                             remote Go agent (:8080) replaces it at appliance
 *                             integration (deploy/AGENT_ADAPTER_CHECKLIST.md).
 */

import type { SystemAdapter } from "./types";
import { SimulatedAdapter } from "./simulated";
import { HostAdapter } from "./host";

export function getAdapter(): SystemAdapter {
  const mode = (process.env.ADAPTER_MODE ?? "host").toLowerCase();
  if (mode === "simulated") return new SimulatedAdapter();
  return new HostAdapter();
}

export type { SystemAdapter, DashboardSummary } from "./types";

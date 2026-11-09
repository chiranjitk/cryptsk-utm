/**
 * Adapter factory (ADR-004 + ADR-021) — ADAPTER_MODE:
 *   • "host"      (default) → HostAdapter   : real LOCAL telemetry (HostCollector)
 *   • "agent"               → AgentAdapter  : real REMOTE sensor telemetry
 *                                             (Go agent :8080 — AGENT_BASE_URL +
 *                                             AGENT_SHARED_SECRET, checklist contract)
 *   • "simulated"           → SimulatedAdapter : legacy demo plane (MockEngine)
 *
 * NO-MOCK MANDATE (ADR-021): in production the simulated plane is FORBIDDEN —
 * selecting it throws at startup instead of silently serving fabricated data.
 */

import type { SystemAdapter } from "./types";
import { SimulatedAdapter } from "./simulated";
import { HostAdapter } from "./host";
import { AgentAdapter } from "./agent";

export type AdapterMode = "host" | "agent" | "simulated";

export function getAdapterMode(): AdapterMode {
  const mode = (process.env.ADAPTER_MODE ?? "host").toLowerCase() as AdapterMode;
  if (mode !== "host" && mode !== "agent" && mode !== "simulated") return "host";
  if (mode === "simulated" && process.env.NODE_ENV === "production") {
    throw new Error(
      "ADAPTER_MODE=simulated is FORBIDDEN in production (no-mock mandate, ADR-021). " +
        "Set ADAPTER_MODE=host (local real telemetry) or agent (remote sensor).",
    );
  }
  return mode;
}

export function getAdapter(): SystemAdapter {
  switch (getAdapterMode()) {
    case "simulated":
      return new SimulatedAdapter();
    case "agent":
      return new AgentAdapter();
    default:
      return new HostAdapter();
  }
}

export type { SystemAdapter, DashboardSummary } from "./types";

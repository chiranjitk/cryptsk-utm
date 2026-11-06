/**
 * Adapter factory (ADR-004) — ADAPTER_MODE=simulated|agent (default simulated).
 * AgentAdapter is a Phase-2 stub that fails fast with a clear error.
 */

import type { SystemAdapter } from "./types";
import { SimulatedAdapter } from "./simulated";

export function getAdapter(): SystemAdapter {
  const mode = process.env.ADAPTER_MODE ?? "simulated";
  if (mode === "agent") {
    throw new Error("AgentAdapter arrives with the appliance build (Phase 2) — set ADAPTER_MODE=simulated");
  }
  return new SimulatedAdapter();
}

export type { SystemAdapter, DashboardSummary } from "./types";

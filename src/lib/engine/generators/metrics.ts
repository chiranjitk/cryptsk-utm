/**
 * metrics generator — SIMULATION_LAYER §6:
 * per-iface rxKbps/txKbps (wan 40k–300k, lan 20k–150k, dmz 5k–40k), bursty cpu,
 * slow-drift mem, conntrack 5k–50k. QoS caps flatten series at the cap.
 */

import type { MetricsTick, IfaceTick } from "../events";

export interface IfaceMeta {
  name: string;
  role: string;
  enabled: boolean;
}

export class MetricsGenerator {
  private memPct = 47;
  private cpuSpikeTicks = 0;

  constructor(private readonly rand: () => number) {}

  tick(ifaces: IfaceMeta[], tickNo: number, profileBaselines: Record<string, [number, number]>): MetricsTick {
    const ts = new Date().toISOString();
    const out: IfaceTick[] = ifaces.map((i) => {
      const [min, max] = profileBaselines[i.role] ?? [0, 0];
      if (!i.enabled) return { name: i.name, rxKbps: 0, txKbps: 0 };
      // diurnal shape: busier during "office" hours of the (simulated) day
      const dayPhase = 0.75 + 0.25 * Math.sin((tickNo / 1800) * Math.PI * 2);
      const jitter = 0.75 + this.rand() * 0.5;
      const rx = Math.round((min + (max - min) * this.rand()) * dayPhase * jitter);
      const tx = Math.round(rx * (0.2 + this.rand() * 0.4));
      return { name: i.name, rxKbps: Math.max(0, rx), txKbps: Math.max(0, tx) };
    });

    // cpu: 5–85 bursty
    if (this.cpuSpikeTicks > 0) this.cpuSpikeTicks -= 1;
    else if (this.rand() < 0.04) this.cpuSpikeTicks = 2 + Math.floor(this.rand() * 4);
    const baseCpu = 14 + 26 * Math.abs(Math.sin(tickNo / 90));
    const cpuPct = clamp(
      this.cpuSpikeTicks > 0 ? baseCpu + 40 + this.rand() * 25 : baseCpu + this.rand() * 18 - 6,
      3,
      97,
    );

    // mem: slow drift 40–72
    this.memPct = clamp(this.memPct + (this.rand() - 0.5) * 0.8, 38, 74);

    // conntrack: 5k–50k correlated with lan throughput
    const lanRx = out.filter((o) => o.name.startsWith("lan") || o.name.startsWith("vlan")).reduce((s, o) => s + o.rxKbps, 0);
    const conntrackCount = Math.round(clamp(8000 + lanRx * 0.18 + this.rand() * 4000, 5000, 50000));

    return { ts, ifaces: out, cpuPct: Math.round(cpuPct * 10) / 10, memPct: Math.round(this.memPct * 10) / 10, conntrackCount };
  }
}

export function clamp(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v));
}

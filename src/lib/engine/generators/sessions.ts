/**
 * wan-probes + vpn + session state machines — SIMULATION_LAYER §5.
 * UP → DEGRADED → DOWN per probe thresholds; tunnels CONNECTING → UP after
 * 2–5 DPD ticks; vpn sessions churn (connect / idle / disconnect).
 */

import type { VpnSessionState } from "../mock-engine";

export type WanState = "up" | "degraded" | "down" | "unknown";

export interface WanProbeState {
  iface: string;
  enabled: boolean;
  state: WanState;
  goodProbes: number;
  badProbes: number;
}

export class WanProbeMachine {
  constructor(private readonly rand: () => number, private flapRate: number) {}

  setFlapRate(rate: number) {
    this.flapRate = rate;
  }

  step(p: WanProbeState): WanState | null {
    if (!p.enabled) {
      if (p.state !== "down") {
        p.state = "down";
        return p.state;
      }
      return null;
    }
    // enabled links stay healthy; profile-driven flap probability
    if (this.rand() < this.flapRate && p.state === "up") {
      p.state = "degraded";
      p.badProbes = 1;
      return p.state;
    }
    if (p.state === "degraded") {
      if (this.rand() < 0.5) {
        p.goodProbes += 1;
        if (p.goodProbes >= 3) {
          p.state = "up";
          p.goodProbes = 0;
          p.badProbes = 0;
          return p.state;
        }
      } else {
        p.badProbes += 1;
        if (p.badProbes >= 3) {
          p.state = "down";
          p.badProbes = 0;
          return p.state;
        }
      }
    } else if (p.state === "down" && this.rand() < 0.25) {
      // recovery path
      p.state = "degraded";
      return p.state;
    }
    return null;
  }
}

export type VpnTunnelStatus = "up" | "down" | "connecting" | "error";

export interface VpnTunnelState {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  status: VpnTunnelStatus;
  dpdTicks: number;
  /** first peer / remote ip — named in the handshake statusMessage (M05 §5) */
  peerLabel?: string | null;
}

export class VpnStateMachine {
  constructor(private readonly rand: () => number) {}

  step(t: VpnTunnelState): VpnTunnelStatus | null {
    if (!t.enabled) {
      if (t.status !== "down") {
        t.status = "down";
        return t.status;
      }
      return null;
    }
    if (t.status === "connecting") {
      t.dpdTicks += 1;
      if (t.dpdTicks >= 2 + Math.floor(this.rand() * 4)) {
        t.status = "up";
        return t.status;
      }
    } else if (t.status === "up" && this.rand() < 0.002) {
      // rare renegotiation
      t.status = "connecting";
      t.dpdTicks = 0;
      return t.status;
    }
    return null;
  }
}

export interface SessionChurnEvent {
  id: number;
  userName: string | null;
  status?: string;
  bytesIn?: number;
  bytesOut?: number;
  lastActivity?: string;
}

export class SessionChurnMachine {
  constructor(private readonly rand: () => number) {}

  /**
   * Grow byte counters for active sessions; occasionally idle one out.
   * M05 §5: per-session churn timers (group policy) — `idleChanceMul` /
   * `disconnectChanceMul` shorten the idle path for group members and
   * `expiresAt` enforces a max session duration (idle → disconnected
   * sooner than non-member sessions).
   */
  step(sessions: VpnSessionState[]): SessionChurnEvent[] {
    const diffs: SessionChurnEvent[] = [];
    for (const s of sessions) {
      if (s.status === "disconnected") continue;
      const bytesIn = Math.floor(this.rand() * 120_000);
      const bytesOut = Math.floor(this.rand() * 60_000);
      s.bytesIn += bytesIn;
      s.bytesOut += bytesOut;
      s.lastActivity = new Date().toISOString();
      const diff: SessionChurnEvent = {
        id: s.id,
        userName: s.userName,
        bytesIn,
        bytesOut,
        lastActivity: s.lastActivity,
      };
      // max session duration (VpnUserGroup.maxSessionMin) — hard cut
      if (s.expiresAt && Date.parse(s.expiresAt) <= Date.now()) {
        s.status = "disconnected";
        diff.status = "disconnected";
        diffs.push(diff);
        continue;
      }
      const idleChance = 0.006 * (s.idleChanceMul ?? 1);
      const disconnectChance = 0.2 * (s.disconnectChanceMul ?? 1);
      if (s.status === "active" && this.rand() < idleChance) {
        s.status = "idle";
        diff.status = "idle";
      } else if (s.status === "idle" && this.rand() < disconnectChance) {
        s.status = "active";
        diff.status = "active";
      }
      diffs.push(diff);
    }
    return diffs;
  }
}

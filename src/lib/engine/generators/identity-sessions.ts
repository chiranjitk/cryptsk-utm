/**
 * Identity session churn — SIMULATION_LAYER §6 / M07 §5.5.
 * Plans identity-session changes per tick: lastSeen bumps, timeout expiry,
 * simulated logins (captive portal self-registration + voucher consumption,
 * VPN, local/RADIUS), and the concurrent-session cap
 * (auth-settings.sessionLimits.maxConcurrentPerUser — oldest session expires).
 * The engine executes the DB I/O (planner/executor split, M06 §5.4 pattern).
 */

export type IdentityMethod = "local" | "radius" | "captive_portal" | "vpn";

export interface IdentitySessionRuntime {
  id: number;
  userName: string;
  sourceIp: string;
  method: string;
  state: string;
  lastSeenMs: number;
}

export interface IdentityNewLogin {
  userName: string;
  sourceIp: string;
  method: IdentityMethod;
  deviceMac: string | null;
}

export interface IdentityPlan {
  /** active session ids seen this tick (lastSeen bump is a bulk updateMany) */
  bumpAll: boolean;
  /** ids aged out by the per-method timeout */
  expireIds: number[];
  /** sessions replaced by the concurrent cap — expire oldest of these userNames */
  capExpiredIds: number[];
  /** simulated logins to upsert (one identity per source IP) */
  logins: IdentityNewLogin[];
}

export interface IdentityChurnConfig {
  portalEnabled: boolean;
  portalMode: string;
  portalTimeoutMin: number;
  maxConcurrentPerUser: number;
  /** enabled console users (local + radius logins come from these) */
  userNames: string[];
}

const GUEST_POOL = "192.168.20.";
const LAN_POOL = "192.168.10.";
const VPN_POOL = "10.99.1.";
/** non-captive sessions age out after 12 h of no lastSeen bump */
const DEFAULT_TIMEOUT_MIN = 720;

export class IdentitySessionMachine {
  constructor(private readonly rand: () => number) {}

  private hostAt(pool: string): string {
    return `${pool}${20 + Math.floor(this.rand() * 200)}`;
  }

  private mac(): string {
    const hex = () => Math.floor(this.rand() * 256).toString(16).padStart(2, "0");
    return `aa:bb:cc:${hex()}:${hex()}:${hex()}`;
  }

  private pick<T>(arr: T[]): T | undefined {
    if (arr.length === 0) return undefined;
    return arr[Math.floor(this.rand() * arr.length)];
  }

  step(sessions: IdentitySessionRuntime[], cfg: IdentityChurnConfig): IdentityPlan {
    const plan: IdentityPlan = { bumpAll: false, expireIds: [], capExpiredIds: [], logins: [] };
    const now = Date.now();

    // 1) timeout expiry — captive_portal sessions use the portal profile
    //    timeout; everything else ages out on the default window
    for (const s of sessions) {
      if (s.state !== "active") continue;
      const timeoutMin = s.method === "captive_portal" ? cfg.portalTimeoutMin : DEFAULT_TIMEOUT_MIN;
      if (now - s.lastSeenMs > timeoutMin * 60_000) plan.expireIds.push(s.id);
    }

    // 2) simulated logins (low rate — sandbox churn, not a flood)
    if (cfg.portalEnabled) {
      if (cfg.portalMode === "voucher" && this.rand() < 0.04) {
        plan.logins.push({
          userName: `guest-${100 + Math.floor(this.rand() * 900)}`,
          sourceIp: this.hostAt(GUEST_POOL),
          method: "captive_portal",
          deviceMac: this.mac(),
        });
      } else if (cfg.portalMode === "credentials" && this.rand() < 0.02) {
        plan.logins.push({
          userName: `guest-${100 + Math.floor(this.rand() * 900)}`,
          sourceIp: this.hostAt(GUEST_POOL),
          method: "captive_portal",
          deviceMac: this.mac(),
        });
      } else if (cfg.portalMode === "clickthrough" && this.rand() < 0.01) {
        plan.logins.push({
          userName: "clickthrough-guest",
          sourceIp: this.hostAt(GUEST_POOL),
          method: "captive_portal",
          deviceMac: this.mac(),
        });
      }
    }
    if (this.rand() < 0.012) {
      const user = this.pick(cfg.userNames);
      if (user) {
        plan.logins.push({
          userName: user,
          sourceIp: this.hostAt(LAN_POOL),
          method: this.rand() < 0.5 ? "local" : "radius",
          deviceMac: this.mac(),
        });
      }
    }
    if (this.rand() < 0.01) {
      const vpnNames = ["c.reyes", "m.okafor", "j.tanaka", "l.novak", "s.patel", "d.kim", "r.almeida", "k.johnson", "a.hassan", "p.muller"];
      const user = this.pick(vpnNames);
      if (user) {
        plan.logins.push({ userName: user, sourceIp: this.hostAt(VPN_POOL), method: "vpn", deviceMac: null });
      }
    }

    // 3) concurrent-session cap — a login that would exceed the cap expires
    //    the user's OLDEST active session (replaced, M07 §5.2/§5.5)
    if (plan.logins.length > 0 && cfg.maxConcurrentPerUser >= 1) {
      const activeByUser = new Map<string, IdentitySessionRuntime[]>();
      for (const s of sessions) {
        if (s.state !== "active") continue;
        const list = activeByUser.get(s.userName) ?? [];
        list.push(s);
        activeByUser.set(s.userName, list);
      }
      for (const login of plan.logins) {
        const existing = activeByUser.get(login.userName) ?? [];
        // logins landing in this same plan count toward the cap too
        const planned = plan.logins.filter((l) => l.userName === login.userName).length;
        if (existing.length + planned > cfg.maxConcurrentPerUser) {
          const oldest = [...existing].sort((a, b) => a.lastSeenMs - b.lastSeenMs)[0];
          if (oldest && !plan.capExpiredIds.includes(oldest.id)) {
            plan.capExpiredIds.push(oldest.id);
          }
        }
      }
    }

    plan.bumpAll = sessions.some((s) => s.state === "active");
    return plan;
  }
}

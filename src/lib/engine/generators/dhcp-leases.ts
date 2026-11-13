/**
 * DHCP lease churn machine (M06 §5.3/§5.4) — a pure planner; all DB I/O stays
 * in the engine (same generator↔engine split as the IPS/FW generators).
 *
 * Per 2 s tick it plans: expiry (endsAt reached → expired, kept 7 d), renewals
 * (active lease nearing its endsAt renews), occasional releases (keeps the
 * released state visible), and new dynamic leases from enabled IPv4 subnets'
 * pool ranges MINUS reservation IPs (reserved IPs are excluded; a dynamic
 * lease holding a newly reserved IP is released — the client reassigns on
 * next renew, M06 §5.3). @@unique([subnetId, ip]) is honored by the used-set;
 * engine prunes stale non-active rows whose IP gets re-picked (release frees
 * the IP for reuse, M06 §3).
 */

export interface DhcpSubnetRuntime {
  id: number;
  subnetCidr: string;
  rangeStart: string;
  rangeEnd: string;
  leaseTime: number;
  dnsServers: string[];
}

export interface DhcpReservationRuntime {
  subnetId: number;
  mac: string;
  ip: string;
}

export interface DhcpLeaseRuntime {
  id: number;
  subnetId: number;
  mac: string;
  ip: string;
  hostname: string | null;
  endsAtMs: number;
  leaseTimeSec: number;
}

export interface DhcpRuntime {
  subnets: DhcpSubnetRuntime[];
  reservations: DhcpReservationRuntime[];
  leases: DhcpLeaseRuntime[];
}

export interface LeasePlan {
  expireIds: number[];
  renewIds: number[];
  releaseIds: number[];
  creates: Array<{ subnetId: number; mac: string; ip: string; hostname: string; endsAtMs: number }>;
}

const HOST_STEMS = [
  "ws-eng", "ws-sales", "ws-hr", "mac-design", "ipad-lobby", "phone-conf", "tablet-ward",
  "pos", "cam-side", "sensor-door", "chromebox", "laptop-guest", "printer-2f", "clock-floor",
];

// ── v4 helpers (churn stays IPv4 — M06 §5.4) ────────────────────────────────

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

function intToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function randomMac(rand: () => number): string {
  const hex = () => Math.floor(rand() * 256).toString(16).padStart(2, "0");
  return `aa:bb:cc:${hex()}:${hex()}:${hex()}`;
}

export class DhcpLeaseMachine {
  constructor(private readonly rand: () => number) {}

  step(runtime: DhcpRuntime, nowMs: number): LeasePlan {
    const plan: LeasePlan = { expireIds: [], renewIds: [], releaseIds: [], creates: [] };
    if (runtime.subnets.length === 0) return plan;

    // 1) expiry + renewals + reserved-IP reassignment
    for (const lease of runtime.leases) {
      if (lease.endsAtMs <= nowMs) {
        plan.expireIds.push(lease.id);
        continue;
      }
      const reserved = runtime.reservations.some((r) => r.subnetId === lease.subnetId && r.ip === lease.ip);
      if (reserved && this.rand() < 0.5) {
        // dynamic client on a newly reserved IP → reassigned at renew (M06 §5.3)
        plan.releaseIds.push(lease.id);
        continue;
      }
      const remaining = lease.endsAtMs - nowMs;
      const renewWindow = Math.min(60_000, (lease.leaseTimeSec * 1000) / 10);
      if (remaining < renewWindow && this.rand() < 0.7) {
        plan.renewIds.push(lease.id);
      }
    }

    // 2) occasional visible release
    if (runtime.leases.length > 3 && this.rand() < 0.06) {
      const victim = runtime.leases[Math.floor(this.rand() * runtime.leases.length)];
      if (victim && !plan.expireIds.includes(victim.id) && !plan.releaseIds.includes(victim.id)) {
        plan.releaseIds.push(victim.id);
      }
    }

    // 3) new dynamic leases — pool range minus reserved minus in-use IPs
    const used = new Set<string>();
    for (const r of runtime.reservations) used.add(`${r.subnetId}:${r.ip}`);
    for (const l of runtime.leases) used.add(`${l.subnetId}:${l.ip}`);

    const createChance = 0.35;
    const attempts = 2;
    for (let i = 0; i < attempts && this.rand() < createChance; i++) {
      const subnet = runtime.subnets[Math.floor(this.rand() * runtime.subnets.length)]!;
      const start = ipv4ToInt(subnet.rangeStart);
      const end = ipv4ToInt(subnet.rangeEnd);
      if (start === null || end === null || end <= start) continue;
      const span = end - start + 1;
      let picked: number | null = null;
      for (let tries = 0; tries < 12 && picked === null; tries++) {
        const candidate = start + Math.floor(this.rand() * span);
        if (!used.has(`${subnet.id}:${intToIpv4(candidate)}`)) picked = candidate;
      }
      if (picked === null) continue;
      const ip = intToIpv4(picked);
      used.add(`${subnet.id}:${ip}`);
      const stem = HOST_STEMS[Math.floor(this.rand() * HOST_STEMS.length)]!;
      const hostname = `${stem}-${Math.floor(this.rand() * 90 + 10)}`;
      plan.creates.push({
        subnetId: subnet.id,
        mac: randomMac(this.rand),
        ip,
        hostname,
        endsAtMs: nowMs + subnet.leaseTime * 1000,
      });
    }
    return plan;
  }
}

/**
 * DHCP lease churn machine (M06 §5.3/§5.4) — regression tests for the T1
 * renewal semantics (audit F-a fix 13): a lease renews when remaining < 50%
 * of the lease time (RFC 2131 T1, no synthetic 60 s cap), the renewal
 * extends endsAtMs in the runtime copy, and the probabilistic release churn
 * only fires OUTSIDE the renewal window.
 */

import { describe, expect, test } from "vitest";
import { DhcpLeaseMachine, type DhcpRuntime } from "@/lib/engine/generators/dhcp-leases";

const SUBNET = {
  id: 7,
  subnetCidr: "10.20.0.0/24",
  rangeStart: "10.20.0.100",
  rangeEnd: "10.20.0.200",
  leaseTime: 3600,
  dnsServers: ["10.20.0.1"],
};

function runtimeWithLeases(
  leases: Array<{ id: number; endsAtSec: number; leaseTimeSec: number }>,
): DhcpRuntime {
  return {
    subnets: [SUBNET],
    reservations: [],
    leases: leases.map((l) => ({
      id: l.id,
      subnetId: SUBNET.id,
      mac: "aa:bb:cc:00:00:01",
      ip: `10.20.0.${100 + l.id}`,
      hostname: `host-${l.id}`,
      endsAtMs: l.endsAtSec * 1000,
      leaseTimeSec: l.leaseTimeSec,
    })),
  };
}

/** rand() = 0 → every probabilistic branch fires (renew roll passes, churn roll passes). */
const alwaysZero = () => 0;

describe("DhcpLeaseMachine T1 renewal window", () => {
  test("renews at 40% remaining — inside the old 60 s window this never fired", () => {
    const now = 1_000_000_000;
    // leaseTimeSec 3600 → T1 window = 1800 s; remaining 1440 s (40%) < 1800 s
    const rt = runtimeWithLeases([{ id: 1, endsAtSec: now / 1000 + 1440, leaseTimeSec: 3600 }]);
    const plan = new DhcpLeaseMachine(alwaysZero).step(rt, now);
    expect(plan.renewIds).toContain(1);
    // renewal extends endsAt to a full fresh lease (now + leaseTime)
    expect(rt.leases[0]!.endsAtMs).toBe(now + 3600 * 1000);
  });

  test("does NOT renew while remaining ≥ 50% of the lease time", () => {
    const now = 1_000_000_000;
    // remaining 3000 s of 3600 s lease (83%) — outside T1
    const rt = runtimeWithLeases([{ id: 2, endsAtSec: now / 1000 + 3000, leaseTimeSec: 3600 }]);
    const plan = new DhcpLeaseMachine(alwaysZero).step(rt, now);
    expect(plan.renewIds).not.toContain(2);
    expect(rt.leases[0]!.endsAtMs).toBe((now / 1000 + 3000) * 1000);
  });

  test("renewal fires for long leases deep inside T1 (no 60 s cap anymore)", () => {
    const now = 1_000_000_000;
    // 86400 s lease, remaining 40000 s (46%) — old window capped at 60 s so
    // this lease would never renew; T1 semantics must renew it
    const rt = runtimeWithLeases([{ id: 3, endsAtSec: now / 1000 + 40_000, leaseTimeSec: 86_400 }]);
    const plan = new DhcpLeaseMachine(alwaysZero).step(rt, now);
    expect(plan.renewIds).toContain(3);
    expect(rt.leases[0]!.endsAtMs).toBe(now + 86_400 * 1000);
  });
});

describe("DhcpLeaseMachine release churn stays outside the renewal window", () => {
  test("a lease inside T1 is never picked as the churn victim", () => {
    const now = 1_000_000_000;
    const rt = runtimeWithLeases([
      { id: 1, endsAtSec: now / 1000 + 600, leaseTimeSec: 3600 }, // 17% remaining → in T1
      { id: 2, endsAtSec: now / 1000 + 600, leaseTimeSec: 3600 },
      { id: 3, endsAtSec: now / 1000 + 600, leaseTimeSec: 3600 },
      { id: 4, endsAtSec: now / 1000 + 600, leaseTimeSec: 3600 },
      { id: 5, endsAtSec: now / 1000 + 600, leaseTimeSec: 3600 },
    ]);
    const plan = new DhcpLeaseMachine(alwaysZero).step(rt, now);
    // churn roll passes (rand 0 < 0.06) but every victim candidate is inside
    // its renewal window → no release
    expect(plan.releaseIds).toEqual([]);
    // ...and the leases were renewed instead
    expect(plan.renewIds.length).toBe(5);
  });

  test("a lease outside T1 can still be released by the churn roll", () => {
    const now = 1_000_000_000;
    const rt = runtimeWithLeases([
      { id: 1, endsAtSec: now / 1000 + 3500, leaseTimeSec: 3600 },
      { id: 2, endsAtSec: now / 1000 + 3500, leaseTimeSec: 3600 },
      { id: 3, endsAtSec: now / 1000 + 3500, leaseTimeSec: 3600 },
      { id: 4, endsAtSec: now / 1000 + 3500, leaseTimeSec: 3600 },
      { id: 5, endsAtSec: now / 1000 + 3500, leaseTimeSec: 3600 },
    ]);
    const plan = new DhcpLeaseMachine(alwaysZero).step(rt, now);
    // victim = leases[0] (rand 0 → index 0), outside the renewal window
    expect(plan.releaseIds).toContain(1);
    expect(plan.renewIds).toEqual([]);
  });
});

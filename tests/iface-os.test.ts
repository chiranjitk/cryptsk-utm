/**
 * Unit tests for the OS sync module (src/lib/network/iface-os.ts) — bun test.
 * Pins the drift diff and the generated iproute2 apply plan.
 */
import { describe, expect, test } from "bun:test";

import { buildApplyPlan, diffIfaceOs } from "@/lib/network/iface-os";
import type { IfaceRuleView } from "@/lib/network/iface-rules";
import type { RealInterface } from "@/lib/host/proc";

function view(overrides: Partial<IfaceRuleView> & { name: string }): IfaceRuleView {
  return {
    type: "physical",
    mode: "l3",
    role: "lan",
    mtu: 1500,
    enabled: true,
    config: {},
    ...overrides,
  };
}

function os(overrides: Partial<RealInterface> & { name: string }): RealInterface {
  return {
    operState: "up",
    mtu: 1500,
    mac: "aa:bb:cc:dd:ee:ff",
    ipv4: [],
    ipv6: [],
    carrier: true,
    isDefaultRoute: false,
    ...overrides,
  };
}

// ── drift ───────────────────────────────────────────────────────────────────

describe("diffIfaceOs", () => {
  test("missing OS interface → unmanaged", () => {
    const d = diffIfaceOs(view({ name: "vlan99", type: "vlan" }), undefined);
    expect(d.managed).toBe(false);
    expect(d.inSync).toBe(false);
  });

  test("matching mtu + admin → in sync", () => {
    const d = diffIfaceOs(view({ name: "eth0" }), os({ name: "eth0" }));
    expect(d.managed).toBe(true);
    expect(d.inSync).toBe(true);
    expect(d.drift).toHaveLength(0);
  });

  test("mtu mismatch reported", () => {
    const d = diffIfaceOs(view({ name: "eth0", mtu: 1400 }), os({ name: "eth0", mtu: 1500 }));
    expect(d.drift).toContainEqual({ field: "mtu", db: "1400", os: "1500" });
  });

  test("admin-down while console enabled reported", () => {
    const d = diffIfaceOs(view({ name: "eth0", enabled: true }), os({ name: "eth0", operState: "down" }));
    expect(d.drift).toContainEqual({ field: "admin", db: "enabled", os: "down" });
  });

  test("missing primary IP reported", () => {
    const d = diffIfaceOs(
      view({ name: "wan0", config: { ip: "10.1.1.5", cidrPrefix: 24 } }),
      os({ name: "wan0", ipv4: [] }),
    );
    expect(d.drift).toContainEqual({ field: "ip", db: "10.1.1.5/24", os: "none" });
  });

  test("extra unmanaged OS address reported", () => {
    const d = diffIfaceOs(
      view({ name: "wan0", config: { ip: "10.1.1.5", cidrPrefix: 24 } }),
      os({ name: "wan0", ipv4: ["10.1.1.5", "172.16.9.9"] }),
    );
    expect(d.drift).toContainEqual({ field: "ip-extra", db: "10.1.1.5", os: "172.16.9.9" });
  });
});

// ── apply plan ──────────────────────────────────────────────────────────────

describe("buildApplyPlan", () => {
  test("MTU mismatch emits ip link set", () => {
    const plan = buildApplyPlan(view({ name: "eth0", mtu: 1400 }), os({ name: "eth0", mtu: 1500 }));
    expect(plan.steps).toContainEqual({ cmd: "ip link set eth0 mtu 1400", summary: "MTU 1500 -> 1400" });
  });

  test("missing VLAN interface emits creation with parent + id", () => {
    const plan = buildApplyPlan(
      view({ name: "vlan99", type: "vlan", parentName: "ens32", vlanId: 99, mtu: 1500 }),
      undefined,
    );
    expect(plan.steps[0]).toEqual({
      cmd: "ip link add link ens32 name vlan99 type vlan id 99",
      summary: "create VLAN 99 on ens32",
    });
  });

  test("missing bridge emits bridge creation + STP + member enslaving", () => {
    const plan = buildApplyPlan(
      view({ name: "br0", type: "bridge", mtu: 1500, config: { members: ["eth0", "eth1"], stp: true, stpMode: "rstp", stpPriority: 4096, forwardDelay: 10 } }),
      undefined,
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("ip link add name br0 type bridge");
    expect(cmds).toContain("ip link set br0 type bridge stp_state 1");
    expect(cmds).toContain("ip link set br0 type bridge stp_protocol mstp");
    expect(cmds).toContain("ip link set br0 type bridge stp_priority 4096");
    expect(cmds).toContain("ip link set br0 type bridge forward_delay 10");
    expect(cmds).toContain("ip link set eth0 down");
    expect(cmds).toContain("ip link set eth0 master br0");
    expect(cmds).toContain("ip link set eth1 master br0");
  });

  test("bond creation includes mode + LACP rate + miimon", () => {
    const plan = buildApplyPlan(
      view({ name: "bond0", type: "bond", mtu: 1500, config: { members: ["eth0", "eth1"], mode: "802.3ad", lacpRate: "fast", miimon: 100 } }),
      undefined,
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("ip link add name bond0 type bond mode 802.3ad");
    expect(cmds).toContain("ip link set bond0 type bond lacp_rate fast");
    expect(cmds).toContain("ip link set bond0 type bond miimon 100");
  });

  test("L3 addressing emits addr replace + default route + secondary + mss", () => {
    const plan = buildApplyPlan(
      view({
        name: "wan0",
        mtu: 1476,
        mssClamp: 1436,
        config: {
          ip: "10.1.1.5",
          cidrPrefix: 24,
          gateway: "10.1.1.1",
          secondaryIps: [{ ip: "10.1.1.6", cidrPrefix: 24 }],
        },
      }),
      os({ name: "wan0", mtu: 1476 }),
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("ip addr replace 10.1.1.5/24 dev wan0");
    expect(cmds).toContain("ip addr replace 10.1.1.6/24 dev wan0");
    expect(cmds).toContain("ip route replace default via 10.1.1.1 dev wan0");
    expect(cmds).toContain("ip route change default dev wan0 advmss 1436");
  });

  test("unmanaged extra OS address gets removed for static interfaces", () => {
    const plan = buildApplyPlan(
      view({ name: "wan0", config: { ip: "10.1.1.5", cidrPrefix: 24 } }),
      os({ name: "wan0", ipv4: ["10.1.1.5", "192.0.2.77"] }),
    );
    expect(plan.steps.map((s) => s.cmd)).toContain("ip addr del 192.0.2.77 dev wan0");
  });

  test("disabled interface emits ip link down", () => {
    const plan = buildApplyPlan(view({ name: "eth0", enabled: false }), os({ name: "eth0", operState: "up" }));
    expect(plan.steps.map((s) => s.cmd)).toContain("ip link set eth0 down");
  });

  test("in-sync interface produces an empty plan", () => {
    const plan = buildApplyPlan(view({ name: "eth0" }), os({ name: "eth0" }));
    expect(plan.steps).toHaveLength(0);
  });

  test("missing physical cannot be created by the console (no steps)", () => {
    const plan = buildApplyPlan(view({ name: "eth9", type: "physical" }), undefined);
    expect(plan.steps.filter((s) => s.cmd.includes("add"))).toHaveLength(0);
  });
});

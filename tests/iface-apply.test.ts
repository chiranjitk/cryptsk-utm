/**
 * Unit tests for the guarded OS executor helpers — bun test.
 * Pins the protection parsing and the default-route ownership semantics that
 * keep the appliance from cutting its own management access.
 */
import { describe, expect, test } from "bun:test";

import { buildApplyPlan, buildDeletePlan } from "@/lib/network/iface-os";
import { protectedIfaces } from "@/lib/network/iface-apply";
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

const wanView = () =>
  view({
    name: "wan0",
    mssClamp: 1436,
    config: { ip: "10.1.1.5", cidrPrefix: 24, gateway: "10.1.1.1" },
  });

// ── default-route ownership ────────────────────────────────────────────────

describe("buildApplyPlan default-route ownership", () => {
  test("route info unknown (undefined) → legacy behavior, default emitted", () => {
    const cmds = buildApplyPlan(wanView(), os({ name: "wan0" })).steps.map((s) => s.cmd);
    expect(cmds).toContain("ip route replace default via 10.1.1.1 dev wan0");
    expect(cmds).toContain("ip route change default dev wan0 advmss 1436");
  });

  test("interface owns the default route → default + advmss emitted", () => {
    const cmds = buildApplyPlan(wanView(), os({ name: "wan0" }), "wan0").steps.map((s) => s.cmd);
    expect(cmds).toContain("ip route replace default via 10.1.1.1 dev wan0");
    expect(cmds).toContain("ip route change default dev wan0 advmss 1436");
  });

  test("another interface owns the default → gateway step suppressed (no hijack)", () => {
    const cmds = buildApplyPlan(wanView(), os({ name: "wan0" }), "ens32").steps.map((s) => s.cmd);
    expect(cmds).not.toContain("ip route replace default via 10.1.1.1 dev wan0");
    expect(cmds).not.toContain("ip route change default dev wan0 advmss 1436");
    // addressing itself still converges
    expect(cmds).toContain("ip addr replace 10.1.1.5/24 dev wan0");
  });

  test("no default route on host (null) → gateway creates one, advmss skipped", () => {
    const cmds = buildApplyPlan(wanView(), os({ name: "wan0" }), null).steps.map((s) => s.cmd);
    expect(cmds).toContain("ip route replace default via 10.1.1.1 dev wan0");
    expect(cmds).not.toContain("ip route change default dev wan0 advmss 1436");
  });
});

// ── creation admin steps ───────────────────────────────────────────────────

describe("buildApplyPlan creation admin handling", () => {
  test("new enabled logical interface gets an explicit up", () => {
    const cmds = buildApplyPlan(
      view({ name: "vlan99", type: "vlan", parentName: "ens32", vlanId: 99 }),
      undefined,
    ).steps.map((s) => s.cmd);
    expect(cmds).toContain("ip link set vlan99 up");
  });

  test("new disabled logical interface is created admin-down", () => {
    const cmds = buildApplyPlan(
      view({ name: "vlan99", type: "vlan", parentName: "ens32", vlanId: 99, enabled: false }),
      undefined,
    ).steps.map((s) => s.cmd);
    expect(cmds).toContain("ip link set vlan99 down");
    expect(cmds).not.toContain("ip link set vlan99 up");
  });
});

// ── teardown plan ──────────────────────────────────────────────────────────

describe("buildDeletePlan", () => {
  test("logical interface present on host → ip link del", () => {
    const plan = buildDeletePlan(view({ name: "vlan99", type: "vlan" }), os({ name: "vlan99" }));
    expect(plan.steps).toEqual([{ cmd: "ip link del vlan99", summary: "remove interface from host" }]);
  });

  test("logical interface not on host → no steps", () => {
    const plan = buildDeletePlan(view({ name: "vlan99", type: "vlan" }), undefined);
    expect(plan.steps).toHaveLength(0);
  });

  test("physical interface → no teardown (kernel owns the port)", () => {
    const plan = buildDeletePlan(view({ name: "ens34", type: "physical" }), os({ name: "ens34" }));
    expect(plan.steps).toHaveLength(0);
  });
});

// ── protection list parsing ────────────────────────────────────────────────

describe("protectedIfaces", () => {
  test("parses CONSOLE_OS_PROTECT with whitespace tolerance, defaults to lo", () => {
    const prev = process.env.CONSOLE_OS_PROTECT;
    try {
      delete process.env.CONSOLE_OS_PROTECT;
      expect(protectedIfaces()).toEqual(["lo"]);
      process.env.CONSOLE_OS_PROTECT = "lo, ens32 , br-lan,";
      expect(protectedIfaces()).toEqual(["lo", "ens32", "br-lan"]);
      process.env.CONSOLE_OS_PROTECT = "";
      expect(protectedIfaces()).toEqual(["lo"]);
    } finally {
      if (prev === undefined) delete process.env.CONSOLE_OS_PROTECT;
      else process.env.CONSOLE_OS_PROTECT = prev;
    }
  });
});

// ── L2 conversion strips kernel addressing (BR-L2-L3 convergence) ──────────

describe("L2 conversion address handling", () => {
  test("l2 port with kernel IPv4 emits ip addr del steps", () => {
    const plan = buildApplyPlan(
      view({ name: "ens34", mode: "l2" }),
      os({ name: "ens34", ipv4: ["20.20.30.2", "20.20.30.3"] }),
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("ip addr del 20.20.30.2 dev ens34");
    expect(cmds).toContain("ip addr del 20.20.30.3 dev ens34");
    expect(cmds).not.toContain("ip addr replace 20.20.30.2/24 dev ens34");
  });

  test("l2 port with clean kernel emits no addressing steps", () => {
    const plan = buildApplyPlan(view({ name: "ens34", mode: "l2" }), os({ name: "ens34" }));
    expect(plan.steps.filter((s) => s.cmd.startsWith("ip addr"))).toHaveLength(0);
  });

  test("l2 port with kernel IPv4 reports ip-extra drift", () => {
    const { diffIfaceOs } = require("@/lib/network/iface-os") as typeof import("@/lib/network/iface-os");
    const d = diffIfaceOs(view({ name: "ens34", mode: "l2" }), os({ name: "ens34", ipv4: ["20.20.30.2"] }));
    expect(d.inSync).toBe(false);
    expect(d.drift).toContainEqual({ field: "ip-extra", db: "(l2 — no addressing)", os: "20.20.30.2" });
  });
});

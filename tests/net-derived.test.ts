import { describe, it, expect } from "vitest";
import { parseLldpKeyValue } from "@/lib/network/lldp-ctl";
import { parseBridgeFdb } from "@/lib/network/bridge-fdb";
import { parseTcFilterShow, mirrorKernelState, buildMirrorApplyPlan, buildMirrorTeardownPlan } from "@/lib/network/mirror-os";

describe("parseLldpKeyValue (lldpctl -f keyvalue)", () => {
  const sample = `
================================================================================
lldp.eth0.chassis.name=core-sw-01
lldp.eth0.chassis.id.MAC=00:11:22:33:44:55
lldp.eth0.chassis.cap.available=Router,Switch
lldp.eth0.port.ifname=Gi0/1
lldp.eth0.port.desc=Uplink to core
lldp.eth0.port.ttl=120
lldp.eth1.chassis.id.local=switch-local-42
lldp.eth1.port.ifname=eth3
lldp.eth2.port.ifname=orphan-port
`;

  it("groups neighbors per local interface", () => {
    const rows = parseLldpKeyValue(sample);
    // eth2 carries neither chassis id nor system name → unusable, dropped
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.localIface).sort()).toEqual(["eth0", "eth1"]);
  });

  it("extracts chassis id, system name, port and capabilities", () => {
    const [n] = parseLldpKeyValue(sample);
    expect(n.localIface).toBe("eth0");
    expect(n.chassisId).toBe("00:11:22:33:44:55");
    expect(n.systemName).toBe("core-sw-01");
    expect(n.portId).toBe("Gi0/1");
    expect(n.portDesc).toBe("Uplink to core");
    expect(n.capabilities).toEqual(["Router", "Switch"]);
  });

  it("falls back to (unnamed) when chassis.name is absent but id exists", () => {
    const rows = parseLldpKeyValue(sample);
    const eth1 = rows.find((r) => r.localIface === "eth1");
    expect(eth1?.chassisId).toBe("switch-local-42");
    expect(eth1?.systemName).toBe("(unnamed)");
  });

  it("keeps entries with only port info (chassis-less)", () => {
    const rows = parseLldpKeyValue(sample);
    // eth2 has neither chassis.id nor chassis.name → dropped as unusable
    expect(rows.find((r) => r.localIface === "eth2")).toBeUndefined();
  });

  it("ignores non-lldp lines and lines without =", () => {
    const rows = parseLldpKeyValue("garbage\nlldp.eth0.chassis.name=x\n====\nnonsense");
    expect(rows).toHaveLength(1);
    expect(rows[0].systemName).toBe("x");
  });
});

describe("parseBridgeFdb (bridge fdb show)", () => {
  const sample = `
33:33:00:00:00:01 dev ens32 vlan 0 self permanent
00:11:22:33:44:55 dev ens34 vlan 1 master br-lan dynamic
aa:bb:cc:dd:ee:ff dev eth5 vid 10 master br-srv static
11:22:33:44:55:66 dev eth6 vlan 0 self permanent
`;

  it("keeps only master-backed FDB entries", () => {
    const rows = parseBridgeFdb(sample);
    expect(rows).toHaveLength(2);
  });

  it("maps vlan 0 (untagged) to 1 and parses vid syntax", () => {
    const rows = parseBridgeFdb(sample);
    expect(rows.find((r) => r.mac === "00:11:22:33:44:55")).toMatchObject({ vlan: 1, iface: "ens34", type: "dynamic" });
    expect(rows.find((r) => r.mac === "aa:bb:cc:dd:ee:ff")).toMatchObject({ vlan: 10, iface: "eth5", type: "static" });
  });

  it("drops lines without a device or with non-MAC heads", () => {
    const rows = parseBridgeFdb("not-a-mac dev eth0 master br0\nff:ee:dd master-only-no-dev");
    expect(rows).toHaveLength(0);
  });
});

describe("mirror-os planner + kernel state", () => {
  const mirror = { id: 1, name: "span-lan", srcIface: "lan0", dstIface: "ens34", direction: "both" as const, enabled: true };

  it("apply plan installs clsact + both direction filters", () => {
    const plan = buildMirrorApplyPlan(mirror);
    expect(plan.steps.map((s) => s.cmd)).toEqual([
      "tc qdisc replace dev lan0 clsact",
      "tc filter del dev lan0 ingress",
      "tc filter add dev lan0 ingress protocol all pref 1 matchall action mirred egress mirror dev ens34",
      "tc filter del dev lan0 egress",
      "tc filter add dev lan0 egress protocol all pref 1 matchall action mirred egress mirror dev ens34",
    ]);
    expect(plan.steps[1].soft).toBe(true);
    expect(plan.steps[2].soft).toBeUndefined();
  });

  it("teardown clears only the configured direction", () => {
    const plan = buildMirrorTeardownPlan({ ...mirror, direction: "ingress" });
    expect(plan.steps.map((s) => s.cmd)).toEqual(["tc filter del dev lan0 ingress"]);
    expect(plan.steps[0].soft).toBe(true);
  });

  it("disabled mirrors produce a teardown-only plan", () => {
    const plan = buildMirrorApplyPlan({ ...mirror, enabled: false });
    expect(plan.dstIface).toBeNull();
    expect(plan.steps.every((s) => s.cmd.includes("filter del"))).toBe(true);
  });

  it("parseTcFilterShow reads mirred targets from tc filter show output", () => {
    const ingress = parseTcFilterShow(
      "filter protocol all pref 1 matchall chain 0 handle 0x1 \n  action order 1: mirred (Egress Mirror to device ens34) pipe",
      "ingress",
    );
    expect(ingress).toEqual([{ block: "ingress", pref: 1, mirrorDev: "ens34" }]);

    const egress = parseTcFilterShow(
      "filter protocol all pref 2 matchall chain 0 handle 0x1\n  action order 1: mirred egress mirror dev ens34 pipe\n  action order 2: mirred egress mirror dev wrong-if pipe",
      "egress",
    );
    expect(egress).toEqual([{ block: "egress", pref: 2, mirrorDev: "ens34" }]);
  });

  it("kernel state reflects installed / missing / disabled / unknown", () => {
    const kernel = [
      { block: "ingress" as const, pref: 1, mirrorDev: "ens34" },
      { block: "egress" as const, pref: 1, mirrorDev: "ens34" },
    ];
    expect(mirrorKernelState(mirror, kernel)).toBe("in-kernel");
    expect(mirrorKernelState({ ...mirror, direction: "egress" }, [{ block: "ingress", pref: 1, mirrorDev: "ens34" }])).toBe("missing");
    expect(mirrorKernelState({ ...mirror, enabled: false }, kernel)).toBe("disabled");
    expect(mirrorKernelState(mirror, null)).toBeNull();
  });
});

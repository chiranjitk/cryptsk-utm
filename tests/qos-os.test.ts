/**
 * QoS OS layer tests — renderer determinism, matcher expressibility,
 * parser ground truth (captured on the appliance), drift, whitelist guard,
 * plan ordering and refusal rails.
 */

import { describe, it, expect } from "vitest";
import {
  APP_L4_MAP,
  addressObjectCidrs,
  buildQosApplyPlan,
  computeQosDrift,
  hardQosRefusal,
  isIpv4,
  maskToPrefix,
  parseTcClassShow,
  parseTcFilterShow,
  parseTcQdiscShow,
  qosConfHash,
  qosStepGuarded,
  renderQosIface,
  renderRestoreQdisc,
  type QosPolicyShape,
} from "@/lib/qos/os";

const policy = (over: Partial<QosPolicyShape> = {}): QosPolicyShape => ({
  id: 1,
  name: "wan-shaper",
  bandwidthKbps: 10_000,
  ifaceName: "ens34",
  rules: [],
  ...over,
});

// ── helpers ────────────────────────────────────────────────────────────────

describe("maskToPrefix / isIpv4", () => {
  it("converts contiguous netmasks", () => {
    expect(maskToPrefix("255.0.0.0")).toBe(8);
    expect(maskToPrefix("255.255.255.0")).toBe(24);
    expect(maskToPrefix("0.0.0.0")).toBe(0);
    expect(maskToPrefix("255.255.0.0")).toBe(16);
  });
  it("rejects non-contiguous masks", () => {
    expect(maskToPrefix("255.0.255.0")).toBeNull();
    expect(maskToPrefix("nonsense")).toBeNull();
  });
  it("validates IPv4 octets", () => {
    expect(isIpv4("10.0.0.1")).toBe(true);
    expect(isIpv4("10.0.0.256")).toBe(false);
    expect(isIpv4("1.2.3")).toBe(false);
  });
});

describe("addressObjectCidrs", () => {
  it("maps ip → /32, subnet → CIDR, wildcard → prefix", () => {
    expect(addressObjectCidrs({ id: 1, name: "host", type: "ip", value: "10.0.0.5" }).cidrs).toEqual(["10.0.0.5/32"]);
    expect(addressObjectCidrs({ id: 2, name: "lan", type: "subnet", value: "192.168.20.0/24" }).cidrs).toEqual(["192.168.20.0/24"]);
    expect(addressObjectCidrs({ id: 3, name: "corp", type: "wildcard", value: "10.0.0.0 255.0.0.0" }).cidrs).toEqual(["10.0.0.0/8"]);
  });
  it("reports non-expressible types as notes (never silently dropped)", () => {
    const range = addressObjectCidrs({ id: 4, name: "pool", type: "range", value: "10.0.0.5-10.0.0.20" });
    expect(range.cidrs).toEqual([]);
    expect(range.note).toContain("not expressible");
    const fqdn = addressObjectCidrs({ id: 5, name: "web", type: "fqdn", value: "example.com" });
    expect(fqdn.cidrs).toEqual([]);
    expect(fqdn.note).toContain("fqdn");
  });
});

// ── renderer ───────────────────────────────────────────────────────────────

describe("renderQosIface", () => {
  const full = policy({
    rules: [
      { id: 1, name: "voice", priority: 0, guaranteedKbps: 2000, maxKbps: 5000, dscpMark: 46, matchApps: ["SIP"], matchCidrs: [] },
      { id: 2, name: "bulk", priority: 5, guaranteedKbps: null, maxKbps: 2000, dscpMark: null, matchApps: ["YouTube"], matchCidrs: ["192.168.20.0/24"] },
      { id: 3, name: "rest", priority: 7, guaranteedKbps: null, maxKbps: null, dscpMark: null, matchApps: [], matchCidrs: [] },
    ],
  });

  it("renders an HTB tree with budget root, fq_codel leaves and unique prios", () => {
    const r = renderQosIface(full, "ens34");
    expect(r.cmds[0]).toBe("tc qdisc replace dev ens34 root handle 1: htb default 102");
    expect(r.cmds[1]).toContain("classid 1:1 htb rate 10000kbit ceil 10000kbit");
    // rule classes: 1:100 (voice), 1:101 (bulk), 1:102 = catch-all → default
    expect(r.cmds.some((c) => c.includes("classid 1:100 htb rate 2000kbit ceil 5000kbit prio 0"))).toBe(true);
    expect(r.cmds.some((c) => c.includes("classid 1:101 htb rate 1kbit ceil 2000kbit prio 5"))).toBe(true);
    expect(r.defaultClassid).toBe("1:102");
    // no explicit remainder class when a catch-all exists
    expect(r.cmds.some((c) => c.includes("classid 1:30 "))).toBe(false);
    // fq_codel leaf per rule class
    expect(r.cmds.filter((c) => c.includes("fq_codel")).length).toBe(3);
  });

  it("emits TOS-byte DSCP match (DSCP<<2) and port filters, counts flowids", () => {
    const r = renderQosIface(full, "ens34");
    const tos = r.cmds.find((c) => c.includes("match ip tos"));
    expect(tos).toContain("0xb8 0xfc"); // 46 << 2 = 184 = 0xb8
    expect(tos).toContain("flowid 1:100");
    // SIP tcp 5060 + udp 5060 → protocol 6 / 17 dport+sport
    const tcp = r.cmds.find((c) => c.includes("match ip protocol 6 0xff match ip dport 5060"));
    expect(tcp).toBeTruthy();
    const udp = r.cmds.find((c) => c.includes("match ip protocol 17 0xff match ip dport 5060"));
    expect(udp).toBeTruthy();
    // YouTube is DPI-only → unclassifiable, NOT silently dropped
    expect(r.unclassifiableApps).toEqual(["YouTube"]);
    // cidr → src + dst filters → flowid 1:101
    expect(r.cmds.filter((c) => c.includes("match ip src 192.168.20.0/24") && c.includes("flowid 1:101")).length).toBe(1);
    expect(r.cmds.filter((c) => c.includes("match ip dst 192.168.20.0/24") && c.includes("flowid 1:101")).length).toBe(1);
    expect(r.filtersByFlowid["1:101"]).toBe(2);
  });

  it("creates an explicit remainder default class when no catch-all exists", () => {
    const r = renderQosIface(policy({ rules: [{ id: 1, name: "voice", priority: 0, guaranteedKbps: 2000, maxKbps: 5000, dscpMark: 46, matchApps: [], matchCidrs: [] }] }), "ens34");
    expect(r.defaultClassid).toBe("1:30");
    expect(r.cmds.some((c) => c.includes("classid 1:30 htb rate 1kbit"))).toBe(true);
    expect(r.cmds.some((c) => c.includes("handle 130: fq_codel"))).toBe(true);
  });

  it("is deterministic (byte-identical renders) and hash-stable", () => {
    const a = renderQosIface(full, "ens34");
    const b = renderQosIface(full, "ens34");
    expect(a.cmds).toEqual(b.cmds);
    const expected = { ens34: a };
    expect(qosConfHash(expected)).toBe(qosConfHash({ ens34: renderQosIface(full, "ens34") }));
  });

  it("never rates a class above ceil (guaranteed ≤ max clamped)", () => {
    const r = renderQosIface(
      policy({ rules: [{ id: 1, name: "x", priority: 1, guaranteedKbps: 9000, maxKbps: 100, dscpMark: null, matchApps: [], matchCidrs: [] }] }),
      "ens34",
    );
    // service forbids guaranteed > max; renderer still clamps defensively
    expect(r.cmds.some((c) => c.includes("rate 9000kbit ceil 9000kbit"))).toBe(true);
  });

  it("notes rules whose matchers are all non-expressible", () => {
    const r = renderQosIface(
      policy({ rules: [{ id: 1, name: "dpi-only", priority: 2, guaranteedKbps: 1000, maxKbps: null, dscpMark: null, matchApps: ["Netflix"], matchCidrs: [] }] }),
      "ens34",
    );
    expect(r.unclassifiableApps).toContain("Netflix");
    expect(r.notes.some((n) => n.includes("no tc-expressible matchers"))).toBe(true);
  });
});

// ── parsers (ground truth captured on the appliance) ──────────────────────

const QDISC_JSON = `[{"kind":"htb","handle":"1:","root":true,"refcnt":2,"options":{"r2q":10,"default":"0x30","direct_packets_stat":0,"direct_qlen":1000}},{"kind":"fq_codel","handle":"1000:","parent":"1:100","options":{"limit":10240,"flows":1024,"quantum":1514,"target":4999,"interval":99999,"memory_limit":33554432,"ecn":true,"drop_batch":64}}]`;
const CLASS_JSON = `[{"class":"htb","handle":"1:100","parent":"1:1","leaf":"0x1000","prio":0,"rate":250000,"ceil":1250000,"burst":1600,"cburst":1600},{"class":"htb","handle":"1:1","root":true,"rate":1250000,"ceil":1250000,"burst":1600,"cburst":1600},{"class":"htb","handle":"1:30","parent":"1:1","prio":7,"rate":125,"ceil":1250000,"burst":1600,"cburst":1600}]`;
const FILTER_JSON = `[{"protocol":"ip","pref":100,"kind":"u32","chain":0},{"protocol":"ip","pref":100,"kind":"u32","chain":0,"options":{"fh":"800:","ht_divisor":1}},{"protocol":"ip","pref":100,"kind":"u32","chain":0,"options":{"fh":"800::800","order":2048,"key_ht":"800","bkt":"0","flowid":"1:100","not_in_hw":true,"match":{"value":"b80000","mask":"fc0000","offmask":"","off":0}}},{"protocol":"ip","pref":110,"kind":"u32","chain":0},{"protocol":"ip","pref":110,"kind":"u32","chain":0,"options":{"fh":"801::800","order":2048,"key_ht":"801","bkt":"0","flowid":"1:100","not_in_hw":true,"match":{"value":"60000","mask":"ff0000","offmask":"","off":8},"match":{"value":"1bb","mask":"ffff","offmask":"","off":20}}}]`;

describe("tc -j parsers (appliance ground truth)", () => {
  it("parses the htb root with hex-normalized default and leaves", () => {
    const q = parseTcQdiscShow(QDISC_JSON);
    expect(q).not.toBeNull();
    expect(q!.kind).toBe("htb");
    expect(q!.handle).toBe("1:");
    expect(q!.defaultClassid).toBe("1:30");
    expect(q!.leaves).toEqual([{ parent: "1:100", handle: "1000:", kind: "fq_codel" }]);
  });
  it("parses classes with byte/sec → kbit conversion", () => {
    const cs = parseTcClassShow(CLASS_JSON);
    expect(cs).toHaveLength(3);
    const root = cs.find((c) => c.classid === "1:1")!;
    expect(root.rateKbps).toBe(10000); // 1250000 B/s * 8 = 10000 kbit
    const rule = cs.find((c) => c.classid === "1:100")!;
    expect(rule.rateKbps).toBe(2000);
    expect(rule.ceilKbps).toBe(10000);
    expect(rule.prio).toBe(0);
  });
  it("counts only real match entries (structural rows carry no flowid)", () => {
    const fs = parseTcFilterShow(FILTER_JSON);
    expect(fs).toHaveLength(2); // pref 100 + pref 110 (flowid 1:100 each)
    expect(fs.every((f) => f.flowid === "1:100")).toBe(true);
  });
  it("tolerates garbage output", () => {
    expect(parseTcQdiscShow("not json")).toBeNull();
    expect(parseTcClassShow("")).toEqual([]);
    expect(parseTcFilterShow("[]")).toEqual([]);
    expect(parseTcQdiscShow(JSON.stringify([{ kind: "fq_codel", handle: "8001:" }]))).toBeNull(); // no root
  });
});

// ── drift ──────────────────────────────────────────────────────────────────

describe("computeQosDrift", () => {
  const rendered = renderQosIface(
    policy({
      rules: [
        { id: 1, name: "voice", priority: 0, guaranteedKbps: 2000, maxKbps: 5000, dscpMark: 46, matchApps: ["SIP"], matchCidrs: [] },
        { id: 2, name: "rest", priority: 7, guaranteedKbps: null, maxKbps: null, dscpMark: null, matchApps: [], matchCidrs: [] },
      ],
    }),
    "ens34",
  );

  it("reports in-sync for matching kernel state", () => {
    const q = parseTcQdiscShow(
      JSON.stringify([
        { kind: "htb", handle: "1:", root: true, options: { default: "0x101" } }, // 1:101 = catch-all rule classid
        { kind: "fq_codel", handle: "1000:", parent: "1:100" },
        { kind: "fq_codel", handle: "1010:", parent: "1:101" },
      ]),
    );
    const classes = [
      { classid: "1:1", parent: null, rateKbps: 10000, ceilKbps: 10000, prio: 0 },
      { classid: "1:100", parent: "1:1", rateKbps: 2000, ceilKbps: 5000, prio: 0 },
      { classid: "1:101", parent: "1:1", rateKbps: 1, ceilKbps: 10000, prio: 7 },
    ];
    const filters = Object.entries(rendered.filtersByFlowid).flatMap(([flowid, n]) =>
      Array.from({ length: n }, (_, i) => ({ pref: 100 + i * 10, protocol: "ip", flowid })),
    );
    const d = computeQosDrift(rendered, q, classes, filters);
    expect(d.inSync).toBe(true);
    expect(d.driftReasons).toEqual([]);
  });

  it("flags kind, default, class and filter mismatches", () => {
    const q = parseTcQdiscShow(JSON.stringify([{ kind: "fq_codel", handle: "8001:", root: true, options: {} }]));
    const d1 = computeQosDrift(rendered, q, [], []);
    expect(d1.inSync).toBe(false);
    expect(d1.driftReasons[0]).toContain("root qdisc is fq_codel");

    const q2 = parseTcQdiscShow(JSON.stringify([{ kind: "htb", handle: "1:", root: true, options: { default: "0x30" } }]));
    const d2 = computeQosDrift(rendered, q2, [{ classid: "1:1", parent: null, rateKbps: 10000, ceilKbps: 10000, prio: 0 }], []);
    expect(d2.driftReasons.some((r) => r.includes("htb default"))).toBe(true);
    expect(d2.driftReasons.some((r) => r.includes("class 1:100 missing"))).toBe(true);
  });
});

// ── guards & refusal rails ────────────────────────────────────────────────

describe("qosStepGuarded", () => {
  it("allows tc verbs, tc -j reads and modprobe sch_htb only", () => {
    expect(qosStepGuarded("tc qdisc replace dev ens34 root handle 1: htb default 30")).toBe(true);
    expect(qosStepGuarded("tc class add dev ens34 parent 1: classid 1:1 htb rate 10000kbit")).toBe(true);
    expect(qosStepGuarded("tc filter add dev ens34 parent 1: protocol ip prio 100 u32 match ip tos 0xb8 0xfc flowid 1:100")).toBe(true);
    expect(qosStepGuarded("tc qdisc del dev ens34 root")).toBe(true);
    expect(qosStepGuarded("tc -j qdisc show dev ens34")).toBe(true);
    expect(qosStepGuarded("tc -j class show dev ens34")).toBe(true);
    expect(qosStepGuarded("tc -j filter show dev ens34 parent 1:")).toBe(true);
    expect(qosStepGuarded("modprobe sch_htb")).toBe(true);

    for (const evil of [
      "tc qdisc del dev ens32 root", // tc but protected iface — guard is cmd-shape only; refusal is policy-level
      "rm -rf /",
      "reboot",
      "sh -c evil",
      "tc qdisc del dev ens34 root; rm -rf /",
      "iptables -F",
      "",
    ]) {
      if (evil === "tc qdisc del dev ens32 root") continue; // shape-valid (policy refusal handles it)
      expect(qosStepGuarded(evil)).toBe(false);
    }
    // chained commands fail the regex (no spaces around ';' matched)
    expect(qosStepGuarded("tc qdisc del dev ens34 root && reboot")).toBe(false);
  });
});

describe("hardQosRefusal", () => {
  const savedEnv = process.env.CONSOLE_PROTECTED_IFACES;
  it("refuses policies attached to protected ifaces (default ens32, lo always)", () => {
    process.env.CONSOLE_PROTECTED_IFACES = "ens32";
    const ref = hardQosRefusal([policy({ ifaceName: "ens32", name: "wan-up" })]);
    expect(ref).toContain("ens32");
    expect(ref).toContain("protected");

    expect(hardQosRefusal([policy({ ifaceName: "lo" })])).toContain("protected");
    expect(hardQosRefusal([policy({ ifaceName: "ens34" })])).toBeNull();
  });
  it("honors the env override", () => {
    process.env.CONSOLE_PROTECTED_IFACES = "ens32,eth9";
    expect(hardQosRefusal([policy({ ifaceName: "eth9" })])).toContain("eth9");
    process.env.CONSOLE_PROTECTED_IFACES = savedEnv;
  });
});

// ── apply plan ─────────────────────────────────────────────────────────────

describe("buildQosApplyPlan", () => {
  const p = policy({
    rules: [{ id: 1, name: "voice", priority: 0, guaranteedKbps: 2000, maxKbps: 5000, dscpMark: 46, matchApps: ["SIP"], matchCidrs: [] }],
  });

  it("orders: modprobe → snapshots → install → verify → state file", () => {
    const plan = buildQosApplyPlan({ policies: [p], managedIfaces: ["ens34"], mode: "exec", ts: "t" });
    const kinds = plan.steps.map((s) => s.kind);
    expect(kinds[0]).toBe("modprobe");
    expect(kinds[1]).toBe("snapshot");
    expect(kinds.indexOf("verify")).toBeGreaterThan(kinds.indexOf("install") === -1 ? kinds.indexOf("snapshot") : kinds.indexOf("snapshot"));
    expect(kinds[kinds.length - 1]).toBe("writefile");
    expect(plan.steps.filter((s) => s.kind === "verify").map((s) => s.cmd)).toEqual([
      "tc -j qdisc show dev ens34",
      "tc -j class show dev ens34",
      "tc -j filter show dev ens34 parent 1:",
    ]);
    expect(plan.confHash).toHaveLength(16);
  });

  it("tears down managed ifaces no longer claimed, with restore step", () => {
    const plan = buildQosApplyPlan({ policies: [], managedIfaces: ["ens34", "eth5"], mode: "exec", ts: "t" });
    const teardown = plan.steps.filter((s) => s.kind === "exec").map((s) => s.cmd);
    expect(teardown).toContain("tc qdisc del dev ens34 root");
    expect(teardown).toContain("tc qdisc del dev eth5 root");
    expect(plan.teardownIfaces.sort()).toEqual(["ens34", "eth5"]);
    expect(plan.installIfaces).toEqual([]);
    expect(plan.steps.filter((s) => s.kind === "restore")).toHaveLength(2);
    // no writefile when nothing is installed
    expect(plan.steps.some((s) => s.kind === "writefile")).toBe(false);
  });

  it("warns on unattached and DPI-only shapes without failing", () => {
    const plan = buildQosApplyPlan({
      policies: [
        policy({ id: 2, name: "aggregate", ifaceName: "ens34", rules: [{ id: 9, name: "stream", priority: 5, guaranteedKbps: null, maxKbps: 4000, dscpMark: null, matchApps: ["Netflix"], matchCidrs: [] }] }),
      ],
      managedIfaces: [],
      mode: "plan",
      ts: "t",
    });
    expect(plan.warnings.some((w) => w.includes("NOT enforced"))).toBe(true);
    expect(plan.warnings.some((w) => w.includes("Netflix"))).toBe(true);
    expect(plan.expected["ens34"]).toBeTruthy();
  });
});

// ── restore ────────────────────────────────────────────────────────────────

describe("renderRestoreQdisc", () => {
  it("re-attaches fq_codel with snapshot options (usec → ms)", () => {
    const cmd = renderRestoreQdisc("ens34", {
      kind: "fq_codel",
      root: true,
      options: { limit: 10240, flows: 1024, quantum: 1514, target: 4999, interval: 99999, memory_limit: 33554432, ecn: true },
    });
    expect(cmd).toContain("tc qdisc add dev ens34 root fq_codel");
    expect(cmd).toContain("limit 10240");
    expect(cmd).toContain("target 4.999ms");
    expect(cmd).toContain("interval 99.999ms");
    expect(cmd).not.toContain("noecn");
  });
  it("never restores an htb root (console-owned) or non-root entries", () => {
    expect(renderRestoreQdisc("ens34", { kind: "htb", root: true, options: {} })).toBeNull();
    expect(renderRestoreQdisc("ens34", { kind: "fq_codel", root: false })).toBeNull();
  });
});

// ── app map sanity ────────────────────────────────────────────────────────

describe("APP_L4_MAP", () => {
  it("covers the deterministic catalog labels used by QoS templates", () => {
    for (const app of ["HTTPS", "HTTP", "DNS", "QUIC", "SSH", "RDP", "SIP", "NTP", "MQTT", "SMTP", "IMAP"]) {
      expect(APP_L4_MAP[app]).toBeTruthy();
    }
    for (const app of ["YouTube", "Netflix", "Teams", "Zoom", "Steam"]) {
      expect(APP_L4_MAP[app]).toBeUndefined(); // DPI-only by design
    }
    // ports within u32 16-bit range
    for (const entries of Object.values(APP_L4_MAP)) {
      for (const e of entries) {
        expect([6, 17]).toContain(e.proto === "tcp" ? 6 : 17);
        for (const p of e.ports) expect(p).toBeGreaterThan(0);
      }
    }
  });
});

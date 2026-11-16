/**
 * IPv6 OS layer — unit tests for the pure core of lib/ipv6/os.ts (kea6 +
 * radvd + nat66 renderers, plan builder, step guard, drift) plus executor
 * ordering tests against STUBBED appliance binaries in a tmp root (kea6
 * render → validate → install → service → sysctl → state.json LAST; failure
 * → rollback restores confs + service pre-states).
 *
 * The dhcp/os.ts consistency check at the bottom pins the IMPL-6 contract:
 * v6 subnets in the DHCPv4 module stay "unsupported" for kea-dhcp4 with the
 * updated "handled by ipv6 module (kea-dhcp6)" note.
 */

import fs from "node:fs";
import path from "node:path";
import { beforeAll, afterEach, describe, expect, it, vi } from "vitest";
import {
  buildIpv6ApplyPlan,
  computeIpv6Drift,
  extractNat66TableBlock,
  fnv1aHash,
  ipv6BigIntToAddr,
  ipv6StepGuarded,
  ipv6SubnetCidr,
  liveKea6ManagedIds,
  MANAGED_ID_BASE,
  nat66BlocksInSync,
  nat66Statements,
  parseKea6Conf,
  radvdPrefix64,
  renderKea6Conf,
  renderNat66Nft,
  renderRadvdConf,
  sysctlNeededFor,
  validateIpv6Inputs,
  KEA6_CONF_FILE,
  KEA6_STAGE_FILE,
  MANAGED_HEADER,
  type Dhcpv6ServerInput,
  type Ipv6OsFacts,
  type Ipv6OsInput,
  type Nat66RuleInput,
} from "@/lib/ipv6/os";

// ── fixtures ────────────────────────────────────────────────────────────────

const settings = (over: Partial<Ipv6OsInput["settings"]> = {}): Ipv6OsInput["settings"] => ({
  enabled: true,
  dhcpv6Enabled: true,
  slaacEnabled: true,
  rdnssEnabled: true,
  pdWanInterface: "wan0",
  pdPrefixLength: 56,
  raMode: "slaac_dhcpv6",
  ...over,
});

const server = (over: Partial<Dhcpv6ServerInput> = {}): Dhcpv6ServerInput => ({
  id: 7,
  interfaceName: "ens34",
  poolStart: "fd00:60::100",
  poolEnd: "fd00:60::1ff",
  prefixLength: 64,
  preferredLifetimeSec: 3600,
  validLifetimeSec: 7200,
  dnsServers: ["2001:db8:1::1"],
  domainSearch: "lab.example",
  enabled: true,
  ...over,
});

const natRule = (over: Partial<Nat66RuleInput> = {}): Nat66RuleInput => ({
  id: 3,
  name: "npt-lab",
  type: "nptv6",
  sourcePrefix: "2001:db8:a::/64",
  translatedPrefix: "2001:db8:b::/64",
  destPort: null,
  interfaceName: "wan0",
  enabled: true,
  ...over,
});

const input = (over: Partial<Ipv6OsInput> = {}): Ipv6OsInput => ({
  settings: settings(),
  servers: [server()],
  nat66: [natRule()],
  ...over,
});

const facts = (over: Partial<Ipv6OsFacts> = {}): Ipv6OsFacts => ({
  keaAvailable: true,
  radvdAvailable: true,
  nftAvailable: true,
  keaVersion: "2.6.3",
  radvdVersion: "2.20",
  keaRunning: false,
  radvdRunning: false,
  keaConfPresent: false,
  keaConfText: null,
  radvdConfPresent: false,
  radvdConfText: null,
  nat66EtcPresent: false,
  liveRuleset: null,
  rulesetAvailable: true,
  sysctlForwarding: null,
  udp547Bound: null,
  ...over,
});

// ── IPv6 math ───────────────────────────────────────────────────────────────

describe("ipv6 math helpers", () => {
  it("masks host bits and compresses the result", () => {
    expect(ipv6SubnetCidr("fd00:60::100", 64)).toBe("fd00:60::/64");
    expect(ipv6SubnetCidr("fd00:60::1ff", 56)).toBe("fd00:60::/56");
    expect(ipv6SubnetCidr("fd00:60::1ff", 48)).toBe("fd00:60::/48");
    expect(ipv6SubnetCidr("fd00:60::1ff", 32)).toBe("fd00:60::/32");
    expect(ipv6SubnetCidr("fd00:60::1ff", 16)).toBe("fd00::/16");
    expect(ipv6SubnetCidr("2001:db8:1::1", 128)).toBe("2001:db8:1::1/128");
    expect(ipv6SubnetCidr("not-an-ip", 64)).toBeNull();
  });

  it("renders canonical compressed addresses", () => {
    expect(ipv6BigIntToAddr((0xfd00n << 112n) | (0x60n << 96n))).toBe("fd00:60::");
    expect(ipv6BigIntToAddr((0x20010db8n << 96n) | 1n)).toBe("2001:db8::1");
    expect(ipv6BigIntToAddr((1n << 64n) | 1n)).toBe("::1:0:0:0:1"); // tie → leftmost run compressed (RFC 5952)
  });

  it("derives the radvd /64 prefix from poolStart", () => {
    expect(radvdPrefix64("fd00:60::100")).toBe("fd00:60::/64");
    expect(radvdPrefix64("bogus")).toBeNull();
  });
});

// ── kea-dhcp6.conf renderer ─────────────────────────────────────────────────

describe("renderKea6Conf", () => {
  it("is deterministic (identical input → byte-identical output)", () => {
    expect(renderKea6Conf(input()).text).toBe(renderKea6Conf(input()).text);
  });

  it("renders ids, subnet, pools, option-data and interfaces", () => {
    const text = renderKea6Conf(input()).text;
    expect(text.startsWith(MANAGED_HEADER)).toBe(true);
    expect(text).toContain(`"id": ${MANAGED_ID_BASE + 7}`);
    expect(text).toContain('"subnet": "fd00:60::/64"');
    expect(text).toContain('"pool": "fd00:60::100 - fd00:60::1ff"');
    expect(text).toContain('"interface": "ens34"');
    expect(text).toContain('"name": "domain-name-servers"');
    expect(text).toContain('"data": "2001:db8:1::1"');
    expect(text).toContain('"name": "domain-search"');
    expect(text).toContain('"data": "lab.example"');
    expect(text).toContain('"valid-lifetime": 7200'); // min of servers
    expect(text).toContain('"utm-managed": true');
    expect(text).toContain('"type": "memfile"');
    expect(text).toContain('"persist": true');
    const doc = parseKea6Conf(text);
    expect((doc.Dhcp6?.["interfaces-config"] as { interfaces: string[] }).interfaces).toEqual(["ens34"]);
  });

  it("round-trips through parseKea6Conf and exposes managed ids", () => {
    const text = renderKea6Conf(input()).text;
    const doc = parseKea6Conf(text);
    expect(liveKea6ManagedIds(doc)).toEqual([MANAGED_ID_BASE + 7]);
  });

  it("refuses a foreign non-Dhcp6 document", () => {
    expect(() => parseKea6Conf('{"Dhcp4": {}}')).toThrow();
  });

  it("renders the honest empty state when dhcpv6Enabled=false", () => {
    const r = renderKea6Conf(input({ settings: settings({ dhcpv6Enabled: false }) }));
    expect(r.text).toContain('"subnet6": []');
    expect(r.text).toContain("kea-dhcp6-server is stopped on apply");
    expect(r.enabledServers).toHaveLength(0);
  });

  it("renders the honest empty state when no server is enabled", () => {
    const r = renderKea6Conf(input({ servers: [server({ enabled: false })] }));
    expect(r.text).toContain('"subnet6": []');
  });

  it("uses 3600 as the default valid-lifetime with no servers", () => {
    const r = renderKea6Conf(input({ settings: settings({ dhcpv6Enabled: false }) }));
    expect(r.text).toContain('"valid-lifetime": 3600');
  });
});

// ── radvd.conf renderer ─────────────────────────────────────────────────────

describe("renderRadvdConf (mode matrix)", () => {
  it("router_only: advertises with managed/other/autonomous OFF", () => {
    const r = renderRadvdConf(input({ settings: settings({ raMode: "router_only" }) }));
    expect(r.text).toContain("interface ens34 {");
    expect(r.text).toContain("AdvSendAdvert on;");
    expect(r.text).toContain("AdvManagedFlag off;");
    expect(r.text).toContain("AdvOtherConfigFlag off;");
    expect(r.text).toContain("AdvAutonomous off;");
    expect(r.text).toContain("prefix fd00:60::/64 {");
    expect(r.text).toContain("AdvOnLink on;");
    expect(r.ifaces).toEqual([{ iface: "ens34", prefix: "fd00:60::/64", mode: "router_only" }]);
  });

  it("slaac: autonomous ON, managed/other OFF", () => {
    const r = renderRadvdConf(input({ settings: settings({ raMode: "slaac" }) }));
    expect(r.text).toContain("AdvAutonomous on;");
    expect(r.text).toContain("AdvManagedFlag off;");
    expect(r.text).toContain("AdvOtherConfigFlag off;");
  });

  it("slaac_dhcpv6: managed + other + autonomous all ON", () => {
    const r = renderRadvdConf(input({ settings: settings({ raMode: "slaac_dhcpv6" }) }));
    expect(r.text).toContain("AdvManagedFlag on;");
    expect(r.text).toContain("AdvOtherConfigFlag on;");
    expect(r.text).toContain("AdvAutonomous on;");
  });

  it("disabled: empty conf without interface stanzas", () => {
    const r = renderRadvdConf(input({ settings: settings({ raMode: "disabled" }) }));
    expect(r.text).toContain("RA disabled in console");
    expect(r.text).not.toContain("interface ");
    expect(r.ifaces).toHaveLength(0);
  });

  it("rdnssEnabled renders the RDNSS stanza; off omits it", () => {
    const on = renderRadvdConf(input()).text;
    expect(on).toContain("RDNSS 2001:db8:1::1 {");
    expect(on).toContain("AdvRDNSSLifetime 600;");
    const off = renderRadvdConf(input({ settings: settings({ rdnssEnabled: false }) })).text;
    expect(off).not.toContain("RDNSS ");
  });

  it("never advertises on pdWanInterface without a server row there", () => {
    const r = renderRadvdConf(input({ settings: settings({ pdWanInterface: "wan0" }) }));
    expect(r.text).not.toContain("interface wan0 {");
  });
});

// ── NAT66 nft renderer ──────────────────────────────────────────────────────

describe("renderNat66Nft", () => {
  it("renders nptv6 as stateless dnat + reverse snat pair", () => {
    const { statements } = nat66Statements([natRule()]);
    expect(statements).toContainEqual({
      id: 3,
      hook: "prerouting",
      line: `dnat ip6 saddr 2001:db8:a::/64 prefix 2001:db8:b::/64 comment "nat66:3:npt-lab"`,
    });
    expect(statements).toContainEqual({
      id: 3,
      hook: "postrouting",
      line: `snat ip6 daddr 2001:db8:b::/64 prefix 2001:db8:a::/64 comment "nat66:3:npt-lab"`,
    });
  });

  it("renders masquerade66 in postrouting with oifname match", () => {
    const { statements } = nat66Statements([
      natRule({ id: 4, name: "masq-lan", type: "masquerade66", sourcePrefix: null, translatedPrefix: null, interfaceName: "ens34" }),
    ]);
    expect(statements).toHaveLength(1);
    expect(statements[0].hook).toBe("postrouting");
    expect(statements[0].line).toContain(`oifname "ens34" masquerade`);
  });

  it("renders dnat66 in prerouting; destPort adds tcp+udp legs", () => {
    const plain = nat66Statements([
      natRule({ id: 5, name: "dnat-web", type: "dnat66", sourcePrefix: "2001:db8:2::/64", translatedPrefix: "fd00:60::100/128", destPort: null }),
    ]).statements;
    expect(plain).toHaveLength(1);
    expect(plain[0].line).toBe(`dnat ip6 daddr 2001:db8:2::/64 to fd00:60::100/128 comment "nat66:5:dnat-web"`);

    const ported = nat66Statements([
      natRule({ id: 5, name: "dnat-443", type: "dnat66", sourcePrefix: "2001:db8:2::/64", translatedPrefix: "fd00:60::100/128", destPort: 443 }),
    ]).statements;
    expect(ported).toHaveLength(2);
    expect(ported[0].line).toContain(`tcp dport 443 dnat ip6 daddr 2001:db8:2::/64 to fd00:60::100/128`);
    expect(ported[1].line).toContain(`udp dport 443 dnat ip6 daddr 2001:db8:2::/64 to fd00:60::100/128`);
  });

  it("warns on mismatched nptv6 prefix lengths and skips disabled rules", () => {
    const out = nat66Statements([
      natRule({ id: 9, name: "bad-len", sourcePrefix: "2001:db8:a::/64", translatedPrefix: "2001:db8:b::/48" }),
      natRule({ id: 10, name: "off", enabled: false }),
    ]);
    expect(out.statements.some((s) => s.id === 9)).toBe(true);
    expect(out.statements.some((s) => s.id === 10)).toBe(false);
    expect(out.warnings.some((w) => w.includes("equal lengths"))).toBe(true);
  });

  it("dedicates the table and NEVER flushes the ruleset", () => {
    const text = renderNat66Nft([natRule()]).text;
    expect(text).toContain("destroy table inet utm_nat66");
    expect(text).toContain("table inet utm_nat66 {");
    expect(text).toContain("type nat hook prerouting priority dstnat; policy accept;");
    expect(text).toContain("type nat hook postrouting priority srcnat; policy accept;");
    expect(text).not.toContain("flush ruleset");
    expect(text).not.toContain("table inet console-firewall");
  });

  it("block-compare matches a simulated kernel dump (counters + comments stripped)", () => {
    const gen = renderNat66Nft([natRule()]).text;
    const liveDump = [
      "table inet utm_nat66 {",
      "\tchain prerouting {",
      "\t\ttype nat hook prerouting priority dstnat; policy accept;",
      `\t\tdnat ip6 saddr 2001:db8:a::/64 prefix 2001:db8:b::/64 counter packets 12 bytes 984 comment "nat66:3:npt-lab"`,
      "\t}",
      "\tchain postrouting {",
      "\t\ttype nat hook postrouting priority srcnat; policy accept;",
      `\t\tsnat ip6 daddr 2001:db8:b::/64 prefix 2001:db8:a::/64 counter packets 4 bytes 300 comment "nat66:3:npt-lab"`,
      "\t}",
      "}",
    ].join("\n");
    expect(nat66BlocksInSync(gen, liveDump)).toBe(true);
    expect(nat66BlocksInSync(gen, gen)).toBe(true);
    expect(nat66BlocksInSync(gen, "table inet other { }")).toBe(false);
    expect(extractNat66TableBlock(gen)[1]).toContain("type nat hook prerouting");
  });
});

// ── input validation ────────────────────────────────────────────────────────

describe("validateIpv6Inputs", () => {
  it("accepts the happy path", () => {
    expect(validateIpv6Inputs(input())).toEqual([]);
  });

  it("refuses poolEnd <= poolStart and out-of-subnet pools", () => {
    const bad = input({
      servers: [
        server({ id: 1, poolEnd: "fd00:60::100" }),
        server({ id: 2, poolStart: "2001:db8:99::1" }),
      ],
    });
    const problems = validateIpv6Inputs(bad);
    expect(problems.some((p) => p.includes("pool end must be greater"))).toBe(true);
    expect(problems.some((p) => p.includes("outside"))).toBe(true);
  });

  it("refuses duplicate subnet6 declarations (kea constraint)", () => {
    const dup = input({ servers: [server({ id: 1 }), server({ id: 2, interfaceName: "ens35" })] });
    expect(validateIpv6Inputs(dup).some((p) => p.includes("duplicate"))).toBe(true);
  });
});

// ── sysctl decision ─────────────────────────────────────────────────────────

describe("sysctlNeededFor", () => {
  it("wants forwarding when dhcpv6Enabled or RA mode is active", () => {
    expect(sysctlNeededFor(input())).toBe(true);
    expect(sysctlNeededFor(input({ settings: settings({ dhcpv6Enabled: false, raMode: "slaac" }) }))).toBe(true);
    expect(sysctlNeededFor(input({ settings: settings({ enabled: false }) }))).toBe(false);
    expect(sysctlNeededFor(input({ settings: settings({ dhcpv6Enabled: false, raMode: "disabled" }) }))).toBe(false);
  });
});

// ── plan builder ────────────────────────────────────────────────────────────

describe("buildIpv6ApplyPlan", () => {
  it("orders: dir → backups → stage(write) → validate → install → service → probes → sysctl", () => {
    const plan = buildIpv6ApplyPlan(input(), facts(), "plan", "TS");
    const cmds = plan.steps.map((s) => s.cmd);
    const idx = (c: string) => cmds.findIndex((x) => x.includes(c));
    expect(cmds[0]).toBe("mkdir -p /var/lib/console/ipv6");
    expect(idx("kea-dhcp6 -t")).toBeGreaterThan(idx("write-file"));
    expect(idx("install -m 0644 /etc/kea/kea-dhcp6.conf.staged")).toBeGreaterThan(idx("kea-dhcp6 -t"));
    expect(idx("systemctl restart kea-dhcp6-server")).toBeGreaterThan(idx("install -m 0644 /etc/kea/kea-dhcp6.conf.staged"));
    expect(idx("systemctl is-active kea-dhcp6-server")).toBeGreaterThan(idx("systemctl restart kea-dhcp6-server"));
    expect(idx("radvd -c")).toBeGreaterThan(idx("write-file /var/lib/console/ipv6/radvd.conf.staged"));
    expect(idx("nft -c -f")).toBeGreaterThan(idx("write-file /var/lib/console/ipv6/nat66-"));
    expect(idx("nft -f /var/lib/console/ipv6/nat66-")).toBeGreaterThan(idx("nft -c -f"));
    const sysctlIdx = cmds.indexOf("sysctl -w net.ipv6.conf.all.forwarding=1");
    expect(sysctlIdx).toBeGreaterThan(idx("install -m 0644"));
    expect(plan.guarded).toBe(true);
    expect(plan.refused).toBeNull();
    // kea conf install mode is 0644 (_kea uid must read the conf)
    expect(cmds).toContain(`install -m 0644 ${KEA6_STAGE_FILE} ${KEA6_CONF_FILE}`);
  });

  it("carries the rendered files for staging (kea6 + radvd + nat66)", () => {
    const plan = buildIpv6ApplyPlan(input(), facts(), "plan", "TS");
    const kinds = plan.files.map((f) => f.kind).sort();
    expect(kinds).toEqual(["kea6", "nat66", "radvd"]);
    const keaFile = plan.files.find((f) => f.kind === "kea6")!;
    expect(keaFile.content).toBe(renderKea6Conf(input()).text);
    expect(plan.confHash).toBe(fnv1aHash(renderKea6Conf(input()).text));
    expect(plan.keaSubnets).toEqual([{ id: 7, subnet: "fd00:60::/64", iface: "ens34", pool: "fd00:60::100 - fd00:60::1ff" }]);
    expect(plan.radvdIfaces).toEqual([{ iface: "ens34", prefix: "fd00:60::/64", mode: "slaac_dhcpv6" }]);
  });

  it("STOPs kea + radvd when dhcpv6 and RA are disabled (honest empty state)", () => {
    const plan = buildIpv6ApplyPlan(
      input({ settings: settings({ dhcpv6Enabled: false, raMode: "disabled" }) }),
      facts({ keaConfPresent: false }),
      "plan",
      "TS",
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("systemctl stop kea-dhcp6-server");
    expect(cmds).toContain("systemctl stop radvd");
    expect(cmds).not.toContain("systemctl restart kea-dhcp6-server");
    expect(cmds).not.toContain("systemctl restart radvd");
    // no configtest for the disabled radvd conf (radvd -c rejects empty confs)
    expect(cmds.some((c) => c.startsWith("radvd -c"))).toBe(false);
    expect(plan.keaServiceWanted).toBe("stopped");
    expect(plan.radvdServiceWanted).toBe("stopped");
    expect(plan.sysctlNeeded).toBe(false);
    expect(cmds).not.toContain("sysctl -w net.ipv6.conf.all.forwarding=1");
  });

  it("zero-churn: rendered == live + services in wanted state + table in kernel → empty plan", () => {
    const f = facts({
      keaConfText: renderKea6Conf(input()).text,
      radvdConfText: renderRadvdConf(input()).text,
      liveRuleset: renderNat66Nft([natRule()]).text,
      keaRunning: true,
      radvdRunning: true,
      sysctlForwarding: true,
    });
    const plan = buildIpv6ApplyPlan(input(), f, "plan", "TS");
    expect(plan.empty).toBe(true);
    expect(plan.steps.every((s) => s.kind === "dir")).toBe(true);
    expect(plan.keaChanged).toBe(false);
    expect(plan.radvdChanged).toBe(false);
    expect(plan.nat66Changed).toBe(false);
    expect(plan.sysctlNeeded).toBe(false);
  });

  it("emits the sysctl step only when forwarding is not already 1", () => {
    const withStep = buildIpv6ApplyPlan(input(), facts({ sysctlForwarding: false }), "plan", "TS");
    expect(withStep.steps.map((s) => s.cmd)).toContain("sysctl -w net.ipv6.conf.all.forwarding=1");
    const without = buildIpv6ApplyPlan(input(), facts({ sysctlForwarding: true }), "plan", "TS");
    expect(without.steps.map((s) => s.cmd)).not.toContain("sysctl -w net.ipv6.conf.all.forwarding=1");
  });

  it("refuses the plan (no files, no steps) on invalid pools / duplicates", () => {
    const plan = buildIpv6ApplyPlan(input({ servers: [server({ poolEnd: "fd00:60::100" })] }), facts(), "plan", "TS");
    expect(plan.files).toHaveLength(0);
    expect(plan.steps).toHaveLength(0);
    expect(plan.refused).toContain("refused: ");
  });
});

// ── step guard ──────────────────────────────────────────────────────────────

describe("ipv6StepGuarded", () => {
  it("allows exactly the whitelisted step shapes", () => {
    expect(ipv6StepGuarded("kea-dhcp6 -t /var/lib/console/ipv6/kea-dhcp6.conf.staged")).toBe(true);
    expect(ipv6StepGuarded("kea-dhcp6 -t /etc/kea/kea-dhcp6.conf")).toBe(true);
    expect(ipv6StepGuarded("radvd -c /var/lib/console/ipv6/radvd.conf.staged")).toBe(true);
    expect(ipv6StepGuarded("radvd -c /etc/radvd.conf")).toBe(true);
    expect(ipv6StepGuarded("nft -c -f /var/lib/console/ipv6/nat66-TS.nft")).toBe(true);
    expect(ipv6StepGuarded("nft -f /var/lib/console/ipv6/nat66-TS.nft")).toBe(true);
    expect(ipv6StepGuarded("install -m 0644 /var/lib/console/ipv6/kea-dhcp6.conf.staged /etc/kea/kea-dhcp6.conf")).toBe(true);
    expect(ipv6StepGuarded("cp /etc/kea/kea-dhcp6.conf /var/lib/console/ipv6/backup-TS/kea-dhcp6.conf")).toBe(true);
    expect(ipv6StepGuarded("cp /etc/radvd.conf /var/lib/console/ipv6/backup-TS/radvd.conf")).toBe(true);
    expect(ipv6StepGuarded("sysctl -w net.ipv6.conf.all.forwarding=1")).toBe(true);
    expect(ipv6StepGuarded("systemctl restart kea-dhcp6-server")).toBe(true);
    expect(ipv6StepGuarded("systemctl stop kea-dhcp6-server")).toBe(true);
    expect(ipv6StepGuarded("systemctl restart radvd")).toBe(true);
    expect(ipv6StepGuarded("systemctl stop radvd")).toBe(true);
    expect(ipv6StepGuarded("systemctl is-active radvd")).toBe(true);
    expect(ipv6StepGuarded("ss -ltn")).toBe(true);
    expect(ipv6StepGuarded("ss -lun")).toBe(true);
    expect(ipv6StepGuarded("rm -f /var/lib/console/ipv6/nat66-TS.nft")).toBe(true);
    expect(ipv6StepGuarded("mkdir -p /var/lib/console/ipv6")).toBe(true);
  });

  it("rejects anything outside the red lines", () => {
    expect(ipv6StepGuarded("nft flush ruleset")).toBe(false);
    expect(ipv6StepGuarded("nft -f /etc/nftables.conf")).toBe(false);
    expect(ipv6StepGuarded("rm -rf /")).toBe(false);
    expect(ipv6StepGuarded("systemctl restart sshd")).toBe(false);
    expect(ipv6StepGuarded("kea-dhcp6 -t /etc/passwd")).toBe(false);
    expect(ipv6StepGuarded("install -m 0644 /etc/shadow /etc/kea/kea-dhcp6.conf")).toBe(false);
    expect(ipv6StepGuarded("")).toBe(false);
  });
});

// ── drift ───────────────────────────────────────────────────────────────────

describe("computeIpv6Drift", () => {
  const rendered = (inp: Ipv6OsInput) => ({
    kea: { ...renderKea6Conf(inp) },
    radvd: renderRadvdConf(inp),
    nat66: renderNat66Nft(inp.nat66),
  });

  it("in-sync when hashes + table + sysctl match; drift/missing otherwise", () => {
    const inp = input();
    const r = rendered(inp);
    const syncFacts = facts({
      keaConfPresent: true,
      keaConfText: r.kea.text,
      radvdConfPresent: true,
      radvdConfText: r.radvd.text,
      liveRuleset: r.nat66.text,
      keaRunning: true,
      radvdRunning: true,
      sysctlForwarding: true,
    });
    const d = computeIpv6Drift(inp, syncFacts, r);
    expect(d.filter((x) => x.osState === "in-sync").length).toBeGreaterThan(0);
    expect(d.filter((x) => x.osState === "drift" || x.osState === "missing")).toHaveLength(0);

    // conf hash differs → kea row drift, server row drift
    const driftFacts = facts({ keaConfText: `${r.kea.text}\n`, radvdConfText: r.radvd.text, liveRuleset: r.nat66.text, keaRunning: true, radvdRunning: true, sysctlForwarding: true });
    const d2 = computeIpv6Drift(inp, driftFacts, r);
    expect(d2.filter((x) => x.kind === "kea6" && x.osState === "drift").length).toBeGreaterThan(0);

    // nothing deployed → missing
    const d3 = computeIpv6Drift(inp, facts(), r);
    expect(d3.filter((x) => x.osState === "missing").length).toBeGreaterThan(0);
  });

  it("disabled servers and disabled settings report disabled (not drift)", () => {
    const inp = input({ servers: [server({ enabled: false })] });
    const d = computeIpv6Drift(inp, facts(), rendered(inp));
    expect(d.some((x) => x.kind === "kea6" && x.osState === "disabled")).toBe(true);
    const inp2 = input({ settings: settings({ dhcpv6Enabled: false }) });
    const d2 = computeIpv6Drift(inp2, facts(), rendered(inp2));
    expect(d2.some((x) => x.kind === "kea6" && x.osState === "disabled" && x.id === 7)).toBe(true);
  });

  it("unsupported when kea-dhcp6 / radvd / nft binaries are missing", () => {
    const inp = input();
    const r = rendered(inp);
    const d = computeIpv6Drift(inp, facts({ keaAvailable: false, radvdAvailable: false, nftAvailable: false }), r);
    expect(d.filter((x) => x.osState === "unsupported").map((x) => x.kind)).toEqual(
      expect.arrayContaining(["kea6", "radvd", "nat66"]),
    );
  });

  it("sysctl row: drift when forwarding is off while serving is wanted", () => {
    const d = computeIpv6Drift(input(), facts({ sysctlForwarding: false }), rendered(input()));
    const sysctlRow = d.find((x) => x.kind === "sysctl");
    expect(sysctlRow?.osState).toBe("drift");
    const d2 = computeIpv6Drift(input({ settings: settings({ enabled: false }) }), facts({ sysctlForwarding: false }), rendered(input()));
    expect(d2.find((x) => x.kind === "sysctl")?.osState).toBe("in-sync");
  });
});

// ── executor ordering (stubbed binaries, real fs, real tmp state dir) ───────

const TMP = path.join("/tmp", `ipv6-os-test-${process.pid}`);

function writeStub(bin: string, body: string): void {
  const p = path.join(TMP, "bin", bin);
  fs.writeFileSync(p, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

async function freshModules(env: Record<string, string>) {
  vi.resetModules();
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  return {
    os: await import("@/lib/ipv6/os"),
    svc: await import("@/lib/ipv6/os-service"),
  };
}

function envFor(): Record<string, string> {
  return {
    CONSOLE_OS_APPLY: "1",
    ADAPTER_MODE: "host",
    CONSOLE_IPV6_DIR: path.join(TMP, "state"),
    CONSOLE_KEA6_CONF: path.join(TMP, "etc", "kea", "kea-dhcp6.conf"),
    CONSOLE_RADVD_CONF: path.join(TMP, "etc", "radvd.conf"),
    CONSOLE_NFT_ETC_DIR: path.join(TMP, "etc", "console-nft"),
    CONSOLE_NFT_CONF: path.join(TMP, "etc", "nftables.conf"),
    CONSOLE_IPV6_SYSCTL_FILE: path.join(TMP, "etc", "sysctl-ipv6.conf"),
  };
}

beforeAll(() => {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(path.join(TMP, "bin"), { recursive: true });
  // appliance stubs — kea-dhcp6/radvd/nft/systemctl/ss/sysctl all "work"
  writeStub("kea-dhcp6", `case "$1" in
  -v) echo "Kea dhcp6 daemon version 2.6.3"; exit 0 ;;
  -t) test -f "$2" || exit 1 ;;
esac
exit 0`);
  writeStub("radvd", `[ -f "$(dirname "$0")/../radvd-fail" ] && exit 7
case "$1" in
  --version*) echo "radvd version 2.20"; exit 0 ;;
  -c) test -f "$2" || exit 1 ;;
esac
exit 0`);
  writeStub("nft", `case "$1 $2" in
  "list ruleset") exit 0 ;;
esac
exit 0`);
  writeStub("systemctl", `case "$1" in
  is-active) echo "active"; exit 0 ;;
esac
exit 0`);
  writeStub("ss", "exit 0");
  writeStub("sysctl", `case "$1" in
  -n) echo "0" ;;
esac
exit 0`);
  process.env.PATH = `${path.join(TMP, "bin")}:${process.env.PATH ?? ""}`;
});

afterEach(() => {
  fs.rmSync(path.join(TMP, "radvd-fail"), { force: true });
});

describe("execIpv6ApplyPlan (stubbed appliance)", () => {
  it("green path: validates staged confs, installs, starts services, writes state.json LAST", async () => {
    const { os, svc } = await freshModules(envFor());
    const plan = os.buildIpv6ApplyPlan(input(), facts({ sysctlForwarding: false }), "exec", "TS1");
    expect(plan.refused).toBeNull();
    const outcome = await svc.execIpv6ApplyPlan(plan);

    expect(outcome.gate).toBe("on");
    expect(outcome.applied).toBe(true);
    expect(outcome.rolledBack).toBe(false);

    // installed confs match the render (hash-stable) — kea conf world-readable
    const keaText = renderKea6Conf(input()).text;
    expect(fs.readFileSync(os.KEA6_CONF_FILE, "utf8")).toBe(keaText);
    const radvdText = renderRadvdConf(input()).text;
    expect(fs.readFileSync(os.RADVD_CONF_FILE, "utf8")).toBe(radvdText);
    expect(fs.existsSync(os.NAT66_ETC_FILE)).toBe(true);
    expect(fs.readFileSync(os.FORWARDING_SYSCTL_FILE, "utf8")).toContain("net.ipv6.conf.all.forwarding=1");

    // state.json LAST: carries the applied hashes AND the FULL step results —
    // a state write before the steps would leave results empty
    const state = JSON.parse(fs.readFileSync(path.join(os.IPV6_STATE_DIR, "state.json"), "utf8")) as Record<string, unknown>;
    expect(state.confHash).toBe(fnv1aHash(keaText));
    expect(state.radvdHash).toBe(fnv1aHash(radvdText));
    expect(state.sysctlForwarding).toBe(true);
    expect((state.results as unknown[]).length).toBe(outcome.results.length);
    expect((state.lastApply as { applied: boolean }).applied).toBe(true);
  }, 30000);

  it("failure path: a bad radvd conf fails validation → full rollback + honest state", async () => {
    const { os, svc } = await freshModules(envFor());
    fs.writeFileSync(path.join(TMP, "radvd-fail"), "1");
    // clean state file — the merge semantics keep the LAST SUCCESSFUL confHash
    fs.rmSync(path.join(TMP, "state"), { recursive: true, force: true });
    // pre-existing kea conf must be RESTORED verbatim on rollback
    fs.mkdirSync(path.dirname(os.KEA6_CONF_FILE), { recursive: true });
    fs.writeFileSync(os.KEA6_CONF_FILE, "# pre-apply kea conf\n{}\n");

    const plan = os.buildIpv6ApplyPlan(input(), facts({ keaConfPresent: true, keaConfText: "# pre-apply kea conf\n{}\n" }), "exec", "TS2");
    const outcome = await svc.execIpv6ApplyPlan(plan);

    expect(outcome.applied).toBe(false);
    expect(outcome.rolledBack).toBe(true);
    expect(outcome.reason).toContain("radvd");
    // kea conf restored to the pre-apply bytes (not the rendered content)
    expect(fs.readFileSync(os.KEA6_CONF_FILE, "utf8")).toBe("# pre-apply kea conf\n{}\n");
    // state LAST on failure: honest lastApply, never a confHash we did not install
    const state = JSON.parse(fs.readFileSync(path.join(os.IPV6_STATE_DIR, "state.json"), "utf8")) as Record<string, unknown>;
    expect(state.confHash).toBeUndefined();
    expect((state.lastApply as { applied: boolean }).applied).toBe(false);
  }, 30000);

  it("gate off: plan preview only — no fs writes at all", async () => {
    const { os, svc } = await freshModules({ ...envFor(), CONSOLE_OS_APPLY: "0" });
    // fresh root for THIS test — the green-path test wrote state into TMP
    fs.rmSync(path.join(TMP, "state"), { recursive: true, force: true });
    fs.rmSync(path.join(TMP, "etc"), { recursive: true, force: true });
    const plan = os.buildIpv6ApplyPlan(input(), facts(), "plan", "TS3");
    const outcome = await svc.execIpv6ApplyPlan(plan);
    expect(outcome.gate).toBe("off");
    expect(outcome.applied).toBe(false);
    expect(outcome.results).toHaveLength(0);
    expect(fs.existsSync(path.join(os.IPV6_STATE_DIR, "state.json"))).toBe(false);
    expect(fs.existsSync(os.KEA6_CONF_FILE)).toBe(false);
  }, 30000);
});

// ── dhcp/os.ts consistency (IMPL-6 note update, osState stays unsupported) ──

describe("dhcp/os.ts ipv6-subnet note consistency", () => {
  it("reports unsupported for kea-dhcp4 with the kea-dhcp6 hand-off note", async () => {
    const { computeDhcpDrift } = await import("@/lib/dhcp/os");
    const entry = computeDhcpDrift(
      [
        {
          id: 9,
          interfaceName: "ens34",
          family: "ipv6",
          subnetCidr: "fd00::/64",
          rangeStart: "fd00::100",
          rangeEnd: "fd00::150",
          gateway: null,
          dnsServers: [],
          leaseTime: 600,
          options: {},
          enabled: true,
        },
      ],
      [],
      null,
      {
        available: true,
        gate: "on",
        tools: { keaDhcp4: true, dhcrelay: false },
        running: true,
        port67Bound: true,
        configValid: true,
        version: "2.6.3",
        confPresent: true,
        confHash: null,
        liveManagedSubnetIds: [],
        liveForeignSubnetIds: [],
        relayUnitExists: false,
        relayDefaultsPresent: false,
        leases: [],
        leaseReadError: null,
      },
      null,
    );
    expect(entry[0].osState).toBe("unsupported");
    expect(entry[0].detail).toContain("kea-dhcp6");
    expect(entry[0].detail).toContain("ipv6 module");
  });
});

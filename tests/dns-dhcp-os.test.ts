/**
 * DNS & DHCP OS integration — unit tests for the pure core of
 * lib/dns/os.ts (unbound renderer/parser/guard/drift/plan) and
 * lib/dhcp/os.ts (kea merge/leases/guard/drift/plan). Filesystem and
 * process boundaries are NOT exercised here (prod E2E covers those with
 * unbound-checkconf / kea-dhcp4 -t on the appliance); everything below is
 * deterministic.
 */

import { describe, it, expect } from "vitest";
import {
  fnv1aHash,
  recordOwner,
  recordRdata,
  renderUnboundManaged,
  dnsStepGuarded,
  parseUnboundControlStatus,
  computeDnsDrift,
  buildDnsApplyPlan,
  MANAGED_UNBOUND_FILE,
  DOT_KEY_FILE,
  type DnsPolicyInput,
  type DnsRecordInput,
  type DnsOsFacts,
} from "@/lib/dns/os";
import {
  fnv1aHash as dhcpHash,
  parseKeaLeases,
  isManagedKeaSubnet,
  renderKeaSubnet,
  renderDhcrelayDefaults,
  mergeKeaConfig,
  validateSubnetInputs,
  buildDhcpApplyPlan,
  dhcpStepGuarded,
  computeDhcpDrift,
  MANAGED_ID_BASE,
  type DhcpSubnetInput,
  type DhcpReservationInput,
  type DhcpOsFacts,
} from "@/lib/dhcp/os";
import { resolverSettingsSchema } from "@/lib/validators/dns-dhcp";
import type { ResolverSettings } from "@/lib/validators/dns-dhcp";
import { ApiError } from "@/lib/api/errors";

// ── fixtures ────────────────────────────────────────────────────────────────

const resolver = (over: Partial<ResolverSettings> = {}): ResolverSettings => ({
  forwarders: ["1.1.1.1"],
  cacheSizeMb: 64,
  rrl: false,
  dot: false,
  forwardZones: [],
  doh: { enabled: false, port: 443 },
  listenInterfaces: ["127.0.0.1", "::1"],
  accessControl: [],
  logQueries: false,
  ...over,
});

const policy = (over: Partial<DnsPolicyInput> = {}): DnsPolicyInput => ({
  id: 1,
  name: "corp-block",
  enabled: true,
  blockCategories: [],
  customBlock: ["ads.example.com", "tracker.io"],
  customAllow: ["good.example.com"],
  action: "sinkhole",
  sinkholeIp: "0.0.0.0",
  ...over,
});

const record = (over: Partial<DnsRecordInput> = {}): DnsRecordInput => ({
  id: 1,
  zone: "corp.local",
  name: "nas",
  type: "A",
  value: "10.99.99.5",
  ttl: 3600,
  priority: null,
  enabled: true,
  ...over,
});

const subnet = (over: Partial<DhcpSubnetInput> = {}): DhcpSubnetInput => ({
  id: 7,
  interfaceName: "ens34",
  family: "ipv4",
  subnetCidr: "10.99.99.0/24",
  rangeStart: "10.99.99.100",
  rangeEnd: "10.99.99.150",
  gateway: "10.99.99.1",
  dnsServers: ["10.99.99.1"],
  leaseTime: 600,
  options: {},
  enabled: true,
  ...over,
});

const reservation = (over: Partial<DhcpReservationInput> = {}): DhcpReservationInput => ({
  id: 3,
  subnetId: 7,
  mac: "aa:bb:cc:dd:ee:ff",
  ip: "10.99.99.120",
  hostname: "printer",
  ...over,
});

// ── unbound renderer ────────────────────────────────────────────────────────

describe("renderUnboundManaged", () => {
  it("renders loopback listeners + forward-zone with the default settings", () => {
    const out = renderUnboundManaged({ settings: resolver(), policies: [], records: [] });
    expect(out).toContain("interface: 127.0.0.1");
    expect(out).toContain("interface: ::1");
    expect(out).toContain("port: 53");
    expect(out).toContain("access-control: 127.0.0.0/8 allow");
    expect(out).toContain("forward-zone:");
    expect(out).toContain('name: "."');
    expect(out).toContain("forward-addr: 1.1.1.1");
    expect(out).not.toContain("forward-addr: 1.1.1.1\n\nforward-zone"); // forward-addr stays inside the zone
  });

  it("maps policy actions to local-zone types with allow-list override semantics", () => {
    const out = renderUnboundManaged({ settings: resolver(), policies: [policy()], records: [] });
    expect(out).toContain('local-zone: "good.example.com." transparent'); // allow entry
    expect(out).toContain('local-zone: "ads.example.com." redirect'); // sinkhole action
    expect(out).toContain('local-data: "ads.example.com. 300 IN A 0.0.0.0"');
    expect(out).not.toContain("always_nxdomain");
  });

  it("renders always_nxdomain for nxdomain-action policies", () => {
    const out = renderUnboundManaged({
      settings: resolver(),
      policies: [policy({ action: "nxdomain" })],
      records: [],
    });
    expect(out).toContain('local-zone: "ads.example.com." always_nxdomain');
    expect(out).not.toContain("redirect");
  });

  it("renders per-type local-data rdata (MX/SRV priority, TXT quoting)", () => {
    const out = renderUnboundManaged({
      settings: resolver(),
      policies: [],
      records: [
        record(),
        record({ id: 2, name: "mail.corp.local", type: "MX", value: "mx.corp.local", priority: 10 }),
        record({ id: 3, name: "_sip._tcp", type: "SRV", value: "10 60 5060 sip.corp.local", priority: 20 }),
        record({ id: 4, name: "dkim", type: "TXT", value: 'v=DKIM1; "quoted"' }),
        record({ id: 5, name: "nas", type: "PTR", value: "nas.corp.local", zone: "99.99.10.in-addr.arpa" }),
      ],
    });
    expect(out).toContain('local-data: "nas.corp.local. 3600 IN A 10.99.99.5"');
    expect(out).toContain('local-data: "mail.corp.local. 3600 IN MX 10 mx.corp.local"');
    expect(out).toContain('local-data: "_sip._tcp.corp.local. 3600 IN SRV 20 10 60 5060 sip.corp.local"');
    // TXT value carries double quotes → the local-data line uses SINGLE quotes
    // (verified empirically: unbound-checkconf rejects nested double quotes)
    expect(out).toContain(`local-data: 'dkim.corp.local. 3600 IN TXT "v=DKIM1; \\"quoted\\""'`);
    expect(out).toContain('local-data: "nas.99.99.10.in-addr.arpa. 3600 IN PTR nas.corp.local"');
  });

  it("renders cache sizes, RRL, log-queries, DoT cert paths and ACL CIDRs when enabled", () => {
    const out = renderUnboundManaged({
      settings: resolver({ rrl: true, logQueries: true, dot: true, cacheSizeMb: 128, accessControl: ["10.99.99.0/24"] }),
      policies: [],
      records: [],
    });
    expect(out).toContain("msg-cache-size: 128m");
    expect(out).toContain("rrset-cache-size: 512m");
    expect(out).toContain("ratelimit: 1000");
    expect(out).toContain("log-queries: yes");
    expect(out).toContain("tls-port: 853");
    expect(out).toContain(`ssl-service-key: "${DOT_KEY_FILE}"`);
    expect(out).toContain("access-control: 10.99.99.0/24 allow");
  });

  it("render output is byte-stable (deterministic hash) for identical input", () => {
    const a = renderUnboundManaged({ settings: resolver(), policies: [policy()], records: [record()] });
    const b = renderUnboundManaged({ settings: resolver(), policies: [policy()], records: [record()] });
    expect(a).toBe(b);
    expect(fnv1aHash(a)).toBe(fnv1aHash(b));
  });

  it("disabled policies/records are excluded from the render", () => {
    const out = renderUnboundManaged({
      settings: resolver(),
      policies: [policy({ enabled: false })],
      records: [record({ enabled: false })],
    });
    expect(out).not.toContain("ads.example.com");
    expect(out).not.toContain("local-data: \"nas");
  });
});

// ── record helpers ──────────────────────────────────────────────────────────

describe("recordOwner / recordRdata", () => {
  it("appends zone when the name is bare, keeps qualified names, apex for @", () => {
    expect(recordOwner("corp.local", "nas")).toBe("nas.corp.local");
    expect(recordOwner("corp.local", "nas.corp.local")).toBe("nas.corp.local");
    expect(recordOwner("corp.local", "_sip._tcp")).toBe("_sip._tcp.corp.local");
    expect(recordOwner("corp.local", "@")).toBe("corp.local");
    expect(recordOwner("corp.local", "")).toBe("corp.local");
  });

  it("rdata per type", () => {
    expect(recordRdata({ type: "A", value: "1.2.3.4", priority: null })).toBe("1.2.3.4");
    expect(recordRdata({ type: "MX", value: "mx.x", priority: 10 })).toBe("10 mx.x");
    expect(recordRdata({ type: "TXT", value: 'a"b', priority: null })).toBe('"a\\"b"');
    expect(recordRdata({ type: "SRV", value: "1 2 t", priority: 15 })).toBe("15 1 2 t");
    expect(recordRdata({ type: "BOGUS", value: "x", priority: null })).toBeNull();
  });
});

// ── unbound guard ───────────────────────────────────────────────────────────

describe("dnsStepGuarded", () => {
  it("allows only the pinned validate/reload/status + DoT pki set", () => {
    expect(dnsStepGuarded(`unbound-checkconf ${MANAGED_UNBOUND_FILE}`)).toBe(true);
    expect(dnsStepGuarded("unbound-control reload")).toBe(true);
    expect(dnsStepGuarded("unbound-control status")).toBe(true);
    expect(dnsStepGuarded(`openssl ecparam -name prime256v1 -genkey -noout -out ${DOT_KEY_FILE}`)).toBe(true);
    expect(dnsStepGuarded(`chmod 600 ${DOT_KEY_FILE} /var/lib/console/dns/dot.pem`)).toBe(true);
    expect(dnsStepGuarded("systemctl restart unbound")).toBe(false);
    expect(dnsStepGuarded("rm -rf /etc/unbound")).toBe(false);
    expect(dnsStepGuarded("unbound-control reload ; rm -rf /")).toBe(false);
    expect(dnsStepGuarded("")).toBe(false);
  });
});

// ── unbound facts parser + drift ────────────────────────────────────────────

describe("parseUnboundControlStatus", () => {
  it("extracts version and running state", () => {
    const st = parseUnboundControlStatus("version: 1.26.2\nuptime: 251973 seconds\nunbound (pid 884) is running...");
    expect(st.version).toBe("1.26.2");
    expect(st.running).toBe(true);
    expect(parseUnboundControlStatus("unbound is not running").running).toBe(false);
  });
});

describe("computeDnsDrift", () => {
  const facts = (over: Partial<DnsOsFacts> = {}): DnsOsFacts => ({
    available: true,
    gate: "on",
    tools: { unbound: true, checkconf: true, control: true },
    running: true,
    ports53Bound: true,
    checkconfOk: true,
    controlOk: true,
    version: "1.26.2",
    managedFilePresent: true,
    managedFileHash: null,
    logQueriesEnabled: false,
    logFileBytes: 0,
    effectiveInterfaces: ["127.0.0.1", "::1"],
    ...over,
  });

  it("in-sync when live hash equals rendered hash", () => {
    const d = computeDnsDrift(resolver(), [policy()], [record()], facts({ managedFileHash: "abc123" }), "abc123");
    expect(d.every((x) => x.osState === "in-sync")).toBe(true);
  });

  it("drift when hashes differ, missing when file absent, unsupported when unbound missing", () => {
    const drift = computeDnsDrift(resolver(), [policy()], [], facts({ managedFileHash: "aaa" }), "bbb");
    expect(drift.every((x) => x.osState === "drift")).toBe(true);
    const missing = computeDnsDrift(resolver(), [], [], facts({ managedFilePresent: false }), "bbb");
    expect(missing.every((x) => x.osState === "missing")).toBe(true);
    const unsupported = computeDnsDrift(resolver(), [], [], facts({ tools: { unbound: false, checkconf: false, control: false } }), "bbb");
    expect(unsupported.every((x) => x.osState === "unsupported")).toBe(true);
  });
});

// ── unbound plan builder ────────────────────────────────────────────────────

describe("buildDnsApplyPlan", () => {
  const facts = (over: Partial<DnsOsFacts> = {}): DnsOsFacts => ({
    available: true,
    gate: "on",
    tools: { unbound: true, checkconf: true, control: true },
    running: true,
    ports53Bound: true,
    checkconfOk: true,
    controlOk: true,
    version: "1.26.2",
    managedFilePresent: true,
    managedFileHash: null,
    logQueriesEnabled: false,
    logFileBytes: 0,
    effectiveInterfaces: ["127.0.0.1"],
    ...over,
  });

  it("writes the managed file + validate + reload + status steps", () => {
    const plan = buildDnsApplyPlan({ settings: resolver(), policies: [policy()], records: [record()] }, facts());
    expect(plan.files.map((f) => f.path)).toEqual([MANAGED_UNBOUND_FILE]);
    expect(plan.files[0].backup).toBe(true);
    expect(plan.steps.map((s) => s.cmd)).toEqual([
      `unbound-checkconf ${MANAGED_UNBOUND_FILE}`,
      "unbound-control reload",
      "unbound-control status",
    ]);
    expect(plan.managedZones).toEqual(["allow:good.example.com", "block:ads.example.com", "block:tracker.io"]);
    expect(plan.managedRecords).toEqual(["nas.corp.local A"]);
  });

  it("adds guarded DoT pki steps when dot enabled", () => {
    const plan = buildDnsApplyPlan({ settings: resolver({ dot: true }), policies: [], records: [] }, facts());
    expect(plan.steps.some((s) => s.cmd.startsWith("openssl ecparam"))).toBe(true);
    expect(plan.steps.every((s) => dnsStepGuarded(s.cmd) || s.cmd.startsWith("test -f") || s.cmd === `mkdir -p /var/lib/console/dns`)).toBe(true);
  });

  it("honestly skips block categories without RPZ feeds", () => {
    const plan = buildDnsApplyPlan({ settings: resolver(), policies: [policy({ blockCategories: ["ads", "malware"] })], records: [] }, facts());
    expect(plan.skipped.some((s) => s.name === "corp-block" && s.reason.includes("RPZ feed"))).toBe(true);
    expect(plan.reasons.some((r) => r.includes("RPZ feed"))).toBe(true);
  });

  it("warns when unbound is down or control missing", () => {
    const down = buildDnsApplyPlan({ settings: resolver(), policies: [], records: [] }, facts({ running: false }));
    expect(down.reasons.some((r) => r.includes("unbound.service is down"))).toBe(true);
    const noCtl = buildDnsApplyPlan({ settings: resolver(), policies: [], records: [] }, facts({ tools: { unbound: true, checkconf: true, control: false } }));
    expect(noCtl.reasons.some((r) => r.includes("unbound-control missing"))).toBe(true);
  });
});

// ── settings grammar ────────────────────────────────────────────────────────

describe("resolverSettingsSchema (extended)", () => {
  it("accepts defaults and fills listenInterfaces/ACL/logQueries", () => {
    const v = resolverSettingsSchema.parse({ forwarders: ["9.9.9.9"], cacheSizeMb: 32 });
    expect(v.listenInterfaces).toEqual(["127.0.0.1", "::1"]);
    expect(v.accessControl).toEqual([]);
    expect(v.logQueries).toBe(false);
  });

  it("validates CIDR ACLs and rejects bad ones", () => {
    expect(() => resolverSettingsSchema.parse({ forwarders: [], cacheSizeMb: 32, accessControl: ["10.99.99.0/24"] })).not.toThrow();
    expect(() => resolverSettingsSchema.parse({ forwarders: [], cacheSizeMb: 32, accessControl: ["10.99.99.0"] })).toThrow();
    expect(() => resolverSettingsSchema.parse({ forwarders: [], cacheSizeMb: 32, accessControl: ["300.1.1.0/24"] })).toThrow();
    expect(() => resolverSettingsSchema.parse({ forwarders: [], cacheSizeMb: 32, listenInterfaces: ["127.0.0.1", "::1"] })).not.toThrow();
    expect(() => resolverSettingsSchema.parse({ forwarders: [], cacheSizeMb: 32, listenInterfaces: ["not-an-ip"] })).toThrow();
  });
});

// ── kea renderer ────────────────────────────────────────────────────────────

describe("renderKeaSubnet / reservations", () => {
  it("renders managed subnet entry with id namespace, pool, options and marker", () => {
    const e = renderKeaSubnet(subnet(), [reservation()]);
    expect(e["id"]).toBe(MANAGED_ID_BASE + 7);
    expect(e["subnet"]).toBe("10.99.99.0/24");
    expect(e["interface"]).toBe("ens34");
    expect(e["valid-lifetime"]).toBe(600);
    expect((e["pools"] as Array<{ pool: string }>)[0].pool).toBe("10.99.99.100 - 10.99.99.150");
    const opt = e["option-data"] as Array<Record<string, unknown>>;
    expect(opt).toContainEqual({ name: "routers", data: "10.99.99.1" });
    expect(opt).toContainEqual({ name: "domain-name-servers", data: "10.99.99.1" });
    expect(e["reservations"]).toEqual([{ "hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "10.99.99.120", hostname: "printer" }]);
    expect(isManagedKeaSubnet(e as { "user-context"?: Record<string, unknown> })).toBe(true);
  });

  it("renders numeric custom options with csv-format false", () => {
    const e = renderKeaSubnet(subnet({ options: { "42": "10.99.99.1" } }), []);
    expect((e["option-data"] as Array<Record<string, unknown>>)).toContainEqual({ code: 42, data: "10.99.99.1", "csv-format": false });
  });
});

describe("mergeKeaConfig", () => {
  const prodLike = JSON.stringify({
    Dhcp4: {
      "interfaces-config": { interfaces: ["ens34"] },
      "lease-database": { type: "memfile", name: "/var/lib/kea/kea-leases4.csv", persist: true, "lfc-interval": 300 },
      "valid-lifetime": 600,
      "subnet4": [
        {
          id: 1,
          subnet: "10.99.99.0/24",
          interface: "ens34",
          pools: [{ pool: "10.99.99.100 - 10.99.99.150" }],
          "option-data": [
            { name: "routers", data: "10.99.99.1" },
            { name: "domain-name-servers", data: "10.99.99.1" },
          ],
        },
      ],
      loggers: [{ name: "kea-dhcp4", "output-options": [{ output: "/var/log/kea/kea-dhcp4.log" }], severity: "INFO" }],
    },
  }, null, 2) + "\n";

  it("ADOPTS a foreign subnet with the same CIDR (bootstrap prod id 1 → managed)", () => {
    const m = mergeKeaConfig(prodLike, [subnet()], [reservation()]);
    expect(m.managed).toEqual([{ id: 7, cidr: "10.99.99.0/24", iface: "ens34", pool: "10.99.99.100 - 10.99.99.150" }]);
    expect(m.preserved).toEqual([]);
    const doc = JSON.parse(m.text);
    expect(doc.Dhcp4.subnet4).toHaveLength(1);
    expect(doc.Dhcp4.subnet4[0].id).toBe(MANAGED_ID_BASE + 7);
    expect(doc.Dhcp4.subnet4[0]["user-context"]["utm-managed"]).toBe(true);
    expect(doc.Dhcp4.subnet4[0].reservations).toHaveLength(1);
    // lease-database + loggers preserved verbatim
    expect(doc.Dhcp4["lease-database"].name).toBe("/var/lib/kea/kea-leases4.csv");
    expect(doc.Dhcp4.loggers[0].severity).toBe("INFO");
  });

  it("preserves foreign subnets with different CIDR verbatim", () => {
    const m = mergeKeaConfig(prodLike, [subnet({ subnetCidr: "10.99.98.0/24" })], []);
    expect(m.preserved).toEqual(["10.99.99.0/24"]);
    const doc = JSON.parse(m.text);
    expect(doc.Dhcp4.subnet4).toHaveLength(2);
    expect(doc.Dhcp4.subnet4.find((s: { id: number }) => s.id === 1).subnet).toBe("10.99.99.0/24");
    expect(doc.Dhcp4.subnet4.find((s: { id: number }) => s.id === MANAGED_ID_BASE + 7).subnet).toBe("10.99.98.0/24");
  });

  it("drops managed entries for disabled subnets and union-extends interfaces", () => {
    const m = mergeKeaConfig(prodLike, [subnet({ enabled: false }), subnet({ id: 8, subnetCidr: "10.99.98.0/24", interfaceName: "ens35" })], []);
    const doc = JSON.parse(m.text);
    const ids = doc.Dhcp4.subnet4.map((s: { id: number }) => s.id);
    expect(ids).toContain(1); // foreign preserved
    expect(ids).toContain(MANAGED_ID_BASE + 8);
    expect(ids).not.toContain(MANAGED_ID_BASE + 7); // disabled dropped
    expect(doc.Dhcp4["interfaces-config"].interfaces.sort()).toEqual(["ens34", "ens35"]);
    expect(m.changedInterfaces).toBe(true);
  });

  it("builds a skeleton from scratch when no conf exists", () => {
    const m = mergeKeaConfig(null, [subnet()], []);
    const doc = JSON.parse(m.text);
    expect(doc.Dhcp4["interfaces-config"].interfaces).toEqual(["ens34"]);
    expect(doc.Dhcp4.subnet4).toHaveLength(1);
    expect(doc.Dhcp4["lease-database"].type).toBe("memfile");
  });

  it("refuses to merge when the live file is not a Dhcp4 document", () => {
    expect(() => mergeKeaConfig("{ broken json", [subnet()], [])).toThrow(ApiError);
    expect(() => mergeKeaConfig(JSON.stringify({ "other": true }), [subnet()], [])).toThrow(ApiError);
  });
});

// ── kea leases parser ───────────────────────────────────────────────────────

describe("parseKeaLeases", () => {
  it("parses the memfile CSV header + rows (empty file → [])", () => {
    expect(parseKeaLeases("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n")).toEqual([]);
    const csv = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n" +
      "10.99.99.101,aa:bb:cc:dd:ee:01,01:02,600,1752650000,1001,0,0,printer,0,,0\n" +
      "10.99.99.102,aa:bb:cc:dd:ee:02,,600,1752650000,1,0,0,,2,,0\n";
    const now = 1752649000;
    const leases = parseKeaLeases(csv, now);
    expect(leases).toHaveLength(2);
    expect(leases[0]).toMatchObject({ address: "10.99.99.101", hwaddr: "aa:bb:cc:dd:ee:01", hostname: "printer", subnetId: 1001, state: "active", expiresinSec: 1000 });
    expect(leases[1].state).toBe("declined");
  });
});

// ── kea guard + validation ──────────────────────────────────────────────────

describe("dhcpStepGuarded", () => {
  it("allows only kea -t, kea unit lifecycle and state-dir mkdir", () => {
    expect(dhcpStepGuarded("kea-dhcp4 -t /etc/kea/kea-dhcp4.conf")).toBe(true);
    expect(dhcpStepGuarded("systemctl restart kea-dhcp4-server")).toBe(true);
    expect(dhcpStepGuarded("systemctl is-active kea-dhcp4-server")).toBe(true);
    expect(dhcpStepGuarded("systemctl restart isc-dhcp-relay.service")).toBe(true);
    expect(dhcpStepGuarded("rm -rf /etc/kea")).toBe(false);
    expect(dhcpStepGuarded("systemctl restart unbound")).toBe(false);
    expect(dhcpStepGuarded("kea-dhcp4 -t /etc/shadow")).toBe(false);
    expect(dhcpStepGuarded("")).toBe(false);
  });
});

describe("validateSubnetInputs", () => {
  it("accepts a consistent pool + reservation", () => {
    expect(validateSubnetInputs([subnet()], [reservation()])).toEqual([]);
  });
  it("flags pools outside the subnet, reservations outside, and overlapping subnets", () => {
    expect(validateSubnetInputs([subnet({ rangeStart: "10.99.100.10" })], [])).toContainEqual(expect.stringContaining("pool start"));
    expect(validateSubnetInputs([subnet({ rangeEnd: "10.99.100.200" })], [])).toContainEqual(expect.stringContaining("pool end"));
    expect(validateSubnetInputs([subnet()], [reservation({ ip: "10.99.100.50" })])).toContainEqual(expect.stringContaining("reservation 10.99.100.50"));
    expect(validateSubnetInputs([subnet(), subnet({ id: 8, subnetCidr: "10.99.99.128/25" })], [])).toContainEqual(expect.stringContaining("overlap"));
  });
});

// ── kea plan builder ────────────────────────────────────────────────────────

describe("buildDhcpApplyPlan", () => {
  const facts = (over: Partial<DhcpOsFacts> = {}): DhcpOsFacts => ({
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
    ...over,
  });

  it("full plan: merged file + kea -t + restart + is-active", async () => {
    const plan = await buildDhcpApplyPlan({ subnets: [subnet()], reservations: [reservation()], relay: null }, facts());
    expect(plan.files.map((f) => f.path)).toEqual(["/etc/kea/kea-dhcp4.conf"]);
    expect(plan.steps.map((s) => s.cmd)).toEqual([
      "kea-dhcp4 -t /etc/kea/kea-dhcp4.conf",
      "systemctl restart kea-dhcp4-server",
      "systemctl is-active kea-dhcp4-server",
    ]);
    expect(plan.managedSubnets).toEqual([{ id: 7, cidr: "10.99.99.0/24", iface: "ens34", pool: "10.99.99.100 - 10.99.99.150" }]);
    expect(plan.steps.every((s) => dhcpStepGuarded(s.cmd))).toBe(true);
  });

  it("refused plan (no files) on invalid pools / overlapping subnets", async () => {
    const plan = await buildDhcpApplyPlan({ subnets: [subnet({ rangeStart: "10.99.100.10" })], reservations: [], relay: null }, facts());
    expect(plan.files).toHaveLength(0);
    expect(plan.reasons.some((r) => r.startsWith("refused:"))).toBe(true);
  });

  it("honestly skips DHCPv6 + reservations of disabled subnets + relay without unit", async () => {
    const plan = await buildDhcpApplyPlan(
      {
        subnets: [subnet(), subnet({ id: 9, family: "ipv6", subnetCidr: "fd00::/64", rangeStart: "fd00::100", rangeEnd: "fd00::150", interfaceName: "ens34" })],
        reservations: [reservation({ subnetId: 99 })],
        relay: { enabled: true, servers: ["10.99.99.254"], interfaces: ["ens34"] },
      },
      facts(),
    );
    expect(plan.skipped.some((s) => s.name.startsWith("fd00::"))).toBe(true);
    expect(plan.skipped.some((s) => s.name === "10.99.99.120 (aa:bb:cc:dd:ee:ff)")).toBe(true);
    expect(plan.skipped.some((s) => s.name === "dhcp-relay" && s.reason.includes("missing"))).toBe(true);
    expect(plan.steps.every((s) => !s.cmd.includes("isc-dhcp-relay"))).toBe(true);
  });

  it("relay steps added when dhcrelay + unit exist", async () => {
    const plan = await buildDhcpApplyPlan(
      { subnets: [], reservations: [], relay: { enabled: true, servers: ["10.99.99.254"], interfaces: ["ens34"] } },
      facts({ tools: { keaDhcp4: true, dhcrelay: true }, relayUnitExists: true }),
    );
    expect(plan.files.some((f) => f.path === "/etc/default/isc-dhcp-relay")).toBe(true);
    expect(plan.steps).toContainEqual(expect.objectContaining({ cmd: "systemctl restart isc-dhcp-relay.service" }));
  });
});

// ── relay renderer ──────────────────────────────────────────────────────────

describe("renderDhcrelayDefaults", () => {
  it("renders SERVERS/INTERFACES quoting", () => {
    const out = renderDhcrelayDefaults({ enabled: true, servers: ["10.99.99.254", "10.0.0.1"], interfaces: ["ens34", "ens35"] });
    expect(out).toContain('SERVERS="10.99.99.254 10.0.0.1"');
    expect(out).toContain('INTERFACES="ens34 ens35"');
    expect(out).toContain("UTM CONSOLE MANAGED");
  });
});

// ── drift (kea) ─────────────────────────────────────────────────────────────

describe("computeDhcpDrift", () => {
  const facts = (over: Partial<DhcpOsFacts> = {}): DhcpOsFacts => ({
    available: true,
    gate: "on",
    tools: { keaDhcp4: true, dhcrelay: false },
    running: true,
    port67Bound: true,
    configValid: true,
    version: "2.6.3",
    confPresent: true,
    confHash: null,
    liveManagedSubnetIds: [MANAGED_ID_BASE + 7],
    liveForeignSubnetIds: [],
    relayUnitExists: false,
    relayDefaultsPresent: false,
    leases: [],
    leaseReadError: null,
    ...over,
  });

  it("in-sync when live hash matches the rendered merge", () => {
    const rendered = mergeKeaConfig(null, [subnet()], [reservation()]).text;
    const d = computeDhcpDrift([subnet()], [reservation()], null, facts({ confHash: dhcpHash(rendered) }), rendered);
    expect(d[0].osState).toBe("in-sync");
    expect(d[0].detail).toContain("1 reservation(s)");
  });

  it("drift / missing / disabled / unsupported / v6 per state", () => {
    const rendered = mergeKeaConfig(null, [subnet()], []).text;
    expect(computeDhcpDrift([subnet()], [], null, facts({ confHash: "differs" }), rendered)[0].osState).toBe("drift");
    expect(computeDhcpDrift([subnet()], [], null, facts({ liveManagedSubnetIds: [] }), rendered)[0].osState).toBe("missing");
    expect(computeDhcpDrift([subnet({ enabled: false })], [], null, facts({ liveManagedSubnetIds: [] }), null)[0].osState).toBe("disabled");
    expect(computeDhcpDrift([subnet({ family: "ipv6" })], [], null, facts(), null)[0].osState).toBe("unsupported");
    expect(computeDhcpDrift([subnet()], [], null, facts({ tools: { keaDhcp4: false, dhcrelay: false } }), null)[0].osState).toBe("unsupported");
  });
});

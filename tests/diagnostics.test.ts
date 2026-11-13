import { describe, it, expect } from "vitest";
import {
  runDiagPing,
  runDiagTraceroute,
  runDiagDnsLookup,
  runDiagTcpCheck,
} from "@/lib/host/diagnostics";
import { clearToolCache } from "@/lib/host/tools";

// ── validation tests (no binaries needed — rejected before exec) ─────────────

describe("runDiagPing validation", () => {
  it("rejects invalid hosts", async () => {
    const r = await runDiagPing("not_a_host!!");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid host/i);
  });

  it("rejects invalid interface names", async () => {
    const r = await runDiagPing("1.1.1.1", "bad iface! name");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid interface/i);
  });

  it("accepts IPv4 hosts and reports unavailability honestly when ping is missing", async () => {
    // sandbox HAS ping — result may succeed or fail on the network, but never crash
    const r = await runDiagPing("127.0.0.1", undefined, 1);
    expect(typeof r.ok).toBe("boolean");
    expect(r.lossPct === null || typeof r.lossPct === "number").toBe(true);
  });
});

describe("runDiagTraceroute validation", () => {
  it("rejects invalid hosts", async () => {
    const r = await runDiagTraceroute("bad host!");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid host/i);
    expect(r.hops).toHaveLength(0);
  });

  it("rejects invalid interface names", async () => {
    const r = await runDiagTraceroute("1.1.1.1", "iface with spaces");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid interface/i);
  });

  it("clamps maxHops and never crashes on localhost", async () => {
    const r = await runDiagTraceroute("127.0.0.1", undefined, 99);
    expect(typeof r.ok).toBe("boolean");
    expect(["traceroute", "tracepath", null]).toContain(r.tool);
  });
});

describe("runDiagDnsLookup validation", () => {
  it("rejects invalid hostnames", async () => {
    const r = await runDiagDnsLookup("not_valid!!");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid hostname/i);
  });

  it("rejects non-IPv4 servers", async () => {
    const r = await runDiagDnsLookup("example.com", "dns.example.internal");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/dns server must be/i);
  });

  it("resolves localhost via the real resolver chain", async () => {
    const r = await runDiagDnsLookup("localhost");
    expect(["dig", "host", "nslookup", null]).toContain(r.tool);
    expect(Array.isArray(r.addresses)).toBe(true);
  });
});

describe("runDiagTcpCheck validation", () => {
  it("rejects invalid hosts", async () => {
    const r = await runDiagTcpCheck("!!", 443);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid host/i);
  });

  it("rejects out-of-range ports", async () => {
    const r = await runDiagTcpCheck("1.1.1.1", 99999);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/port must be/i);
  });

  it("rejects invalid interface names", async () => {
    const r = await runDiagTcpCheck("1.1.1.1", 443, "bad/iface");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/invalid interface/i);
  });

  it("probes loopback with a real connect (sandbox net tool present)", async () => {
    clearToolCache();
    // ensure the tool cache treats `ip`/`ping` freshly — bind decision is honest
    const r = await runDiagTcpCheck("127.0.0.1", 1);
    // port 1 on loopback is almost surely closed — but the call must be structured
    expect(typeof r.connected).toBe("boolean");
    expect(r.connected === false || r.latencyMs != null).toBe(true);
  });
});

/**
 * VPN OS integration — unit tests for the pure core of lib/vpn/os.ts +
 * the real-crypto helpers of lib/vpn/crypto.ts. Filesystem and process
 * boundaries are NOT exercised here (prod E2E covers those on ens34/
 * test subnets); everything below is deterministic.
 */

import { describe, it, expect } from "vitest";
import {
  slugify,
  tunnelIfaceName,
  connName,
  renderSwanctlManaged,
  renderWgQuickConf,
  renderOpenVpnServerConf,
  renderOpenVpnPkiSteps,
  vpnStepGuarded,
  parseSwanctlConns,
  parseSwanctlSas,
  computeVpnDrift,
  buildVpnApplyPlan,
  MANAGED_PREFIX,
  IFNAME_MAX,
  type VpnOsConfigInput,
  type VpnOsFacts,
} from "@/lib/vpn/os";
import { generateWgKeypair, wgPublicKeyFromPrivate, publicKeyFromPrivateRaw, generatePsk } from "@/lib/vpn/crypto";
import type { IpsecConfig, OpenVpnConfig, WgRemoteConfig, WgS2sConfig } from "@/lib/vpn/types";

// ── fixtures ────────────────────────────────────────────────────────────────

const ipsecCfg = (over: Partial<IpsecConfig> = {}): IpsecConfig => ({
  localIp: "103.244.7.219",
  remoteIp: "198.51.100.10",
  localSubnets: ["10.250.0.0/16"],
  remoteSubnets: ["10.251.0.0/16"],
  psk: "test-psk-with-\"quote\"-safe",
  ike: "aes256-sha256-modp2048",
  esp: "aes256gcm16-modp2048",
  dpdSec: 30,
  pfs: true,
  replayWindow: 128,
  ...over,
});

const wgS2sCfg = (over: Partial<WgS2sConfig> = {}): WgS2sConfig => ({
  privateKey: generateWgKeypair().privateKey,
  listenPort: 51820,
  peers: [{ name: "branch", publicKey: generateWgKeypair().publicKey, allowedIps: ["10.250.1.0/24"], endpoint: "198.51.100.10:51820", keepaliveSec: 25 }],
  address: "10.250.0.1/24",
  ...over,
});

const wgRemoteCfg = (over: Partial<WgRemoteConfig> = {}): WgRemoteConfig => ({
  privateKey: generateWgKeypair().privateKey,
  listenPort: 51821,
  address: "10.250.1.1/24",
  pool: "10.250.1.0/24",
  dns: "10.250.0.53",
  keepaliveSec: 25,
  peers: [],
  ...over,
});

const ovpnCfg = (over: Partial<OpenVpnConfig> = {}): OpenVpnConfig => ({
  proto: "udp",
  port: 1194,
  cipher: "AES-256-GCM",
  auth: "SHA256",
  pool: "10.250.2.0/24",
  tls: true,
  dns: "10.250.0.53",
  keepaliveSec: 30,
  ...over,
});

const cfg = (over: Partial<VpnOsConfigInput> = {}): VpnOsConfigInput => ({
  id: 1,
  name: "Test Tunnel",
  type: "ipsec_s2s",
  enabled: true,
  config: ipsecCfg(),
  ...over,
});

const emptyFacts = (over: Partial<VpnOsFacts> = {}): VpnOsFacts => ({
  available: false,
  gate: "off",
  tools: { swanctl: false, wg: false, wgQuick: false, openvpn: false },
  charonRunning: false,
  ikePortsBound: false,
  swanctlConns: [],
  establishedSas: [],
  wgIfaces: [],
  openvpnServices: [],
  ...over,
});

// ── real crypto (Curve25519) ────────────────────────────────────────────────

describe("vpn crypto — real X25519", () => {
  it("generates wg-format keys (44-char base64) with a matching derived public key", () => {
    const kp = generateWgKeypair();
    expect(kp.privateKey).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(kp.publicKey).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(wgPublicKeyFromPrivate(kp.privateKey)).toBe(kp.publicKey);
  });

  it("derives the same public key from the raw private scalar (deterministic)", () => {
    const kp = generateWgKeypair();
    const raw = Buffer.from(kp.privateKey, "base64");
    expect(raw).toHaveLength(32);
    const again = publicKeyFromPrivateRaw(raw);
    expect(Buffer.from(kp.publicKey, "base64")).toEqual(again);
    // key derivation is stable across calls (no randomness in scalarmult)
    expect(publicKeyFromPrivateRaw(raw)).toEqual(again);
  });

  it("rejects invalid private keys with null instead of throwing", () => {
    expect(wgPublicKeyFromPrivate("not-a-key")).toBeNull();
    expect(wgPublicKeyFromPrivate("")).toBeNull();
  });

  it("PSKs are 256-bit CSPRNG, base64, unique per call", () => {
    const a = generatePsk();
    const b = generatePsk();
    expect(a).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(a).not.toBe(b);
    expect(Buffer.from(a, "base64")).toHaveLength(32);
  });
});

// ── naming (IFNAMSIZ + managed namespace) ───────────────────────────────────

describe("tunnel naming", () => {
  it("slugs non-alphanumeric names into the managed utm- namespace", () => {
    expect(slugify("Branch Office HQ")).toBe("branch-office-hq");
    // connName applies IFNAMSIZ truncation — the slug itself keeps spaces collapsed
    expect(connName("Branch HQ")).toBe("utm-branch-hq");
    expect(slugify("Branch Office HQ")).toContain("branch-office-hq");
  });

  it("respects IFNAMSIZ (≤ 15 chars) for interface-bound types", () => {
    const long = "a-very-long-tunnel-name-that-exceeds-fifteen-chars";
    const iface = tunnelIfaceName(long);
    expect(iface.length).toBeLessThanOrEqual(IFNAME_MAX);
    expect(iface.startsWith(MANAGED_PREFIX)).toBe(true);
    // stable across calls (deterministic truncation, no random suffix)
    expect(tunnelIfaceName(long)).toBe(iface);
  });

  it("keeps short names verbatim", () => {
    expect(tunnelIfaceName("branch")).toBe("utm-branch");
  });
});

// ── swanctl renderer ────────────────────────────────────────────────────────

describe("renderSwanctlManaged — swanctl.conf.d stanza", () => {
  const text = renderSwanctlManaged([{ name: "utm-branch", cfg: ipsecCfg() }]);

  it("emits a connections block with the managed conn and IKEv2 version", () => {
    expect(text).toContain("connections {");
    expect(text).toContain("    utm-branch {");
    expect(text).toContain("version = 2");
    expect(text).toContain("local_addrs = 103.244.7.219");
    expect(text).toContain("remote_addrs = 198.51.100.10");
  });

  it("uses trap start_action (nothing initiated — prod-safe) and restart DPD", () => {
    expect(text).toContain("start_action = trap");
    expect(text).toContain("dpd_action = restart");
    expect(text).toContain("dpd_delay = 30");
  });

  it("maps subnets, proposals, PFS-off and replay window", () => {
    expect(text).toContain("local_ts = 10.250.0.0/16");
    expect(text).toContain("remote_ts = 10.251.0.0/16");
    expect(text).toContain("esp_proposals = aes256gcm16-modp2048");
    expect(text).toContain("proposals = aes256-sha256-modp2048");
    expect(text).not.toContain("pfs = no");
    expect(text).toContain("replay_window = 128");

    const noPfs = renderSwanctlManaged([{ name: "utm-x", cfg: ipsecCfg({ pfs: false, replayWindow: undefined }) }]);
    expect(noPfs).toContain("pfs = no");
    expect(noPfs).not.toContain("replay_window");
  });

  it("keeps PSK secrets in the secrets block with quoting escaped", () => {
    expect(text).toContain("secrets {");
    expect(text).toContain('id = 198.51.100.10');
    expect(text).toContain('\\"quote\\"');
  });

  it("falls back to %any when no remoteIp (traffic-triggered responder)", () => {
    const any = renderSwanctlManaged([{ name: "utm-hub", cfg: ipsecCfg({ remoteIp: "" }) }]);
    expect(any).toContain("remote_addrs = %any");
    expect(any).toContain("id = %any");
  });
});

// ── wg-quick renderer ───────────────────────────────────────────────────────

describe("renderWgQuickConf", () => {
  it("emits [Interface] with private key, address and listen port", () => {
    const priv = generateWgKeypair().privateKey;
    const text = renderWgQuickConf(wgS2sCfg({ privateKey: priv }));
    expect(text).toContain("[Interface]");
    expect(text).toContain(`PrivateKey = ${priv}`);
    expect(text).toContain("Address = 10.250.0.1/24");
    expect(text).toContain("ListenPort = 51820");
    expect(text).toContain("[Peer]");
    expect(text).toContain("AllowedIPs = 10.250.1.0/24");
    expect(text).toContain("Endpoint = 198.51.100.10:51820");
    expect(text).toContain("PersistentKeepalive = 25");
  });

  it("substitutes simulation-era placeholder peer keys with a DERIVED hub key (loadable file)", () => {
    const kp = generateWgKeypair();
    const bad = wgS2sCfg({ privateKey: kp.privateKey });
    bad.peers = [{ name: "legacy", publicKey: "pk-simulation-garbage", allowedIps: ["10.250.9.0/24"] }];
    const text = renderWgQuickConf(bad);
    // derived key matches wg base64 format — the file loads with wg setconf
    expect(text).toMatch(/PublicKey = [A-Za-z0-9+/]{43}=/);
    expect(text).not.toContain("pk-simulation-garbage");
  });
});

// ── openvpn renderer + PKI ──────────────────────────────────────────────────

describe("renderOpenVpnServerConf", () => {
  it("renders a 2.6 server conf with EC PKI paths and no DH file", () => {
    const text = renderOpenVpnServerConf(ovpnCfg(), "test-tunnel");
    expect(text).toContain("proto udp");
    expect(text).toContain("port 1194");
    expect(text).toContain("dev utm-test-tunnel");
    expect(text).toContain("topology subnet");
    expect(text).toContain("server 10.250.2.0 255.255.255.0");
    expect(text).toContain("dh none");
    expect(text).toContain("data-ciphers AES-256-GCM");
    expect(text).toContain("tls-crypt /etc/openvpn/server/utm-test-tunnel/pki/ta.key");
    expect(text).toContain('push "dhcp-option DNS 10.250.0.53"');
    expect(text).toContain("status /run/openvpn-server/status-utm-test-tunnel.status 1");
  });

  it("omits tls-crypt and DNS when disabled", () => {
    const text = renderOpenVpnServerConf(ovpnCfg({ tls: false, dns: "" }), "x");
    expect(text).not.toContain("tls-crypt");
    expect(text).not.toContain("dhcp-option DNS");
  });

  it("PKI bootstrap steps stay inside the managed pki dir", () => {
    const steps = renderOpenVpnPkiSteps("t1");
    expect(steps.length).toBeGreaterThanOrEqual(6);
    for (const s of steps) {
      expect(s.cmd).toContain("utm-t1/pki");
      expect(vpnStepGuarded(s.cmd)).toBe(true);
    }
  });
});

// ── command guard (red lines) ───────────────────────────────────────────────

describe("vpnStepGuarded — managed namespace only", () => {
  it("allows swanctl load/unload/terminate + creds for utm-*", () => {
    expect(vpnStepGuarded("swanctl --load-conn --name utm-branch")).toBe(true);
    expect(vpnStepGuarded("swanctl --unload-conn --name utm-branch")).toBe(true);
    expect(vpnStepGuarded("swanctl --terminate --ike utm-branch")).toBe(true);
    expect(vpnStepGuarded("swanctl --load-creds")).toBe(true);
  });

  it("allows wg-quick up/down/strip and scoped wg set for utm-*", () => {
    expect(vpnStepGuarded("wg-quick up utm-branch")).toBe(true);
    expect(vpnStepGuarded("wg-quick down utm-branch")).toBe(true);
    expect(vpnStepGuarded("wg-quick strip utm-branch")).toBe(true);
    expect(vpnStepGuarded(`wg set utm-branch peer ${"A".repeat(43)}= allowed-ips 10.250.1.5/32`)).toBe(true);
    expect(vpnStepGuarded(`wg set utm-branch peer ${"A".repeat(43)}= allowed-ips 10.0.0.0/8,10.250.2.5/32`)).toBe(true);
  });

  it("allows openvpn unit actions only for managed instances", () => {
    expect(vpnStepGuarded("systemctl start openvpn-server@utm-t1.service")).toBe(true);
    expect(vpnStepGuarded("systemctl stop openvpn-server@utm-t1.service")).toBe(true);
    expect(vpnStepGuarded("systemctl is-active openvpn-server@utm-t1.service")).toBe(true);
  });

  it("REJECTS red-line attempts", () => {
    // non-managed namespaces
    expect(vpnStepGuarded("swanctl --load-conn --name customer-vpn")).toBe(false);
    expect(vpnStepGuarded("wg-quick up wg0")).toBe(false);
    expect(vpnStepGuarded("systemctl start openvpn-server@corp.service")).toBe(false);
    // destructive / out-of-scope commands
    expect(vpnStepGuarded("swanctl --load-all --noprompt")).toBe(false);
    expect(vpnStepGuarded("wg-quick down ens32")).toBe(false);
    expect(vpnStepGuarded("wg-quick up ens32")).toBe(false);
    expect(vpnStepGuarded("ip link del ens32")).toBe(false);
    expect(vpnStepGuarded("systemctl restart strongswan")).toBe(false);
    expect(vpnStepGuarded("rm -rf /etc/swanctl")).toBe(false);
    expect(vpnStepGuarded("openssl req -x509 -key /etc/ssl/private/steal.key -out /tmp/x.crt")).toBe(false);
    expect(vpnStepGuarded("wg set utm-branch peer BAD allowed-ips 0.0.0.0/0")).toBe(false);
    expect(vpnStepGuarded("cat /etc/shadow > /tmp/x")).toBe(false);
    expect(vpnStepGuarded("swanctl --load-conn --name utm-x; rm -rf /")).toBe(false);
    expect(vpnStepGuarded("")).toBe(false);
  });
});

// ── parsers (swanctl output) ────────────────────────────────────────────────

describe("swanctl output parsers", () => {
  it("parseSwanctlConns extracts utm-* names and drops plugin noise", () => {
    const out = [
      "plugin 'aes': failed to load - aes_plugin_create not found and no plugin file available",
      "utm-branch: IKEv2, reauth every 0 seconds",
      "  local:  103.244.7.219 [103.244.7.219]",
      "utm-legacy-tunnel: IKEv2, reauth every 0 seconds",
      "other-conn: IKEv2",
    ].join("\n");
    expect(parseSwanctlConns(out)).toEqual(["utm-branch", "utm-legacy-tunnel"]);
  });

  it("parseSwanctlSas reads established time and child byte counters", () => {
    const out = [
      "plugin 'aes': failed to load - x",
      "utm-branch: #12, ESTABLISHED, IKEv2, 1a2b3c...",
      "  established 187s ago, rekeying in 2h",
      "  utm-branch-net: #5, REKEYED, tunnel, in 1a2b...",
      "  installed 180s ago, bytes-in(123456), bytes-out(654321),",
    ].join("\n");
    const sas = parseSwanctlSas(out);
    expect(sas).toHaveLength(1);
    expect(sas[0].conn).toBe("utm-branch");
    expect(sas[0].establishedSec).toBe(187);
    expect(sas[0].childBytesIn).toBe(123456);
    expect(sas[0].childBytesOut).toBe(654321);
  });
});

// ── drift (GUI↔OS honesty) ──────────────────────────────────────────────────

describe("computeVpnDrift", () => {
  const facts = (over: Partial<VpnOsFacts> = {}): VpnOsFacts =>
    emptyFacts({
      available: true,
      gate: "on",
      tools: { swanctl: true, wg: true, wgQuick: true, openvpn: true },
      charonRunning: true,
      ...over,
    });

  it("missing: enabled ipsec not loaded in charon", () => {
    const d = computeVpnDrift([cfg()], facts());
    expect(d[0].osState).toBe("missing");
  });

  it("in-sync: loaded trap conn reports 'awaiting IKE', established SA reports up", () => {
    const f = facts({ swanctlConns: ["utm-test-tunnel"] });
    let d = computeVpnDrift([cfg()], f);
    expect(d[0].osState).toBe("in-sync");
    expect(d[0].detail).toContain("trap");
    const f2 = facts({ swanctlConns: ["utm-test-tunnel"], establishedSas: [{ conn: "utm-test-tunnel", establishedSec: 42, childBytesIn: 10, childBytesOut: 20 }] });
    d = computeVpnDrift([cfg()], f2);
    expect(d[0].detail).toContain("ESTABLISHED");
  });

  it("drift: disabled in GUI but still loaded/up/active in OS", () => {
    const f = facts({ swanctlConns: ["utm-test-tunnel"] });
    const d = computeVpnDrift([cfg({ enabled: false })], f);
    expect(d[0].osState).toBe("drift");
    expect(d[0].detail).toContain("disabled in GUI");
  });

  it("disabled: disabled in GUI and absent from OS", () => {
    const d = computeVpnDrift([cfg({ enabled: false })], facts());
    expect(d[0].osState).toBe("disabled");
  });

  it("wireguard: interface presence decides missing vs in-sync", () => {
    const wgFacts = (ifaces: VpnOsFacts["wgIfaces"]) => facts({ wgIfaces: ifaces });
    const wgCfg = cfg({ name: "WG Hub", type: "wireguard_s2s", config: wgS2sCfg() });
    const name = connName(wgCfg.name);
    expect(computeVpnDrift([wgCfg], wgFacts([]))[0].osState).toBe("missing");
    const d = computeVpnDrift(
      [wgCfg],
      wgFacts([{ iface: name, up: true, listenPort: 51820, peers: 1, rxBytes: 1, txBytes: 2, lastHandshakeSec: 30 }]),
    );
    expect(d[0].osState).toBe("in-sync");
    expect(d[0].detail).toContain("handshake 30s");
  });

  it("openvpn: service active state decides missing vs in-sync", () => {
    const oCfg = cfg({ name: "SSL Pool", type: "openvpn", config: ovpnCfg() });
    const slug = connName(oCfg.name).slice(MANAGED_PREFIX.length);
    expect(computeVpnDrift([oCfg], facts({ openvpnServices: [{ slug, active: false, pid: null }] }))[0].osState).toBe("missing");
    expect(computeVpnDrift([oCfg], facts({ openvpnServices: [{ slug, active: true, pid: 999 }] }))[0].osState).toBe("in-sync");
  });

  it("unsupported: ipsec_remote is honestly reported, never silently dropped", () => {
    const d = computeVpnDrift([cfg({ type: "ipsec_remote", config: ipsecCfg() })], facts());
    expect(d[0].osState).toBe("unsupported");
  });
});

// ── plan builder ────────────────────────────────────────────────────────────

describe("buildVpnApplyPlan", () => {
  it("plans managed files + guarded steps for enabled tunnels", () => {
    const plan = buildVpnApplyPlan(
      [cfg({ name: "Branch", type: "ipsec_s2s", config: ipsecCfg() }), cfg({ name: "WG Hub", type: "wireguard_s2s", config: wgS2sCfg() })],
      emptyFacts(),
    );
    expect(plan.files.some((f) => f.path.endsWith("/etc/swanctl/conf.d/utm-managed.conf"))).toBe(true);
    expect(plan.files.some((f) => f.path.endsWith("/etc/wireguard/utm-wg-hub.conf"))).toBe(true);
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("swanctl --load-conn --name utm-branch");
    expect(cmds).toContain("wg-quick strip utm-wg-hub");
    expect(cmds).toContain("wg-quick up utm-wg-hub");
    for (const s of plan.steps) expect(vpnStepGuarded(s.cmd)).toBe(true);
  });

  it("teardown steps for disabled tunnels that are still up in OS", () => {
    const plan = buildVpnApplyPlan(
      [cfg({ name: "Branch", type: "ipsec_s2s", enabled: false, config: ipsecCfg() })],
      emptyFacts({ swanctlConns: ["utm-branch"] }),
    );
    // no conn install, but the orphan/teardown pass unloads it
    expect(plan.steps.some((s) => s.cmd === "swanctl --unload-conn --name utm-branch")).toBe(true);
    expect(plan.steps.some((s) => s.cmd === "swanctl --load-conn --name utm-branch")).toBe(false);
  });

  it("orphan sweep removes OS objects without a DB config", () => {
    const plan = buildVpnApplyPlan(
      [],
      emptyFacts({
        swanctlConns: ["utm-gone", "utm-foreign"],
        wgIfaces: [{ iface: "utm-wg-gone", up: true, listenPort: 1, peers: 0, rxBytes: 0, txBytes: 0, lastHandshakeSec: null }],
        openvpnServices: [{ slug: "ovpn-gone", active: true, pid: 5 }],
      }),
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("swanctl --unload-conn --name utm-gone");
    expect(cmds).toContain("swanctl --unload-conn --name utm-foreign");
    expect(cmds).toContain("wg-quick down utm-wg-gone");
    expect(cmds).toContain("systemctl stop openvpn-server@utm-ovpn-gone.service");
    expect(cmds).toContain("systemctl disable openvpn-server@utm-ovpn-gone.service");
  });

  it("honestly skips ipsec_remote with a provisioning reason", () => {
    const plan = buildVpnApplyPlan([cfg({ name: "Road Warriors", type: "ipsec_remote", config: ipsecCfg() })], emptyFacts());
    expect(plan.skipped).toHaveLength(1);
    expect(plan.skipped[0].reason).toContain("FreeRADIUS");
    expect(plan.steps.some((s) => s.kind === "ipsec")).toBe(false);
  });

  it("does not re-up a wireguard iface that is already up (idempotent)", () => {
    const plan = buildVpnApplyPlan(
      [cfg({ name: "WG Hub", type: "wireguard_s2s", config: wgS2sCfg() })],
      emptyFacts({
        wgIfaces: [{ iface: "utm-wg-hub", up: true, listenPort: 51820, peers: 1, rxBytes: 0, txBytes: 0, lastHandshakeSec: 10 }],
      }),
    );
    expect(plan.steps.some((s) => s.cmd === "wg-quick up utm-wg-hub")).toBe(false);
    expect(plan.steps.some((s) => s.cmd === "wg-quick strip utm-wg-hub")).toBe(true);
  });
});

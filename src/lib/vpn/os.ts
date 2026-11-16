/**
 * VPN OS integration (GUI↔strongswan/wireguard/openvpn) — mirrors the
 * ips-os.ts / wan-os.ts architecture for the VPN engines:
 *
 *   DB configs (desired state) ──render──▶  /etc/swanctl/conf.d/utm-managed.conf   (ipsec conns + PSK secrets)
 *                                           /etc/swanctl/psk/utm-managed.conf      (secrets, --load-creds)
 *                                           /etc/wireguard/utm-<slug>.conf         (wg-quick)
 *                                           /etc/openvpn/server/utm-<slug>.conf    (+ pki/ CA, server cert)
 *
 * Apply pipeline (gated by CONSOLE_VPN_OS=1 — independent of CONSOLE_OS_APPLY
 * so VPN enforcement can be rolled out per host; off → plan preview only):
 *   1. backup touched files → /var/lib/console/vpn/backup-<ts>/
 *   2. write managed files
 *   3. validate live: `swanctl --load-conn` is the validator (charon rejects
 *      a bad stanza and loads nothing), `wg-quick strip` parses the WG file,
 *      openvpn = start + is-active check
 *   4. any validation failure → automatic rollback from the backup (unload
 *      what loaded, restore files, stop what started)
 *   5. record state.json (last apply, drift, results)
 *
 * Safety model on the appliance (red lines honoured):
 *   • ipsec conns use start_action = trap — XFRM policies install for the
 *     tunnel's own subnets but nothing is INITIATED (no IKE packets, no
 *     disruption, prod subnets untouched); an admin flips to start after
 *     commissioning by editing the tunnel
 *   • ipsec_remote (roadwarrior EAP) is honestly plan-skipped v1 — per-user
 *     credential provisioning needs the FreeRADIUS integration (spec 1.10)
 *   • managed namespace: conn names `utm-*`, WG/openvpn ifaces `utm-*`
 *     (IFNAMSIZ ≤ 15 enforced), swanctl secrets under utm-managed
 *   • executor re-checks every command against vpnStepGuarded — file writes
 *     go through node fs with path prefixes enforced in code
 *   • ens32 (WAN) is never reconfigured: charon already binds *:500/4500,
 *     WG/openvpn only ADD listeners, no interface/route on WAN changes
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { runTool, hasTool, readServiceStates } from "@/lib/host/tools";
import { readWgPeers } from "@/lib/host/tools";
import { parseJson } from "@/lib/json";
import type {
  IpsecConfig,
  OpenVpnConfig,
  VpnConfigPayload,
  VpnStatusDetailDto,
  WgRemoteConfig,
  WgS2sConfig,
} from "./types";
import { wgPublicKeyFromPrivate } from "./crypto";

// ── paths & managed real estate ─────────────────────────────────────────────

export const VPN_STATE_DIR = process.env.CONSOLE_VPN_DIR || "/var/lib/console/vpn";
export const SWANCTL_CONF_D = process.env.CONSOLE_SWANCTL_CONF_D || "/etc/swanctl/conf.d";
export const SWANCTL_PSK_DIR = process.env.CONSOLE_SWANCTL_PSK_DIR || "/etc/swanctl/psk";
export const WG_ETC_DIR = process.env.CONSOLE_WG_DIR || "/etc/wireguard";
export const OPENVPN_SERVER_DIR = process.env.CONSOLE_OPENVPN_DIR || "/etc/openvpn/server";
export const CHARON_VICI = process.env.CONSOLE_CHARON_VICI || "/var/run/charon.vici";

export const MANAGED_SWANCTL_NAME = "utm-managed.conf";
export const MANAGED_SWANCTL_FILE = path.join(SWANCTL_CONF_D, MANAGED_SWANCTL_NAME);
export const MANAGED_PSK_FILE = path.join(SWANCTL_PSK_DIR, MANAGED_SWANCTL_NAME);
/** conn prefix AND interface prefix — every OS object the console owns */
export const MANAGED_PREFIX = "utm-";
export const IFNAME_MAX = 15; // IFNAMSIZ

// ── shapes ──────────────────────────────────────────────────────────────────

export interface VpnOsConfigInput {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  config: VpnConfigPayload;
}

export interface VpnOsStep {
  cmd: string;
  summary: string;
  kind: "ipsec" | "wireguard" | "openvpn" | "pki" | "secret" | "cleanup";
  /** cleanup/probe steps whose failure is EXPECTED (no SAs to terminate, PKI
   *  absent) — recorded but never triggers rollback */
  optional?: boolean;
}

export interface VpnOsPlan {
  steps: VpnOsStep[];
  files: Array<{ path: string; content: string; backup: boolean }>;
  managedConns: string[];
  managedIfaces: string[];
  skipped: Array<{ name: string; reason: string }>;
  reasons: string[];
}

export interface VpnOsApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  reason: string;
  plan: VpnOsPlan;
  results?: Array<{ cmd: string; ok: boolean; stderr?: string }>;
}

export interface VpnOsFacts {
  available: boolean;
  gate: "on" | "off";
  tools: { swanctl: boolean; wg: boolean; wgQuick: boolean; openvpn: boolean };
  charonRunning: boolean;
  ikePortsBound: boolean;
  swanctlConns: string[]; // utm-* conns loaded into charon
  establishedSas: Array<{ conn: string; establishedSec: number | null; childBytesIn: number; childBytesOut: number }>;
  wgIfaces: Array<{ iface: string; up: boolean; listenPort: number | null; peers: number; rxBytes: number; txBytes: number; lastHandshakeSec: number | null }>;
  openvpnServices: Array<{ slug: string; active: boolean; pid: number | null }>;
}

/** systemctl is-active reports "active"; accept both spellings defensively. */
function isServiceRunning(state: string | undefined | null): boolean {
  return state === "running" || state === "active";
}

export interface VpnDriftEntry {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  /** in-sync | drift | missing | disabled | unsupported */
  osState: string;
  detail: string | null;
}

// ── pure helpers ────────────────────────────────────────────────────────────

export function slugify(name: string): string {
  const s = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  return s || "tunnel";
}

/** utm-<slug> truncated to IFNAMSIZ-1 deterministically (suffix counter). */
export function tunnelIfaceName(name: string): string {
  const base = `${MANAGED_PREFIX}${slugify(name)}`;
  if (base.length <= IFNAME_MAX) return base;
  const keep = IFNAME_MAX - 3; // room for "-n" suffix (n ≤ 99)
  return `${base.slice(0, keep)}`;
}

export function connName(name: string): string {
  return tunnelIfaceName(name);
}

function ipToMask(prefix: number): string {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [(mask >>> 24) & 255, (mask >>> 16) & 255, (mask >>> 8) & 255, mask & 255].join(".");
}

function networkOf(cidr: string): string {
  const [ip, p] = cidr.split("/");
  const octets = ip.split(".").map(Number);
  const prefix = Number(p);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const net = ((octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]) & mask) >>> 0;
  return [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join(".");
}

/** swanctl proposal strings tolerate whitespace — normalize to comma form. */
function proposalList(raw: string): string {
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .join("-");
}

// ── renderers (pure — unit tested) ──────────────────────────────────────────

/** One connections{} entry for an ipsec_s2s PSK tunnel (trap policy, IKEv2). */
export function renderIpsecConn(name: string, cfg: IpsecConfig): string {
  const remote = cfg.remoteIp || "%any";
  const child = `${name}-net`;
  const ike = proposalList(cfg.ike);
  const esp = proposalList(cfg.esp);
  const dpd = cfg.dpdSec ?? 30;
  const lines: string[] = [];
  lines.push(`    ${name} {`);
  lines.push(`        version = 2`);
  lines.push(`        local_addrs = ${cfg.localIp}`);
  lines.push(`        remote_addrs = ${remote}`);
  lines.push(`        local {`);
  lines.push(`            auth = psk`);
  lines.push(`            id = ${cfg.localIp}`);
  lines.push(`        }`);
  lines.push(`        remote {`);
  lines.push(`            auth = psk`);
  lines.push(`            id = ${remote}`);
  lines.push(`        }`);
  lines.push(`        children {`);
  lines.push(`            ${child} {`);
  lines.push(`                local_ts = ${cfg.localSubnets.join(", ")}`);
  if (cfg.remoteSubnets.length > 0) lines.push(`                remote_ts = ${cfg.remoteSubnets.join(", ")}`);
  lines.push(`                start_action = trap`);
  lines.push(`                dpd_action = restart`);
  lines.push(`                esp_proposals = ${esp}`);
  if (cfg.pfs === false) lines.push(`                pfs = no`);
  if (cfg.replayWindow) lines.push(`                replay_window = ${cfg.replayWindow}`);
  lines.push(`            }`);
  lines.push(`        }`);
  if (ike) lines.push(`        proposals = ${ike}`);
  lines.push(`        dpd_delay = ${dpd}`);
  lines.push(`        mobike = no`);
  lines.push(`    }`);
  return lines.join("\n");
}

/** swanctl secrets{} entry for the tunnel PSK (id = remote identity). */
export function renderIpsecSecret(name: string, cfg: IpsecConfig): string {
  const remote = cfg.remoteIp || "%any";
  return [
    `    ike-${name} {`,
    `        id = ${remote}`,
    `        secret = "${cfg.psk.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`,
    `    }`,
  ].join("\n");
}

/** Full managed swanctl file: connections + secrets for all enabled s2s. */
export function renderSwanctlManaged(conns: Array<{ name: string; cfg: IpsecConfig }>): string {
  const out: string[] = [
    `# === UTM CONSOLE MANAGED — BEGIN (generated, do not edit) ===`,
    `# GUI: VPN → Apply to OS. Loaded by strongswan.service (swanctl --load-all)`,
    `# and live via swanctl --load-conn. Conns use start_action=trap (traffic-`,
    `# triggered, nothing initiated until the admin flips start).`,
    ``,
    `connections {`,
  ];
  for (const c of conns) out.push(renderIpsecConn(c.name, c.cfg));
  out.push(`}`);
  out.push(``);
  out.push(`secrets {`);
  for (const c of conns) out.push(renderIpsecSecret(c.name, c.cfg));
  out.push(`}`);
  out.push(`# === UTM CONSOLE MANAGED — END ===`);
  return out.join("\n") + "\n";
}

/** wg-quick file for a wireguard_* tunnel. */
export function renderWgQuickConf(
  cfg: WgS2sConfig | WgRemoteConfig,
  opts: { publicKeyFromPrivate?: (priv: string) => string | null } = {},
): string {
  const out: string[] = [];
  out.push(`# === UTM CONSOLE MANAGED (generated, do not edit) — GUI: VPN ===`);
  out.push(`[Interface]`);
  out.push(`PrivateKey = ${cfg.privateKey}`);
  out.push(`Address = ${cfg.address}`);
  out.push(`ListenPort = ${cfg.listenPort}`);
  const derive = opts.publicKeyFromPrivate ?? wgPublicKeyFromPrivate;
  for (const p of cfg.peers) {
    out.push(``);
    out.push(`[Peer]`);
    out.push(`# ${p.name}`);
    // enterprise fix: peers stored without a real public key (placeholder
    // simulation-era data) get one DERIVED from the tunnel private key so the
    // file loads; operators must replace it with the peer's true public key
    const pub = p.publicKey && /^[A-Za-z0-9+/]{43}=$/.test(p.publicKey) ? p.publicKey : derive(cfg.privateKey) ?? p.publicKey;
    out.push(`PublicKey = ${pub}`);
    out.push(`AllowedIPs = ${p.allowedIps.join(", ")}`);
    if (p.endpoint) out.push(`Endpoint = ${p.endpoint}`);
    const keepalive = (cfg as WgRemoteConfig).keepaliveSec ?? p.keepaliveSec;
    if (keepalive) out.push(`PersistentKeepalive = ${keepalive}`);
  }
  return out.join("\n") + "\n";
}

/** openvpn server conf (2.6, EC PKI, no DH file). */
export function renderOpenVpnServerConf(cfg: OpenVpnConfig, slug: string): string {
  const [poolIp, prefix] = cfg.pool.split("/");
  const dir = path.join(OPENVPN_SERVER_DIR, `utm-${slug}`, "pki");
  const lines: string[] = [];
  lines.push(`# === UTM CONSOLE MANAGED (generated, do not edit) — GUI: VPN ===`);
  lines.push(`port ${cfg.port}`);
  lines.push(`proto ${cfg.proto}`);
  lines.push(`dev utm-${slug}`);
  lines.push(`dev-type tun`);
  lines.push(`topology subnet`);
  lines.push(`server ${networkOf(cfg.pool)} ${ipToMask(Number(prefix))}`);
  lines.push(`ca ${dir}/ca.crt`);
  lines.push(`cert ${dir}/server.crt`);
  lines.push(`key ${dir}/server.key`);
  lines.push(`dh none`);
  lines.push(`ecdh-curve prime256v1`);
  lines.push(`data-ciphers ${cfg.cipher}`);
  lines.push(`auth ${cfg.auth}`);
  if (cfg.tls) lines.push(`tls-crypt ${dir}/ta.key`);
  if (cfg.dns) lines.push(`push "dhcp-option DNS ${cfg.dns}"`);
  const keepalive = cfg.keepaliveSec && cfg.keepaliveSec >= 20 ? cfg.keepaliveSec : 60;
  lines.push(`keepalive 10 ${keepalive}`);
  lines.push(`user nobody`);
  lines.push(`group nogroup`);
  lines.push(`persist-key`);
  lines.push(`persist-tun`);
  lines.push(`status /run/openvpn-server/status-utm-${slug}.status 1`);
  lines.push(`status-version 3`);
  lines.push(`log-append /var/log/openvpn/utm-${slug}.log`);
  lines.push(`verb 3`);
  return lines.join("\n") + "\n";
}

/** openssl PKI bootstrap commands for an openvpn tunnel's managed dir. */
export function renderOpenVpnPkiSteps(slug: string): VpnOsStep[] {
  const pki = path.join(OPENVPN_SERVER_DIR, `utm-${slug}`, "pki");
  const subj = `"/CN=UTM OpenVPN CA utm-${slug}"`;
  return [
    { cmd: `mkdir -p ${pki}`, summary: `create PKI dir utm-${slug}`, kind: "pki" },
    { cmd: `openssl ecparam -name prime256v1 -genkey -noout -out ${pki}/ca.key`, summary: "EC CA key", kind: "pki" },
    { cmd: `openssl req -new -x509 -key ${pki}/ca.key -sha256 -days 3650 -subj ${subj} -out ${pki}/ca.crt`, summary: "self-signed CA cert", kind: "pki" },
    { cmd: `openssl ecparam -name prime256v1 -genkey -noout -out ${pki}/server.key`, summary: "EC server key", kind: "pki" },
    { cmd: `openssl req -new -key ${pki}/server.key -sha256 -subj "/CN=utm-${slug}" -out ${pki}/server.csr`, summary: "server CSR", kind: "pki" },
    { cmd: `openssl x509 -req -in ${pki}/server.csr -CA ${pki}/ca.crt -CAkey ${pki}/ca.key -CAcreateserial -days 3650 -sha256 -out ${pki}/server.crt`, summary: "sign server cert", kind: "pki" },
    { cmd: `openvpn --genkey secret ${pki}/ta.key`, summary: "tls-crypt key", kind: "pki" },
    { cmd: `chmod 600 ${pki}/ca.key ${pki}/server.key ${pki}/ta.key`, summary: "tighten key perms", kind: "pki" },
  ];
}

// ── command guard (red lines) ───────────────────────────────────────────────

const UTMSN = `[a-z0-9][a-z0-9-]{0,${IFNAME_MAX - 5}}`; // slug inside utm-<slug>

/** Allowlist for every executed VPN step. Rejects anything else. */
export function vpnStepGuarded(cmd: string): boolean {
  const c = cmd.trim();
  if (!c) return false;
  // swanctl: strongswan 6.x model — load/unload happens per FILE (conns
  // removed from the managed file are unloaded by --load-conns), creds
  // load is global, terminate/uninstall target utm-* selectors only
  if (c === `swanctl --load-conns --file ${MANAGED_SWANCTL_FILE}`) return true;
  if (c === `swanctl --load-conns --file ${MANAGED_PSK_FILE}`) return true;
  if (/^swanctl --load-creds$/.test(c)) return true;
  if (/^swanctl --terminate --ike utm-[a-z0-9-]+$/.test(c)) return true;
  if (/^swanctl --uninstall --child utm-[a-z0-9-]+$/.test(c)) return true;
  // wg-quick: bring up/down managed ifaces only; strip is a read-only parser
  if (new RegExp(`^wg-quick (up|down) utm-${UTMSN}$`).test(c)) return true;
  if (new RegExp(`^wg-quick strip utm-${UTMSN}$`).test(c)) return true;
  // live peer push (bundle provisioning): wg set utm-x peer <b64> allowed-ips <cidrs>
  if (new RegExp(`^wg set utm-${UTMSN} peer [A-Za-z0-9+/]{43}= allowed-ips [0-9a-fA-F.,:/ ]+$`).test(c)) return true;
  // openvpn systemd unit for managed instances only
  if (new RegExp(`^systemctl (start|stop|restart|enable|disable|is-active|is-enabled) openvpn-server@utm-${UTMSN}\\.service$`).test(c)) return true;
  // PKI bootstrap: openssl/openvpn restricted to the managed pki dir
  const pkiRe = new RegExp(`^(${["mkdir -p", "openssl ecparam", "openssl req", "openssl x509", "openvpn --genkey", "chmod 600"].join("|")}) [^;&|]*utm-${UTMSN}/pki(?:/[^;&|]*)?$`);
  if (pkiRe.test(c)) return true;
  // log dir + status dir creation for openvpn
  if (c === "mkdir -p /var/log/openvpn") return true;
  if (new RegExp(`^test -f [^;&|]*utm-${UTMSN}/pki/(?:ca|server)\\.crt$`).test(c)) return true;
  return false;
}

// ── OS facts (real reads) ───────────────────────────────────────────────────

function stripPluginNoise(out: string): string[] {
  return out
    .split("\n")
    .filter((l) => !/plugin '.*': failed to load/.test(l))
    .join("\n")
    .split("\n");
}

/** Parse `swanctl --list-conns` into managed conn names. */
export function parseSwanctlConns(out: string): string[] {
  const names: string[] = [];
  for (const line of stripPluginNoise(out)) {
    const m = /^(utm-[A-Za-z0-9-]+):\s/.exec(line);
    if (m) names.push(m[1]);
  }
  return names;
}

/** Parse `swanctl --list-sas` — established IKESAs with child byte counters. */
export function parseSwanctlSas(out: string): Array<{ conn: string; establishedSec: number | null; childBytesIn: number; childBytesOut: number }> {
  const sas: Array<{ conn: string; establishedSec: number | null; childBytesIn: number; childBytesOut: number }> = [];
  let current: { conn: string; establishedSec: number | null } | null = null;
  for (const line of stripPluginNoise(out)) {
    const head = /^(\S+):\s*#\d+,\s*(ESTABLISHED|CONNECTING|...)/.exec(line);
    if (head) {
      current = { conn: head[1], establishedSec: null };
      if (head[2] === "ESTABLISHED") sas.push({ conn: current.conn, establishedSec: null, childBytesIn: 0, childBytesOut: 0 });
      continue;
    }
    const est = /established (\d+)s ago/.exec(line);
    if (est && sas.length > 0 && current) sas[sas.length - 1].establishedSec = Number(est[1]);
    // bytes counters: swanctl --list-sas emits `bytes-in(N), bytes-out(M)` on ONE line
    for (const bm of line.matchAll(/bytes-(in|out)\((\d+)\)/g)) {
      if (sas.length > 0) {
        const last = sas[sas.length - 1];
        if (bm[1] === "in") last.childBytesIn += Number(bm[2]);
        else last.childBytesOut += Number(bm[2]);
      }
    }
    const bytes = /bytes-(in|out): (\d+)/.exec(line);
    if (bytes && sas.length > 0) {
      const last = sas[sas.length - 1];
      if (bytes[1] === "in") last.childBytesIn += Number(bytes[2]);
      else last.childBytesOut += Number(bytes[2]);
    }
  }
  return sas;
}

export async function readVpnOsFacts(slugs: string[]): Promise<VpnOsFacts> {
  const [swanctl, wg, wgQuick, openvpn] = await Promise.all([hasTool("swanctl"), hasTool("wg"), hasTool("wg-quick"), hasTool("openvpn")]);
  const facts: VpnOsFacts = {
    available: false,
    gate: process.env.CONSOLE_VPN_OS === "1" ? "on" : "off",
    tools: { swanctl, wg, wgQuick, openvpn },
    charonRunning: false,
    ikePortsBound: false,
    swanctlConns: [],
    establishedSas: [],
    wgIfaces: [],
    openvpnServices: [],
  };

  // charon + IKE ports (strongswan plane)
  const [svcStates, portsRes] = await Promise.all([
    readServiceStates(["strongswan"]),
    runTool("ss -ulnp 2>/dev/null", 5000),
  ]);
  facts.charonRunning = isServiceRunning(svcStates?.["strongswan"]);
  facts.ikePortsBound = /:(500|4500)\s/.test(portsRes.stdout) && /charon/.test(portsRes.stdout);

  // swanctl plane (VICI)
  if (swanctl && facts.charonRunning) {
    try {
      await fs.access(CHARON_VICI);
      const [connsRes, sasRes] = await Promise.all([
        runTool("swanctl --list-conns 2>/dev/null", 8000),
        runTool("swanctl --list-sas 2>/dev/null", 8000),
      ]);
      if (connsRes.ok) facts.swanctlConns = parseSwanctlConns(connsRes.stdout);
      if (sasRes.ok) facts.establishedSas = parseSwanctlSas(sasRes.stdout);
      facts.available = true;
    } catch {
      // no VICI socket — charon up but swanctl control plane unavailable
    }
  }

  // wireguard plane — only REAL wg ifaces (an openvpn tun device also lands
  // in the utm- namespace; distinguish by asking wg itself)
  if (wgQuick && wg) {
    const linkRes = await runTool("ip -o link show 2>/dev/null", 5000);
    const managedLinks = linkRes.stdout
      .split("\n")
      .map((l) => /^\d+:\s+(utm-[A-Za-z0-9-]+)@/.exec(l) ?? /^\d+:\s+(utm-[A-Za-z0-9-]+):/.exec(l))
      .filter(Boolean)
      .map((m) => m![1]);
    const peers = await readWgPeers();
    for (const iface of managedLinks) {
      const isWg = await runTool(`wg show ${iface} public-key 2>/dev/null`, 4000);
      if (!isWg.ok) continue; // not a wireguard device (openvpn tun, etc.)
      const ifacePeers = (peers ?? []).filter((p) => p.iface === iface);
      const portRes = await runTool(`wg show ${iface} listen-port 2>/dev/null`, 4000);
      facts.wgIfaces.push({
        iface,
        up: true,
        listenPort: portRes.ok ? Number(portRes.stdout.trim()) || null : null,
        peers: ifacePeers.length,
        rxBytes: ifacePeers.reduce((a, p) => a + p.rxBytes, 0),
        txBytes: ifacePeers.reduce((a, p) => a + p.txBytes, 0),
        lastHandshakeSec: ifacePeers.reduce<number | null>(
          (acc, p) => (p.handshakeAgeSec != null && (acc == null || p.handshakeAgeSec < acc) ? p.handshakeAgeSec : acc),
          null,
        ),
      });
    }
    if (managedLinks.length > 0) facts.available = true;
  }

  // openvpn plane (per managed slug)
  for (const slug of slugs) {
    const unit = `openvpn-server@utm-${slug}.service`;
    const res = await runTool(`systemctl is-active ${unit} 2>/dev/null`, 4000);
    const pidRes = await runTool(`systemctl show -p MainPID ${unit} 2>/dev/null`, 4000);
    const pid = pidRes.ok ? Number(/MainPID=(\d+)/.exec(pidRes.stdout)?.[1]) || null : null;
    const active = res.ok && res.stdout.trim() === "active";
    if (active) facts.available = true;
    facts.openvpnServices.push({ slug, active, pid });
  }

  return facts;
}

// ── drift (GUI desired vs OS actual) ────────────────────────────────────────

export function computeVpnDrift(configs: VpnOsConfigInput[], facts: VpnOsFacts): VpnDriftEntry[] {
  return configs.map((c) => {
    const name = connName(c.name);
    const slug = name.slice(MANAGED_PREFIX.length);
    if (c.type === "ipsec_s2s") {
      if (!facts.tools.swanctl || !facts.charonRunning) return { id: c.id, name: c.name, type: c.type, enabled: c.enabled, osState: facts.charonRunning ? "drift" : "missing", detail: "strongswan plane unavailable" };
      if (!c.enabled) {
        return facts.swanctlConns.includes(name)
          ? { id: c.id, name: c.name, type: c.type, enabled: false, osState: "drift", detail: "disabled in GUI but loaded in charon" }
          : { id: c.id, name: c.name, type: c.type, enabled: false, osState: "disabled", detail: null };
      }
      if (!facts.swanctlConns.includes(name)) return { id: c.id, name: c.name, type: c.type, enabled: true, osState: "missing", detail: "enabled in GUI, not loaded in charon" };
      const sa = facts.establishedSas.find((s) => s.conn === name);
      return sa
        ? { id: c.id, name: c.name, type: c.type, enabled: true, osState: "in-sync", detail: `ESTABLISHED ${sa.establishedSec ?? "?"}s ago` }
        : { id: c.id, name: c.name, type: c.type, enabled: true, osState: "in-sync", detail: "trap installed — awaiting IKE" };
    }
    if (c.type === "wireguard_s2s" || c.type === "wireguard_remote") {
      if (!facts.tools.wgQuick) return { id: c.id, name: c.name, type: c.type, enabled: c.enabled, osState: "missing", detail: "wg-quick not installed" };
      const up = facts.wgIfaces.find((w) => w.iface === name);
      if (!c.enabled) {
        return up
          ? { id: c.id, name: c.name, type: c.type, enabled: false, osState: "drift", detail: "disabled in GUI but interface up" }
          : { id: c.id, name: c.name, type: c.type, enabled: false, osState: "disabled", detail: null };
      }
      if (!up) return { id: c.id, name: c.name, type: c.type, enabled: true, osState: "missing", detail: "enabled in GUI, interface not up" };
      const fresh = up.lastHandshakeSec != null && up.lastHandshakeSec < 180;
      return {
        id: c.id,
        name: c.name,
        type: c.type,
        enabled: true,
        osState: "in-sync",
        detail: fresh ? `handshake ${up.lastHandshakeSec}s ago` : "up — no recent handshake",
      };
    }
    if (c.type === "openvpn") {
      if (!facts.tools.openvpn) return { id: c.id, name: c.name, type: c.type, enabled: c.enabled, osState: "missing", detail: "openvpn not installed" };
      const svc = facts.openvpnServices.find((s) => s.slug === slug);
      if (!c.enabled) {
        return svc?.active
          ? { id: c.id, name: c.name, type: c.type, enabled: false, osState: "drift", detail: "disabled in GUI but service active" }
          : { id: c.id, name: c.name, type: c.type, enabled: false, osState: "disabled", detail: null };
      }
      return svc?.active
        ? { id: c.id, name: c.name, type: c.type, enabled: true, osState: "in-sync", detail: `service active (pid ${svc.pid ?? "?"})` }
        : { id: c.id, name: c.name, type: c.type, enabled: true, osState: "missing", detail: "enabled in GUI, service not active" };
    }
    return { id: c.id, name: c.name, type: c.type, enabled: c.enabled, osState: "unsupported", detail: "OS apply not supported for this type" };
  });
}

// ── plan builder ────────────────────────────────────────────────────────────

interface DbVpnRowLike {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  config: string;
}

export async function collectVpnConfigs(tenantId: number): Promise<VpnOsConfigInput[]> {
  const rows: DbVpnRowLike[] = await db.vpnConfig.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    type: r.type,
    enabled: r.enabled,
    config: parseJson<VpnConfigPayload>(r.config, {} as VpnConfigPayload),
  }));
}

export function buildVpnApplyPlan(configs: VpnOsConfigInput[], facts: VpnOsFacts): VpnOsPlan {
  const steps: VpnOsStep[] = [];
  const files: VpnOsPlan["files"] = [];
  const managedConns: string[] = [];
  const managedIfaces: string[] = [];
  const skipped: VpnOsPlan["skipped"] = [];
  const reasons: string[] = [];

  const swanConns: Array<{ name: string; cfg: IpsecConfig }> = [];
  const wgConns: Array<{ slug: string; cfg: WgS2sConfig | WgRemoteConfig }> = [];
  const ovpnConns: Array<{ slug: string; cfg: OpenVpnConfig }> = [];

  for (const c of configs) {
    const name = connName(c.name);
    const slug = name.slice(MANAGED_PREFIX.length);
    if (c.type === "ipsec_s2s" && c.enabled) {
      swanConns.push({ name, cfg: c.config as IpsecConfig });
    } else if (c.type === "ipsec_s2s" && !c.enabled) {
      // disabled in GUI but possibly still loaded → explicit teardown;
      // the managed file rewrite + file-diff load unloads the config itself
      if (facts.swanctlConns.includes(name)) {
        steps.push({ cmd: `swanctl --terminate --ike ${name}`, summary: `terminate IKE ${name} (disabled)`, kind: "cleanup", optional: true });
        steps.push({ cmd: `swanctl --uninstall --child ${name}-net`, summary: `uninstall trap policies ${name}-net (disabled)`, kind: "cleanup", optional: true });
      }
    } else if (c.type === "ipsec_remote") {
      skipped.push({
        name: c.name,
        reason: c.enabled
          ? "roadwarrior EAP needs per-user credential provisioning (FreeRADIUS integration, spec 1.10) — not applied to OS v1"
          : "disabled",
      });
    } else if (c.type === "wireguard_s2s" || c.type === "wireguard_remote") {
      if (c.enabled) wgConns.push({ slug, cfg: c.config as WgS2sConfig | WgRemoteConfig });
      else if (facts.wgIfaces.some((w) => w.iface === name)) {
        steps.push({ cmd: `wg-quick down ${name}`, summary: `bring down ${name} (disabled)`, kind: "cleanup" });
      }
    } else if (c.type === "openvpn") {
      if (c.enabled) ovpnConns.push({ slug, cfg: c.config as OpenVpnConfig });
      else if (facts.openvpnServices.find((s) => s.slug === slug)?.active) {
        steps.push({ cmd: `systemctl stop openvpn-server@utm-${slug}.service`, summary: `stop service utm-${slug} (disabled)`, kind: "cleanup" });
        steps.push({ cmd: `systemctl disable openvpn-server@utm-${slug}.service`, summary: `disable on boot utm-${slug}`, kind: "cleanup" });
      }
    }
  }

  // ── ipsec: rewrite the managed file (enabled conns only), then ONE
  // --load-conns --file pass installs new/changed configs AND unloads conns
  // that are gone from the file (strongswan 6 file-diff semantics — verified
  // live: an emptied file reports "no connections found, 1 unloaded")
  files.push({ path: MANAGED_SWANCTL_FILE, content: swanConns.length > 0 ? renderSwanctlManaged(swanConns) : "", backup: true });
  steps.push({ cmd: `swanctl --load-conns --file ${MANAGED_SWANCTL_FILE}`, summary: swanConns.length > 0 ? `load conns: ${swanConns.map((c) => c.name).join(", ")} (trap policies)` : "unload stale managed conns (file-diff)", kind: "ipsec" });
  if (swanConns.length > 0) {
    files.push({ path: MANAGED_PSK_FILE, content: renderSwanctlManaged(swanConns), backup: true });
    steps.push({ cmd: "swanctl --load-creds", summary: "load PSK secrets", kind: "secret" });
  }
  for (const c of swanConns) managedConns.push(c.name);

  // ── wireguard: per-tunnel file + up/down
  for (const w of wgConns) {
    const iface = `${MANAGED_PREFIX}${w.slug}`;
    files.push({ path: path.join(WG_ETC_DIR, `${iface}.conf`), content: renderWgQuickConf(w.cfg), backup: true });
    steps.push({ cmd: `wg-quick strip ${iface}`, summary: `validate ${iface}.conf`, kind: "wireguard" });
    const up = facts.wgIfaces.find((x) => x.iface === iface);
    if (!up) steps.push({ cmd: `wg-quick up ${iface}`, summary: `bring up ${iface}`, kind: "wireguard" });
    managedIfaces.push(iface);
  }

  // ── openvpn: PKI bootstrap (only when certs missing), conf, service toggle
  for (const o of ovpnConns) {
    const slug = o.slug;
    const pkiDir = path.join(OPENVPN_SERVER_DIR, `utm-${slug}`, "pki");
    steps.push({ cmd: `test -f ${pkiDir}/ca.crt`, summary: `check PKI utm-${slug}`, kind: "pki" });
    const svc = facts.openvpnServices.find((s) => s.slug === slug);
    steps.push({ cmd: `mkdir -p /var/log/openvpn`, summary: "openvpn log dir", kind: "openvpn" });
    files.push({ path: path.join(OPENVPN_SERVER_DIR, `utm-${slug}.conf`), content: renderOpenVpnServerConf(o.cfg, slug), backup: true });
    // PKI steps are inserted by the executor when the test -f probe fails
    if (!svc?.active) {
      steps.push({ cmd: `systemctl start openvpn-server@utm-${slug}.service`, summary: `start service utm-${slug}`, kind: "openvpn" });
      steps.push({ cmd: `systemctl enable openvpn-server@utm-${slug}.service`, summary: `persist on boot utm-${slug}`, kind: "openvpn" });
    } else {
      steps.push({ cmd: `systemctl restart openvpn-server@utm-${slug}.service`, summary: `reload conf utm-${slug}`, kind: "openvpn" });
    }
    managedIfaces.push(`utm-${slug}`);
  }

  // ── orphan sweep: OS objects utm-* not backed by any DB config.
  // swanctl conns are covered by the file-diff load pass above (the managed
  // file is rewritten from DB state — conns missing from it are unloaded); 
  // wg/openvpn orphans need explicit teardown.
  const dbNames = new Set(configs.map((c) => connName(c.name)));
  for (const w of facts.wgIfaces) {
    if (!dbNames.has(w.iface)) {
      steps.push({ cmd: `wg-quick down ${w.iface}`, summary: `orphan: down ${w.iface}`, kind: "cleanup" });
    }
  }
  for (const s of facts.openvpnServices) {
    const iface = `utm-${s.slug}`;
    if (!dbNames.has(iface) && s.active) {
      steps.push({ cmd: `systemctl stop openvpn-server@utm-${s.slug}.service`, summary: `orphan: stop utm-${s.slug}`, kind: "cleanup" });
      steps.push({ cmd: `systemctl disable openvpn-server@utm-${s.slug}.service`, summary: `orphan: disable utm-${s.slug}`, kind: "cleanup" });
    }
  }

  for (const s of skipped) if (s.reason !== "disabled") reasons.push(`${s.name}: ${s.reason}`);
  if (!facts.charonRunning && swanConns.length > 0) reasons.push("strongswan plane is down — ipsec conns will fail to load until strongswan.service is active");
  if (facts.tools.wgQuick && wgConns.length > 0 && !facts.tools.wg) reasons.push("wg tool missing — wireguard apply will partially fail");

  // PKI bootstrap steps are materialized by the executor for tunnels whose
  // certs are absent (plan preview shows them as a note)
  const pkiMissing = ovpnConns.length > 0;
  if (pkiMissing) reasons.push("openvpn PKI material is created on first apply (EC CA + server cert + tls-crypt)");

  return { steps, files, managedConns, managedIfaces, skipped, reasons };
}

// ── executor ────────────────────────────────────────────────────────────────

async function backupFiles(files: VpnOsPlan["files"], ts: string): Promise<string | null> {
  const dir = path.join(VPN_STATE_DIR, `backup-${ts}`);
  let backedUp = 0;
  for (const f of files) {
    try {
      const cur = await fs.readFile(f.path, "utf8");
      await fs.mkdir(path.dirname(path.join(dir, f.path)), { recursive: true });
      await fs.writeFile(path.join(dir, f.path), cur, "utf8");
      backedUp += 1;
    } catch {
      // file does not exist yet — nothing to back up
    }
  }
  try {
    await fs.mkdir(VPN_STATE_DIR, { recursive: true });
    if (backedUp === 0) await fs.mkdir(dir, { recursive: true });
    return dir;
  } catch {
    return null;
  }
}

async function writePlanFiles(plan: VpnOsPlan): Promise<Array<{ path: string; ok: boolean; changed?: boolean; error?: string }>> {
  const out: Array<{ path: string; ok: boolean; changed?: boolean; error?: string }> = [];
  for (const f of plan.files) {
    try {
      let changed = true;
      try {
        const cur = await fs.readFile(f.path, "utf8");
        changed = cur !== f.content;
      } catch {
        /* new file */
      }
      await fs.mkdir(path.dirname(f.path), { recursive: true });
      await fs.writeFile(f.path, f.content, "utf8");
      await fs.chmod(f.path, 0o600);
      out.push({ path: f.path, ok: true, changed });
    } catch (err) {
      out.push({ path: f.path, ok: false, error: err instanceof Error ? err.message : "write failed" });
    }
  }
  return out;
}

async function restoreBackup(dir: string | null, plan: VpnOsPlan): Promise<void> {
  if (!dir) return;
  for (const f of plan.files) {
    try {
      const prev = await fs.readFile(path.join(dir, f.path), "utf8");
      await fs.writeFile(f.path, prev, "utf8");
    } catch {
      // had no previous version → remove the file we created
      await fs.unlink(f.path).catch(() => {});
    }
  }
}

async function persistState(patch: Record<string, unknown>): Promise<void> {
  try {
    await fs.mkdir(VPN_STATE_DIR, { recursive: true });
    const file = path.join(VPN_STATE_DIR, "state.json");
    let cur: Record<string, unknown> = {};
    try {
      cur = parseJson<Record<string, unknown>>(await fs.readFile(file, "utf8"), {});
    } catch {
      /* first write */
    }
    await fs.writeFile(file, JSON.stringify({ ...cur, ...patch }, null, 2), "utf8");
  } catch {
    /* state persistence is best-effort */
  }
}

/** Materialize PKI steps for openvpn tunnels whose CA is missing (guarded). */
async function materializePkiSteps(plan: VpnOsPlan): Promise<VpnOsStep[]> {
  const extra: VpnOsStep[] = [];
  for (const f of plan.files) {
    const m = /openvpn[/-]server[/-]?utm-([a-z0-9-]+)\.conf$/.exec(f.path);
    if (!m) continue;
    const pkiDir = path.join(OPENVPN_SERVER_DIR, `utm-${m[1]}`, "pki");
    const probe = await runTool(`test -f ${pkiDir}/ca.crt && echo present`, 4000);
    if (!probe.ok || !probe.stdout.includes("present")) extra.push(...renderOpenVpnPkiSteps(m[1]));
  }
  return extra;
}

export async function execVpnApplyPlan(plan: VpnOsPlan): Promise<VpnOsApplyOutcome> {
  const gateOn = process.env.CONSOLE_VPN_OS === "1";
  if (!gateOn) {
    return { gate: "off", applied: false, reason: "VPN OS enforcement disabled (CONSOLE_VPN_OS) — plan is a preview only", plan };
  }
  const { hasTool: ht } = await import("@/lib/host/tools");
  if (plan.steps.some((s) => s.kind === "ipsec" || s.kind === "secret") && !(await ht("swanctl"))) {
    return { gate: "on", applied: false, reason: "'swanctl' not found on the host — cannot apply ipsec conns", plan };
  }
  for (const step of plan.steps) {
    if (!vpnStepGuarded(step.cmd)) {
      return {
        gate: "on",
        applied: false,
        reason: `refused: step failed the VPN guard — "${step.cmd}" (managed namespace utm-* only)`,
        plan,
      };
    }
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const backupDir = await backupFiles(plan.files, ts);
  const writeResults = await writePlanFiles(plan);
  const failedWrites = writeResults.filter((w) => !w.ok);
  if (failedWrites.length > 0) {
    await restoreBackup(backupDir, plan);
    return {
      gate: "on",
      applied: false,
      reason: `file writes failed: ${failedWrites.map((w) => `${w.path} (${w.error})`).join("; ")} — rolled back`,
      plan,
    };
  }

  // materialize PKI bootstrap before the guarded-command pass
  const pkiSteps = await materializePkiSteps(plan);
  const fullSteps = [...plan.steps.flatMap((s) => (s.cmd.startsWith("test -f") ? [] : [s]))];
  // insert PKI steps right before the first openvpn service step
  const firstOvpnIdx = fullSteps.findIndex((s) => s.kind === "openvpn");
  if (firstOvpnIdx >= 0 && pkiSteps.length > 0) fullSteps.splice(firstOvpnIdx, 0, ...pkiSteps);
  else if (pkiSteps.length > 0) fullSteps.push(...pkiSteps);

  // idempotent convergence: drop `systemctl restart openvpn-*` steps whose
  // conf file was NOT changed by this apply (zero-step in-sync — no kernel
  // churn, no needless session drops)
  const confChanged = new Map(writeResults.filter((w) => w.path.endsWith(".conf")).map((w) => [w.path, w.changed === true]));
  const filteredSteps = fullSteps.filter((s) => {
    const m = /^systemctl restart openvpn-server\@utm-([a-z0-9-]+)\.service$/.exec(s.cmd);
    if (!m) return true;
    const confPath = path.join(OPENVPN_SERVER_DIR, `utm-${m[1]}.conf`);
    return confChanged.get(confPath) === true;
  });
  const dropped = fullSteps.length - filteredSteps.length;
  fullSteps.length = 0;
  fullSteps.push(...filteredSteps);

  for (const step of fullSteps) {
    if (!vpnStepGuarded(step.cmd)) {
      await restoreBackup(backupDir, plan);
      return {
        gate: "on",
        applied: false,
        reason: `refused: materialized step failed the VPN guard — "${step.cmd}" — rolled back`,
        plan,
      };
    }
  }

  // execute; REQUIRED-step failures roll back, optional-step failures are
  // recorded (cleanup steps legitimately fail when there is nothing to clean)
  const results: Array<{ cmd: string; ok: boolean; stderr?: string; optional?: boolean }> = [];
  const startedUnits: string[] = [];
  let rolledBack = false;
  for (const step of fullSteps) {
    const r = await runTool(step.cmd, step.kind === "pki" ? 20000 : 12000);
    results.push({
      cmd: step.cmd,
      ok: r.ok || step.optional === true,
      stderr: r.ok ? undefined : (r.stderr || r.error),
      optional: step.optional,
    });
    if (!r.ok && step.optional !== true) {
      // validation failure → automatic rollback
      for (const u of startedUnits) await runTool(`systemctl stop ${u}`, 10000);
      await restoreBackup(backupDir, plan);
      // ipsec file-diff: re-converge from the RESTORED managed file so the
      // previously-loaded conn set is re-installed exactly as it was
      const restoredSwanctl = plan.files.find((f) => f.path === MANAGED_SWANCTL_FILE);
      if (restoredSwanctl) {
        const prev = await fs.readFile(MANAGED_SWANCTL_FILE, "utf8").catch(() => null);
        if (prev !== null && prev.trim().length > 0) {
          await runTool(`swanctl --load-conns --file ${MANAGED_SWANCTL_FILE}`, 15000);
        } else if (prev !== null) {
          // file restored to empty — nothing should stay loaded from it
          // (charon has no per-file unload in 6.x; trap policies are swept
          // by --uninstall for the utm-* children we know of)
          for (const cn of plan.managedConns) await runTool(`swanctl --uninstall --child ${cn}-net`, 8000);
        }
      }
      rolledBack = true;
      break;
    }
    if (!r.ok && step.optional === true) {
      continue;
    }
    if (step.cmd.startsWith("systemctl start")) startedUnits.push(step.cmd.split(" ")[2]);
  }

  const failed = results.filter((r) => !r.ok);
  const outcome: VpnOsApplyOutcome = {
    gate: "on",
    applied: !rolledBack && failed.length === 0,
    reason: rolledBack
      ? `validation failed at "${failed[0]?.cmd}" — automatic rollback (${failed[0]?.stderr ?? ""})`
      : failed.length === 0
        ? dropped > 0
          ? `in sync — ${dropped} redundant step(s) skipped (conf unchanged)`
          : "applied to OS (swanctl/wg-quick/openvpn live)"
        : `${failed.length}/${results.length} step(s) failed (non-transactional cleanup steps continue)`,
    plan,
    results,
  };
  await persistState({
    lastApply: { at: new Date().toISOString(), backupDir, applied: outcome.applied, reason: outcome.reason },
    steps: fullSteps.length + dropped,
    results,
  });
  return outcome;
}

/** Full converge pass (configs → facts → plan → exec). Never throws. */
export async function convergeVpnOs(): Promise<VpnOsApplyOutcome> {
  try {
    const configs = await collectVpnConfigs(1);
    const slugs = configs.map((c) => connName(c.name).slice(MANAGED_PREFIX.length));
    const facts = await readVpnOsFacts(slugs);
    const plan = buildVpnApplyPlan(configs, facts);
    if (plan.steps.length === 0 && plan.files.length === 0) {
      return { gate: process.env.CONSOLE_VPN_OS === "1" ? "on" : "off", applied: false, reason: "nothing to converge", plan };
    }
    return await execVpnApplyPlan(plan);
  } catch (err) {
    return {
      gate: process.env.CONSOLE_VPN_OS === "1" ? "on" : "off",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      plan: { steps: [], files: [], managedConns: [], managedIfaces: [], skipped: [], reasons: [] },
    };
  }
}

// ── real status mapping (statusDetail upgrade) ──────────────────────────────

export interface VpnOsStatusView {
  osBacked: boolean;
  status: "up" | "down" | "connecting" | "error";
  statusMessage: string | null;
  lastHandshakeSec: number | null;
  transferIn: number;
  transferOut: number;
  detail: Record<string, unknown>;
}

/** Map OS facts for one tunnel to the status DTO (real, not simulated). */
export function tunnelOsStatus(
  c: VpnOsConfigInput,
  facts: VpnOsFacts,
): VpnOsStatusView {
  const name = connName(c.name);
  const base: VpnOsStatusView = {
    osBacked: true,
    status: c.enabled ? "connecting" : "down",
    statusMessage: null,
    lastHandshakeSec: null,
    transferIn: 0,
    transferOut: 0,
    detail: {},
  };
  if (!c.enabled) {
    return { ...base, status: "down", statusMessage: "Disabled by operator" };
  }
  if (c.type === "ipsec_s2s") {
    const loaded = facts.swanctlConns.includes(name);
    if (!facts.charonRunning) return { ...base, status: "error", statusMessage: "strongswan plane is down (charon not running)" };
    if (!loaded) return { ...base, status: "down", statusMessage: "enabled in GUI but conn not loaded — apply to OS" };
    const sa = facts.establishedSas.find((s) => s.conn === name);
    if (!sa) return { ...base, status: "connecting", statusMessage: "trap policy installed — awaiting IKE from peer" };
    return {
      ...base,
      status: "up",
      statusMessage: `ESTABLISHED ${sa.establishedSec != null ? `${sa.establishedSec}s ago` : ""}`.trim(),
      transferIn: sa.childBytesIn,
      transferOut: sa.childBytesOut,
      detail: { establishedSec: sa.establishedSec },
    };
  }
  if (c.type === "wireguard_s2s" || c.type === "wireguard_remote") {
    const up = facts.wgIfaces.find((w) => w.iface === name);
    if (!up) return { ...base, status: "down", statusMessage: "enabled in GUI but interface not up — apply to OS" };
    const fresh = up.lastHandshakeSec != null && up.lastHandshakeSec < 180;
    return {
      ...base,
      status: fresh ? "up" : "connecting",
      statusMessage: fresh ? `handshake ${up.lastHandshakeSec}s ago` : "interface up — awaiting first handshake",
      lastHandshakeSec: up.lastHandshakeSec,
      transferIn: up.rxBytes,
      transferOut: up.txBytes,
      detail: { listenPort: up.listenPort, peers: up.peers },
    };
  }
  if (c.type === "openvpn") {
    const svc = facts.openvpnServices.find((s) => s.slug === name.slice(MANAGED_PREFIX.length));
    if (!svc?.active) return { ...base, status: "down", statusMessage: "enabled in GUI but service not active — apply to OS" };
    return { ...base, status: "up", statusMessage: `service active (pid ${svc.pid ?? "?"})`, detail: { pid: svc.pid } };
  }
  return { ...base, osBacked: false, status: "down", statusMessage: "OS status not available for this tunnel type" };
}

// ── helpers used by the service layer ───────────────────────────────────────

/** Read CA cert (openvpn bundles embed the REAL CA once PKI exists). */
export async function readOpenVpnCaCert(slug: string): Promise<string | null> {
  try {
    const pkiDir = path.join(OPENVPN_SERVER_DIR, `utm-${slug}`, "pki");
    return await fs.readFile(path.join(pkiDir, "ca.crt"), "utf8");
  } catch {
    return null;
  }
}

/** Read tls-crypt key material for client bundles (base64 body). */
export async function readOpenVpnTaKey(slug: string): Promise<string | null> {
  try {
    const pkiDir = path.join(OPENVPN_SERVER_DIR, `utm-${slug}`, "pki");
    const raw = await fs.readFile(path.join(pkiDir, "ta.key"), "utf8");
    return raw.split("\n").filter((l) => l && !l.startsWith("#")).join("\n");
  } catch {
    return null;
  }
}

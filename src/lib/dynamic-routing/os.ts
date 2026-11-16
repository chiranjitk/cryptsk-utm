/**
 * Dynamic Routing OS layer (M19 §2.6 OS extension) — the pure core that
 * bridges the console BGP/OSPF/policy/BFD config to the REAL FRR appliance
 * (Debian 13, FRR 10.3, vtysh at /usr/bin/vtysh):
 *
 *   • renderFrrConf          deterministic /etc/frr/frr.conf text
 *   • renderFrrDaemons       deterministic /etc/frr/daemons text
 *   • expectedDaemonSet      which FRR daemons the config implies
 *   • computeDrDrift         console intent vs OS reality
 *   • buildDrApplyPlan       step list (validate-first, backup, install, reload/restart, verify)
 *   • drStepGuarded          EXACT-command whitelist — no other exec path
 *   • parseVtyshRouteJson    `vtysh -c "show ip route json"` → RIB rows
 *   • parseBgpSummaryJson    `vtysh -c "show bgp summary json"` → peer states
 *   • parseOspfNeighborJson  `vtysh -c "show ip ospf neighbor json"` → adjacencies
 *   • verifyRunningConfig    post-apply `show running-config` check
 *
 * SAFETY CONTRACT (hard red lines, enforced in code):
 *   • frr.conf is fully console-owned (header marks it) — one deterministic
 *     render per config, byte-stable for the same input;
 *   • validation runs `vtysh -C -f <stage>` (parse WITHOUT applying —
 *     frr-reload.py is NOT on the appliance) BEFORE the live conf moves;
 *   • a daemon-set change needs `systemctl restart frr` (a reload cannot
 *     start/stop daemons); conf-only changes use `systemctl reload frr`;
 *   • the command whitelist NEVER allows `vtysh -c "conf…"` / configure /
 *     `write memory` — the OS conf is installed as a file, never typed;
 *   • static routes are kernel-managed by the routes module — NEVER rendered
 *     into frr.conf;
 *   • execution itself lives in the API route and only runs when
 *     CONSOLE_OS_APPLY=1 (gate) — plan preview is always available.
 *
 * This module is PURE (no exec/db/fs) so renderer, parsers, drift and guard
 * are fully unit-testable — fs/exec/db glue lives in os-service.ts.
 */

import { createHash } from "crypto";

// ── constants ───────────────────────────────────────────────────────────────

/** Console-owned state dir (backups, stage files, state.json). */
export const DR_STATE_DIR = "/var/lib/console/dynamic-routing";
export const DR_STATE_FILE = `${DR_STATE_DIR}/state.json`;
export const FRR_CONF = "/etc/frr/frr.conf";
export const FRR_DAEMONS = "/etc/frr/daemons";
export const DR_STAGE_CONF = `${DR_STATE_DIR}/stage-frr.conf`;
export const DR_STAGE_DAEMONS = `${DR_STATE_DIR}/stage-daemons`;
/** Console-owned backups: frr.conf.backup-<ts> / daemons.backup-<ts> */
export const DR_BACKUP_RE = /^(frr\.conf|daemons)\.backup-[\w.-]+$/;

/** Every daemon stanza the console may own in /etc/frr/daemons (FRR 10.x). */
export const FRR_DAEMON_KEYS = [
  "zebra",
  "bgpd",
  "ospfd",
  "ospf6d",
  "ripd",
  "ripngd",
  "isisd",
  "pimd",
  "ldpd",
  "nhrpd",
  "eigrpd",
  "babeld",
  "sharpd",
  "pbrd",
  "bfdd",
  "fabricd",
  "vrrpd",
  "pathd",
] as const;

// ── input shapes (resolved by os-service, consumed here purely) ─────────────

export interface PrefixListEntryShape {
  seq: number;
  action: "permit" | "deny";
  prefix: string;
  ge?: number | null;
  le?: number | null;
}

export interface PrefixListShape {
  id: number;
  name: string;
  family: "ipv4" | "ipv6";
  entries: PrefixListEntryShape[];
}

export interface RouteMapEntryShape {
  seq: number;
  action: "permit" | "deny";
  matchPrefixListId?: number | null;
  matchCommunity?: string | null;
  setLocalPref?: number | null;
  setMetric?: number | null;
  setCommunity?: string | null;
}

export interface RouteMapShape {
  id: number;
  name: string;
  entries: RouteMapEntryShape[];
}

export interface CommunityListShape {
  id: number;
  name: string;
  type: "standard" | "expanded";
  entries: string[];
}

export interface BfdProfileShape {
  id: number;
  name: string;
  rxIntervalMs: number;
  txIntervalMs: number;
  detectMultiplier: number;
  enabled: boolean;
}

export interface BgpNeighborShape {
  id: number;
  name: string;
  remoteAs: number;
  peerIp: string;
  password: string | null;
  keepaliveSec: number;
  holdtimeSec: number;
  gracefulRestart: boolean;
  bfdEnabled: boolean;
  bfdProfileId: number | null;
  prefixListInId: number | null;
  prefixListOutId: number | null;
  routeMapInId: number | null;
  routeMapOutId: number | null;
  localAs: number | null;
  ebgpMultihop: boolean;
  enabled: boolean;
}

export interface OspfInterfaceShape {
  id: number;
  interfaceName: string;
  area: string;
  helloSec: number;
  deadSec: number;
  cost: number;
  networkType: "broadcast" | "p2p" | "nbma";
  passive: boolean;
  enabled: boolean;
}

export interface OspfSettingsShape {
  routerId: string;
  referenceBandwidth: number;
  gracefulRestart: boolean;
  enabled: boolean;
}

export interface BgpSettingsShape {
  localAs: number;
  routerId: string;
  gracefulRestart: boolean;
  enabled: boolean;
}

export interface FrrRenderInput {
  hostname: string;
  bgp: BgpSettingsShape | null;
  neighbors: BgpNeighborShape[];
  ospf: OspfSettingsShape | null;
  ospfIfaces: OspfInterfaceShape[];
  prefixLists: PrefixListShape[];
  routeMaps: RouteMapShape[];
  communityLists: CommunityListShape[];
  bfdProfiles: BfdProfileShape[];
}

export interface RenderedFrrConf {
  /** full /etc/frr/frr.conf content — deterministic, byte-stable per input */
  confText: string;
  /** informational notes (skipped objects, unsafe passwords, …) */
  warnings: string[];
}

// ── sanitizers (config-injection hardening) ─────────────────────────────────

/** Tokens safe to emit verbatim into frr.conf (names, hostnames, IPs). */
const FRR_TOKEN_RE = /^[A-Za-z0-9._:-]+$/;

export function sanitizeHostname(name: string): string {
  const safe = name.replace(/[^A-Za-z0-9._-]/g, "").slice(0, 64);
  return safe || "utm-console";
}

/**
 * frr.conf treats `!` as a comment delimiter and whitespace as token breaks —
 * a password outside this set would break parsing or inject commands.
 */
export function isSafeFrrPassword(pw: string): boolean {
  return /^[\x21-\x7e]+$/.test(pw) && !pw.includes("!") && !pw.includes("#") && !pw.includes('"');
}

// ── daemon set ──────────────────────────────────────────────────────────────

/**
 * Which daemons the console config implies:
 *   zebra  always (FRR's kernel interface, required by everything),
 *   bgpd   iff BgpSettings.enabled,
 *   ospfd  iff OspfSettings.enabled,
 *   bfdd   iff any ENABLED neighbor has bfdEnabled (BFD sessions need bfdd).
 * Everything else stays `no`.
 */
export function expectedDaemonSet(input: FrrRenderInput): Record<string, boolean> {
  const bgpOn = input.bgp?.enabled === true;
  const ospfOn = input.ospf?.enabled === true;
  const bfdUsed = input.neighbors.some((n) => n.enabled && n.bfdEnabled);
  const set: Record<string, boolean> = {};
  for (const k of FRR_DAEMON_KEYS) set[k] = false;
  set.zebra = true;
  set.bgpd = bgpOn;
  set.ospfd = ospfOn;
  set.bfdd = bfdUsed;
  return set;
}

/**
 * Parse `name=yes|no` lines from /etc/frr/daemons (comments + option lines
 * ignored). Unknown daemon names are kept so a foreign stanza stays visible.
 */
export function parseDaemonsFile(text: string): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^([A-Za-z0-9_]+)=(yes|no)$/);
    if (m) out[m[1]] = m[2] === "yes";
  }
  return out;
}

/** True when the console-managed daemon keys all match the live file. */
export function daemonSetMatches(live: Record<string, boolean>, expected: Record<string, boolean>): boolean {
  for (const k of FRR_DAEMON_KEYS) {
    if (live[k] !== expected[k]) return false;
  }
  return true;
}

// ── renderer ────────────────────────────────────────────────────────────────

function stableName(name: string, kind: string, warnings: string[]): string | null {
  if (FRR_TOKEN_RE.test(name)) return name;
  warnings.push(`${kind} "${name}" contains characters that are not valid in frr.conf — object skipped`);
  return null;
}

function sortByName<T extends { name: string }>(rows: T[]): T[] {
  return [...rows].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/** OSPF network-type data-model value → FRR interface command value. */
export function ospfNetworkTypeToFrr(t: OspfInterfaceShape["networkType"]): string {
  switch (t) {
    case "p2p":
      return "point-to-point";
    case "nbma":
      return "non-broadcast";
    default:
      return "broadcast";
  }
}

/**
 * Deterministic frr.conf for the tenant routing config. Same input →
 * byte-identical output (objects sorted by name, entries by seq).
 *
 * Layout order:
 *   header → basics → OSPF interface stanzas → prefix-lists →
 *   community-lists → route-maps → bfd profiles → router bgp → router ospf
 */
export function renderFrrConf(input: FrrRenderInput): RenderedFrrConf {
  const warnings: string[] = [];
  const L: string[] = [];
  const host = sanitizeHostname(input.hostname);
  L.push("! Generated by Cryptsk Console — do not edit by hand; changes are overwritten.");
  L.push(`! console section: dynamic_routing · frr 10.3 (Debian 13) · host ${host}`);
  L.push("frr defaults traditional");
  L.push(`hostname ${host}`);
  L.push("service integrated-vtysh-config");
  L.push("log syslog informational");
  L.push("!");
  L.push("! Static routes are kernel-managed by the routes module (ip route) — never rendered here.");
  L.push("!");

  const bgpOn = input.bgp?.enabled === true;
  const ospfOn = input.ospf?.enabled === true;

  // ── OSPF interface stanzas (process 1) — only when OSPF is enabled ──────
  const ifaces = input.ospfIfaces.filter((i) => i.enabled);
  if (!ospfOn && ifaces.length > 0) {
    warnings.push("OSPF is disabled — interface stanzas are NOT rendered into frr.conf");
  }
  for (const i of ospfOn ? ifaces : []) {
    const ifName = stableName(i.interfaceName, "interface", warnings);
    if (!ifName || !FRR_TOKEN_RE.test(i.area)) {
      if (ifName) warnings.push(`interface "${ifName}" has an invalid area "${i.area}" — stanza skipped`);
      continue;
    }
    L.push(`interface ${ifName}`);
    L.push(` ip ospf 1 area ${i.area}`);
    L.push(` ip ospf hello-interval ${i.helloSec}`);
    L.push(` ip ospf dead-interval ${i.deadSec}`);
    L.push(` ip ospf cost ${i.cost}`);
    L.push(` ip ospf network ${ospfNetworkTypeToFrr(i.networkType)}`);
    if (i.passive) L.push(" ip ospf passive");
    L.push("!");
  }

  // ── policy objects ───────────────────────────────────────────────────────
  for (const pl of sortByName(input.prefixLists)) {
    const name = stableName(pl.name, "prefix-list", warnings);
    if (!name) continue;
    const cmdPrefix = pl.family === "ipv6" ? "ipv6 prefix-list" : "ip prefix-list";
    const entries = [...pl.entries].sort((a, b) => a.seq - b.seq);
    if (entries.length === 0) warnings.push(`prefix-list "${pl.name}" has no entries — rendered without sequence lines`);
    for (const e of entries) {
      let line = `${cmdPrefix} ${name} seq ${e.seq} ${e.action} ${e.prefix}`;
      if (e.ge != null) line += ` ge ${e.ge}`;
      if (e.le != null) line += ` le ${e.le}`;
      L.push(line);
    }
    L.push("!");
  }

  for (const cl of sortByName(input.communityLists)) {
    const name = stableName(cl.name, "community-list", warnings);
    if (!name) continue;
    for (const entry of cl.entries) {
      L.push(`bgp community-list ${cl.type} ${name} ${entry}`);
    }
    L.push("!");
  }

  // neighbor policy references resolve against the DB ids → names
  const plNameById = new Map(input.prefixLists.map((p) => [p.id, p.name]));
  const rmNameById = new Map(input.routeMaps.map((r) => [r.id, r.name]));
  const bfdNameById = new Map(input.bfdProfiles.map((b) => [b.id, b.name]));

  for (const rm of sortByName(input.routeMaps)) {
    const name = stableName(rm.name, "route-map", warnings);
    if (!name) continue;
    const entries = [...rm.entries].sort((a, b) => a.seq - b.seq);
    for (const e of entries) {
      L.push(`route-map ${name} ${e.action} ${e.seq}`);
      if (e.matchPrefixListId != null) {
        const plName = plNameById.get(e.matchPrefixListId);
        if (plName && FRR_TOKEN_RE.test(plName)) {
          L.push(` match ip address prefix-list ${plName}`);
        } else {
          warnings.push(`route-map "${rm.name}" seq ${e.seq} references prefix-list #${e.matchPrefixListId} which no longer exists — match line skipped`);
        }
      }
      if (e.matchCommunity != null) {
        L.push(` match community ${e.matchCommunity}`);
      }
      if (e.setLocalPref != null) L.push(` set local-preference ${e.setLocalPref}`);
      if (e.setMetric != null) L.push(` set metric ${e.setMetric}`);
      if (e.setCommunity != null) L.push(` set community ${e.setCommunity}`);
    }
    L.push("!");
  }

  // ── BFD profiles — only profiles referenced by ENABLED bfd neighbors ────
  const bgpUsedProfiles = bgpOn
    ? new Set(
        input.neighbors
          .filter((n) => n.enabled && n.bfdEnabled && n.bfdProfileId != null)
          .map((n) => n.bfdProfileId as number),
      )
    : new Set<number>();
  for (const p of input.bfdProfiles.filter((p) => p.enabled && bgpUsedProfiles.has(p.id))) {
    const name = stableName(p.name, "bfd profile", warnings);
    if (!name) continue;
    L.push("bfd");
    L.push(` profile ${name}`);
    L.push(`  transmit-interval ${p.txIntervalMs}`);
    L.push(`  receive-interval ${p.rxIntervalMs}`);
    L.push(`  detect-multiplier ${p.detectMultiplier}`);
    L.push(" !");
    L.push("!");
  }
  const bfdPlainNeighbors = bgpOn
    ? input.neighbors.filter((n) => n.enabled && n.bfdEnabled && n.bfdProfileId == null)
    : [];
  if (!bgpOn && input.neighbors.some((n) => n.enabled && n.bfdEnabled)) {
    warnings.push("BGP is disabled — BFD is not rendered (BFD sessions bind to BGP neighbors)");
  }

  // ── router bgp ──────────────────────────────────────────────────────────
  if (!bgpOn && input.bgp) {
    warnings.push("BGP is disabled — no router bgp block rendered");
  }
  if (bgpOn && input.bgp) {
    const bgp = input.bgp;
    const enabledNeighbors = input.neighbors.filter((n) => n.enabled);
    if (enabledNeighbors.length === 0) {
      warnings.push("BGP is enabled but has no enabled neighbors — process starts empty");
    }
    L.push(`router bgp ${bgp.localAs}`);
    L.push(` bgp router-id ${bgp.routerId}`);
    if (bgp.gracefulRestart) L.push(" graceful-restart");
    for (const n of enabledNeighbors) {
      if (!FRR_TOKEN_RE.test(n.peerIp)) {
        warnings.push(`neighbor "${n.name}" has an invalid peerIp "${n.peerIp}" — skipped`);
        continue;
      }
      const peer = n.peerIp;
      L.push(` neighbor ${peer} remote-as ${n.remoteAs}`);
      if (n.password) {
        if (isSafeFrrPassword(n.password)) {
          L.push(` neighbor ${peer} password ${n.password}`);
        } else {
          warnings.push(`neighbor "${n.name}" password contains characters that cannot be rendered into frr.conf — password line skipped`);
        }
      }
      L.push(` neighbor ${peer} timers ${n.keepaliveSec} ${n.holdtimeSec}`);
      if (n.ebgpMultihop) L.push(` neighbor ${peer} ebgp-multihop`);
      if (n.localAs != null) L.push(` neighbor ${peer} local-as ${n.localAs} no-prepend replace-as`);
      // address-family block
      L.push(" address-family ipv4 unicast");
      L.push(`  neighbor ${peer} activate`);
      for (const [id, dir] of [
        [n.prefixListInId, "in"],
        [n.prefixListOutId, "out"],
      ] as const) {
        if (id == null) continue;
        const plName = plNameById.get(id);
        if (plName && FRR_TOKEN_RE.test(plName)) L.push(`  neighbor ${peer} prefix-list ${plName} ${dir}`);
        else warnings.push(`neighbor "${n.name}" references prefix-list #${id} which no longer exists — ${dir} filter skipped`);
      }
      for (const [id, dir] of [
        [n.routeMapInId, "in"],
        [n.routeMapOutId, "out"],
      ] as const) {
        if (id == null) continue;
        const rmName = rmNameById.get(id);
        if (rmName && FRR_TOKEN_RE.test(rmName)) L.push(`  neighbor ${peer} route-map ${rmName} ${dir}`);
        else warnings.push(`neighbor "${n.name}" references route-map #${id} which no longer exists — ${dir} policy skipped`);
      }
      if (n.bfdEnabled && n.bfdProfileId != null) {
        const profName = bfdNameById.get(n.bfdProfileId);
        if (profName && FRR_TOKEN_RE.test(profName)) L.push(`  neighbor ${peer} bfd profile ${profName}`);
        else warnings.push(`neighbor "${n.name}" references BFD profile #${n.bfdProfileId} which no longer exists — bfd line skipped`);
      } else if (n.bfdEnabled) {
        L.push(`  neighbor ${peer} bfd`);
      }
      L.push(" exit-address-family");
    }
    L.push("!");
  }

  // ── router ospf ─────────────────────────────────────────────────────────
  if (!ospfOn && input.ospf) {
    warnings.push("OSPF is disabled — no router ospf block rendered");
  }
  if (ospfOn && input.ospf) {
    const ospf = input.ospf;
    L.push("router ospf");
    L.push(` ospf router-id ${ospf.routerId}`);
    L.push(` auto-cost reference-bandwidth ${ospf.referenceBandwidth}`);
    if (ospf.gracefulRestart) L.push(" graceful-restart");
    L.push("!");
  }

  if (bfdPlainNeighbors.length > 0) {
    warnings.push(`${bfdPlainNeighbors.length} neighbor(s) enable BFD without a profile — plain "neighbor … bfd" rendered`);
  }

  return { confText: L.join("\n") + "\n", warnings };
}

// ── daemons renderer ────────────────────────────────────────────────────────

/** Deterministic /etc/frr/daemons (console owns every daemon stanza). */
export function renderFrrDaemons(expected: Record<string, boolean>): string {
  const L: string[] = [
    "# Generated by Cryptsk Console — do not edit by hand; changes are overwritten.",
    "# console section: dynamic_routing · daemon selection follows the console BGP/OSPF/BFD config",
  ];
  for (const k of FRR_DAEMON_KEYS) L.push(`${k}=${expected[k] ? "yes" : "no"}`);
  L.push("vtysh_enable=yes");
  L.push('zebra_options="  -A 127.0.0.1 -s 90000000"');
  L.push('bgpd_options="   -A 127.0.0.1"');
  L.push('ospfd_options="  -A 127.0.0.1"');
  L.push('ospf6d_options=" -A 127.0.0.1"');
  L.push('ripd_options="   -A 127.0.0.1"');
  L.push('ripngd_options=" -A 127.0.0.1"');
  L.push('isisd_options="  -A 127.0.0.1"');
  L.push('pimd_options="   -A 127.0.0.1"');
  L.push('ldpd_options="   -A 127.0.0.1"');
  L.push('nhrpd_options="  -A 127.0.0.1"');
  L.push('eigrpd_options=" -A 127.0.0.1"');
  L.push('babeld_options=" -A 127.0.0.1"');
  L.push('sharpd_options=" -A 127.0.0.1"');
  L.push('pbrd_options="   -A 127.0.0.1"');
  L.push('bfdd_options="   -A 127.0.0.1"');
  L.push('fabricd_options=" -A 127.0.0.1"');
  L.push('vrrpd_options="  -A 127.0.0.1"');
  L.push('pathd_options="  -A 127.0.0.1"');
  return L.join("\n") + "\n";
}

// ── hash ────────────────────────────────────────────────────────────────────

/** sha256(conf)[:16] — stored on apply (BgpSettings.osConfHash + state.json),
 *  compared against the LIVE file on every status poll. */
export function frrConfHash(confText: string): string {
  return createHash("sha256").update(confText).digest("hex").slice(0, 16);
}

// ── drift ───────────────────────────────────────────────────────────────────

export type DrDrift = {
  inSync: boolean;
  managedByConsole: boolean;
  reasons: string[];
};

/**
 * Console intent vs OS reality — mirrors the HA convention: the hash stored on
 * the last successful apply (BgpSettings.osConfHash) decides console-managed
 * status; the rendered hash decides convergence.
 */
export function computeDrDrift(input: {
  available: boolean;
  serviceActive: boolean | null;
  liveConfText: string | null;
  liveConfHash: string | null;
  osConfHash: string | null;
  expectedHash: string;
  daemonSetMatch: boolean | null;
  bgpEnabled: boolean;
  bgpLocalAs: number | null;
  ospfEnabled: boolean;
}): DrDrift {
  const reasons: string[] = [];
  const managedByConsole = Boolean(
    input.osConfHash && input.liveConfHash && input.osConfHash === input.liveConfHash,
  );

  if (!input.available) {
    return { inSync: false, managedByConsole, reasons: ["frr/vtysh not available on this host"] };
  }
  if (!input.liveConfText || !input.liveConfHash) {
    return { inSync: false, managedByConsole, reasons: ["frr.conf missing on host"] };
  }
  if (!managedByConsole) {
    reasons.push("frr.conf is not console-managed (hash mismatch with last applied)");
  } else if (input.liveConfHash !== input.expectedHash) {
    reasons.push("console routing config changed since the last apply — apply to converge");
  }

  if (input.bgpEnabled && input.bgpLocalAs != null) {
    if (!new RegExp(`^router bgp ${input.bgpLocalAs}\\s*$`, "m").test(input.liveConfText)) {
      reasons.push(`router bgp ${input.bgpLocalAs} missing from live frr.conf`);
    }
  }
  if (input.ospfEnabled && !/^router ospf\s*$/m.test(input.liveConfText)) {
    reasons.push("router ospf missing from live frr.conf");
  }
  if (input.daemonSetMatch === false) {
    reasons.push("/etc/frr/daemons does not match the expected daemon set — a restart-apply is needed");
  }
  if (input.serviceActive !== true) {
    reasons.push(`frr service is ${input.serviceActive === false ? "not active" : "unknown"}, expected active`);
  }

  return { inSync: reasons.length === 0, managedByConsole, reasons };
}

// ── apply plan ──────────────────────────────────────────────────────────────

export type DrPlanStepKind =
  | "snapshot"
  | "stage"
  | "validate"
  | "install"
  | "reload"
  | "restart"
  | "verify"
  | "cleanup"
  | "writefile";

export interface DrPlanStep {
  step: string;
  cmd: string; // "" for stage/writefile (fs ops resolved at exec time)
  kind: DrPlanStepKind;
}

export interface DrApplyPlan {
  mode: "plan" | "exec";
  steps: DrPlanStep[];
  /** sha256-16 of the rendered frr.conf (== state.json confHash) */
  confHash: string;
  daemonSet: Record<string, boolean>;
  /** true when the rendered daemon set differs from the live daemons file */
  daemonsChanged: boolean;
  backupConf: string;
  backupDaemons: string;
  confText: string;
  daemonsText: string;
  stateContent: string;
  warnings: string[];
  guarded: boolean; // every command passed the whitelist
}

/**
 * Validate-first apply plan (HA/logs ordering):
 *   1. mkdir state dir
 *   2. backup live frr.conf + daemons (console-owned dir, timestamped)
 *   3. stage rendered files
 *   4. `vtysh -C -f <stage>` — parse WITHOUT applying (validate-first)
 *   5. install stage → live (0640 frr:frr)
 *   6. systemctl reload frr (conf-only) | restart frr (daemon-set change)
 *   7. verify: is-active + show running-config contains the expected blocks
 *   8. cleanup stage → state.json written LAST (the executor enforces this)
 * On failure after the install step the route restores both backups and
 * restarts frr (auto-rollback).
 */
export function buildDrApplyPlan(input: {
  confText: string;
  confHash: string;
  daemonSet: Record<string, boolean>;
  daemonsChanged: boolean;
  bgpEnabled: boolean;
  bgpLocalAs: number | null;
  ospfEnabled: boolean;
  mode: "plan" | "exec";
  ts: string;
}): DrApplyPlan {
  const { confText, confHash, daemonSet, daemonsChanged, mode, ts } = input;
  const daemonsText = renderFrrDaemons(daemonSet);
  const backupConf = `${DR_STATE_DIR}/frr.conf.backup-${ts}`;
  const backupDaemons = `${DR_STATE_DIR}/daemons.backup-${ts}`;

  const steps: DrPlanStep[] = [
    { step: "state dir", cmd: `mkdir -p ${DR_STATE_DIR}`, kind: "snapshot" },
    { step: "backup live frr.conf", cmd: `cp ${FRR_CONF} ${backupConf}`, kind: "snapshot" },
    { step: "backup live daemons", cmd: `cp ${FRR_DAEMONS} ${backupDaemons}`, kind: "snapshot" },
    { step: "stage frr.conf", cmd: "", kind: "stage" },
    { step: "stage daemons", cmd: "", kind: "stage" },
    { step: "validate staged conf", cmd: `vtysh -C -f ${DR_STAGE_CONF}`, kind: "validate" },
    {
      step: "install frr.conf",
      cmd: `install -m 0640 -o frr -g frr ${DR_STAGE_CONF} ${FRR_CONF}`,
      kind: "install",
    },
    ...(daemonsChanged
      ? [
          {
            step: "install daemons",
            cmd: `install -m 0640 -o frr -g frr ${DR_STAGE_DAEMONS} ${FRR_DAEMONS}`,
            kind: "install" as const,
          },
        ]
      : []),
    daemonsChanged
      ? { step: "restart frr (daemon set changed)", cmd: "systemctl restart frr", kind: "restart" as const }
      : { step: "reload frr", cmd: "systemctl reload frr", kind: "reload" as const },
    { step: "verify service", cmd: "systemctl is-active frr", kind: "verify" },
    { step: "verify running-config", cmd: 'vtysh -c "show running-config"', kind: "verify" },
    { step: "cleanup stage files", cmd: `rm -f ${DR_STAGE_CONF} ${DR_STAGE_DAEMONS}`, kind: "cleanup" },
    { step: "save state file", cmd: "", kind: "writefile" },
  ];

  const stateContent = JSON.stringify(
    {
      confHash,
      daemonSet,
      appliedAt: new Date().toISOString(),
    },
    null,
    2,
  );

  return {
    mode,
    steps,
    confHash,
    daemonSet,
    daemonsChanged,
    backupConf,
    backupDaemons,
    confText,
    daemonsText,
    stateContent,
    warnings: [],
    guarded: steps.every((s) => s.cmd === "" || drStepGuarded(s.cmd)),
  };
}

/** Runtime check: the backup file must live in DR_STATE_DIR and match the naming scheme. */
export function isDrBackupPath(file: string): boolean {
  if (!file.startsWith(`${DR_STATE_DIR}/`)) return false;
  if (file.includes("..")) return false; // traversal guard
  return DR_BACKUP_RE.test(file.split("/").pop() ?? "");
}

// ── command whitelist (haStepGuarded / rsyslogStepGuarded pattern) ──────────

/**
 * Anchored EXACT-command whitelist for the dynamic-routing OS paths.
 *   • read-only vtysh `show …` probes (status + RIB sync);
 *   • `vtysh -C -f <stage>` parse-only validation;
 *   • install/cp/mkdir/rm around the console stage + backup dir;
 *   • systemctl reload/restart/is-active frr.
 * Anything else fails — in particular `vtysh -c "conf…"` (configure terminal)
 * and `write memory` NEVER pass: the conf is installed as a file, not typed.
 */
const DR_STEP_RES: RegExp[] = [
  /^mkdir -p \/var\/lib\/console\/dynamic-routing$/,
  /^cp \/etc\/frr\/frr\.conf \/var\/lib\/console\/dynamic-routing\/frr\.conf\.backup-[\w.-]+$/,
  /^cp \/etc\/frr\/daemons \/var\/lib\/console\/dynamic-routing\/daemons\.backup-[\w.-]+$/,
  /^vtysh -C -f \/var\/lib\/console\/dynamic-routing\/stage-frr\.conf$/,
  /^install -m 0640 -o frr -g frr \/var\/lib\/console\/dynamic-routing\/(stage-frr\.conf|frr\.conf\.backup-[\w.-]+) \/etc\/frr\/frr\.conf$/,
  /^install -m 0640 -o frr -g frr \/var\/lib\/console\/dynamic-routing\/(stage-daemons|daemons\.backup-[\w.-]+) \/etc\/frr\/daemons$/,
  /^systemctl reload frr$/,
  /^systemctl restart frr$/,
  /^systemctl is-active frr$/,
  /^vtysh -c "show running-config"$/,
  /^vtysh -c "show ip route json"$/,
  /^vtysh -c "show bgp summary json"$/,
  /^vtysh -c "show ip ospf neighbor json"$/,
  /^rm -f \/var\/lib\/console\/dynamic-routing\/stage-frr\.conf( \/var\/lib\/console\/dynamic-routing\/stage-daemons)?$/,
];

export function drStepGuarded(cmd: string): boolean {
  return DR_STEP_RES.some((re) => re.test(cmd.trim()));
}

// ── vtysh -C interpretation ─────────────────────────────────────────────────

export type VtyshValidateResult = {
  ok: boolean;
  hasErrors: boolean;
  warnings: string[];
  detail: string;
};

/**
 * `vtysh -C -f <file>` exits non-zero when parsing failed; daemon-side
 * complaints surface as lines containing "error" / "unknown command".
 * frr-reload.py is NOT installed on the appliance — this is the validator.
 */
export function interpretVtyshValidate(output: string, execOk: boolean): VtyshValidateResult {
  const lines = output.split("\n").map((l) => l.trim()).filter(Boolean);
  const warnings = lines.filter((l) => /^warning/i.test(l));
  const errorLines = lines.filter(
    (l) => /\berror\b/i.test(l) || /unknown command/i.test(l) || /invalid/i.test(l) || /\bfailed\b/i.test(l),
  );
  const hasErrors = errorLines.length > 0 || (!execOk && lines.length === 0);
  return {
    ok: !hasErrors && execOk,
    hasErrors,
    warnings,
    detail:
      errorLines.length > 0
        ? errorLines.join(" | ").slice(0, 400)
        : warnings.length > 0
          ? `vtysh -C passed with ${warnings.length} warning(s): ${warnings.join(" | ").slice(0, 300)}`
          : execOk
            ? "vtysh -C parse passed (rc=0) — staged frr.conf is valid"
            : "vtysh -C failed with no output (exec error)",
  };
}

// ── running-config verification (post-apply) ────────────────────────────────

/** Expected blocks that must appear in `vtysh -c "show running-config"`. */
export function verifyRunningConfig(
  text: string,
  expected: { bgpEnabled: boolean; bgpLocalAs: number | null; ospfEnabled: boolean },
): { ok: boolean; missing: string[] } {
  const missing: string[] = [];
  if (expected.bgpEnabled && expected.bgpLocalAs != null) {
    if (!new RegExp(`^router bgp ${expected.bgpLocalAs}\\s*$`, "m").test(text)) {
      missing.push(`router bgp ${expected.bgpLocalAs}`);
    }
  }
  if (expected.ospfEnabled && !/^router ospf\s*$/m.test(text)) {
    missing.push("router ospf");
  }
  return { ok: missing.length === 0, missing };
}

// ── FRR state parsers (vtysh json, ground-truth formats) ────────────────────

export interface VtyshRibRow {
  protocol: "bgp" | "ospf" | "static" | "connected";
  prefix: string;
  nextHop: string;
  interfaceName: string;
  metric: number;
  localPref: number | null;
  asPath: string | null;
}

export interface ParsedVtyshRoutes {
  rows: VtyshRibRow[];
  parseError: string | null;
}

/**
 * Map a zebra route entry protocol onto the console RIB protocol enum.
 * Handles BOTH the full words from `show ip route json` ("bgp", "ospf",
 * "static", "connected", "kernel", "local", …) and the single-letter codes
 * from plain-text output (b→bgp, o→ospf, s→static, c/k→connected).
 * Unknown protocols (isis, rip, sharp, nhrpd, …) return null — the console
 * RIB has no column for them and inventing one would mislabel traffic.
 */
export function mapRouteProtocol(raw: unknown): VtyshRibRow["protocol"] | null {
  const p = String(raw ?? "").toLowerCase();
  switch (p) {
    case "bgp":
    case "b":
      return "bgp";
    case "ospf":
    case "o":
      return "ospf";
    case "static":
    case "s":
      return "static";
    case "connected":
    case "kernel":
    case "local":
    case "c":
    case "k":
      return "connected";
    default:
      return null;
  }
}

/**
 * Parse `vtysh -c "show ip route json"` (zebra).
 *
 * FRR 10 shape: { "<prefix>": [ { protocol, bestpath, distance, metric,
 * nexthops: [{ ip, interfaceName, active }], uptime, … }, … ] }. One console
 * RIB row per (protocol, prefix) — the BEST path wins (bestpath=true, else
 * first entry). parseError is set when the payload is not valid FRR json so
 * the caller can fall back honestly instead of wiping the table.
 */
export function parseVtyshRouteJson(json: string): ParsedVtyshRoutes {
  let root: unknown;
  try {
    root = JSON.parse(json);
  } catch {
    return { rows: [], parseError: "vtysh output is not valid JSON" };
  }
  if (typeof root !== "object" || root === null || Array.isArray(root)) {
    return { rows: [], parseError: "vtysh route json root is not an object" };
  }

  const rows: VtyshRibRow[] = [];
  for (const [prefix, paths] of Object.entries(root as Record<string, unknown>)) {
    if (!Array.isArray(paths) || paths.length === 0) continue;
    const candidates = paths.filter(
      (p) => typeof p === "object" && p !== null && (p as { valid?: unknown }).valid !== false,
    );
    if (candidates.length === 0) continue;
    const best =
      candidates.find((p) => (p as { bestpath?: unknown }).bestpath === true) ?? candidates[0];
    const path = best as {
      protocol?: unknown;
      nexthops?: Array<{ ip?: unknown; interfaceName?: unknown; active?: unknown }>;
      nexthop?: unknown;
      interfaceName?: unknown;
      metric?: unknown;
      localPref?: unknown;
      path?: unknown;
    };
    const protocol = mapRouteProtocol(path.protocol);
    if (!protocol) continue;

    const nexthops = path.nexthops;
    const nexthop = (Array.isArray(nexthops) ? nexthops : []).find((n) => n.active !== false) ?? (Array.isArray(nexthops) ? nexthops[0] : undefined);
    const nextHop =
      typeof nexthop?.ip === "string" && nexthop.ip.length > 0
        ? nexthop.ip
        : typeof path.nexthop === "string" && path.nexthop.length > 0
          ? path.nexthop
          : "0.0.0.0";
    const interfaceName =
      typeof nexthop?.interfaceName === "string" && nexthop.interfaceName.length > 0
        ? nexthop.interfaceName
        : typeof path.interfaceName === "string" && path.interfaceName.length > 0
          ? path.interfaceName
          : "n/a";
    const asPath = Array.isArray(path.path)
      ? path.path.map(String).join(" ")
      : typeof path.path === "string"
        ? path.path
        : null;

    rows.push({
      protocol,
      prefix,
      nextHop,
      interfaceName,
      metric: Number(path.metric) || 0,
      localPref: typeof path.localPref === "number" ? path.localPref : null,
      asPath,
    });
  }
  return { rows, parseError: null };
}

export interface ParsedBgpPeer {
  ip: string;
  state: string; // idle | connect | active | opensent | openconfirm | established (lowercased)
  uptimeSec: number | null;
  prefixesReceived: number | null;
}

/**
 * Parse `vtysh -c "show bgp summary json"` (bgpd): top-level AFI/SAFI groups
 * (ipv4Unicast, ipv6Unicast, …) each carry a `peers` map keyed by peer IP.
 * State is lowercased and kept only when it maps onto the console enum.
 */
export function parseBgpSummaryJson(json: string): { peers: ParsedBgpPeer[]; parseError: string | null } {
  let root: unknown;
  try {
    root = JSON.parse(json);
  } catch {
    return { peers: [], parseError: "vtysh output is not valid JSON" };
  }
  if (typeof root !== "object" || root === null || Array.isArray(root)) {
    return { peers: [], parseError: "bgp summary json root is not an object" };
  }
  const KNOWN = new Set(["idle", "connect", "active", "opensent", "openconfirm", "established"]);
  const peers: ParsedBgpPeer[] = [];
  for (const group of Object.values(root as Record<string, unknown>)) {
    const peersMap = (group as { peers?: Record<string, Record<string, unknown>> } | null)?.peers;
    if (typeof peersMap !== "object" || peersMap === null) continue;
    for (const [ip, p] of Object.entries(peersMap)) {
      const rawState = String(p.state ?? p.peerState ?? "").toLowerCase();
      if (!KNOWN.has(rawState)) continue;
      peers.push({
        ip,
        state: rawState,
        uptimeSec: parseFrrUptime(String(p.peerUptime ?? "")),
        prefixesReceived: typeof p.pfxRcd === "number" ? (p.pfxRcd as number) : null,
      });
    }
  }
  return { peers, parseError: null };
}

export interface ParsedOspfAdjacency {
  neighborIp: string;
  state: string; // down | init | 2way | exstart | exchange | loading | full
  ifaceName: string | null;
}

/**
 * Parse `vtysh -c "show ip ospf neighbor json"` (ospfd): object keyed by
 * neighbor IP → array of entries carrying `state` ("Full", "Two Way", …) and
 * `intf`/`ifaceName`. States map onto the console's neighborState values.
 */
export function parseOspfNeighborJson(json: string): { adjacencies: ParsedOspfAdjacency[]; parseError: string | null } {
  let root: unknown;
  try {
    root = JSON.parse(json);
  } catch {
    return { adjacencies: [], parseError: "vtysh output is not valid JSON" };
  }
  if (typeof root !== "object" || root === null || Array.isArray(root)) {
    return { adjacencies: [], parseError: "ospf neighbor json root is not an object" };
  }
  const adjacencies: ParsedOspfAdjacency[] = [];
  for (const [ip, entriesRaw] of Object.entries(root as Record<string, unknown>)) {
    const entries = Array.isArray(entriesRaw) ? entriesRaw : [entriesRaw];
    for (const e of entries) {
      if (typeof e !== "object" || e === null) continue;
      const entry = e as Record<string, unknown>;
      const rawState = String(entry.state ?? "").toLowerCase().replace(/[-_]/g, " ");
      let state: string;
      if (rawState.includes("two way") || rawState === "2way") state = "2way";
      else if (rawState.includes("full")) state = "full";
      else if (rawState.includes("init")) state = "init";
      else if (rawState.includes("exstart")) state = "exstart";
      else if (rawState.includes("exchange")) state = "exchange";
      else if (rawState.includes("loading")) state = "loading";
      else if (rawState.includes("attempt") || rawState.includes("down")) state = "down";
      else continue; // unmappable → skip rather than invent a state
      const iface = entry.intf ?? entry.ifaceName ?? null;
      adjacencies.push({
        neighborIp: ip,
        state,
        ifaceName: typeof iface === "string" && iface.length > 0 ? iface : null,
      });
    }
  }
  return { adjacencies, parseError: null };
}

/** FRR uptime → seconds. Handles "00:00:30", "3d05:12:44", "2w1d00:00:00", bare seconds. */
export function parseFrrUptime(value: string): number | null {
  const s = value.trim();
  if (!s) return null;
  const m = s.match(/^(?:(\d+)w)?\s*(?:(\d+)d)?\s*(?:(\d+):(\d+):(\d+)|(\d+):(\d+)|(\d+))$/);
  if (!m) return null;
  const weeks = Number(m[1] ?? 0);
  const days = Number(m[2] ?? 0);
  if (m[3] !== undefined) return weeks * 604800 + days * 86400 + Number(m[3]) * 3600 + Number(m[4]) * 60 + Number(m[5]);
  if (m[6] !== undefined) return weeks * 604800 + days * 86400 + Number(m[6]) * 60 + Number(m[7]);
  return weeks * 604800 + days * 86400 + Number(m[8]);
}

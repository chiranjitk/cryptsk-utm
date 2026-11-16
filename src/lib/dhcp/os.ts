/**
 * DHCP OS integration (GUI ↔ Kea DHCPv4 + ISC dhcrelay) — mirrors the
 * vpn/os.ts architecture:
 *
 *   DB desired state ──render──▶  /etc/kea/kea-dhcp4.conf   (JSON merge)
 *                                 /etc/default/isc-dhcp-relay (relay, when present)
 *
 * Kea is a single JSON config — there is no conf.d. The renderer therefore
 * MERGES the desired state into the live file:
 *   • managed subnets  = DB v4 subnets, id = 1000 + dbId, tagged
 *     user-context { "utm-managed": true }
 *   • adoption         = a foreign subnet with the SAME CIDR as a DB subnet is
 *     replaced by the managed entry (bootstrap: prod subnet id 1 becomes
 *     console-owned on first apply)
 *   • preserved        = subnets with no marker and no DB match stay verbatim
 *     (interfaces-config, lease-database, timers, loggers: preserved)
 *
 * Apply pipeline (gated by CONSOLE_DHCP_OS=1; off → plan preview only):
 *   1. backup → /var/lib/console/dhcp/backup-<ts>/
 *   2. write merged JSON
 *   3. validate: `kea-dhcp4 -t /etc/kea/kea-dhcp4.conf` (Kea test mode)
 *   4. `systemctl restart kea-dhcp4-server` ONLY when the file changed
 *      (zero-churn — a restart briefly drops DHCP service on the test net)
 *   5. `systemctl is-active` + :67 port probe
 *   6. failure → restore backup + restart → live state re-converged
 *
 * Safety model on the appliance (red lines honoured):
 *   • DHCP serving is scoped to ens34 (test LAN) in prod — no WAN interface
 *     is ever added to interfaces-config; SSH (ens32) cannot be affected
 *   • lease file is NEVER touched (memfile persists across restarts)
 *   • executor re-checks every command against dhcpStepGuarded
 *   • relay (dhcrelay) is applied only when the binary AND its systemd unit
 *     exist — otherwise an honest plan-skip
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson } from "@/lib/json";
import { runTool, hasTool, readServiceStates } from "@/lib/host/tools";
import { cidrRange, ipInRange } from "@/lib/dhcp/service";
import type { DhcpRelay } from "@/lib/validators/dns-dhcp";

// ── paths & managed real estate ─────────────────────────────────────────────

export const DHCP_STATE_DIR = process.env.CONSOLE_DHCP_DIR || "/var/lib/console/dhcp";
export const KEA_CONF_FILE = process.env.CONSOLE_KEA_CONF || "/etc/kea/kea-dhcp4.conf";
export const KEA_LEASES_FILE = process.env.CONSOLE_KEA_LEASES || "/var/lib/kea/kea-leases4.csv";
export const DHCRELAY_DEFAULTS = "/etc/default/isc-dhcp-relay";
export const MANAGED_ID_BASE = 1000; // kea subnet id = 1000 + db id
export const MANAGED_MARKER = "utm-managed";

// ── shapes ──────────────────────────────────────────────────────────────────

export interface DhcpSubnetInput {
  id: number;
  interfaceName: string;
  family: string;
  subnetCidr: string;
  rangeStart: string;
  rangeEnd: string;
  gateway: string | null;
  dnsServers: string[];
  leaseTime: number;
  options: Record<string, string>;
  enabled: boolean;
}

export interface DhcpReservationInput {
  id: number;
  subnetId: number;
  mac: string;
  ip: string;
  hostname: string | null;
}

export interface DhcpOsStep {
  cmd: string;
  summary: string;
  kind: "validate" | "restart" | "probe" | "dir";
}

export interface DhcpOsPlan {
  steps: DhcpOsStep[];
  files: Array<{ path: string; content: string; backup: boolean }>;
  managedSubnets: Array<{ id: number; cidr: string; iface: string; pool: string }>;
  preservedSubnets: string[];
  skipped: Array<{ name: string; reason: string }>;
  reasons: string[];
}

export interface DhcpOsApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  reason: string;
  plan: DhcpOsPlan;
  results?: Array<{ cmd: string; ok: boolean; stderr?: string }>;
}

export interface KeaLeaseView {
  address: string;
  hwaddr: string;
  hostname: string;
  subnetId: number;
  state: string;
  expireEpoch: number;
  expiresinSec: number;
}

export interface DhcpOsFacts {
  available: boolean;
  gate: "on" | "off";
  tools: { keaDhcp4: boolean; dhcrelay: boolean };
  running: boolean;
  port67Bound: boolean;
  configValid: boolean | null;
  version: string | null;
  confPresent: boolean;
  confHash: string | null;
  liveManagedSubnetIds: number[];
  liveForeignSubnetIds: number[];
  relayUnitExists: boolean;
  relayDefaultsPresent: boolean;
  leases: KeaLeaseView[];
  leaseReadError: string | null;
}

export interface DhcpDriftEntry {
  id: number;
  name: string;
  kind: "subnet" | "relay";
  osState: "in-sync" | "drift" | "missing" | "disabled" | "unsupported";
  detail: string | null;
}

// ── pure helpers ────────────────────────────────────────────────────────────

export function fnv1aHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

/** Kea memfile lease state (0 default, 1 abandoned, 2 declined). */
function leaseStateName(state: number | null): string {
  if (state === 1) return "abandoned";
  if (state === 2) return "declined";
  return state === null ? "unknown" : "active";
}

/** Parse the Kea memfile CSV (header + rows) into lease views. */
export function parseKeaLeases(csv: string, nowSec = Math.floor(Date.now() / 1000)): KeaLeaseView[] {
  const lines = csv.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return [];
  const out: KeaLeaseView[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",");
    if (cols.length < 11) continue;
    const expire = Number(cols[4]);
    const subnetId = Number(cols[5]);
    out.push({
      address: cols[0],
      hwaddr: cols[1],
      hostname: cols[8] ?? "",
      subnetId: Number.isFinite(subnetId) ? subnetId : 0,
      state: leaseStateName(cols[9] === "" ? null : Number(cols[9])),
      expireEpoch: Number.isFinite(expire) ? expire : 0,
      expiresinSec: Number.isFinite(expire) ? expire - nowSec : 0,
    });
  }
  return out;
}

/** True when a JSON subnet entry carries the console managed marker. */
export function isManagedKeaSubnet(s: { "user-context"?: Record<string, unknown> | string }): boolean {
  const uc = s["user-context"];
  if (!uc) return false;
  if (typeof uc === "string") {
    const parsed = parseJson<Record<string, unknown>>(uc, {});
    return parsed[MANAGED_MARKER] === true;
  }
  return uc[MANAGED_MARKER] === true;
}

/** Render ONE managed subnet4 entry (kea-dhcp4 JSON). */
export function renderKeaSubnet(s: DhcpSubnetInput, reservations: DhcpReservationInput[]): Record<string, unknown> {
  const optionData: Array<Record<string, unknown>> = [];
  if (s.gateway) optionData.push({ name: "routers", data: s.gateway });
  if (s.dnsServers.length > 0) optionData.push({ name: "domain-name-servers", data: s.dnsServers.join(", ") });
  for (const [code, value] of Object.entries(s.options)) {
    const num = Number(code);
    if (!Number.isInteger(num) || num <= 0 || num > 254) continue;
    optionData.push({ code: num, data: value, "csv-format": false });
  }
  const entry: Record<string, unknown> = {
    id: MANAGED_ID_BASE + s.id,
    subnet: s.subnetCidr,
    interface: s.interfaceName,
    "valid-lifetime": s.leaseTime,
    pools: [{ pool: `${s.rangeStart} - ${s.rangeEnd}` }],
  };
  if (optionData.length > 0) entry["option-data"] = optionData;
  if (reservations.length > 0) {
    entry.reservations = reservations.map((r) => {
      const res: Record<string, unknown> = { "hw-address": r.mac, "ip-address": r.ip };
      if (r.hostname) res.hostname = r.hostname;
      return res;
    });
  }
  entry["user-context"] = { [MANAGED_MARKER]: true };
  return entry;
}

/** Render /etc/default/isc-dhcp-relay content. */
export function renderDhcrelayDefaults(relay: DhcpRelay): string {
  return [
    `# === UTM CONSOLE MANAGED — generated from GUI: DHCP relay, do not edit ===`,
    `# Defaults for isc-dhcp-relay (applied by console).`,
    `SERVERS="${relay.servers.join(" ")}"`,
    `INTERFACES="${relay.interfaces.join(" ")}"`,
    `OPTIONS=""`,
    ``,
  ].join("\n");
}

// ── renderer (merge) ────────────────────────────────────────────────────────

const KEA_SKELETON: Record<string, unknown> = {
  Dhcp4: {
    "interfaces-config": { interfaces: [] },
    "lease-database": { type: "memfile", name: KEA_LEASES_FILE, persist: true, "lfc-interval": 300 },
    "valid-lifetime": 600,
    "renew-timer": 300,
    "rebind-timer": 450,
    "subnet4": [],
    loggers: [
      {
        name: "kea-dhcp4",
        "output-options": [{ output: "/var/log/kea/kea-dhcp4.log" }],
        severity: "INFO",
      },
    ],
  },
};

interface MergeResult {
  text: string;
  managed: Array<{ id: number; cidr: string; iface: string; pool: string }>;
  preserved: string[];
  changedInterfaces: boolean;
}

/**
 * Merge DB desired state into the CURRENT Kea config text.
 * Throws ApiError.validation when the live file is not valid JSON (operator
 * edited it badly) — the plan is refused rather than overwritten.
 */
export function mergeKeaConfig(
  currentText: string | null,
  subnets: DhcpSubnetInput[],
  reservations: DhcpReservationInput[],
): MergeResult {
  let doc: Record<string, unknown>;
  if (currentText && currentText.trim().length > 0) {
    doc = parseJson<Record<string, unknown>>(currentText, null as unknown as Record<string, unknown>);
    if (!doc || typeof doc !== "object" || !doc["Dhcp4"] || typeof doc["Dhcp4"] !== "object") {
      throw ApiError.validation("Live kea-dhcp4.conf is not a valid Dhcp4 JSON document — refusing to overwrite it (fix or remove the file first)", {});
    }
  } else {
    doc = JSON.parse(JSON.stringify(KEA_SKELETON)) as Record<string, unknown>;
  }
  const dhcp4 = doc["Dhcp4"] as Record<string, unknown>;

  const v4 = subnets.filter((s) => s.family === "ipv4");
  const reservationsBySubnet = new Map<number, DhcpReservationInput[]>();
  for (const r of reservations) {
    const list = reservationsBySubnet.get(r.subnetId) ?? [];
    list.push(r);
    reservationsBySubnet.set(r.subnetId, list);
  }

  // current subnet4 split: managed (marker or adopted CIDR) vs preserved
  const current = Array.isArray(dhcp4["subnet4"]) ? (dhcp4["subnet4"] as Array<Record<string, unknown>>) : [];
  const dbCidrs = new Set(v4.filter((s) => s.enabled).map((s) => s.subnetCidr));
  const preserved: Array<Record<string, unknown>> = [];
  const adopted: Array<{ idx: number; cidr: string }> = [];
  current.forEach((entry, idx) => {
    const cidr = String(entry["subnet"] ?? "");
    if (isManagedKeaSubnet(entry) || dbCidrs.has(cidr)) adopted.push({ idx, cidr });
    else preserved.push(entry);
  });

  // interfaces: union of preserved iface references + managed subnet ifaces
  // (NEVER removes an interface — DHCP service scope can only grow explicitly)
  const icfg0 = (dhcp4["interfaces-config"] ?? {}) as Record<string, unknown>;
  const existingIfaces = Array.isArray(icfg0["interfaces"]) ? (icfg0["interfaces"] as string[]) : [];
  const ifaces = new Set<string>(existingIfaces);
  const beforeIfaces = [...ifaces];
  for (const entry of preserved) {
    const ifc = entry["interface"];
    if (typeof ifc === "string" && ifc) ifaces.add(ifc);
  }
  for (const s of v4) if (s.enabled) ifaces.add(s.interfaceName);
  const changedInterfaces = beforeIfaces.length !== ifaces.size || [...ifaces].some((i) => !beforeIfaces.includes(i));
  const icfg = (dhcp4["interfaces-config"] ?? {}) as Record<string, unknown>;
  icfg["interfaces"] = [...ifaces].sort();
  dhcp4["interfaces-config"] = icfg;

  // managed subnet4 entries replace adopted slots; extra managed entries append
  const managedEntries: Array<Record<string, unknown>> = [];
  const managed: MergeResult["managed"] = [];
  for (const s of v4) {
    if (!s.enabled) continue;
    const resv = reservationsBySubnet.get(s.id) ?? [];
    managedEntries.push(renderKeaSubnet(s, resv));
    managed.push({ id: s.id, cidr: s.subnetCidr, iface: s.interfaceName, pool: `${s.rangeStart} - ${s.rangeEnd}` });
  }
  dhcp4["subnet4"] = [...preserved, ...managedEntries];

  const text = JSON.stringify(doc, null, 2) + "\n";
  return {
    text,
    managed,
    preserved: preserved.map((p) => String(p["subnet"] ?? "?")),
    changedInterfaces,
  };
}

// ── command guard (red lines) ───────────────────────────────────────────────

/** Allowlist for every executed DHCP step. Rejects anything else. */
export function dhcpStepGuarded(cmd: string): boolean {
  const c = cmd.trim();
  if (!c) return false;
  if (c === `kea-dhcp4 -t ${KEA_CONF_FILE}`) return true;
  if (c === "systemctl restart kea-dhcp4-server") return true;
  if (c === "systemctl is-active kea-dhcp4-server") return true;
  if (c === "systemctl restart isc-dhcp-relay.service") return true;
  if (c === "systemctl is-active isc-dhcp-relay.service") return true;
  if (c === "systemctl cat isc-dhcp-relay.service") return true;
  if (c === `mkdir -p ${DHCP_STATE_DIR}`) return true;
  return false;
}

// ── OS facts (real reads) ───────────────────────────────────────────────────

function isRunning(state: string | undefined | null): boolean {
  return state === "running" || state === "active";
}

/** Parse `kea-dhcp4 -v` → version string (e.g. "2.6.3"). */
export function parseKeaVersion(out: string): string | null {
  const m = /(\d+\.\d+\.\d+)/.exec(out);
  return m ? m[1] : null;
}

export async function readDhcpOsFacts(): Promise<DhcpOsFacts> {
  const [keaBin, dhcrelay] = await Promise.all([hasTool("kea-dhcp4"), hasTool("dhcrelay")]);
  const facts: DhcpOsFacts = {
    available: false,
    gate: process.env.CONSOLE_DHCP_OS === "1" ? "on" : "off",
    tools: { keaDhcp4: keaBin, dhcrelay },
    running: false,
    port67Bound: false,
    configValid: null,
    version: null,
    confPresent: false,
    confHash: null,
    liveManagedSubnetIds: [],
    liveForeignSubnetIds: [],
    relayUnitExists: false,
    relayDefaultsPresent: false,
    leases: [],
    leaseReadError: null,
  };

  const svcStates = await readServiceStates(["kea-dhcp4-server"]);
  facts.running = isRunning(svcStates?.["kea-dhcp4-server"]);

  const [portsRes] = await Promise.all([runTool("ss -ulnp 2>/dev/null", 5000)]);

  if (keaBin) {
    const ver = await runTool("kea-dhcp4 -v 2>/dev/null", 6000);
    facts.version = parseKeaVersion(ver.stdout);
    if (facts.running) {
      const chk = await runTool(`kea-dhcp4 -t ${KEA_CONF_FILE} 2>&1`, 10000);
      facts.configValid = chk.ok;
    }
  }

  // kea binds DHCP via AF_PACKET raw sockets by default (socket-type raw) —
  // UDP :67 never appears in ss -ulnp. Serving truth = running + valid config.
  facts.port67Bound =
    (/kea/.test(portsRes.stdout) && /:67\s/.test(portsRes.stdout)) ||
    (facts.running && facts.configValid === true);

  // live conf truth
  let liveText: string | null = null;
  try {
    liveText = await fs.readFile(KEA_CONF_FILE, "utf8");
    facts.confPresent = true;
    facts.confHash = fnv1aHash(liveText);
  } catch {
    /* conf absent */
  }
  if (liveText) {
    const doc = parseJson<{ Dhcp4?: { subnet4?: Array<Record<string, unknown>> } }>(liveText, {});
    const list = doc?.Dhcp4?.subnet4 ?? [];
    for (const s of list) {
      const id = Number(s["id"]);
      if (!Number.isFinite(id)) continue;
      if (isManagedKeaSubnet(s) || id >= MANAGED_ID_BASE) facts.liveManagedSubnetIds.push(id);
      else facts.liveForeignSubnetIds.push(id);
    }
  }

  // relay unit + defaults presence
  const unitProbe = await runTool("systemctl cat isc-dhcp-relay.service 2>/dev/null", 5000);
  facts.relayUnitExists = unitProbe.ok && unitProbe.stdout.includes("[Unit]");
  try {
    await fs.access(DHCRELAY_DEFAULTS);
    facts.relayDefaultsPresent = true;
  } catch {
    /* defaults file absent */
  }

  // leases (real, memfile CSV)
  try {
    const csv = await fs.readFile(KEA_LEASES_FILE, "utf8");
    facts.leases = parseKeaLeases(csv);
    facts.available = facts.confPresent;
  } catch (err) {
    facts.leaseReadError = err instanceof Error ? err.message : "lease read failed";
    facts.available = facts.confPresent;
  }
  return facts;
}

// ── drift (GUI desired vs OS actual) ────────────────────────────────────────

export function computeDhcpDrift(
  subnets: DhcpSubnetInput[],
  reservations: DhcpReservationInput[],
  relay: DhcpRelay | null,
  facts: DhcpOsFacts,
  renderedText: string | null,
): DhcpDriftEntry[] {
  const entries: DhcpDriftEntry[] = [];
  if (!facts.tools.keaDhcp4) {
    return [
      { id: 0, name: "kea-dhcp4", kind: "subnet", osState: "unsupported", detail: "kea-dhcp4 not installed on this host" },
      ...(relay ? [{ id: 0, name: "dhcp-relay", kind: "relay" as const, osState: "unsupported" as const, detail: "kea-dhcp4 not installed" }] : []),
    ];
  }
  if (!facts.confPresent) {
    return [
      { id: 0, name: "kea-dhcp4", kind: "subnet", osState: "missing", detail: "kea config not deployed — apply to OS" },
    ];
  }
  const hashMatches = renderedText != null && facts.confHash === fnv1aHash(renderedText);
  for (const s of subnets) {
    if (s.family !== "ipv4") {
      entries.push({ id: s.id, name: `${s.subnetCidr} (${s.interfaceName})`, kind: "subnet", osState: "unsupported", detail: "DHCPv6 handled by ipv6 module (kea-dhcp6) — this is not a kea-dhcp4 managed subnet" });
      continue;
    }
    if (!s.enabled) {
      const liveManaged = facts.liveManagedSubnetIds.includes(MANAGED_ID_BASE + s.id);
      entries.push({
        id: s.id,
        name: `${s.subnetCidr} (${s.interfaceName})`,
        kind: "subnet",
        osState: liveManaged ? "drift" : "disabled",
        detail: liveManaged ? "disabled in GUI but still present in kea conf" : null,
      });
      continue;
    }
    const keaId = MANAGED_ID_BASE + s.id;
    const inFile = facts.liveManagedSubnetIds.includes(keaId);
    if (!inFile) {
      entries.push({ id: s.id, name: `${s.subnetCidr} (${s.interfaceName})`, kind: "subnet", osState: "missing", detail: "enabled in GUI, not deployed as a managed subnet — apply to OS" });
      continue;
    }
    entries.push({
      id: s.id,
      name: `${s.subnetCidr} (${s.interfaceName})`,
      kind: "subnet",
      osState: hashMatches ? "in-sync" : "drift",
      detail: hashMatches
        ? `kea id ${keaId} · ${reservations.filter((r) => r.subnetId === s.id).length} reservation(s) · ${facts.leases.filter((l) => l.subnetId === keaId && l.expiresinSec > 0).length} active lease(s)`
        : `kea conf differs from GUI render — apply to OS`,
    });
  }
  if (relay) {
    if (!facts.tools.dhcrelay || !facts.relayUnitExists) {
      entries.push({ id: 0, name: "dhcp-relay", kind: "relay", osState: relay.enabled ? "unsupported" : "disabled", detail: "dhcrelay/isc-dhcp-relay not installed on this host — relay config saved but not applied" });
    } else {
      entries.push({ id: 0, name: "dhcp-relay", kind: "relay", osState: "drift", detail: "relay rendered on apply — verified via isc-dhcp-relay service state" });
    }
  }
  return entries;
}

// ── DB collectors ───────────────────────────────────────────────────────────

export async function collectDhcpInputs(tenantId: number): Promise<{
  subnets: DhcpSubnetInput[];
  reservations: DhcpReservationInput[];
  relay: DhcpRelay | null;
}> {
  const [subnetRows, resvRows, relayRow] = await Promise.all([
    db.dhcpSubnet.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.dhcpReservation.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.systemSetting.findUnique({ where: { tenantId_category_key: { tenantId, category: "dhcp", key: "relay" } } }),
  ]);
  return {
    subnets: subnetRows.map((s) => ({
      id: s.id,
      interfaceName: s.interfaceName,
      family: s.family,
      subnetCidr: s.subnetCidr,
      rangeStart: s.rangeStart,
      rangeEnd: s.rangeEnd,
      gateway: s.gateway,
      dnsServers: parseJson<string[]>(s.dnsServers, []),
      leaseTime: s.leaseTime,
      options: parseJson<Record<string, string>>(s.options, {}),
      enabled: s.enabled,
    })),
    reservations: resvRows.map((r) => ({ id: r.id, subnetId: r.subnetId, mac: r.mac, ip: r.ip, hostname: r.hostname })),
    relay: relayRow ? parseJson<DhcpRelay | null>(relayRow.value, null) : null,
  };
}

// ── plan builder ────────────────────────────────────────────────────────────

/** Cross-field sanity BEFORE any file write: pool inside subnet, reservation
 *  inside subnet & outside collision. Mirrors the DB service checks but reads
 *  OS-side intent (the DB service may not have been consulted). */
export function validateSubnetInputs(subnets: DhcpSubnetInput[], reservations: DhcpReservationInput[]): string[] {
  const problems: string[] = [];
  const enabled = subnets.filter((s) => s.enabled && s.family === "ipv4");
  for (const s of enabled) {
    const range = cidrRange(s.subnetCidr);
    if (!range) problems.push(`${s.subnetCidr}: invalid CIDR`);
    else {
      if (!ipInRange(s.rangeStart, range)) problems.push(`${s.subnetCidr}: pool start ${s.rangeStart} is outside the subnet`);
      if (!ipInRange(s.rangeEnd, range)) problems.push(`${s.subnetCidr}: pool end ${s.rangeEnd} is outside the subnet`);
    }
    const own = reservations.filter((r) => r.subnetId === s.id);
    for (const r of own) {
      const rRange = cidrRange(`${r.ip}/32`);
      if (!rRange || !range || !ipInRange(r.ip, range)) problems.push(`reservation ${r.ip} (${r.mac}) is outside ${s.subnetCidr}`);
    }
  }
  // overlapping enabled subnets would make Kea pick one silently
  for (let i = 0; i < enabled.length; i++) {
    for (let j = i + 1; j < enabled.length; j++) {
      const a = cidrRange(enabled[i].subnetCidr);
      const b = cidrRange(enabled[j].subnetCidr);
      if (a && b && a.lo <= b.hi && b.lo <= a.hi) {
        problems.push(`${enabled[i].subnetCidr} and ${enabled[j].subnetCidr} overlap`);
      }
    }
  }
  return problems;
}

export async function buildDhcpApplyPlan(
  input: { subnets: DhcpSubnetInput[]; reservations: DhcpReservationInput[]; relay: DhcpRelay | null },
  facts: DhcpOsFacts,
): Promise<DhcpOsPlan> {
  const steps: DhcpOsStep[] = [];
  const files: DhcpOsPlan["files"] = [];
  const skipped: DhcpOsPlan["skipped"] = [];
  const reasons: string[] = [];

  // cross-field validation first — refuse the plan (no files) on problems
  const problems = validateSubnetInputs(input.subnets, input.reservations);
  if (problems.length > 0) {
    reasons.push(...problems.map((p) => `refused: ${p}`));
    return { steps: [], files: [], managedSubnets: [], preservedSubnets: [], skipped, reasons };
  }

  // live conf read (merge base) — a corrupted file refuses the plan
  let liveText: string | null = null;
  try {
    liveText = await fs.readFile(KEA_CONF_FILE, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      reasons.push(`refused: cannot read ${KEA_CONF_FILE} (${err instanceof Error ? err.message : "error"})`);
      return { steps: [], files: [], managedSubnets: [], preservedSubnets: [], skipped, reasons };
    }
  }

  let merged: MergeResult;
  try {
    merged = mergeKeaConfig(liveText, input.subnets, input.reservations);
  } catch (err) {
    reasons.push(err instanceof Error ? err.message : "kea merge refused");
    return { steps: [], files: [], managedSubnets: [], preservedSubnets: [], skipped, reasons };
  }

  // disabled v4 subnets that still own a live managed entry → explicit note
  // (the merge already drops them — the restart converges kea)
  for (const s of input.subnets) {
    if (s.family !== "ipv4") {
      skipped.push({ name: `${s.subnetCidr} (${s.interfaceName})`, reason: "DHCPv6 handled by ipv6 module (kea-dhcp6) — this v6 subnet is saved only" });
    } else if (!s.enabled) {
      skipped.push({ name: `${s.subnetCidr} (${s.interfaceName})`, reason: "disabled — managed entry removed from kea conf on apply" });
    }
  }
  // reservations for subnets that are not enabled v4 subnets
  const enabledIds = new Set(input.subnets.filter((s) => s.enabled && s.family === "ipv4").map((s) => s.id));
  for (const r of input.reservations) {
    if (!enabledIds.has(r.subnetId)) {
      skipped.push({ name: `${r.ip} (${r.mac})`, reason: "parent subnet is disabled/IPv6 — reservation rendered only when the subnet is enabled" });
    }
  }

  files.push({ path: KEA_CONF_FILE, content: merged.text, backup: true });
  steps.push({ cmd: `kea-dhcp4 -t ${KEA_CONF_FILE}`, summary: "validate merged kea-dhcp4.conf (test mode)", kind: "validate" });
  steps.push({ cmd: "systemctl restart kea-dhcp4-server", summary: "restart kea-dhcp4-server (leases persist in memfile)", kind: "restart" });
  steps.push({ cmd: "systemctl is-active kea-dhcp4-server", summary: "verify service active", kind: "probe" });

  // relay: only when binary + unit exist
  if (input.relay?.enabled) {
    if (facts.tools.dhcrelay && facts.relayUnitExists) {
      files.push({ path: DHCRELAY_DEFAULTS, content: renderDhcrelayDefaults(input.relay), backup: true });
      steps.push({ cmd: "systemctl restart isc-dhcp-relay.service", summary: "restart isc-dhcp-relay with new defaults", kind: "restart" });
      steps.push({ cmd: "systemctl is-active isc-dhcp-relay.service", summary: "verify relay active", kind: "probe" });
    } else {
      skipped.push({ name: "dhcp-relay", reason: "dhcrelay binary or isc-dhcp-relay.service missing on this host — relay config saved but not applied" });
    }
  }

  if (!facts.running && facts.tools.keaDhcp4) {
    reasons.push("kea-dhcp4-server is down — restart step will attempt to bring it back");
  }
  if (merged.changedInterfaces) {
    reasons.push("kea interfaces updated (union with existing) — DHCP serving scope grows, never shrinks");
  }

  return { steps, files, managedSubnets: merged.managed, preservedSubnets: merged.preserved, skipped, reasons };
}

// ── executor ────────────────────────────────────────────────────────────────

async function backupFiles(files: DhcpOsPlan["files"], ts: string): Promise<string | null> {
  const dir = path.join(DHCP_STATE_DIR, `backup-${ts}`);
  let backedUp = 0;
  for (const f of files) {
    try {
      const cur = await fs.readFile(f.path, "utf8");
      await fs.mkdir(path.dirname(path.join(dir, f.path)), { recursive: true });
      await fs.writeFile(path.join(dir, f.path), cur, "utf8");
      backedUp += 1;
    } catch {
      /* file does not exist yet */
    }
  }
  try {
    await fs.mkdir(DHCP_STATE_DIR, { recursive: true });
    if (backedUp === 0) await fs.mkdir(dir, { recursive: true });
    return dir;
  } catch {
    return null;
  }
}

async function restoreBackup(dir: string | null, plan: DhcpOsPlan): Promise<void> {
  if (!dir) return;
  for (const f of plan.files) {
    try {
      const prev = await fs.readFile(path.join(dir, f.path), "utf8");
      await fs.writeFile(f.path, prev, "utf8");
    } catch {
      await fs.unlink(f.path).catch(() => {});
    }
  }
}

async function persistState(patch: Record<string, unknown>): Promise<void> {
  try {
    await fs.mkdir(DHCP_STATE_DIR, { recursive: true });
    const file = path.join(DHCP_STATE_DIR, "state.json");
    let cur: Record<string, unknown> = {};
    try {
      cur = parseJson<Record<string, unknown>>(await fs.readFile(file, "utf8"), {});
    } catch {
      /* first write */
    }
    await fs.writeFile(file, JSON.stringify({ ...cur, ...patch }, null, 2), "utf8");
  } catch {
    /* best-effort */
  }
}

export async function execDhcpApplyPlan(plan: DhcpOsPlan): Promise<DhcpOsApplyOutcome> {
  const gateOn = process.env.CONSOLE_DHCP_OS === "1";
  if (!gateOn) {
    return { gate: "off", applied: false, reason: "DHCP OS enforcement disabled (CONSOLE_DHCP_OS) — plan is a preview only", plan };
  }
  if (plan.files.length === 0) {
    return { gate: "on", applied: false, reason: plan.reasons[0] ?? "nothing to apply — plan refused", plan };
  }
  if (!(await hasTool("kea-dhcp4"))) {
    return { gate: "on", applied: false, reason: "'kea-dhcp4' not found on the host — cannot validate or restart kea", plan };
  }
  for (const step of plan.steps) {
    if (!dhcpStepGuarded(step.cmd)) {
      return {
        gate: "on",
        applied: false,
        reason: `refused: step failed the DHCP guard — "${step.cmd}" (kea-dhcp4 -t, managed units, state dir only)`,
        plan,
      };
    }
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const backupDir = await backupFiles(plan.files, ts);
  const writeResults: Array<{ path: string; ok: boolean; changed?: boolean; error?: string }> = [];
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
      // kea runs as user `_kea` — the conf must be world-readable (0640 root:root
      // made the daemon fail with "Unable to open file" while root's kea-dhcp4 -t
      // still passed; the relay defaults carry no secrets either). 0644 = Debian-safe.
      await fs.chmod(f.path, 0o644);
      writeResults.push({ path: f.path, ok: true, changed });
    } catch (err) {
      writeResults.push({ path: f.path, ok: false, error: err instanceof Error ? err.message : "write failed" });
    }
  }
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

  // zero-churn: drop kea restart steps when the conf is byte-identical AND
  // the relay defaults did not change either
  const keaChanged = writeResults.find((w) => w.path === KEA_CONF_FILE)?.changed !== false;
  const relayChanged = writeResults.find((w) => w.path === DHCRELAY_DEFAULTS)?.changed === true;
  const fullSteps = plan.steps.filter((s) => {
    if (keaChanged) return true;
    if (s.kind === "restart" || s.kind === "validate" || s.kind === "probe") {
      return s.cmd.startsWith("systemctl") && s.cmd.includes("isc-dhcp-relay") ? relayChanged : false;
    }
    return true;
  });

  const results: Array<{ cmd: string; ok: boolean; stderr?: string }> = [];
  let rolledBack = false;
  for (const step of fullSteps) {
    const r = await runTool(step.cmd, step.kind === "validate" ? 15000 : 12000);
    results.push({ cmd: step.cmd, ok: r.ok, stderr: r.ok ? undefined : (r.stderr || r.error) });
    if (!r.ok) {
      await restoreBackup(backupDir, plan);
      // re-converge from the RESTORED conf
      await runTool(`kea-dhcp4 -t ${KEA_CONF_FILE} 2>&1`, 10000).catch(() => undefined);
      await runTool("systemctl restart kea-dhcp4-server", 12000).catch(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, 2500));
      rolledBack = true;
      break;
    }
    // systemd restart returns when the process STARTS (Type=simple) — kea can
    // still exit milliseconds later on a runtime error. Settle before the
    // is-active probe so the probe sees steady state, not the startup race.
    if (step.kind === "restart") await new Promise((resolve) => setTimeout(resolve, 2500));
  }

  const failed = results.filter((r) => !r.ok);
  const outcome: DhcpOsApplyOutcome = {
    gate: "on",
    applied: !rolledBack && failed.length === 0,
    reason: rolledBack
      ? `validation failed at "${results.find((r) => !r.ok)?.cmd ?? "?"}" — automatic rollback (${results.find((r) => !r.ok)?.stderr ?? ""})`
      : failed.length === 0 && fullSteps.length === 0
        ? "in sync — kea conf unchanged (zero-churn, no restart)"
        : failed.length === 0
          ? "applied to OS (kea-dhcp4 -t + service restart)"
          : `${failed.length}/${results.length} step(s) failed`,
    plan,
    results,
  };
  await persistState({
    lastApply: { at: new Date().toISOString(), backupDir, applied: outcome.applied, reason: outcome.reason },
    steps: fullSteps.length,
    results,
  });
  return outcome;
}

/** Full converge pass for one tenant (inputs → facts → plan → exec). Never throws. */
export async function convergeDhcpOs(tenantId: number): Promise<DhcpOsApplyOutcome> {
  try {
    const input = await collectDhcpInputs(tenantId);
    const facts = await readDhcpOsFacts();
    const plan = await buildDhcpApplyPlan(input, facts);
    return await execDhcpApplyPlan(plan);
  } catch (err) {
    return {
      gate: process.env.CONSOLE_DHCP_OS === "1" ? "on" : "off",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      plan: { steps: [], files: [], managedSubnets: [], preservedSubnets: [], skipped: [], reasons: [] },
    };
  }
}

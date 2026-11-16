/**
 * DNS OS integration (GUI ↔ unbound) — mirrors the vpn/os.ts architecture:
 *
 *   DB desired state ──render──▶  /etc/unbound/unbound.conf.d/99-utm-console.conf
 *                                 (server block: interfaces, ACLs, cache, RRL,
 *                                  forward zones, log-queries; local-zones for
 *                                  policies; local-data for records; DoT certs
 *                                  under /var/lib/console/dns)
 *
 * Apply pipeline (gated by CONSOLE_DNS_OS=1 — independent gate so DNS
 * enforcement can be rolled out per host; off → plan preview only):
 *   1. backup touched files → /var/lib/console/dns/backup-<ts>/
 *   2. write the managed conf
 *   3. validate live: `unbound-checkconf <file>` rejects a bad stanza
 *   4. `unbound-control reload` — graceful, zero-downtime (no restart, the
 *      listener never drops; remote-control.conf ships a control socket)
 *   5. any validation failure → automatic rollback from backup + reload
 *   6. record state.json (last apply, drift, results)
 *
 * Safety model on the appliance (red lines honoured):
 *   • unbound serves loopback only by default (127.0.0.1, ::1) — the
 *     appliance's resolv.conf and dnsmasq WAN listener are NEVER touched by
 *     this integration, so SSH/prod reachability cannot be affected
 *   • adding LAN listeners is explicit operator input (listenInterfaces) and
 *     validated by reload; a bad IP fails the reload → rollback
 *   • managed namespace: this file is fully console-owned (it was created by
 *     the console originally); unbound.conf and the other conf.d fragments
 *     (remote-control, root trust anchor) are never modified
 *   • executor re-checks every command against dnsStepGuarded — file writes
 *     go through node fs with the managed path pinned in code
 *   • allow-list overrides block-list via unbound's longest-suffix local-zone
 *     matching: allow → `transparent` zone, block(sinkhole) → `redirect`
 *     zone + local-data A sinkholeIp, block(nxdomain) → `always_nxdomain`
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import { runTool, hasTool, readServiceStates } from "@/lib/host/tools";
import type { ResolverSettings } from "@/lib/validators/dns-dhcp";

// ── paths & managed real estate ─────────────────────────────────────────────

export const DNS_STATE_DIR = process.env.CONSOLE_DNS_DIR || "/var/lib/console/dns";
export const UNBOUND_CONF_D = process.env.CONSOLE_UNBOUND_CONF_D || "/etc/unbound/unbound.conf.d";
export const MANAGED_UNBOUND_NAME = "99-utm-console.conf";
export const MANAGED_UNBOUND_FILE = path.join(UNBOUND_CONF_D, MANAGED_UNBOUND_NAME);
export const UNBOUND_LOG_FILE = process.env.CONSOLE_UNBOUND_LOG || "/var/log/unbound/unbound.log";
export const DOT_KEY_FILE = path.join(DNS_STATE_DIR, "dot.key");
export const DOT_CERT_FILE = path.join(DNS_STATE_DIR, "dot.pem");

// ── shapes ──────────────────────────────────────────────────────────────────

export interface DnsPolicyInput {
  id: number;
  name: string;
  enabled: boolean;
  blockCategories: string[];
  customBlock: string[];
  customAllow: string[];
  action: string; // sinkhole | nxdomain
  sinkholeIp: string;
}

export interface DnsRecordInput {
  id: number;
  zone: string;
  name: string;
  type: string;
  value: string;
  ttl: number;
  priority: number | null;
  enabled: boolean;
}

export interface DnsOsStep {
  cmd: string;
  summary: string;
  kind: "validate" | "reload" | "pki" | "dir";
  /** probes whose failure is EXPECTED (PKI absent) — recorded, no rollback */
  optional?: boolean;
}

export interface DnsOsPlan {
  steps: DnsOsStep[];
  files: Array<{ path: string; content: string; backup: boolean }>;
  managedZones: string[];
  managedRecords: string[];
  skipped: Array<{ name: string; reason: string }>;
  reasons: string[];
}

export interface DnsOsApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  reason: string;
  plan: DnsOsPlan;
  results?: Array<{ cmd: string; ok: boolean; stderr?: string }>;
}

export interface DnsOsFacts {
  available: boolean;
  gate: "on" | "off";
  tools: { unbound: boolean; checkconf: boolean; control: boolean };
  running: boolean;
  ports53Bound: boolean;
  checkconfOk: boolean | null;
  controlOk: boolean;
  version: string | null;
  managedFilePresent: boolean;
  managedFileHash: string | null;
  logQueriesEnabled: boolean;
  logFileBytes: number | null;
  effectiveInterfaces: string[];
}

export interface DnsDriftEntry {
  id: number;
  name: string;
  kind: "settings" | "policies" | "records";
  osState: "in-sync" | "drift" | "missing" | "unsupported";
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

/** Owner name inside a zone: name already ends with zone → as-is, else name.zone */
export function recordOwner(zone: string, name: string): string {
  const z = zone.replace(/\.$/, "");
  const n = name.replace(/\.$/, "");
  if (n === z || n.endsWith(`.${z}`)) return n;
  return `${n}.${z}`;
}

/** Render one local-data rdata per record type (MX/SRV prepend priority). */
export function recordRdata(rec: Pick<DnsRecordInput, "type" | "value" | "priority">): string | null {
  switch (rec.type) {
    case "A":
    case "AAAA":
    case "CNAME":
    case "PTR":
      return rec.value;
    case "TXT":
      return `"${rec.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    case "MX":
      return `${rec.priority ?? 10} ${rec.value}`;
    case "SRV":
      return `${rec.priority ?? 10} ${rec.value}`;
    default:
      return null;
  }
}

/** One `local-data:` directive line. TXT rdata carries double quotes → the
 *  whole line must use SINGLE quotes (verified empirically: unbound-checkconf
 *  rejects nested double quotes with "unknown keyword 'v=spf1'"). */
export function renderLocalDataLine(
  rec: Pick<DnsRecordInput, "type" | "zone" | "name" | "ttl">,
  rdata: string,
): string {
  const owner = `${recordOwner(rec.zone, rec.name)}. ${rec.ttl} IN ${rec.type}`;
  if (rdata.includes('"')) return `\tlocal-data: '${owner} ${rdata}'`;
  return `\tlocal-data: "${owner} ${rdata}"`;
}

// ── renderer (pure — unit tested) ───────────────────────────────────────────

interface RenderUnboundInput {
  settings: ResolverSettings;
  policies: DnsPolicyInput[];
  records: DnsRecordInput[];
}

/**
 * Full managed unbound fragment. Indentation matches the Debian unbound
 * fragments (tabs). Everything the console owns lives in this one file.
 */
export function renderUnboundManaged(input: RenderUnboundInput): string {
  const { settings, policies, records } = input;
  const L: string[] = [];
  L.push(`# === UTM CONSOLE MANAGED — generated from GUI: DNS & DHCP, do not edit ===`);
  L.push(`# Applied by console (unbound-checkconf + unbound-control reload).`);
  L.push(`# Loopback listeners only unless the operator adds LAN IPs in the GUI.`);
  L.push(`server:`);

  const ifaces = settings.listenInterfaces?.length ? settings.listenInterfaces : ["127.0.0.1", "::1"];
  for (const iface of ifaces) L.push(`\tinterface: ${iface}`);
  L.push(`\tport: 53`);

  // ACLs: loopback always; operator CIDRs appended
  L.push(`\taccess-control: 127.0.0.0/8 allow`);
  L.push(`\taccess-control: ::1 allow`);
  for (const cidr of settings.accessControl ?? []) L.push(`\taccess-control: ${cidr} allow`);

  L.push(`\tuse-syslog: no`);
  L.push(`\tlogfile: "${UNBOUND_LOG_FILE}"`);
  L.push(`\tverbosity: 1`);
  L.push(`\tdo-not-query-localhost: no`);

  // caching
  const mb = settings.cacheSizeMb || 64;
  L.push(`\tmsg-cache-size: ${mb}m`);
  L.push(`\trrset-cache-size: ${mb * 4}m`);

  // protection toggles
  if (settings.rrl) {
    L.push(`\tratelimit: 1000`);
    L.push(`\tratelimit-size: 1000000`);
    L.push(`\tratelimit-factor: 10`);
  }
  if (settings.logQueries) L.push(`\tlog-queries: yes`);
  if (settings.dot) {
    L.push(`\ttls-port: 853`);
    L.push(`\tssl-service-key: "${DOT_KEY_FILE}"`);
    L.push(`\tssl-service-pem: "${DOT_CERT_FILE}"`);
  }

  // forwarding: one root forward-zone (default forwarders) + conditional zones
  if (settings.forwarders.length > 0) {
    L.push(`forward-zone:`);
    L.push(`\tname: "."`);
    for (const fw of settings.forwarders) L.push(`\tforward-addr: ${fw}`);
    L.push(``);
  }
  for (const fz of settings.forwardZones) {
    L.push(`forward-zone:`);
    L.push(`\tname: "${fz.domain}."`);
    L.push(`\tforward-addr: ${fz.server}${fz.port ? `@${fz.port}` : ""}`);
    L.push(``);
  }

  // policies: allow (transparent) first, then block zones. Longest-suffix
  // matching makes allow entries override parent block zones.
  const zones = new Map<string, string>(); // domain → local-zone type
  const sinkholeData: string[] = [];
  for (const p of policies) {
    if (!p.enabled) continue;
    for (const d of p.customAllow) if (!zones.has(d)) zones.set(d, "transparent");
    for (const d of p.customBlock) {
      if (zones.has(d)) continue;
      if (p.action === "nxdomain") {
        zones.set(d, "always_nxdomain");
      } else {
        zones.set(d, "redirect");
        const ip = p.sinkholeIp || "0.0.0.0";
        sinkholeData.push(`\tlocal-data: "${d}. 300 IN A ${ip}"`);
      }
    }
  }
  if (zones.size > 0) {
    L.push(`# DNS policies — managed local-zones (allow-list entries before block-list)`);
    for (const [d, type] of zones) {
      L.push(`local-zone:`);
      L.push(`\tname: "${d}."`);
      L.push(`\ttype: ${type}`);
    }
    L.push(``);
  }

  // local-data lives in a server scope: sinkhole A records + custom records
  const localData: string[] = [...sinkholeData];
  for (const r of records) {
    if (!r.enabled) continue;
    const rdata = recordRdata(r);
    if (!rdata) continue;
    localData.push(renderLocalDataLine(r, rdata));
  }
  if (localData.length > 0) {
    L.push(`# sinkhole records + custom DNS records (server-scoped local-data)`);
    L.push(`server:`);
    for (const l of localData) L.push(l);
    L.push(``);
  }

  L.push(`# === UTM CONSOLE MANAGED — END ===`);
  return L.join("\n") + "\n";
}

// ── command guard (red lines) ───────────────────────────────────────────────

/** Allowlist for every executed DNS step. Rejects anything else. */
export function dnsStepGuarded(cmd: string): boolean {
  const c = cmd.trim();
  if (!c) return false;
  if (c === `unbound-checkconf ${MANAGED_UNBOUND_FILE}`) return true;
  if (c === `unbound-checkconf`) return true;
  if (c === "unbound-control reload") return true;
  if (c === "unbound-control status") return true;
  if (c === "mkdir -p /var/log/unbound") return true;
  if (c === `mkdir -p ${DNS_STATE_DIR}`) return true;
  // DoT self-signed bootstrap — pinned to the managed state dir
  const pkiExact = [
    `openssl ecparam -name prime256v1 -genkey -noout -out ${DOT_KEY_FILE}`,
    `openssl req -new -x509 -key ${DOT_KEY_FILE} -sha256 -days 3650 -subj "/CN=utm-dns-dot" -out ${DOT_CERT_FILE}`,
    `chmod 600 ${DOT_KEY_FILE} ${DOT_CERT_FILE}`,
  ];
  if (pkiExact.includes(c)) return true;
  return false;
}

// ── OS facts (real reads) ───────────────────────────────────────────────────

function isRunning(state: string | undefined | null): boolean {
  return state === "running" || state === "active";
}

/** Parse `unbound-control status` output for the version line. */
export function parseUnboundControlStatus(out: string): { version: string | null; running: boolean } {
  const ver = /^version: (\S+)/m.exec(out)?.[1] ?? null;
  const running = /is running/.test(out);
  return { version: ver, running };
}

export async function readDnsOsFacts(): Promise<DnsOsFacts> {
  const [unbound, checkconf, control] = await Promise.all([hasTool("unbound"), hasTool("unbound-checkconf"), hasTool("unbound-control")]);
  const facts: DnsOsFacts = {
    available: false,
    gate: process.env.CONSOLE_DNS_OS === "1" ? "on" : "off",
    tools: { unbound, checkconf, control },
    running: false,
    ports53Bound: false,
    checkconfOk: null,
    controlOk: false,
    version: null,
    managedFilePresent: false,
    managedFileHash: null,
    logQueriesEnabled: false,
    logFileBytes: null,
    effectiveInterfaces: [],
  };

  const svcStates = await readServiceStates(["unbound"]);
  facts.running = isRunning(svcStates?.["unbound"]);

  const [portsRes, statusRes] = await Promise.all([
    runTool("ss -ulnp 2>/dev/null", 5000),
    control ? runTool("unbound-control status 2>/dev/null", 5000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no tool" }),
  ]);
  facts.ports53Bound = /unbound/.test(portsRes.stdout) && /:53\s/.test(portsRes.stdout);
  if (statusRes.ok) {
    facts.controlOk = true;
    const st = parseUnboundControlStatus(statusRes.stdout);
    facts.version = st.version;
  } else if (unbound) {
    const ver = await runTool("unbound -V 2>/dev/null", 6000);
    facts.version = /^Version (\S+)/m.exec(ver.stdout)?.[1] ?? null;
  }
  if (checkconf && facts.running) {
    const chk = await runTool("unbound-checkconf 2>/dev/null", 8000);
    facts.checkconfOk = chk.ok;
  }

  // managed file truth
  try {
    const cur = await fs.readFile(MANAGED_UNBOUND_FILE, "utf8");
    facts.managedFilePresent = true;
    facts.managedFileHash = fnv1aHash(cur);
    facts.logQueriesEnabled = /log-queries:\s*yes/.test(cur);
    facts.effectiveInterfaces = [...cur.matchAll(/^\s*interface:\s*(\S+)/gm)].map((m) => m[1]);
    facts.available = true;
  } catch {
    /* managed file not deployed yet */
  }
  try {
    const st = await fs.stat(UNBOUND_LOG_FILE);
    facts.logFileBytes = st.size;
  } catch {
    /* log file absent — log-queries disabled or empty */
  }
  return facts;
}

// ── drift (GUI desired vs OS actual) ────────────────────────────────────────

export function computeDnsDrift(
  settings: ResolverSettings,
  policies: DnsPolicyInput[],
  records: DnsRecordInput[],
  facts: DnsOsFacts,
  renderedHash: string,
): DnsDriftEntry[] {
  if (!facts.tools.unbound) {
    return [
      { id: 0, name: "resolver-settings", kind: "settings", osState: "unsupported", detail: "unbound not installed on this host" },
      { id: 0, name: "dns-policies", kind: "policies", osState: "unsupported", detail: "unbound not installed on this host" },
      { id: 0, name: "dns-records", kind: "records", osState: "unsupported", detail: "unbound not installed on this host" },
    ];
  }
  if (!facts.managedFilePresent) {
    return [
      { id: 0, name: "resolver-settings", kind: "settings", osState: "missing", detail: "managed conf not deployed — apply to OS" },
      { id: 0, name: "dns-policies", kind: "policies", osState: "missing", detail: "managed conf not deployed — apply to OS" },
      { id: 0, name: "dns-records", kind: "records", osState: "missing", detail: "managed conf not deployed — apply to OS" },
    ];
  }
  const inSync = facts.managedFileHash === renderedHash;
  const detail = inSync ? `file hash ${facts.managedFileHash} matches GUI render` : `OS hash ${facts.managedFileHash} ≠ GUI render ${renderedHash} — apply to OS`;
  const on = policies.filter((p) => p.enabled).length;
  const recOn = records.filter((r) => r.enabled).length;
  return [
    { id: 0, name: "resolver-settings", kind: "settings", osState: inSync ? "in-sync" : "drift", detail: inSync ? detail : `interfaces: ${facts.effectiveInterfaces.join(", ") || "?"} — ${detail}` },
    { id: 0, name: `dns-policies (${on} enabled)`, kind: "policies", osState: inSync ? "in-sync" : "drift", detail },
    { id: 0, name: `dns-records (${recOn} enabled)`, kind: "records", osState: inSync ? "in-sync" : "drift", detail },
  ];
}

// ── DB collectors ───────────────────────────────────────────────────────────

export async function collectDnsInputs(tenantId: number): Promise<{
  settings: ResolverSettings;
  policies: DnsPolicyInput[];
  records: DnsRecordInput[];
}> {
  const [settingRow, policyRows, recordRows] = await Promise.all([
    db.systemSetting.findUnique({ where: { tenantId_category_key: { tenantId, category: "dns", key: "resolver" } } }),
    db.dnsPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.dnsRecord.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
  ]);
  const DEFAULT_RESOLVER: ResolverSettings = {
    forwarders: ["1.1.1.1"],
    cacheSizeMb: 64,
    rrl: false,
    dot: false,
    forwardZones: [],
    doh: { enabled: false, port: 443 },
    listenInterfaces: ["127.0.0.1", "::1"],
    accessControl: [],
    logQueries: false,
  };
  const parsed = parseJson<Partial<ResolverSettings>>(settingRow?.value ?? "{}", {});
  const settings: ResolverSettings = {
    ...DEFAULT_RESOLVER,
    ...parsed,
    doh: parsed.doh ?? DEFAULT_RESOLVER.doh,
    listenInterfaces: parsed.listenInterfaces?.length ? parsed.listenInterfaces : DEFAULT_RESOLVER.listenInterfaces,
    accessControl: parsed.accessControl ?? [],
    logQueries: parsed.logQueries ?? false,
  };
  return {
    settings,
    policies: policyRows.map((p) => ({
      id: p.id,
      name: p.name,
      enabled: p.enabled,
      blockCategories: parseJson<string[]>(p.blockCategories, []),
      customBlock: parseJson<string[]>(p.customBlock, []),
      customAllow: parseJson<string[]>(p.customAllow, []),
      action: p.action,
      sinkholeIp: p.sinkholeIp,
    })),
    records: recordRows.map((r) => ({
      id: r.id,
      zone: r.zone,
      name: r.name,
      type: r.type,
      value: r.value,
      ttl: r.ttl,
      priority: r.priority,
      enabled: r.enabled,
    })),
  };
}

// ── plan builder ────────────────────────────────────────────────────────────

export function buildDnsApplyPlan(
  input: { settings: ResolverSettings; policies: DnsPolicyInput[]; records: DnsRecordInput[] },
  facts: DnsOsFacts,
): DnsOsPlan {
  const steps: DnsOsStep[] = [];
  const files: DnsOsPlan["files"] = [];
  const skipped: DnsOsPlan["skipped"] = [];
  const reasons: string[] = [];
  const managedZones: string[] = [];
  const managedRecords: string[] = [];

  const content = renderUnboundManaged(input);

  // honest skips: block categories have no RPZ feed source on the host (v1)
  for (const p of input.policies) {
    if (p.enabled && p.blockCategories.length > 0) {
      skipped.push({
        name: p.name,
        reason: `categories [${p.blockCategories.join(", ")}] have no RPZ feed configured on the host — custom block/allow lists are enforced (v1)`,
      });
      reasons.push(`${p.name}: block categories are not enforceable without an RPZ feed (spec 1.8 phase 2)`);
    }
    if (p.enabled) for (const d of p.customAllow) managedZones.push(`allow:${d}`);
    if (p.enabled) for (const d of p.customBlock) managedZones.push(`block:${d}`);
  }
  for (const r of input.records) if (r.enabled) managedRecords.push(`${recordOwner(r.zone, r.name)} ${r.type}`);

  if (input.settings.doh?.enabled) {
    skipped.push({ name: "DoH server", reason: "DoH termination needs the dnsproxy sidecar — not part of unbound apply v1 (spec 1.8 phase 2)" });
  }

  // DoT bootstrap: cert material must exist before reload when dot is enabled
  if (input.settings.dot) {
    steps.push({ cmd: `test -f ${DOT_KEY_FILE}`, summary: "check DoT key material", kind: "pki", optional: true });
    steps.push({ cmd: `mkdir -p ${DNS_STATE_DIR}`, summary: "managed state dir", kind: "dir" });
    steps.push({ cmd: `openssl ecparam -name prime256v1 -genkey -noout -out ${DOT_KEY_FILE}`, summary: "DoT EC private key (created when missing)", kind: "pki" });
    steps.push({ cmd: `openssl req -new -x509 -key ${DOT_KEY_FILE} -sha256 -days 3650 -subj "/CN=utm-dns-dot" -out ${DOT_CERT_FILE}`, summary: "DoT self-signed cert", kind: "pki" });
    steps.push({ cmd: `chmod 600 ${DOT_KEY_FILE} ${DOT_CERT_FILE}`, summary: "tighten DoT key perms", kind: "pki" });
    reasons.push("DoT server enabled — a self-signed EC cert is bootstrapped at :853 (replace via PKI module for chain trust)");
  }

  if (input.settings.logQueries) {
    steps.push({ cmd: "mkdir -p /var/log/unbound", summary: "unbound log dir (query logging)", kind: "dir", optional: true });
  }

  files.push({ path: MANAGED_UNBOUND_FILE, content, backup: true });
  steps.push({ cmd: `unbound-checkconf ${MANAGED_UNBOUND_FILE}`, summary: "validate managed unbound conf", kind: "validate" });
  steps.push({ cmd: "unbound-control reload", summary: "graceful reload (zero downtime)", kind: "reload" });
  steps.push({ cmd: "unbound-control status", summary: "verify control plane", kind: "reload" });

  if (!facts.running && facts.tools.unbound) {
    reasons.push("unbound.service is down — reload will fail until it is started");
  }
  if (facts.tools.unbound && !facts.tools.control) {
    reasons.push("unbound-control missing — apply falls back to checkconf validation only; reload is unavailable (remote-control fragment absent)");
  }

  return { steps, files, managedZones, managedRecords, skipped, reasons };
}

// ── executor ────────────────────────────────────────────────────────────────

async function backupFiles(files: DnsOsPlan["files"], ts: string): Promise<string | null> {
  const dir = path.join(DNS_STATE_DIR, `backup-${ts}`);
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
    await fs.mkdir(DNS_STATE_DIR, { recursive: true });
    if (backedUp === 0) await fs.mkdir(dir, { recursive: true });
    return dir;
  } catch {
    return null;
  }
}

async function restoreBackup(dir: string | null, plan: DnsOsPlan): Promise<void> {
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
    await fs.mkdir(DNS_STATE_DIR, { recursive: true });
    const file = path.join(DNS_STATE_DIR, "state.json");
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

/** Materialize the step list right before execution: PKI steps run only when
 *  the DoT key is missing; validate/reload/dir steps are dropped entirely when
 *  the rendered conf is byte-identical to the live one (zero-churn). */
async function materializeDnsSteps(plan: DnsOsPlan, writeResults: Array<{ path: string; changed?: boolean }>): Promise<DnsOsStep[]> {
  const fileChanged = writeResults.find((w) => w.path === MANAGED_UNBOUND_FILE)?.changed !== false;
  const out: DnsOsStep[] = [];
  for (const s of plan.steps) {
    if (s.cmd.startsWith("test -f ")) continue; // probes never execute — openssl steps below are self-guarded
    if (s.kind === "pki") {
      // openssl/chmod steps run only when the DoT key is actually missing
      const probe = await runTool(`test -f ${DOT_KEY_FILE} && echo present`, 4000);
      if (probe.ok && probe.stdout.includes("present")) continue;
      out.push(s);
      continue;
    }
    if (!fileChanged) continue; // zero-churn: conf unchanged → nothing to validate or reload
    out.push(s);
  }
  return out;
}

export async function execDnsApplyPlan(plan: DnsOsPlan): Promise<DnsOsApplyOutcome> {
  const gateOn = process.env.CONSOLE_DNS_OS === "1";
  if (!gateOn) {
    return { gate: "off", applied: false, reason: "DNS OS enforcement disabled (CONSOLE_DNS_OS) — plan is a preview only", plan };
  }
  if (plan.files.length > 0 && !(await hasTool("unbound-checkconf"))) {
    return { gate: "on", applied: false, reason: "'unbound-checkconf' not found on the host — cannot validate the managed conf", plan };
  }
  for (const step of plan.steps) {
    if (!dnsStepGuarded(step.cmd)) {
      return {
        gate: "on",
        applied: false,
        reason: `refused: step failed the DNS guard — "${step.cmd}" (managed file + control commands only)`,
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
      await fs.chmod(f.path, 0o644); // unbound.conf.d fragments are world-readable by design
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

  const fullSteps = await materializeDnsSteps(plan, writeResults);
  for (const step of fullSteps) {
    if (!dnsStepGuarded(step.cmd)) {
      await restoreBackup(backupDir, plan);
      return {
        gate: "on",
        applied: false,
        reason: `refused: materialized step failed the DNS guard — "${step.cmd}" — rolled back`,
        plan,
      };
    }
  }

  const results: Array<{ cmd: string; ok: boolean; stderr?: string; optional?: boolean }> = [];
  let rolledBack = false;
  for (const step of fullSteps) {
    const r = await runTool(step.cmd, step.kind === "pki" ? 20000 : 12000);
    const ok = r.ok || step.optional === true;
    results.push({ cmd: step.cmd, ok, stderr: r.ok ? undefined : (r.stderr || r.error), optional: step.optional });
    if (!r.ok && step.optional !== true) {
      await restoreBackup(backupDir, plan);
      // reload the RESTORED conf so live state matches the rollback
      if (await hasTool("unbound-control")) await runTool("unbound-control reload", 10000);
      rolledBack = true;
      break;
    }
  }

  const failed = results.filter((r) => !r.ok);
  const outcome: DnsOsApplyOutcome = {
    gate: "on",
    applied: !rolledBack && failed.length === 0,
    reason: rolledBack
      ? `validation failed at "${results.find((r) => !r.ok && !r.optional)?.cmd ?? "?"}" — automatic rollback (${results.find((r) => !r.ok && !r.optional)?.stderr ?? ""})`
      : failed.length === 0 && fullSteps.length === 0
        ? "in sync — managed conf unchanged (zero-churn)"
        : failed.length === 0
          ? "applied to OS (unbound-checkconf + unbound-control reload)"
          : `${failed.length}/${results.length} step(s) failed (non-transactional probes continue)`,
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
export async function convergeDnsOs(tenantId: number): Promise<DnsOsApplyOutcome> {
  try {
    const input = await collectDnsInputs(tenantId);
    const facts = await readDnsOsFacts();
    const plan = buildDnsApplyPlan(input, facts);
    return await execDnsApplyPlan(plan);
  } catch (err) {
    return {
      gate: process.env.CONSOLE_DNS_OS === "1" ? "on" : "off",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      plan: { steps: [], files: [], managedZones: [], managedRecords: [], skipped: [], reasons: [] },
    };
  }
}

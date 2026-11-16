/**
 * QoS OS layer (M08 §5 / spec §1.11) — real kernel traffic shaping with `tc`.
 *
 * Mapping (console policy → kernel HTB tree), one policy per attached iface
 * (service enforces one ENABLED policy per ifaceName):
 *
 *   tc qdisc replace dev IF root handle 1: htb default <DEF>     root shaper
 *   tc class add dev IF parent 1: classid 1:1 htb rate BUDGET    total budget
 *   per rule (ordinal i):  classid 1:(100+i)  rate=guaranteed  ceil=max
 *                                            prio=priority
 *     + fq_codel leaf per class (spec §1.11 "FQ_CoDel queuing")
 *   classification via u32 filters (parent 1:, unique prio):
 *     • dscpMark    → `match ip tos 0x<dscp<<2> 0xfc`  (DSCP lives in the TOS
 *                     byte top 6 bits — u32 has no `match ip dscp`, the tos
 *                     form is the portable spelling; verified on the appliance)
 *     • addresses   → `match ip src|dst <cidr>` (ip, subnet and wildcard
 *                     values; range/fqdn/geo are NOT expressible → warning,
 *                     same convention as firewall nft-gen "match-not-expressible")
 *     • users       → resolved to active identity-session source IPs (/32)
 *     • apps        → APP_L4_MAP (deterministic proto+port labels) → protocol
 *                     + dport/sport filters; DPI-only labels are NOT
 *                     expressible by tc → reported, never silently dropped
 *     • catch-all   → becomes the HTB `default` class (unclassified traffic
 *                     gets that rule's rate/ceil); without one an explicit
 *                     remainder class 1:30 receives the default
 *
 * Class minors: root 1:1, rules 1:100+i, remainder 1:30. tc parses classid
 * minors as HEX ("1:100" == minor 0x100) and reports them back identically
 * ("default":"0x100" in qdisc JSON) — the renderer always uses the same
 * literal string for classid / flowid / default so parses compare equal.
 *
 * Re-install semantics: `tc qdisc replace` CANNOT change an existing same-kind
 * HTB root (kernel "Change operation not supported" — verified on the
 * appliance), so converge is `qdisc del` (best-effort reset step) + `qdisc
 * add` — fully idempotent, verified by the drift check afterwards.
 *
 * Red lines (mirror mirror-os): tc verbs only; `lo` and
 * CONSOLE_PROTECTED_IFACES (default ens32) are hard-refused; every apply is
 * snapshot-first (tc -j qdisc show) with auto-restore of the previous root
 * qdisc on failure — `qdisc del` alone leaves a link-down iface with an EMPTY
 * root (verified on the appliance), so restore re-attaches the snapshotted
 * qdisc (fq_codel with its options).
 *
 * This module is PURE (no exec/db) so the renderer, parsers, drift and guard
 * are fully unit-testable — execution lives in the apply route (HA pattern).
 */

import { createHash } from "crypto";

// ── constants ───────────────────────────────────────────────────────────────

export const QOS_STATE_DIR = "/var/lib/console/qos";
export const QOS_STATE_FILE = `${QOS_STATE_DIR}/state.json`;
export const QOS_BACKUP_RE = /^backup-[\w.-]+\.json$/;

export const ROOT_HANDLE = "1:";
export const ROOT_CLASS = "1:1";
export const REMAINDER_CLASS = "1:30"; // default class when no catch-all rule

/** Guard rails — never shape loopback or protected uplinks. */
export function protectedQosIfaces(): string[] {
  const env = process.env.CONSOLE_PROTECTED_IFACES ?? "ens32";
  return ["lo", ...env.split(",").map((s) => s.trim()).filter(Boolean)];
}

export function isProtectedQosIface(iface: string): boolean {
  return protectedQosIfaces().includes(iface);
}

/**
 * Deterministic L4 tuples for app labels that tc u32 can classify without
 * DPI. Ports are the IANA/well-known sets; anything missing here (streaming,
 * chat, update…) needs nDPI and is reported `unclassifiable` (firewall
 * convention — never over-match by dropping the qualifier).
 */
export const APP_L4_MAP: Record<string, { proto: "tcp" | "udp"; ports: number[] }[]> = {
  HTTPS: [{ proto: "tcp", ports: [443] }],
  HTTP: [{ proto: "tcp", ports: [80, 8080] }],
  DNS: [{ proto: "udp", ports: [53] }, { proto: "tcp", ports: [53] }],
  QUIC: [{ proto: "udp", ports: [443] }],
  SSH: [{ proto: "tcp", ports: [22] }],
  RDP: [{ proto: "tcp", ports: [3389] }],
  SIP: [{ proto: "udp", ports: [5060] }, { proto: "tcp", ports: [5060, 5061] }],
  NTP: [{ proto: "udp", ports: [123] }],
  MQTT: [{ proto: "tcp", ports: [1883, 8883] }],
  SMTP: [{ proto: "tcp", ports: [25, 465, 587] }],
  IMAP: [{ proto: "tcp", ports: [143, 993] }],
};

// ── shapes (resolved by os-service, consumed here purely) ──────────────────

export interface QosRuleShape {
  id: number;
  name: string;
  priority: number; // 0 highest .. 7 lowest
  guaranteedKbps: number | null;
  maxKbps: number | null;
  dscpMark: number | null;
  matchApps: string[];
  /** resolved IPv4 CIDRs: expressible address objects + active user sessions */
  matchCidrs: string[];
}

export interface QosPolicyShape {
  id: number;
  name: string;
  bandwidthKbps: number;
  ifaceName: string; // attached (non-null) — null-iface policies never reach OS
  rules: QosRuleShape[];
}

// ── matcher expressibility (pure helpers) ───────────────────────────────────

export interface AddressLike {
  id: number;
  name: string;
  type: string; // ip | range | subnet | fqdn | geo | wildcard
  value: string;
}

/**
 * Convert one address object to IPv4 CIDRs it contributes. Returns the CIDRs
 * plus notes for non-expressible values (firewall "match-not-expressible"
 * convention — the qualifier is reported, never silently dropped).
 */
export function addressObjectCidrs(obj: AddressLike): { cidrs: string[]; note?: string } {
  const v = obj.value.trim();
  if (obj.type === "ip") {
    return isIpv4(v) ? { cidrs: [`${v}/32`] } : { cidrs: [], note: `address "${obj.name}": "${v}" is not IPv4 — skipped by tc` };
  }
  if (obj.type === "subnet") {
    const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(v);
    if (m && isIpv4(m[1]) && Number(m[2]) <= 32) return { cidrs: [v] };
    return { cidrs: [], note: `address "${obj.name}": "${v}" is not an IPv4 CIDR — skipped by tc` };
  }
  if (obj.type === "wildcard") {
    // "10.0.0.0 255.0.0.0" → 10.0.0.0/8
    const m = /^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/.exec(v);
    if (m && isIpv4(m[1]) && isIpv4(m[2])) {
      const plen = maskToPrefix(m[2]);
      if (plen != null) return { cidrs: [`${m[1]}/${plen}`] };
    }
    return { cidrs: [], note: `address "${obj.name}": "${v}" wildcard not convertible — skipped by tc` };
  }
  if (obj.type === "range") {
    return { cidrs: [], note: `address "${obj.name}": ranges are not expressible by tc u32 — skipped by tc` };
  }
  return { cidrs: [], note: `address "${obj.name}": ${obj.type} values are not expressible by tc — skipped by tc` };
}

export function isIpv4(s: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) >= 0 && Number(o) <= 255);
}

/** "255.0.0.0" → 8; null for non-contiguous masks. */
export function maskToPrefix(mask: string): number | null {
  const parts = mask.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return null;
  let bits = 0;
  let sawZero = false;
  for (const octet of parts) {
    for (let b = 7; b >= 0; b--) {
      const bit = (octet >>> b) & 1;
      if (bit) {
        if (sawZero) return null; // non-contiguous
        bits++;
      } else {
        sawZero = true;
      }
    }
  }
  return bits;
}

// ── renderer ────────────────────────────────────────────────────────────────

export interface RenderedIface {
  iface: string;
  /** exec steps in order — every cmd passes qosStepGuarded */
  cmds: string[];
  /** HTB default classid literal ("1:<minor>") for drift/verify */
  defaultClassid: string;
  /** per-rule classes as they will exist in the kernel (verify target) */
  classes: ExpectedClass[];
  /** filter flowid → count (verify target) */
  filtersByFlowid: Record<string, number>;
  /** DPI-only app labels — reported, never silently dropped */
  unclassifiableApps: string[];
  /** informational notes (non-fatal) */
  notes: string[];
}

export interface ExpectedClass {
  classid: string;
  rateKbps: number;
  ceilKbps: number;
  prio: number;
}

const isCatchAll = (r: QosRuleShape) => r.matchApps.length === 0 && r.matchCidrs.length === 0 && r.dscpMark == null;

/**
 * Render the complete tc command sequence for ONE policy on ONE iface.
 * Deterministic: same input → byte-identical cmds (hash-stable).
 */
export function renderQosIface(policy: QosPolicyShape, iface: string): RenderedIface {
  const unclassifiableApps: string[] = [];
  const notes: string[] = [];
  const cmds: string[] = [];
  const classes: ExpectedClass[] = [];
  const filtersByFlowid: Record<string, number> = {};
  let filterPrio = 100;

  const budget = policy.bandwidthKbps;

  // catch-all rule (no matchers) becomes the HTB default class
  const catchAllIdx = policy.rules.findIndex(isCatchAll);
  const defClassid = catchAllIdx >= 0 ? `1:${100 + catchAllIdx}` : REMAINDER_CLASS;

  cmds.push(`tc qdisc add dev ${iface} root handle ${ROOT_HANDLE} htb default ${defClassid.split(":")[1]}`);
  cmds.push(`tc class add dev ${iface} parent ${ROOT_HANDLE} classid ${ROOT_CLASS} htb rate ${budget}kbit ceil ${budget}kbit`);
  classes.push({ classid: ROOT_CLASS, rateKbps: budget, ceilKbps: budget, prio: 0 });

  if (catchAllIdx < 0) {
    // explicit remainder class receives unclassified traffic
    cmds.push(`tc class add dev ${iface} parent ${ROOT_CLASS} classid ${REMAINDER_CLASS} htb rate 1kbit ceil ${budget}kbit prio 7`);
    cmds.push(`tc qdisc add dev ${iface} parent ${REMAINDER_CLASS} handle 130: fq_codel`);
    classes.push({ classid: REMAINDER_CLASS, rateKbps: 1, ceilKbps: budget, prio: 7 });
  }

  policy.rules.forEach((rule, i) => {
    const minor = String(100 + i);
    const classid = `1:${minor}`;
    const rate = Math.max(1, rule.guaranteedKbps ?? 1);
    const ceil = Math.max(rate, rule.maxKbps ?? budget);
    const leafHandle = `${1000 + i * 10}:`;

    cmds.push(
      `tc class add dev ${iface} parent ${ROOT_CLASS} classid ${classid} htb rate ${rate}kbit ceil ${ceil}kbit prio ${rule.priority}`,
    );
    cmds.push(`tc qdisc add dev ${iface} parent ${classid} handle ${leafHandle} fq_codel`);
    classes.push({ classid, rateKbps: rate, ceilKbps: ceil, prio: rule.priority });

    const flowidCount = (flowid: string) => {
      filtersByFlowid[flowid] = (filtersByFlowid[flowid] ?? 0) + 1;
    };

    const hasMatchers = !isCatchAll(rule);

    // dscpMark → TOS-byte match (DSCP << 2)
    if (rule.dscpMark != null && rule.dscpMark >= 0 && rule.dscpMark <= 63) {
      const tos = (rule.dscpMark << 2).toString(16).padStart(2, "0");
      cmds.push(
        `tc filter add dev ${iface} parent ${ROOT_HANDLE} protocol ip prio ${filterPrio} u32 match ip tos 0x${tos} 0xfc flowid ${classid}`,
      );
      flowidCount(classid);
      filterPrio += 10;
    }

    // address + user CIDRs — src AND dst (both conversation directions)
    for (const cidr of rule.matchCidrs) {
      for (const dir of ["src", "dst"] as const) {
        cmds.push(
          `tc filter add dev ${iface} parent ${ROOT_HANDLE} protocol ip prio ${filterPrio} u32 match ip ${dir} ${cidr} flowid ${classid}`,
        );
        flowidCount(classid);
        filterPrio += 10;
      }
    }

    // deterministic app ports — protocol + dport/sport in one filter each
    for (const app of rule.matchApps) {
      const l4 = APP_L4_MAP[app];
      if (!l4) {
        if (!unclassifiableApps.includes(app)) unclassifiableApps.push(app);
        continue;
      }
      for (const { proto, ports } of l4) {
        const ipProto = proto === "tcp" ? 6 : 17;
        for (const port of ports) {
          for (const dir of ["dport", "sport"] as const) {
            cmds.push(
              `tc filter add dev ${iface} parent ${ROOT_HANDLE} protocol ip prio ${filterPrio} u32 match ip protocol ${ipProto} 0xff match ip ${dir} ${port} 0xffff flowid ${classid}`,
            );
            flowidCount(classid);
            filterPrio += 10;
          }
        }
      }
    }

    if (hasMatchers && filtersByFlowid[classid] === undefined) {
      notes.push(`rule "${rule.name}" (priority ${rule.priority}): no tc-expressible matchers — its class exists but receives no filters`);
    }
  });

  return {
    iface,
    cmds,
    defaultClassid: defClassid,
    classes,
    filtersByFlowid,
    unclassifiableApps,
    notes,
  };
}

// ── restore (previous root qdisc re-attach) ────────────────────────────────

export interface TcQdiscJson {
  kind?: string;
  handle?: string;
  root?: boolean;
  parent?: string;
  options?: Record<string, unknown>;
}

/**
 * Build the tc command that re-attaches a non-console root qdisc captured
 * BEFORE the apply (console never owned it). Supports fq_codel faithfully;
 * any other kind is restored as `tc qdisc add dev IF root <kind>` with
 * numeric options appended (best effort — the console never touches ifaces
 * it didn't snapshot, so the fallback path is exceptional).
 */
export function renderRestoreQdisc(iface: string, snapshot: TcQdiscJson): string | null {
  if (!snapshot || snapshot.kind === "htb" || !snapshot.root) return null;
  const kind = snapshot.kind ?? "fq_codel";
  if (kind === "fq_codel") {
    // snapshot options are the fq_codel defaults observed on the appliance —
    // re-attach with the same numbers (tc JSON: usec ints, booleans)
    const o = snapshot.options ?? {};
    const parts: string[] = [];
    if (typeof o.limit === "number") parts.push(`limit ${o.limit}`);
    if (typeof o.flows === "number") parts.push(`flows ${o.flows}`);
    if (typeof o.quantum === "number") parts.push(`quantum ${o.quantum}`);
    if (typeof o.target === "number") parts.push(`target ${o.target / 1000}ms`);
    if (typeof o.interval === "number") parts.push(`interval ${o.interval / 1000}ms`);
    if (typeof o.memory_limit === "number") parts.push(`memory_limit ${o.memory_limit}`);
    if (o.ecn === false) parts.push("noecn");
    return `tc qdisc add dev ${iface} root fq_codel ${parts.join(" ")}`.trim();
  }
  return `tc qdisc add dev ${iface} root ${kind}`;
}

// ── kernel state parsers (tc -j JSON, ground truth captured on appliance) ──

export interface ParsedQdisc {
  kind: string | null;
  root: boolean;
  handle: string | null;
  defaultClassid: string | null; // normalized "1:30" from options.default "0x30"
  leaves: { parent: string; handle: string; kind: string }[];
}

export interface ParsedClass {
  classid: string; // "handle" in tc JSON
  parent: string | null;
  rateKbps: number | null; // tc JSON rate is bytes/sec → *8/1000
  ceilKbps: number | null;
  prio: number | null;
}

export interface ParsedFilter {
  pref: number;
  protocol: string | null;
  flowid: string | null;
}

export function parseTcQdiscShow(stdout: string): ParsedQdisc | null {
  let arr: TcQdiscJson[];
  try {
    arr = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (!Array.isArray(arr)) return null;
  const root = arr.find((q) => q.root === true);
  if (!root) return null;
  const defRaw = typeof root.options?.default === "string" ? (root.options.default as string) : null;
  const leaves = arr
    .filter((q) => q.root !== true && q.parent && q.handle && q.kind)
    .map((q) => ({ parent: String(q.parent), handle: String(q.handle), kind: String(q.kind) }));
  return {
    kind: root.kind ?? null,
    root: true,
    handle: root.handle ?? null,
    defaultClassid: defRaw ? `1:${defRaw.replace(/^0x/, "")}` : null,
    leaves,
  };
}

export function parseTcClassShow(stdout: string): ParsedClass[] {
  let arr: Array<{ class?: string; kind?: string; handle?: string; parent?: string; root?: boolean; prio?: number; rate?: number; ceil?: number }>;
  try {
    arr = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (!Array.isArray(arr)) return [];
  return arr
    .filter((c) => (c.class === "htb" || c.kind === "htb") && typeof c.handle === "string")
    .map((c) => ({
      classid: String(c.handle),
      parent: typeof c.parent === "string" ? c.parent : null,
      rateKbps: typeof c.rate === "number" ? Math.round((c.rate * 8) / 1000) : null,
      ceilKbps: typeof c.ceil === "number" ? Math.round((c.ceil * 8) / 1000) : null,
      prio: typeof c.prio === "number" ? c.prio : null,
    }));
}

export function parseTcFilterShow(stdout: string): ParsedFilter[] {
  let arr: Array<{ pref?: number; protocol?: string; kind?: string; options?: { flowid?: string } }>;
  try {
    arr = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (!Array.isArray(arr)) return [];
  // structural entries (hash table rows) carry no flowid — only real matches do
  return arr
    .filter((f) => f.kind === "u32" && typeof f.pref === "number" && typeof f.options?.flowid === "string")
    .map((f) => ({ pref: Number(f.pref), protocol: f.protocol ?? null, flowid: String(f.options?.flowid) }));
}

// ── drift ───────────────────────────────────────────────────────────────────

export interface QosDrift {
  inSync: boolean;
  driftReasons: string[];
}

const rateTolerance = (a: number, b: number) => Math.abs(a - b) <= Math.max(2, Math.max(a, b) * 0.02);

export function computeQosDrift(rendered: RenderedIface, qdisc: ParsedQdisc | null, classes: ParsedClass[], filters: ParsedFilter[]): QosDrift {
  const reasons: string[] = [];
  if (!qdisc || qdisc.kind !== "htb") {
    reasons.push(`root qdisc is ${qdisc?.kind ?? "absent"} — expected htb`);
    return { inSync: false, driftReasons: reasons };
  }
  if (qdisc.handle !== ROOT_HANDLE) reasons.push(`root handle ${qdisc.handle} — expected ${ROOT_HANDLE}`);
  if (qdisc.defaultClassid !== rendered.defaultClassid) {
    reasons.push(`htb default ${qdisc.defaultClassid ?? "—"} — expected ${rendered.defaultClassid}`);
  }
  const parsedByClassid = new Map(classes.map((c) => [c.classid, c]));
  for (const exp of rendered.classes) {
    const got = parsedByClassid.get(exp.classid);
    if (!got) {
      reasons.push(`class ${exp.classid} missing`);
      continue;
    }
    if (got.rateKbps != null && !rateTolerance(got.rateKbps, exp.rateKbps)) {
      reasons.push(`class ${exp.classid} rate ${got.rateKbps}kbit — expected ${exp.rateKbps}kbit`);
    }
    if (got.ceilKbps != null && !rateTolerance(got.ceilKbps, exp.ceilKbps)) {
      reasons.push(`class ${exp.classid} ceil ${got.ceilKbps}kbit — expected ${exp.ceilKbps}kbit`);
    }
    if (exp.classid !== ROOT_CLASS && got.prio != null && got.prio !== exp.prio) {
      reasons.push(`class ${exp.classid} prio ${got.prio} — expected ${exp.prio}`);
    }
  }
  const extra = classes.filter((c) => c.parent === ROOT_CLASS && !rendered.classes.some((e) => e.classid === c.classid));
  for (const c of extra) reasons.push(`unexpected class ${c.classid} under ${ROOT_CLASS}`);

  const parsedCount: Record<string, number> = {};
  for (const f of filters) parsedCount[f.flowid] = (parsedCount[f.flowid] ?? 0) + 1;
  for (const [flowid, want] of Object.entries(rendered.filtersByFlowid)) {
    if ((parsedCount[flowid] ?? 0) !== want) {
      reasons.push(`filters → ${flowid}: ${parsedCount[flowid] ?? 0} — expected ${want}`);
    }
  }
  for (const flowid of Object.keys(parsedCount)) {
    if (!(flowid in rendered.filtersByFlowid)) reasons.push(`unexpected filters → ${flowid}`);
  }
  return { inSync: reasons.length === 0, driftReasons: reasons };
}

// ── apply plan ──────────────────────────────────────────────────────────────

export type QosPlanStepKind = "snapshot" | "modprobe" | "reset" | "exec" | "verify" | "restore" | "writefile";

export interface QosPlanStep {
  step: string;
  cmd: string; // "" for writefile/restore (content resolved at exec time)
  iface?: string;
  kind: QosPlanStepKind;
}

export interface QosApplyPlan {
  mode: "plan" | "exec";
  steps: QosPlanStep[];
  confHash: string;
  backupFile: string;
  stateContent: string;
  installIfaces: string[];
  teardownIfaces: string[];
  expected: Record<string, RenderedIface>;
  warnings: string[];
}

export function qosConfHash(expected: Record<string, RenderedIface>): string {
  const stable = Object.keys(expected)
    .sort()
    .map((k) => `${k}\n${expected[k].cmds.join("\n")}\ndefault=${expected[k].defaultClassid}\n`)
    .join("---\n");
  return createHash("sha256").update(stable).digest("hex").slice(0, 16);
}

/**
 * Hard refusals — protected ifaces can never be shaped.
 * Returns null when nothing is refused.
 */
export function hardQosRefusal(policies: QosPolicyShape[]): string | null {
  for (const p of policies) {
    if (isProtectedQosIface(p.ifaceName)) {
      return `policy "${p.name}" (id ${p.id}) is attached to ${p.ifaceName}, a protected interface — shaping a protected uplink is refused by policy (CONSOLE_PROTECTED_IFACES)`;
    }
  }
  return null;
}

/**
 * Command whitelist — execution route aborts any step failing this.
 * tc verbs + the exact read forms used for snapshot/verify + modprobe sch_htb.
 */
const TC_EXEC_RE = /^tc (qdisc|class|filter) (add|replace|del) dev [\w.:@-]+[\w\s.:/@-]*$/;
const TC_READ_RE = /^tc -j (qdisc show( dev [\w.:@-]+)?|class show dev [\w.:@-]+|filter show dev [\w.:@-]+ parent 1:)$/;
const MODPROBE_RE = /^modprobe sch_htb$/;

export function qosStepGuarded(cmd: string): boolean {
  return TC_EXEC_RE.test(cmd) || TC_READ_RE.test(cmd) || MODPROBE_RE.test(cmd);
}

/**
 * Convergence plan: snapshot → (teardown stale) → (install per iface) →
 * verify → save state. Order matters: the snapshot runs before ANY mutation;
 * verify runs only after all installs for that iface; the state file is
 * written only after every verify passed (the route enforces this).
 */
export function buildQosApplyPlan(input: {
  policies: QosPolicyShape[];
  managedIfaces: string[];
  mode: "plan" | "exec";
  ts: string;
}): QosApplyPlan {
  const { policies, managedIfaces, mode, ts } = input;
  const warnings: string[] = [];
  const expected: Record<string, RenderedIface> = {};
  const snapshotIfaces = new Set([...managedIfaces]);

  for (const p of policies) {
    if (!p.ifaceName) {
      warnings.push(`policy "${p.name}": not attached to an interface — OS shaping requires an attachment (aggregated multi-WAN shaper is out of scope)`);
      continue;
    }
    if (p.rules.length === 0) {
      warnings.push(`policy "${p.name}": no rules — only the budget class and remainder would exist`);
    }
    if (isProtectedQosIface(p.ifaceName)) continue; // refusal surfaces separately
    const rendered = renderQosIface(p, p.ifaceName);
    if (expected[p.ifaceName]) {
      warnings.push(`policy "${p.name}": iface ${p.ifaceName} already claimed by another policy in this plan — skipped`);
      continue;
    }
    snapshotIfaces.add(p.ifaceName);
    expected[p.ifaceName] = rendered;
    for (const n of rendered.notes) warnings.push(`policy "${p.name}": ${n}`);
    if (rendered.unclassifiableApps.length > 0) {
      warnings.push(
        `policy "${p.name}": app labels not expressible by tc (DPI-only) are NOT enforced: ${rendered.unclassifiableApps.join(", ")}`,
      );
    }
  }

  const installIfaces = Object.keys(expected).sort();
  const teardownIfaces = managedIfaces.filter((i) => !installIfaces.includes(i)).sort();

  const steps: QosPlanStep[] = [];
  steps.push({ step: "load sch_htb module", cmd: "modprobe sch_htb", kind: "modprobe" });
  // per-iface snapshot FIRST — restore needs the pre-apply root qdisc of the
  // specific iface (global `tc -j qdisc show` JSON cannot be mapped to ifaces)
  for (const iface of [...snapshotIfaces].sort()) {
    steps.push({ step: `snapshot ${iface}`, cmd: `tc -j qdisc show dev ${iface}`, iface, kind: "snapshot" });
  }

  for (const iface of teardownIfaces) {
    steps.push({ step: `teardown ${iface}`, cmd: `tc qdisc del dev ${iface} root`, iface, kind: "exec" });
    steps.push({ step: `restore ${iface} previous qdisc`, cmd: "", iface, kind: "restore" });
  }

  for (const iface of installIfaces) {
    // best-effort reset — del fails harmlessly when the root is empty; the
    // subsequent `add` is what actually asserts kernel state
    steps.push({ step: `reset ${iface} root`, cmd: `tc qdisc del dev ${iface} root`, iface, kind: "reset" });
    for (const cmd of expected[iface].cmds) {
      steps.push({ step: `install ${iface}`, cmd, iface, kind: "exec" });
    }
    steps.push({ step: `verify ${iface} qdisc`, cmd: `tc -j qdisc show dev ${iface}`, iface, kind: "verify" });
    steps.push({ step: `verify ${iface} classes`, cmd: `tc -j class show dev ${iface}`, iface, kind: "verify" });
    steps.push({ step: `verify ${iface} filters`, cmd: `tc -j filter show dev ${iface} parent 1:`, iface, kind: "verify" });
  }

  const stateContent = JSON.stringify(
    {
      hash: qosConfHash(expected),
      appliedAt: new Date().toISOString(),
      managedIfaces: installIfaces,
      policies: installIfaces.map((i) => ({ iface: i, policyId: policies.find((p) => p.ifaceName === i)?.id ?? null })),
    },
    null,
    2,
  );

  if (installIfaces.length > 0) {
    steps.push({ step: "save state file", cmd: "", kind: "writefile" });
  }

  return {
    mode,
    steps,
    confHash: qosConfHash(expected),
    backupFile: `${QOS_STATE_DIR}/backup-${ts}.json`,
    stateContent,
    installIfaces,
    teardownIfaces,
    expected,
    warnings,
  };
}

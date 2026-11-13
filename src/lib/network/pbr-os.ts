/**
 * PBR (policy-based routing) OS layer — real kernel policy tables.
 *
 * Enterprise semantics (FortiGate policy routes / PAN-OS PBR parity):
 *   • each enabled rule gets a dedicated kernel table (10000 + position) and
 *     `ip rule` entries at priority 5000 + position*10 + comboIndex
 *   • ADDRESS matches map directly to ip rule from/to selectors — real kernel
 *     enforcement for CIDR/IP objects (subnet|ip types)
 *   • SERVICE matches compile into ip rule protocol selectors where the
 *     kernel can express them: `ipproto tcp|udp|icmp` + `sport`/`dport`
 *     single ports or ranges (kernel ≥4.17 fib_rule_port_range). Anything
 *     not expressible (bogus port tokens, >64 fan-out) stays CONFIG-ONLY and
 *     reports honestly instead of pretending to be enforced
 *   • egress: gateway → `default via <gw> dev <if> onlink metric 1 table <t>`;
 *     iface → `default dev <if> metric 1 table <t>` — table-scoped default
 *     always carries metric 1 so the route-apply default-route guard (primary
 *     default protection, 2026-11-13 outage) accepts the step
 *
 * Red-line safety: `ip rule` in the 5000+ priority range and tables 10000+
 * never collide with strongSwan's rule 220/table 220, never touch the nft
 * ruleset, and only steer traffic that matches the rule's source/destination
 * objects (test rules use the ens34 test subnet exclusively).
 */

import { db } from "@/lib/db";
import { parseIdArray } from "@/lib/json";

export interface PbrRuleView {
  id: number;
  name: string;
  position: number;
  enabled: boolean;
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  outgoingIface: string | null;
  gateway: string | null;
}

export interface PbrOsPlanStep {
  cmd: string;
  summary: string;
}

export interface PbrOsPlan {
  name: string;
  position: number;
  table: number | null;
  /** config-only when match objects are not kernel-expressible */
  configOnly: boolean;
  reason: string;
  steps: PbrOsPlanStep[];
}

/** resolve object/group ids → individual CIDR strings (null = unresolvable type). */
export async function resolvePbrCidrs(tenantId: number, ids: number[]): Promise<Array<{ id: number; cidr: string | null }>> {
  const out: Array<{ id: number; cidr: string | null }> = [];
  for (const id of ids) {
    const obj = await db.addressObject.findFirst({ where: { id, tenantId } }).catch(() => null);
    if (obj) {
      out.push({ id, cidr: obj.type === "ip" || obj.type === "subnet" ? obj.value : null });
      continue;
    }
    const grp = await db.addressGroup.findFirst({ where: { id, tenantId } }).catch(() => null);
    if (!grp) {
      out.push({ id, cidr: null });
      continue;
    }
    const memberIds = parseIdArray(grp.memberIds);
    const members = await db.addressObject.findMany({ where: { id: { in: memberIds }, tenantId } });
    for (const m of members) {
      out.push({ id: m.id, cidr: m.type === "ip" || m.type === "subnet" ? m.value : null });
    }
  }
  return out;
}

// ── service selectors (protocol/port compile) ───────────────────────────────

export interface PbrPortToken {
  lo: number;
  hi: number;
}

export interface PbrServiceSelector {
  id: number;
  protocol: "tcp" | "udp" | "icmp" | "any";
  srcPorts: PbrPortToken[];
  dstPorts: PbrPortToken[];
}

export interface ResolvedServiceSelector {
  id: number;
  cidr: null;
  protocol: PbrServiceSelector["protocol"];
  srcPorts: PbrPortToken[];
  dstPorts: PbrPortToken[];
  /** false when a port token is malformed — the rule stays config-only */
  expressible: boolean;
}

/** Parse a port field ("any" | "80" | "5000-5100,6000") → tokens (null = invalid). */
export function parsePortTokens(raw: string | null | undefined): PbrPortToken[] | null {
  if (raw == null || raw === "" || raw === "any") return [];
  const tokens: PbrPortToken[] = [];
  for (const tok of raw.split(",")) {
    const t = tok.trim();
    if (t === "" || t === "any") continue;
    let m = /^(\d{1,5})$/.exec(t);
    if (m) {
      const v = Number(m[1]);
      if (v < 1 || v > 65535) return null;
      tokens.push({ lo: v, hi: v });
      continue;
    }
    m = /^(\d{1,5})-(\d{1,5})$/.exec(t);
    if (m) {
      const lo = Number(m[1]);
      const hi = Number(m[2]);
      if (lo < 1 || hi > 65535 || lo > hi) return null;
      tokens.push({ lo, hi });
      continue;
    }
    return null; // malformed token → not kernel-expressible
  }
  return tokens;
}

/** Resolve service ids (objects ∪ groups) → normalized protocol/port selectors. */
export async function resolveServiceSelectors(tenantId: number, ids: number[]): Promise<ResolvedServiceSelector[]> {
  const out: ResolvedServiceSelector[] = [];
  for (const id of ids) {
    const obj = await db.serviceObject.findFirst({ where: { id, tenantId } }).catch(() => null);
    if (obj) {
      out.push(serviceObjectToSelector(obj.id, obj.protocol, obj.srcPort, obj.dstPort));
      continue;
    }
    const grp = await db.serviceGroup.findFirst({ where: { id, tenantId } }).catch(() => null);
    if (!grp) {
      out.push({ id, cidr: null, protocol: "any", srcPorts: [], dstPorts: [], expressible: false });
      continue;
    }
    const memberIds = parseIdArray(grp.memberIds);
    const members = await db.serviceObject.findMany({ where: { id: { in: memberIds }, tenantId } });
    for (const m of members) {
      out.push(serviceObjectToSelector(m.id, m.protocol, m.srcPort, m.dstPort));
    }
  }
  return out;
}

function serviceObjectToSelector(
  id: number,
  protocol: string,
  srcPort: string | null,
  dstPort: string | null,
): ResolvedServiceSelector {
  const proto = (["tcp", "udp", "icmp", "any"].includes(protocol) ? protocol : "any") as PbrServiceSelector["protocol"];
  const src = parsePortTokens(srcPort);
  const dst = parsePortTokens(dstPort);
  return {
    id,
    cidr: null,
    protocol: proto,
    srcPorts: proto === "tcp" || proto === "udp" ? (src ?? []) : [],
    dstPorts: proto === "tcp" || proto === "udp" ? (dst ?? []) : [],
    expressible: src !== null && dst !== null,
  };
}

export interface CompiledServiceSelector {
  ipproto?: string;
  sport?: string;
  dport?: string;
}

/**
 * Compile service selectors into ip-rule fragments. An empty list (or all
 * "any"-protocol services) yields one empty selector = "all protocols".
 */
export function compileServiceSelectors(svc: ResolvedServiceSelector[]): {
  expressible: boolean;
  reason: string;
  selectors: CompiledServiceSelector[];
} {
  if (svc.some((s) => !s.expressible)) {
    return { expressible: false, reason: "a service match carries malformed or unsupported port syntax", selectors: [] };
  }
  const out: CompiledServiceSelector[] = [];
  for (const s of svc) {
    if (s.protocol === "any" || s.protocol === "icmp") {
      out.push(s.protocol === "any" ? {} : { ipproto: "icmp" });
      continue;
    }
    const srcs = s.srcPorts.length > 0 ? s.srcPorts : [null];
    const dsts = s.dstPorts.length > 0 ? s.dstPorts : [null];
    for (const sp of srcs) {
      for (const dp of dsts) {
        out.push({
          ipproto: s.protocol,
          sport: sp ? (sp.lo === sp.hi ? `${sp.lo}` : `${sp.lo}-${sp.hi}`) : undefined,
          dport: dp ? (dp.lo === dp.hi ? `${dp.lo}` : `${dp.lo}-${dp.hi}`) : undefined,
        });
      }
    }
  }
  if (out.length === 0) out.push({});
  return { expressible: true, reason: "", selectors: out };
}

export const PBR_TABLE_BASE = 10000;
export const PBR_PRIO_BASE = 5000;
/** hard cap on (cidr combos × service selectors) per rule — beyond → config-only */
export const PBR_COMBO_CAP = 64;

function tableFor(position: number): number {
  return PBR_TABLE_BASE + position;
}

/**
 * Build the kernel application plan for ONE rule (replace semantics: callers
 * run the teardown plan first, then this plan).
 */
export function buildPbrApplyPlan(
  rule: PbrRuleView,
  src: Array<{ id: number; cidr: string | null }>,
  dst: Array<{ id: number; cidr: string | null }>,
  svc: ResolvedServiceSelector[] = [],
): PbrOsPlan {
  const table = rule.enabled ? tableFor(rule.position) : null;
  const base: PbrOsPlan = {
    name: rule.name,
    position: rule.position,
    table,
    configOnly: false,
    reason: "",
    steps: [],
  };

  if (!rule.enabled) {
    return { ...base, table: null, reason: "rule disabled — kernel policy withdrawn" };
  }

  // service ids present but nothing resolved — data-plane inconsistency, stay honest
  if (rule.serviceIds.length > 0 && svc.length === 0) {
    return {
      ...base,
      table: null,
      configOnly: true,
      reason: "service matches unresolved (ids missing/invalid) — config plane only",
    };
  }

  const services = compileServiceSelectors(svc);
  if (!services.expressible) {
    return {
      ...base,
      table: null,
      configOnly: true,
      reason: `service match not kernel-expressible: ${services.reason} — config plane only`,
    };
  }

  const srcCidrs = src.map((s) => s.cidr).filter((c): c is string => c !== null);
  const dstCidrs = dst.map((d) => d.cidr).filter((c): c is string => c !== null);
  const unresolvable = [...src, ...dst].some((x) => x.cidr === null);
  if (unresolvable && srcCidrs.length + dstCidrs.length === 0) {
    return {
      ...base,
      table: null,
      configOnly: true,
      reason: "match objects resolve to no CIDR (range/fqdn/geo) — kernel policy not expressible with ip rule",
    };
  }

  // cartesian (src × dst) × service selectors, empty match side = "all" —
  // bounded by PBR_COMBO_CAP for sanity
  const srcs = srcCidrs.length > 0 ? srcCidrs : [null];
  const dsts = dstCidrs.length > 0 ? dstCidrs : [null];
  const cidrCombos: Array<[string | null, string | null]> = [];
  for (const s of srcs) for (const d of dsts) cidrCombos.push([s, d]);
  const totalCombos = cidrCombos.length * services.selectors.length;
  if (totalCombos > PBR_COMBO_CAP) {
    return {
      ...base,
      table: null,
      configOnly: true,
      reason: `match fan-out ${totalCombos} > ${PBR_COMBO_CAP} — narrow the address/service objects`,
    };
  }

  const steps: PbrOsPlanStep[] = [];
  // table-scoped default MUST carry metric >= 1 — route-apply.ts refuses bare
  // default ops (`metric 0` would shadow the interface-managed primary default)
  const egress = rule.gateway
    ? rule.outgoingIface
      ? `default via ${rule.gateway} dev ${rule.outgoingIface} onlink metric 1`
      : `default via ${rule.gateway} onlink metric 1`
    : rule.outgoingIface
      ? `default dev ${rule.outgoingIface} metric 1`
      : null;
  if (!egress) {
    return { ...base, table: null, configOnly: true, reason: "no egress — invalid rule (validated upstream)" };
  }
  steps.push({ cmd: `ip route replace ${egress} table ${table}`, summary: `table ${table}: ${egress}` });

  let comboIndex = 0;
  for (const [s, d] of cidrCombos) {
    for (const sel of services.selectors) {
      const prio = PBR_PRIO_BASE + rule.position * 10 + comboIndex;
      const selStr = [
        sel.ipproto ? `ipproto ${sel.ipproto}` : "",
        sel.sport ? `sport ${sel.sport}` : "",
        sel.dport ? `dport ${sel.dport}` : "",
      ]
        .filter(Boolean)
        .join(" ");
      const parts = [
        `priority ${prio}`,
        s ? `from ${s}` : "",
        d ? `to ${d}` : "",
        selStr,
        `table ${table}`,
      ]
        .filter(Boolean)
        .join(" ");
      steps.push({ cmd: `ip rule add ${parts}`, summary: `ip rule ${parts}` });
      comboIndex++;
    }
  }

  return {
    ...base,
    steps,
    reason: steps.length > 0 ? `kernel policy tables + ip rule entries (${totalCombos} match combo${totalCombos === 1 ? "" : "s"})` : "no CIDR pairs to enforce",
  };
}

/** Teardown plan — delete this rule's ip rule entries + flush its table. */
export function buildPbrTeardownPlan(
  rule: PbrRuleView,
  srcCount: number,
  dstCount: number,
  svcSelectorCount = 1,
): PbrOsPlan {
  const steps: PbrOsPlanStep[] = [];
  const combos = Math.max(1, Math.min(PBR_COMBO_CAP, (srcCount || 1) * (dstCount || 1) * (svcSelectorCount || 1)));
  for (let i = 0; i < combos; i++) {
    const prio = PBR_PRIO_BASE + rule.position * 10 + i;
    steps.push({ cmd: `ip rule del priority ${prio}`, summary: `drop ip rule priority ${prio}` });
  }
  steps.push({ cmd: `ip route flush table ${tableFor(rule.position)}`, summary: `flush policy table ${tableFor(rule.position)}` });
  return { name: rule.name, position: rule.position, table: tableFor(rule.position), configOnly: false, reason: "teardown", steps };
}

export interface KernelPbrRule {
  priority: number;
  from: string | null;
  to: string | null;
  table: number | null;
  ipproto: string | null;
  sport: string | null;
  dport: string | null;
  /** trailing bracket stats from `ip -s rule show` when the kernel reports them */
  stats: string | null;
  raw: string;
}

/** `ip rule show` → structured entries (null when `ip` unavailable). */
export async function readKernelPbrRules(): Promise<KernelPbrRule[] | null> {
  const { hasTool, runTool } = await import("@/lib/host/tools");
  if (!(await hasTool("ip"))) return null;
  const r = await runTool("ip -s rule show 2>/dev/null || ip rule show 2>/dev/null", 6000);
  if (!r.ok) return null;
  return parseKernelPbrRules(r.stdout);
}

export function parseKernelPbrRules(out: string): KernelPbrRule[] {
  const rows: KernelPbrRule[] = [];
  for (const line of out.split("\n")) {
    const raw = line.trim();
    if (!raw) continue;
    const f = raw.split(/\s+/);
    const priority = Number.parseInt(f[0]?.replace(":", "") ?? "", 10);
    if (!Number.isInteger(priority)) continue;
    let from: string | null = null;
    let to: string | null = null;
    let table: number | null = null;
    let ipproto: string | null = null;
    let sport: string | null = null;
    let dport: string | null = null;
    for (let i = 1; i < f.length; i++) {
      if (f[i] === "from" && f[i + 1]) from = f[++i];
      else if (f[i] === "to" && f[i + 1]) to = f[++i];
      else if (f[i] === "lookup" && f[i + 1]) table = Number(f[++i]) || null;
      else if (f[i] === "table" && f[i + 1]) table = Number(f[++i]) || null;
      else if (f[i] === "ipproto" && f[i + 1]) ipproto = f[++i];
      else if (f[i] === "sport" && f[i + 1]) sport = f[++i];
      else if (f[i] === "dport" && f[i + 1]) dport = f[++i];
    }
    // trailing counter bracket, e.g. "[hit_count 12 ref_count 1]" (kernel-dependent)
    const statsMatch = /\[([^\]]+)\]\s*$/.exec(raw.replace(/\s+table\s+\S+.*$/, "")) ?? /\[([^\]]+)\]\s*$/.exec(raw);
    const stats = statsMatch && /^\[/.test(statsMatch[0]) ? statsMatch[1] : null;
    rows.push({ priority, from, to, table, ipproto, sport, dport, stats, raw });
  }
  return rows;
}

export type PbrKernelState = "disabled" | "in-kernel" | "missing" | "config-only";

/** Kernel state for one rule (null kernel → null = unknown). */
export function pbrKernelState(
  rule: PbrRuleView,
  kernel: KernelPbrRule[] | null,
  opts?: { configOnly?: boolean },
): PbrKernelState | null {
  if (!kernel) return null;
  if (opts?.configOnly) return "config-only";
  if (!rule.enabled) return "disabled";
  const table = tableFor(rule.position);
  const prio = PBR_PRIO_BASE + rule.position * 10;
  const hit = kernel.some((k) => k.table === table && k.priority >= prio && k.priority < prio + PBR_COMBO_CAP);
  return hit ? "in-kernel" : "missing";
}

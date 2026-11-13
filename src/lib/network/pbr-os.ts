/**
 * PBR (policy-based routing) OS layer — real kernel policy tables.
 *
 * Enterprise semantics (FortiGate policy routes / PAN-OS PBR parity):
 *   • each enabled rule gets a dedicated kernel table (10000 + position) and
 *     `ip rule` entries at priority 5000 + position*10 + comboIndex
 *   • ADDRESS matches map directly to ip rule from/to selectors — real kernel
 *     enforcement for CIDR/IP objects (subnet|ip types)
 *   • SERVICE matches need nft fwmark (dataplane change) — rules that carry a
 *     service selector stay CONFIG-ONLY and report honestly instead of
 *     pretending to be enforced
 *   • egress: gateway → `default via <gw> dev <if> onlink table <t>`;
 *     iface → `default dev <if> table <t>`
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
  /** config-only when service selectors need the fwmark datapath */
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

export const PBR_TABLE_BASE = 10000;
export const PBR_PRIO_BASE = 5000;

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
  if (rule.serviceIds.length > 0) {
    return {
      ...base,
      table: null,
      configOnly: true,
      reason: "service-matched rules need the nft fwmark datapath (planned) — config plane only, kernel not touched",
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

  // cartesian (src × dst), empty match side = "all" — bounded: every list is
  // distinct object ids, so fan-out stays small; hard cap for sanity
  const srcs = srcCidrs.length > 0 ? srcCidrs : [null];
  const dsts = dstCidrs.length > 0 ? dstCidrs : [null];
  const combos: Array<[string | null, string | null]> = [];
  for (const s of srcs) for (const d of dsts) combos.push([s, d]);
  if (combos.length > 64) {
    return { ...base, table: null, configOnly: true, reason: `match fan-out ${combos.length} > 64 — use subnets instead of huge ranges` };
  }

  const steps: PbrOsPlanStep[] = [];
  const egress = rule.gateway
    ? rule.outgoingIface
      ? `default via ${rule.gateway} dev ${rule.outgoingIface} onlink`
      : `default via ${rule.gateway} onlink`
    : rule.outgoingIface
      ? `default dev ${rule.outgoingIface}`
      : null;
  if (!egress) {
    return { ...base, table: null, configOnly: true, reason: "no egress — invalid rule (validated upstream)" };
  }
  steps.push({ cmd: `ip route replace ${egress} table ${table}`, summary: `table ${table}: ${egress}` });

  combos.forEach(([s, d], i) => {
    const prio = PBR_PRIO_BASE + rule.position * 10 + i;
    const sel = `priority ${prio}${s ? ` from ${s}` : ""}${d ? ` to ${d}` : ""} table ${table}`;
    steps.push({ cmd: `ip rule add ${sel}`, summary: `ip rule ${sel}` });
  });

  return { ...base, steps, reason: steps.length > 0 ? "kernel policy tables + ip rule entries" : "no CIDR pairs to enforce" };
}

/** Teardown plan — delete this rule's ip rule entries + flush its table. */
export function buildPbrTeardownPlan(rule: PbrRuleView, srcCount: number, dstCount: number): PbrOsPlan {
  const steps: PbrOsPlanStep[] = [];
  const combos = Math.max(1, Math.min(64, (srcCount || 1) * (dstCount || 1)));
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
  raw: string;
}

/** `ip rule show` → structured entries (null when `ip` unavailable). */
export async function readKernelPbrRules(): Promise<KernelPbrRule[] | null> {
  const { hasTool, runTool } = await import("@/lib/host/tools");
  if (!(await hasTool("ip"))) return null;
  const r = await runTool("ip rule show", 6000);
  if (!r.ok) return null;
  return parseKernelPbrRules(r.stdout);
}

export function parseKernelPbrRules(out: string): KernelPbrRule[] {
  const rows: KernelPbrRule[] = [];
  for (const line of out.split("\n")) {
    const raw = line.trim();
    if (!raw) continue;
    const f = raw.split(/\s+/);
    const priority = Number(f[0]?.replace(":", ""), 10);
    if (!Number.isInteger(priority)) continue;
    let from: string | null = null;
    let to: string | null = null;
    let table: number | null = null;
    for (let i = 1; i < f.length; i++) {
      if (f[i] === "from" && f[i + 1]) from = f[++i];
      else if (f[i] === "to" && f[i + 1]) to = f[++i];
      else if (f[i] === "lookup" && f[i + 1]) table = Number(f[++i]) || null;
      else if (f[i] === "table" && f[i + 1]) table = Number(f[++i]) || null;
    }
    rows.push({ priority, from, to, table, raw });
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
  if (opts?.configOnly || rule.serviceIds.length > 0) return "config-only";
  if (!rule.enabled) return "disabled";
  const table = tableFor(rule.position);
  const prio = PBR_PRIO_BASE + rule.position * 10;
  const hit = kernel.some((k) => k.table === table && k.priority >= prio && k.priority < prio + 64);
  return hit ? "in-kernel" : "missing";
}

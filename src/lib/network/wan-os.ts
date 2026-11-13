/**
 * Multi-WAN OS layer (M02 §4, enterprise gap G2 fix) — real kernel policy
 * routing for probe-driven failover, priority selection and weighted ECMP.
 *
 * Enterprise semantics (FortiGate SD-WAN / PAN-OS PBR parity):
 *   • every enabled WAN policy that is NOT the default-route owner gets a
 *     dedicated kernel table (260 + idx) holding its connected route + a
 *     default via its gateway, plus an `ip rule` at 3200 + idx*10 scoped
 *     `from <wan-ip>` — secondary-WAN replies always leave the same WAN
 *   • a managed egress table (240) always reflects the engine's CURRENT
 *     decision: single default via the best up WAN, or a weighted multipath
 *     (nexthop … weight …) when every active policy is load_balance
 *   • failover is REAL and kernel-observable: when the primary's probe goes
 *     down, table 240's default flips to the next up WAN — while the MAIN
 *     table default is never touched (outage guard, see route-apply.ts)
 *   • forwarded-traffic redirection INTO table 240 needs nft fwmark (the
 *     dataplane red line on this installation) — table 240 stays rule-less
 *     and dormant until that integration; nothing on the host depends on it
 *
 * Red-line safety: every `ip route` step carries an explicit managed table
 * (240..279 — never main/253/254/255), rules only in the 3200..3299 priority
 * band, `dev lo` never, and the executor re-checks all of it. The primary
 * (default-route owner) is excluded from per-WAN source routing entirely.
 */

import { db } from "@/lib/db";
import { readInterfaces } from "@/lib/host/proc";
import { readGatewayFor } from "@/lib/host/tools";
import type { KernelPbrRule } from "./pbr-os";
import type { WanTransitionEvent } from "./wan-sla";

// ── managed kernel real estate ──────────────────────────────────────────────

/** managed "desired egress" table — the engine's live failover decision */
export const WAN_EGRESS_TABLE = 240;
/** per-WAN source-routing tables 260..271 (max 12 policies enforced) */
export const WAN_TABLE_BASE = 260;
export const WAN_TABLE_LIMIT = 12;
/** `ip rule` priority band owned by multi-WAN (3200..3299) */
export const WAN_PRIO_BASE = 3200;

export type WanMode = "priority" | "failover" | "load_balance";

export interface WanOsWanView {
  id: number;
  iface: string;
  ifaceIp: string | null;
  /** connected subnet in CIDR form (kept so per-WAN tables stay LAN-reachable) */
  ifaceCidr: string | null;
  gateway: string | null;
  mode: WanMode;
  weight: number;
  priority: number;
  state: "up" | "degraded" | "down" | "unknown";
  enabled: boolean;
}

export interface WanOsInput {
  /** the interface owning the MAIN default route — never source-managed */
  primaryIface: string | null;
  wans: WanOsWanView[];
  /** live contents of the managed egress table (240) — enables honest in-sync detection */
  currentEgressRoutes?: string[];
  /** live contents of per-WAN source tables (260..271), keyed by table number */
  currentPerWanRoutes?: Record<number, string[]>;
}

export interface WanOsStep {
  cmd: string;
  summary: string;
}

export interface WanOsPlan {
  steps: WanOsStep[];
  /** null when no egress is currently reachable */
  egressTable: number | null;
  managedTables: number[];
  /** what table 240 currently points at (for UI/audit honesty) */
  activeEgress: { iface: string; style: "primary" | "priority" | "failover" | "ecmp" } | null;
  reasons: string[];
}

export interface WanOsApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  reason: string;
  plan: WanOsPlan;
  results?: Array<{ cmd: string; ok: boolean; stderr?: string }>;
}

// ── input collector (real OS facts) ─────────────────────────────────────────

/**
 * Assemble the planner input from the DB config plane + real OS facts
 * (interface primary IPv4/CIDR, per-iface gateway, main default owner).
 * Gateway source precedence: the OS main-table gateway first (it is the
 * authoritative reachability fact); a secondary WAN that does not own the
 * main default has its gateway suppressed there by the ownership guard, so
 * the console-config plane (interface config.gateway) fills in — exactly
 * where an admin declares WAN2's next hop in a multi-WAN deployment.
 */
export async function buildWanOsInput(): Promise<WanOsInput> {
  const [rows, real, ifaces] = await Promise.all([
    db.wanPolicy.findMany({ where: { tenantId: 1 } }),
    readInterfaces().catch(() => []),
    db.networkInterface.findMany({ where: { tenantId: 1 }, select: { name: true, config: true } }).catch(() => []),
  ]);
  const primaryIface = real.find((r) => r.isDefaultRoute)?.name ?? null;
  const cfgOf = new Map<string, { ip: string | null; prefix: number | null; gateway: string | null }>();
  for (const row of ifaces) {
    try {
      const cfg = JSON.parse(row.config) as { ip?: unknown; cidrPrefix?: unknown; gateway?: unknown };
      cfgOf.set(row.name, {
        ip: typeof cfg.ip === "string" && cfg.ip ? cfg.ip : null,
        prefix: typeof cfg.cidrPrefix === "number" ? cfg.cidrPrefix : null,
        gateway: typeof cfg.gateway === "string" && cfg.gateway ? cfg.gateway : null,
      });
    } catch {
      cfgOf.set(row.name, { ip: null, prefix: null, gateway: null });
    }
  }
  const wans: WanOsWanView[] = [];
  for (const row of rows) {
    const os = real.find((r) => r.name === row.interfaceName);
    // addressing authority = the config plane (the console converges the OS to
    // it); OS facts fill in when a row has no config yet. `os.networkInterfaces`
    // yields BARE addresses (no prefix) — a /32 "connected" route would be
    // useless, so without a config prefix we skip the connected step honestly.
    const cfg = cfgOf.get(row.interfaceName) ?? { ip: null, prefix: null, gateway: null };
    const osPrimary = os?.ipv4[0] ?? null;
    const osIp = osPrimary ? osPrimary.split("/")[0] : null;
    const ip = cfg.ip ?? osIp;
    const cidr =
      ip && cfg.prefix != null
        ? `${networkOf(ip, cfg.prefix)}/${cfg.prefix}`
        : null;
    const gateway = (await readGatewayFor(row.interfaceName).catch(() => null)) ?? cfg.gateway;
    wans.push({
      id: row.id,
      iface: row.interfaceName,
      ifaceIp: ip,
      ifaceCidr: cidr,
      gateway,
      mode: (row.mode as WanMode) ?? "failover",
      weight: row.weight,
      priority: row.priority,
      state: (row.state as WanOsWanView["state"]) ?? "unknown",
      enabled: row.enabled,
    });
  }
  // per-WAN table dumps — ONLY for the candidate tables non-primary WANs can
  // own (idx 0..n-1 of the sorted managed set); zero dumps for single-WAN hosts
  const nonPrimary = wans.filter((w) => w.iface !== primaryIface).length;
  const currentPerWanRoutes: Record<number, string[]> = {};
  const egressRoutes = await readEgressTableDump().catch(() => undefined);
  if (nonPrimary > 0) {
    const { hasTool, runTool } = await import("@/lib/host/tools");
    if (await hasTool("ip")) {
      for (let i = 0; i < Math.min(WAN_TABLE_LIMIT, nonPrimary); i++) {
        const r = await runTool(`ip route show table ${WAN_TABLE_BASE + i} 2>/dev/null`, 4000);
        if (r.ok) currentPerWanRoutes[WAN_TABLE_BASE + i] = parseRouteTableDump(r.stdout);
      }
    }
  }
  return { primaryIface, wans, currentEgressRoutes: egressRoutes, currentPerWanRoutes };
}

/** live dump of the managed egress table (undefined when `ip` is unavailable) */
async function readEgressTableDump(): Promise<string[] | undefined> {
  const { hasTool, runTool } = await import("@/lib/host/tools");
  if (!(await hasTool("ip"))) return undefined;
  const r = await runTool(`ip route show table ${WAN_EGRESS_TABLE} 2>/dev/null`, 4000);
  return r.ok ? parseRouteTableDump(r.stdout) : undefined;
}

/** best-effort zeroed network address for a CIDR (no external ip dep) */
function networkOf(ip: string, prefix: number): string {
  const o = ip.split(".").map((x) => parseInt(x, 10));
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255) || prefix < 0 || prefix > 32) return ip;
  const bits = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const net = (bits & mask) >>> 0;
  return [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join(".");
}

// ── plan builder (pure — unit tested) ───────────────────────────────────────

interface ManagedIdx {
  wan: WanOsWanView;
  idx: number;
  table: number;
  prio: number;
}

function managedSet(input: WanOsInput): ManagedIdx[] {
  // stable identity: sort once by (priority, id) so tables don't wander when
  // probe states flap; only non-primary WANs are source-managed
  return input.wans
    .filter((w) => w.iface !== input.primaryIface)
    .sort((a, b) => a.priority - b.priority || a.id - b.id)
    .slice(0, WAN_TABLE_LIMIT)
    .map((wan, idx) => ({ wan, idx, table: WAN_TABLE_BASE + idx, prio: WAN_PRIO_BASE + idx * 10 }));
}

function kernelHasRule(kernel: KernelPbrRule[] | null, prio: number): boolean {
  return !!kernel?.some((k) => k.priority === prio);
}

const normRoute = (s: string): string => s.replace(/\s+/g, " ").trim();

export interface WanNexthop {
  via: string;
  dev: string | null;
  weight: string | null;
}

/**
 * `ip route show table` output → multipath nexthop triples (ECMP). Tolerates
 * the kernel splitting "default" and "nexthop …" across lines.
 */
export function parseMultipathNexthops(routes: string[]): WanNexthop[] {
  const out: WanNexthop[] = [];
  for (const line of routes) {
    const m = /nexthop\s+via\s+(\S+)(?:\s+dev\s+(\S+))?(?:\s+weight\s+(\S+))?/.exec(line);
    if (m) out.push({ via: m[1], dev: m[2] ?? null, weight: m[3] ?? null });
  }
  return out;
}

function kernelRuleMatches(kernel: KernelPbrRule[] | null, prio: number, table: number, from: string | null): boolean {
  const hit = kernel?.find((k) => k.priority === prio);
  if (!hit) return false;
  return hit.table === table && hit.from === from;
}

/**
 * Build the convergence plan that makes the kernel reflect the engine's
 * current WAN health decision. Idempotent against `kernel` (current
 * `ip rule show`) — adds only missing rules, deletes only stale ones;
 * route steps use `replace`/`flush` semantics so re-runs are no-ops.
 */
export function buildWanOsConvergePlan(input: WanOsInput, kernel: KernelPbrRule[] | null): WanOsPlan {
  const steps: WanOsStep[] = [];
  const managedTables: number[] = [];
  const reasons: string[] = [];
  const managed = managedSet(input);

  // ── per-WAN source routing (secondary WANs only) ──────────────────────────
  for (const { wan, table, prio } of managed) {
    // kernel dump of this table (null = unknown — behave conservatively)
    const curRoutes = input.currentPerWanRoutes?.[table] ?? null;
    const curNorm = curRoutes === null ? null : curRoutes.map(normRoute);
    if (!wan.enabled) {
      if (kernelHasRule(kernel, prio)) {
        steps.push({ cmd: `ip rule del priority ${prio}`, summary: `withdraw stale rule ${prio} (${wan.iface} disabled)` });
      }
      if (curRoutes === null || curRoutes.length > 0) {
        steps.push({ cmd: `ip route flush table ${table}`, summary: `withdraw table ${table} (${wan.iface} disabled)` });
      }
      continue;
    }
    if (!wan.gateway) {
      reasons.push(`${wan.iface}: no kernel gateway — source routing not enforceable (honest skip)`);
      if (kernelHasRule(kernel, prio)) {
        steps.push({ cmd: `ip rule del priority ${prio}`, summary: `withdraw rule ${prio} (${wan.iface} lost its gateway)` });
      }
      continue;
    }
    if (wan.state === "down" || wan.state === "unknown") {
      if (kernelHasRule(kernel, prio)) {
        steps.push({ cmd: `ip rule del priority ${prio}`, summary: `withdraw rule ${prio} (${wan.iface} ${wan.state})` });
      }
      if (curRoutes === null || curRoutes.length > 0) {
        steps.push({ cmd: `ip route flush table ${table}`, summary: `withdraw table ${table} (${wan.iface} ${wan.state})` });
      }
      continue;
    }

    managedTables.push(table);
    // connected route first — without it the table's default would swallow
    // the WAN's own subnet traffic (local delivery must stay direct)
    const src = wan.ifaceIp ? ` src ${wan.ifaceIp}` : "";
    const wantConnected = !!(wan.ifaceCidr && wan.ifaceIp);
    const hasConnected =
      wantConnected && curNorm !== null ? curNorm.some((l) => l.startsWith(`${wan.ifaceCidr} dev ${wan.iface}`)) : !wantConnected;
    const wantDefault = `default via ${wan.gateway} dev ${wan.iface}${src} metric 1`;
    const hasDefault = curNorm !== null && curNorm.includes(normRoute(wantDefault));
    if (hasConnected && hasDefault) {
      reasons.push(`${wan.iface}: table ${table} already matches the kernel (idempotent skip)`);
    } else {
      if (!hasConnected && wantConnected) {
        steps.push({
          cmd: `ip route replace ${wan.ifaceCidr} dev ${wan.iface} src ${wan.ifaceIp} table ${table}`,
          summary: `table ${table}: connected ${wan.ifaceCidr}`,
        });
      }
      if (!hasDefault) {
        steps.push({
          cmd: `ip route replace default via ${wan.gateway} dev ${wan.iface}${src} metric 1 table ${table}`,
          summary: `table ${table}: default via ${wan.gateway} (${wan.iface}, ${wan.state})`,
        });
      }
    }
    const from = wan.ifaceIp;
    if (kernelRuleMatches(kernel, prio, table, from)) {
      reasons.push(`${wan.iface}: ip rule ${prio} already in kernel (idempotent skip)`);
    } else {
      if (kernelHasRule(kernel, prio)) {
        steps.push({ cmd: `ip rule del priority ${prio}`, summary: `replace stale rule at ${prio}` });
      }
      const sel = `priority ${prio}${from ? ` from ${from}` : ""} table ${table}`;
      steps.push({ cmd: `ip rule add ${sel}`, summary: `ip rule ${sel}` });
    }
  }

  // ── orphan sweep: kernel band entries with no owning policy ────────────────
  // a DELETED policy is invisible to the per-WAN loop above — its table/rule
  // would linger in the kernel forever; sweep anything unowned.
  const managedPrios = new Set(managed.map((m) => m.prio));
  for (const k of kernel ?? []) {
    if (k.priority >= WAN_PRIO_BASE && k.priority < WAN_PRIO_BASE + WAN_TABLE_LIMIT * 10 && !managedPrios.has(k.priority)) {
      const t = WAN_TABLE_BASE + Math.floor((k.priority - WAN_PRIO_BASE) / 10);
      steps.push({ cmd: `ip rule del priority ${k.priority}`, summary: `withdraw orphaned multi-WAN rule ${k.priority} (policy deleted)` });
      steps.push({ cmd: `ip route flush table ${t}`, summary: `flush orphaned multi-WAN table ${t}` });
    }
  }

  // ── managed egress decision (table 240; primary participates as candidate) ─
  const upWans = input.wans
    .filter((w) => w.enabled && w.gateway && (w.state === "up" || w.state === "degraded"))
    .sort((a, b) => {
      // primary first, then engine priority
      const ap = a.iface === input.primaryIface ? 0 : 1;
      const bp = b.iface === input.primaryIface ? 0 : 1;
      return ap - bp || a.priority - b.priority || a.id - b.id;
    });

  if (upWans.length === 0) {
    // honest offline — flush only when we don't KNOW the table is already empty
    // (undefined dump = no info → conservative flush; empty dump → skip)
    if (input.currentEgressRoutes !== undefined && input.currentEgressRoutes.length === 0) {
      return {
        steps,
        egressTable: null,
        managedTables,
        activeEgress: null,
        reasons: ["egress table already empty — nothing to withdraw"],
      };
    }
    steps.push({
      cmd: `ip route flush table ${WAN_EGRESS_TABLE}`,
      summary: `no up WAN with a gateway — table ${WAN_EGRESS_TABLE} emptied (honest offline)`,
    });
    return { steps, egressTable: null, managedTables, activeEgress: null, reasons };
  }

  // flush-then-install: multipath (no metric) and single-path (metric 1)
  // defaults are DIFFERENT kernel keys — `replace` alone would stack a stale
  // entry; the managed table must hold exactly the current decision.
  // The flush lives INSIDE each branch: in-sync states return with zero steps.

  const allLb = upWans.length >= 2 && upWans.every((w) => w.mode === "load_balance");
  if (allLb) {
    const nh = upWans
      .map((w) => `nexthop via ${w.gateway} dev ${w.iface} weight ${Math.max(1, Math.min(100, w.weight))}`)
      .join(" ");
    // in-sync detection: compare nexthop triples (via/dev/weight) with the kernel
    const desired = parseMultipathNexthops(nh.split("nexthop").filter((s) => s.trim()).map((s) => `nexthop ${s}`));
    const current = parseMultipathNexthops(input.currentEgressRoutes ?? []);
    const sameEcmp =
      desired.length === current.length &&
      desired.every((d, i) => {
        const c = current[i];
        return c && c.via === d.via && (c.dev ?? null) === d.dev && (c.weight ?? null) === (d.weight ?? null);
      });
    if (sameEcmp) {
      reasons.push(`table ${WAN_EGRESS_TABLE}: weighted ECMP already in kernel (idempotent skip)`);
      return {
        steps,
        egressTable: WAN_EGRESS_TABLE,
        managedTables,
        activeEgress: { iface: upWans.map((w) => w.iface).join("+"), style: "ecmp" },
        reasons,
      };
    }
    steps.push({ cmd: `ip route flush table ${WAN_EGRESS_TABLE}`, summary: `flush egress table ${WAN_EGRESS_TABLE} (decision changed)` });
    steps.push({
      cmd: `ip route replace default table ${WAN_EGRESS_TABLE} ${nh}`,
      summary: `table ${WAN_EGRESS_TABLE}: weighted ECMP across ${upWans.map((w) => w.iface).join(" + ")}`,
    });
    return { steps, egressTable: WAN_EGRESS_TABLE, managedTables, activeEgress: { iface: upWans.map((w) => w.iface).join("+"), style: "ecmp" }, reasons };
  }

  const best = upWans[0];
  // primary up → business as usual; primary exists but a standby took over → failover
  const style: "primary" | "priority" | "failover" =
    best.iface === input.primaryIface
      ? "primary"
      : input.primaryIface && input.wans.some((w) => w.iface === input.primaryIface)
        ? "failover"
        : "priority";
  const src = best.ifaceIp ? ` src ${best.ifaceIp}` : "";
  // in-sync detection: the kernel table already holds EXACTLY this decision →
  // zero steps (no pointless flush/replace churn on every reconverge pass)
  const desiredRoute = `default via ${best.gateway} dev ${best.iface}${src} metric 1`;
  const cur = (input.currentEgressRoutes ?? []).map(normRoute);
  if (cur.length === 1 && cur[0] === normRoute(desiredRoute)) {
    reasons.push(`table ${WAN_EGRESS_TABLE}: default already via ${best.gateway} dev ${best.iface} (idempotent skip)`);
    return { steps, egressTable: WAN_EGRESS_TABLE, managedTables, activeEgress: { iface: best.iface, style }, reasons };
  }
  // flush-then-install: multipath (no metric) and single-path (metric 1)
  // defaults are DIFFERENT kernel keys — `replace` alone would stack a stale
  // entry; the managed table must hold exactly the current decision
  steps.push({ cmd: `ip route flush table ${WAN_EGRESS_TABLE}`, summary: `flush egress table ${WAN_EGRESS_TABLE} (decision changed)` });
  steps.push({
    cmd: `ip route replace default via ${best.gateway} dev ${best.iface}${src} metric 1 table ${WAN_EGRESS_TABLE}`,
    summary: `table ${WAN_EGRESS_TABLE}: default via ${best.gateway} dev ${best.iface} (${style})`,
  });
  return { steps, egressTable: WAN_EGRESS_TABLE, managedTables, activeEgress: { iface: best.iface, style }, reasons };
}

// ── teardown ────────────────────────────────────────────────────────────────

/** Withdraw EVERYTHING multi-WAN ever installed (rules 3200..3299, tables 240..271). */
export function buildWanOsTeardownPlan(kernel: KernelPbrRule[] | null): WanOsPlan {
  const steps: WanOsStep[] = [];
  for (const k of kernel ?? []) {
    if (k.priority >= WAN_PRIO_BASE && k.priority < WAN_PRIO_BASE + WAN_TABLE_LIMIT * 10) {
      steps.push({ cmd: `ip rule del priority ${k.priority}`, summary: `drop multi-WAN rule ${k.priority}` });
    }
  }
  for (let t = WAN_TABLE_BASE; t < WAN_TABLE_BASE + WAN_TABLE_LIMIT; t++) {
    steps.push({ cmd: `ip route flush table ${t}`, summary: `flush policy table ${t}` });
  }
  steps.push({ cmd: `ip route flush table ${WAN_EGRESS_TABLE}`, summary: `flush egress table ${WAN_EGRESS_TABLE}` });
  return { steps, egressTable: null, managedTables: [], activeEgress: null, reasons: ["teardown"] };
}

// ── executor ────────────────────────────────────────────────────────────────

const WAN_EXEC_WHITELIST = /^ip (route (replace|del|add|flush)|rule (add|del)) [a-z0-9].*$/;
const MANAGED_TABLE = /\btable (2[4-7][0-9])\b/;

/**
 * Red-line guard for one WAN-OS step. Every route step must land in a
 * managed 240..279 table (main table is untouchable), rules must live in
 * the 3200..3299 band, loopback is never a device.
 */
export function wanStepGuarded(cmd: string): boolean {
  if (!WAN_EXEC_WHITELIST.test(cmd)) return false;
  if (/(^|\s)dev lo(\s|$)/.test(cmd)) return false;
  if (/ip route flush/.test(cmd)) return MANAGED_TABLE.test(cmd);
  if (/ip rule del/.test(cmd)) return /\bpriority 3[0-9]{3}\b/.test(cmd);
  if (/ip rule add/.test(cmd)) return /\bpriority 3[0-9]{3}\b/.test(cmd) && MANAGED_TABLE.test(cmd);
  // route replace/add/del — MUST target a managed table, never main/253/254/255
  return MANAGED_TABLE.test(cmd) && !/\btable (253|254|255|main|local)\b/.test(cmd);
}

/** Never throws — convergence errors surface as an honest failed outcome. */
export async function execWanOsPlan(plan: WanOsPlan): Promise<WanOsApplyOutcome> {
  if (process.env.CONSOLE_WAN_OS !== "1") {
    return {
      gate: "off",
      applied: false,
      reason: "multi-WAN kernel enforcement disabled (CONSOLE_WAN_OS) — plan is a preview only",
      plan,
    };
  }
  const { hasTool, runTool } = await import("@/lib/host/tools");
  if (!(await hasTool("ip"))) {
    return { gate: "on", applied: false, reason: "'ip' (iproute2) not found on the host — cannot execute the plan", plan };
  }
  for (const step of plan.steps) {
    if (!wanStepGuarded(step.cmd)) {
      return {
        gate: "on",
        applied: false,
        reason: `refused: step failed the multi-WAN guard — "${step.cmd}" (managed tables 240..279 + rules 3200..3299 only)`,
        plan,
      };
    }
  }
  // non-transactional by design: a missing rule to delete must not abort the
  // remaining installs; every step result is collected for audit honesty
  const results: Array<{ cmd: string; ok: boolean; stderr?: string }> = [];
  for (const step of plan.steps) {
    const r = await runTool(step.cmd);
    results.push({ cmd: step.cmd, ok: r.ok, stderr: r.ok ? undefined : r.stderr || r.error });
  }
  const failed = results.filter((r) => !r.ok);
  return {
    gate: "on",
    applied: failed.length === 0,
    reason: failed.length === 0 ? "applied to kernel" : `${failed.length}/${results.length} step(s) failed`,
    plan,
    results,
  };
}

/** Full converge pass (input → plan → exec). Never throws. */
export async function convergeWanOs(
  liveStates?: Record<string, "up" | "degraded" | "down" | "unknown">,
): Promise<WanOsApplyOutcome> {
  try {
    const input = await buildWanOsInput();
    if (liveStates) {
      // the engine's in-memory probe states are the CURRENT health decision —
      // DB rows can lag a just-persisted transition (write/converge race)
      for (const w of input.wans) {
        const s = liveStates[w.iface];
        if (s) w.state = s;
      }
    }
    const { readKernelPbrRules } = await import("./pbr-os");
    const kernel = await readKernelPbrRules();
    const plan = buildWanOsConvergePlan(input, kernel);
    if (plan.steps.length === 0) {
      return { gate: process.env.CONSOLE_WAN_OS === "1" ? "on" : "off", applied: false, reason: "nothing to converge", plan };
    }
    return await execWanOsPlan(plan);
  } catch (err) {
    return {
      gate: process.env.CONSOLE_WAN_OS === "1" ? "on" : "off",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      plan: { steps: [], egressTable: null, managedTables: [], activeEgress: null, reasons: [] },
    };
  }
}

// ── status / kernel visibility (GUI↔OS honesty) ─────────────────────────────

export interface WanOsRouteDump {
  table: number;
  routes: string[];
}

export interface WanOsKernelFacts {
  /** `ip` (iproute2) binary available — everything else needs it */
  ipAvailable: boolean;
  /** managed-band `ip rule` entries (3200..3299) actually in the kernel */
  bandRules: KernelPbrRule[];
  /** managed egress table (240) live contents — the engine's current decision */
  egress: WanOsRouteDump | null;
  /** non-empty per-WAN source tables (260..271) with their rules */
  perWan: WanOsRouteDump[];
}

export interface WanOsStatus {
  gate: "on" | "off";
  /** main-table default-route owner (excluded from source management) */
  primaryIface: string | null;
  /** config-plane view the planner converges from (DB states may lag probes) */
  wans: WanOsWanView[];
  kernel: WanOsKernelFacts;
  /** what the NEXT converge pass would do right now (idempotent preview) */
  preview: { stepCount: number; activeEgress: WanOsPlan["activeEgress"]; reasons: string[]; steps: WanOsStep[] };
  /** real failover event log (newest first) — attached by the route from the engine */
  events?: WanTransitionEvent[];
}

/** keep only the managed multi-WAN rule band (3200..3299) */
export function filterWanBandRules(rules: KernelPbrRule[]): KernelPbrRule[] {
  return rules.filter((k) => k.priority >= WAN_PRIO_BASE && k.priority < WAN_PRIO_BASE + WAN_TABLE_LIMIT * 10);
}

/** `ip route show table N` output → clean route lines */
export function parseRouteTableDump(out: string): string[] {
  return out
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/**
 * Assemble the full GUI↔kernel status: gate, planner input, live kernel facts
 * (band rules + table dumps) and an idempotent preview of the next converge
 * pass. Read-only — never executes a step.
 */
export async function wanOsStatus(): Promise<WanOsStatus> {
  const { hasTool } = await import("@/lib/host/tools");
  const ipAvailable = await hasTool("ip");
  const input = await buildWanOsInput().catch(() => ({ primaryIface: null, wans: [] as WanOsWanView[] }));
  const { readKernelPbrRules } = await import("./pbr-os");
  const kernelRules = ipAvailable ? await readKernelPbrRules().catch(() => null) : null;

  const egressRoutes = input.currentEgressRoutes ?? [];
  const perWan: WanOsRouteDump[] = Object.entries(input.currentPerWanRoutes ?? {})
    .map(([t, routes]) => ({ table: Number(t), routes }))
    .filter((d) => d.routes.length > 0)
    .sort((a, b) => a.table - b.table);

  const plan = buildWanOsConvergePlan(input, kernelRules);
  return {
    gate: process.env.CONSOLE_WAN_OS === "1" ? "on" : "off",
    primaryIface: input.primaryIface,
    wans: input.wans,
    kernel: {
      ipAvailable,
      bandRules: kernelRules ? filterWanBandRules(kernelRules) : [],
      egress: egressRoutes.length > 0 ? { table: WAN_EGRESS_TABLE, routes: egressRoutes } : null,
      perWan,
    },
    preview: { stepCount: plan.steps.length, activeEgress: plan.activeEgress, reasons: plan.reasons, steps: plan.steps },
  };
}

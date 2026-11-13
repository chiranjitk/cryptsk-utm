/**
 * Port mirroring (SPAN) OS layer — real kernel mirroring with `tc`/mirred.
 *
 * Enterprise semantics (FortiGate SPAN / pfSense packet capture parity):
 *   • `tc qdisc replace dev SRC clsact` — shared ingress/egress hook block
 *   • ingress direction (or both):  matchall ingress filter → mirred egress mirror dev DST
 *   • egress direction (or both):   matchall egress filter  → mirred egress mirror dev DST
 *   • one ACTIVE mirror per source iface is enforced upstream (M02 §3 409),
 *     so the console owns the whole filter block of the source — teardown is
 *     a plain `tc filter del` of that block.
 *
 * Red-line safety: tc commands only; `lo` and CONSOLE_PROTECTED_IFACES
 * (default: ens32, the WAN/mgmt uplink) are hard-refused; whitelist allows
 * only `tc qdisc replace` / `tc filter add|del` verbs on clsact blocks.
 */

export interface MirrorOsView {
  id: number;
  name: string;
  srcIface: string;
  dstIface: string;
  direction: "ingress" | "egress" | "both";
  enabled: boolean;
}

export interface MirrorPlanStep {
  cmd: string;
  summary: string;
  /** cleanup step — failure is non-fatal (e.g. del on an empty block) */
  soft?: boolean;
}

export interface MirrorOsPlan {
  name: string;
  srcIface: string;
  dstIface: string | null;
  reason: string;
  steps: MirrorPlanStep[];
}

/** Protected interfaces never receive mirror/qdisc state (never touched). */
export function protectedMirrorIfaces(): string[] {
  return (process.env.CONSOLE_PROTECTED_IFACES ?? "ens32")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function isProtectedMirrorIface(name: string): boolean {
  const n = name.toLowerCase();
  return n === "lo" || protectedMirrorIfaces().includes(n);
}

/** Teardown — clear this mirror's filters off the source interface block(s). */
export function buildMirrorTeardownPlan(mirror: MirrorOsView): MirrorOsPlan {
  const blocks = mirror.direction === "both" ? ["ingress", "egress"] : [mirror.direction];
  const steps: MirrorPlanStep[] = blocks.map((b) => ({
    cmd: `tc filter del dev ${mirror.srcIface} ${b}`,
    summary: `clear ${b} filters on ${mirror.srcIface}`,
    soft: true,
  }));
  return {
    name: mirror.name,
    srcIface: mirror.srcIface,
    dstIface: null,
    reason: mirror.enabled ? "replace pre-step — withdraw stale filters" : "mirror disabled — kernel mirroring withdrawn",
    steps,
  };
}

/** Install plan — clsact block + matchall/mirred filters per direction. */
export function buildMirrorApplyPlan(mirror: MirrorOsView): MirrorOsPlan {
  if (!mirror.enabled) {
    return { ...buildMirrorTeardownPlan(mirror), dstIface: null };
  }
  const blocks = mirror.direction === "both" ? ["ingress", "egress"] : [mirror.direction];
  const steps: MirrorPlanStep[] = [{ cmd: `tc qdisc replace dev ${mirror.srcIface} clsact`, summary: `ensure clsact on ${mirror.srcIface}` }];
  for (const b of blocks) {
    steps.push({
      cmd: `tc filter del dev ${mirror.srcIface} ${b}`,
      summary: `clear stale ${b} filters`,
      soft: true,
    });
    steps.push({
      cmd: `tc filter add dev ${mirror.srcIface} ${b} protocol all pref 1 matchall action mirred egress mirror dev ${mirror.dstIface}`,
      summary: `${b} → mirror to ${mirror.dstIface}`,
    });
  }
  return {
    name: mirror.name,
    srcIface: mirror.srcIface,
    dstIface: mirror.dstIface,
    reason: `clsact + matchall/mirred filters (${mirror.direction}) on ${mirror.srcIface} → ${mirror.dstIface}`,
    steps,
  };
}

// ── kernel state (tc filter show) ───────────────────────────────────────────

export interface KernelMirrorFilter {
  block: "ingress" | "egress";
  pref: number;
  /** mirred target device (null when the filter is not a mirred mirror) */
  mirrorDev: string | null;
}

/** Parse `tc filter show dev X <block>` output for matchall+mirred filters. */
export function parseTcFilterShow(out: string, block: "ingress" | "egress"): KernelMirrorFilter[] {
  const rows: KernelMirrorFilter[] = [];
  let cur: KernelMirrorFilter | null = null;
  for (const raw of out.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const head = /^filter protocol (\S+) pref (\d+) (?:matchall|\S+) chain/.exec(line);
    if (head) {
      cur = { block, pref: Number(head[2]), mirrorDev: null };
      rows.push(cur);
      continue;
    }
    const mir =
      /mirred\s+(?:egress|ingress)\s+mirror\s+(?:to\s+device\s+|dev\s+)(\S+)/i.exec(line) ??
      // older iproute2: "mirred (Egress Mirror to device ens34) pipe"
      /mirred\s*\(\s*(?:[Ee]gress|[Ii]ngress)\s+[Mm]irror\s+to\s+device\s+([^\s)]+)\s*\)/.exec(line);
    if (mir && cur && !cur.mirrorDev) {
      cur.mirrorDev = mir[1].replace(/[:;,]+$/, "");
    }
  }
  return rows;
}

export type MirrorKernelState = "disabled" | "in-kernel" | "missing" | null;

/**
 * Kernel state for one mirror (kernel null → null = host without tc).
 * in-kernel = every required direction block mirrors to dstIface.
 */
export function mirrorKernelState(
  mirror: MirrorOsView,
  kernel: KernelMirrorFilter[] | null,
): MirrorKernelState {
  if (kernel === null) return null;
  if (!mirror.enabled) return "disabled";
  const blocks = mirror.direction === "both" ? (["ingress", "egress"] as const) : ([mirror.direction] as const);
  for (const b of blocks) {
    const hit = kernel.some((k) => k.block === b && k.mirrorDev === mirror.dstIface);
    if (!hit) return "missing";
  }
  return "in-kernel";
}

/** Read real kernel mirror filters for one source interface (null = no tc). */
export async function readKernelMirrorFilters(srcIface: string): Promise<KernelMirrorFilter[] | null> {
  const { hasTool, runTool } = await import("@/lib/host/tools");
  if (!(await hasTool("tc"))) return null;
  const out: KernelMirrorFilter[] = [];
  for (const block of ["ingress", "egress"] as const) {
    const r = await runTool(`tc filter show dev ${srcIface} ${block} 2>/dev/null`, 5000);
    if (r.ok) out.push(...parseTcFilterShow(r.stdout, block));
  }
  return out;
}

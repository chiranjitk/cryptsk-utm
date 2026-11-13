/**
 * Static-route OS layer (appliance-grade routing) — pure planner + kernel
 * reader, mirroring iface-os.ts. The kernel is the FIB; the DB row is desired
 * state; `ip route` (iproute2) is the tool.
 *
 * Metric policy (default-hijack guard by construction):
 *   every static route is installed with `metric <distance>` (distance 1 →
 *   metric 1). The interface-managed primary default carries kernel metric 0,
 *   so a static 0.0.0.0/0 can NEVER shadow it — static defaults are floating
 *   backups by construction. BR-ROUTE-DEFAULT-PRIMARY still warns at 409.
 *
 * ECMP safety: stale-entry removal is SIBLING-AWARE — an entry owned by
 * another enabled DB row (ECMP set member) is never deleted by this row's
 * apply plan.
 *
 * Kernel state per row (vendor Status column parity):
 *   disabled   — row is administratively off (kernel must NOT hold it)
 *   in-kernel  — an entry matches dest+via+dev+metric(+type) exactly
 *   drifted    — dest exists but every entry differs (stale next-hop/metric)
 *   missing    — nothing for this dest in the FIB
 */

import { hasTool, runTool } from "@/lib/host/tools";
import type { RouteRuleView } from "./route-rules";

export interface OsPlanStep {
  cmd: string;
  summary: string;
}

export interface OsPlan {
  name: string;
  osName: string | null;
  steps: OsPlanStep[];
}

export interface KernelRoute {
  /** destination prefix as written by iproute2 ("10.0.0.0/24", "default", "10.0.0.5") */
  dest: string;
  via: string | null;
  dev: string | null;
  metric: number;
  blackhole: boolean;
  raw: string;
}

/** `ip route show` → structured entries (null when `ip` is unavailable). */
export async function readKernelRoutes(): Promise<KernelRoute[] | null> {
  if (!(await hasTool("ip"))) return null;
  const r = await runTool("ip route show", 6000);
  if (!r.ok) return null;
  return parseKernelRoutes(r.stdout);
}

export function parseKernelRoutes(out: string): KernelRoute[] {
  const rows: KernelRoute[] = [];
  for (const line of out.split("\n")) {
    const raw = line.trim();
    if (!raw) continue;
    const f = raw.split(/\s+/);
    let dest = f[0];
    let blackhole = false;
    if (f[0] === "blackhole" && f.length >= 2) {
      blackhole = true;
      dest = f[1];
    }
    if (f[0] === "unreachable" || f[0] === "prohibit" || f[0] === "throw") {
      blackhole = true;
      dest = f[1] ?? f[0];
    }
    let via: string | null = null;
    let dev: string | null = null;
    let metric = 0;
    for (let i = 1; i < f.length; i++) {
      if (f[i] === "via" && f[i + 1]) via = f[++i];
      else if (f[i] === "dev" && f[i + 1]) dev = f[++i];
      else if (f[i] === "metric" && f[i + 1]) metric = Number(f[++i]) || 0;
    }
    rows.push({ dest, via, dev, metric, blackhole, raw });
  }
  return rows;
}

/** canonical FIB dest string for a DB row ("default" for 0.0.0.0/0). */
function fibDest(cidr: string): string {
  return cidr === "0.0.0.0/0" ? "default" : cidr;
}

export type RouteOsState = "disabled" | "in-kernel" | "drifted" | "missing";

function routeMatchesRow(k: KernelRoute, view: RouteRuleView): boolean {
  return (
    k.blackhole === view.blackhole &&
    (k.via ?? null) === (view.gateway ?? null) &&
    (k.dev ?? null) === (view.interfaceName ?? null) &&
    k.metric === view.distance
  );
}

/** Compare one DB row against the kernel FIB (null kernel → null = unknown). */
export function kernelRouteState(view: RouteRuleView, kernel: KernelRoute[] | null): RouteOsState | null {
  if (!kernel) return null; // host without iproute2 — honest absence
  const dest = fibDest(view.destinationCidr);
  const sameDest = kernel.filter((k) => k.dest === dest);
  const mine = sameDest.filter((k) => routeMatchesRow(k, view));
  if (!view.enabled) return mine.length > 0 ? "drifted" : "disabled";
  if (mine.length > 0) return "in-kernel";
  return sameDest.length > 0 ? "drifted" : "missing";
}

// ── plans ────────────────────────────────────────────────────────────────────

function delCmd(k: KernelRoute): string {
  return k.blackhole
    ? `ip route del blackhole ${k.dest}${k.metric ? ` metric ${k.metric}` : ""}`
    : `ip route del ${k.dest}${k.via ? ` via ${k.via}` : ""}${k.dev ? ` dev ${k.dev}` : ""}${k.metric ? ` metric ${k.metric}` : ""}`;
}

/**
 * Convergence plan for one route row.
 *   • removes drifted entries for the destination that NO other enabled row
 *     owns (sibling-aware — ECMP members survive),
 *   • METRIC-SCOPED: an entry is only "stale" for THIS row when its metric
 *     equals the row's distance — foreign entries on the same destination
 *     (e.g. the kernel-managed metric-0 primary default installed by the
 *     interface module, or the user's own metric-1 production default) are
 *     NEVER touched by a row carrying a different metric. This is the guard
 *     that keeps a static 0.0.0.0/0 from deleting the appliance's primary
 *     default (the 2026-11-13 outage root cause — do not relax it),
 *   • installs the desired entry with idempotent `ip route replace`,
 *   • disabled rows only withdraw their own stale entries.
 */
export function buildRouteApplyPlan(
  view: RouteRuleView,
  kernel: KernelRoute[] | null,
  siblings: RouteRuleView[] = [],
  /** the pre-edit row (PUT flows) — its exact historical footprint is withdrawn */
  previous?: RouteRuleView | null,
): OsPlan {
  const steps: OsPlanStep[] = [];
  const dest = fibDest(view.destinationCidr);
  const otherEnabled = siblings.filter((s) => s.id !== view.id && s.enabled);

  if (kernel) {
    const ownedElsewhere = new Set(
      kernel.filter((k) => otherEnabled.some((s) => routeMatchesRow(k, s))).map((k) => k.raw),
    );
    const isMine =
      (k: KernelRoute) =>
        // METRIC-SCOPED slot: this row's distance slot on this destination
        (k.metric === view.distance && k.dest === dest) ||
        // the row's own pre-edit footprint (distance-change cleanup) — exact
        // via/dev/metric/type match, so foreign entries (e.g. a metric-0
        // primary default) can never fall in here
        (previous != null && routeMatchesRow(k, previous));
    const stale = kernel.filter(
      (k) =>
        isMine(k) &&
        !ownedElsewhere.has(k.raw) &&
        (view.enabled ? !routeMatchesRow(k, view) : routeMatchesRow(k, view)),
    );
    for (const k of stale) steps.push({ cmd: delCmd(k), summary: `remove stale FIB entry (${k.raw})` });
  }

  if (!view.enabled) return { name: view.destinationCidr, osName: view.interfaceName ?? null, steps };

  const metric = ` metric ${view.distance}`;
  if (view.blackhole) {
    steps.push({
      cmd: `ip route replace blackhole ${view.destinationCidr}${metric}`,
      summary: `install blackhole ${view.destinationCidr} (metric ${view.distance})`,
    });
  } else if (view.gateway && view.interfaceName) {
    steps.push({
      cmd: `ip route replace ${view.destinationCidr} via ${view.gateway} dev ${view.interfaceName}${metric}`,
      summary: `install ${view.destinationCidr} via ${view.gateway} dev ${view.interfaceName} (metric ${view.distance})`,
    });
  } else if (view.gateway) {
    steps.push({
      cmd: `ip route replace ${view.destinationCidr} via ${view.gateway}${metric}`,
      summary: `install ${view.destinationCidr} via ${view.gateway} (metric ${view.distance}; kernel resolves egress)`,
    });
  } else if (view.interfaceName) {
    steps.push({
      cmd: `ip route replace ${view.destinationCidr} dev ${view.interfaceName}${metric}`,
      summary: `install ${view.destinationCidr} dev ${view.interfaceName} (direct, metric ${view.distance})`,
    });
  }
  // neither gateway nor interface → inert row (validated upstream); nothing to install
  return { name: view.destinationCidr, osName: view.interfaceName ?? null, steps };
}

/** Teardown plan for a deleted row — withdraw every FIB entry this row owns. */
export function buildRouteDeletePlan(view: RouteRuleView, kernel: KernelRoute[] | null): OsPlan {
  const steps: OsPlanStep[] = [];
  const dest = fibDest(view.destinationCidr);
  if (kernel) {
    for (const k of kernel.filter((k2) => k2.dest === dest && routeMatchesRow(k2, view))) {
      steps.push({ cmd: delCmd(k), summary: `withdraw ${k.raw}` });
    }
    return { name: view.destinationCidr, osName: view.interfaceName ?? null, steps };
  }
  // kernel unreadable — best-effort exact del (ENOENT tolerated downstream)
  const metric = ` metric ${view.distance}`;
  if (view.blackhole) steps.push({ cmd: `ip route del blackhole ${view.destinationCidr}${metric}`, summary: `withdraw blackhole ${view.destinationCidr} (best effort)` });
  else if (view.gateway && view.interfaceName)
    steps.push({ cmd: `ip route del ${view.destinationCidr} via ${view.gateway} dev ${view.interfaceName}${metric}`, summary: `withdraw ${view.destinationCidr} via ${view.gateway} dev ${view.interfaceName} (best effort)` });
  else if (view.gateway) steps.push({ cmd: `ip route del ${view.destinationCidr} via ${view.gateway}${metric}`, summary: `withdraw ${view.destinationCidr} via ${view.gateway} (best effort)` });
  else if (view.interfaceName) steps.push({ cmd: `ip route del ${view.destinationCidr} dev ${view.interfaceName}${metric}`, summary: `withdraw ${view.destinationCidr} dev ${view.interfaceName} (best effort)` });
  return { name: view.destinationCidr, osName: view.interfaceName ?? null, steps };
}

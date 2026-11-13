/**
 * Static-route business rules — pure engine (mirrors iface-rules.ts).
 *
 * Enterprise semantics (FortiGate/PAN-OS parity):
 *   • BR-ROUTE-DUP            exact duplicate of another row (same dest+distance+
 *                             gateway+interface+blackhole) → conflict (409, force
 *                             allowed only with a distinct description? no — dup is
 *                             never forceable; caller must edit or delete)
 *   • BR-ROUTE-ECMP           same dest+distance, different gateway/interface →
 *                             ALLOWED (real ECMP set, like FortiGate equal-priority)
 *   • BR-ROUTE-DEFAULT-PRIMARY 0.0.0.0/0 with distance 1 → conflict: the primary
 *                             default belongs to the interface module (kernel metric
 *                             0); static defaults are always floating backups because
 *                             the executor always emits metric ≥ 1. Force-able.
 *   • BR-ROUTE-BLACKHOLE-GW   blackhole + gateway together → invalid
 *   • BR-ROUTE-SELF-GW        gateway inside its own destination network → invalid
 *                             (recursive next-hop; Linux would still install it but
 *                             it never resolves)
 */

export interface RouteRuleView {
  id?: number;
  name?: string | null;
  destinationCidr: string;
  gateway: string | null;
  interfaceName: string | null;
  distance: number;
  bfd?: boolean;
  blackhole: boolean;
  enabled: boolean;
}

export interface RouteIssue {
  code: string;
  message: string;
  field?: string;
  /** conflicts are 409-able (force flows), invalids are hard 400s */
  kind: "conflict" | "invalid" | "info";
}

function cidrNetwork(cidr: string): { addr: string; prefix: number } | null {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(cidr.trim());
  if (!m) return null;
  const prefix = Number(m[2]);
  if (prefix > 32) return null;
  return { addr: m[1], prefix };
}

function ipToLong(ip: string): number | null {
  const f = ip.split(".").map(Number);
  if (f.length !== 4 || f.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((f[0] << 24) >>> 0) + (f[1] << 16) + (f[2] << 8) + f[3];
}

/** true when `ip` falls inside `cidr` (pure, no deps). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const net = cidrNetwork(cidr);
  const probe = ipToLong(ip);
  if (!net || probe === null) return false;
  const base = ipToLong(net.addr);
  if (base === null) return false;
  const mask = net.prefix === 0 ? 0 : (0xffffffff << (32 - net.prefix)) >>> 0;
  return (base & mask) === (probe & mask);
}

/**
 * Validate a create/update against the sibling rows.
 * `excludeId` must be the id of the row being updated.
 */
export function validateRouteMutation(
  candidate: RouteRuleView,
  siblings: RouteRuleView[],
  opts?: { excludeId?: number },
): RouteIssue[] {
  const issues: RouteIssue[] = [];

  if (candidate.blackhole && candidate.gateway) {
    issues.push({
      code: "BR-ROUTE-BLACKHOLE-GW",
      kind: "invalid",
      field: "gateway",
      message: "Blackhole routes must not set a gateway",
    });
  }

  // recursive next-hop: gateway inside its own destination prefix never resolves
  // (skipped for /0 — every gateway is "inside" the default route by definition)
  if (!candidate.blackhole && candidate.gateway && ipInCidr(candidate.gateway, candidate.destinationCidr)) {
    const net = cidrNetwork(candidate.destinationCidr);
    if (net && net.prefix > 0 && net.prefix < 32) {
      issues.push({
        code: "BR-ROUTE-SELF-GW",
        kind: "invalid",
        field: "gateway",
        message: `Gateway ${candidate.gateway} sits inside the destination ${candidate.destinationCidr} — recursive next-hop never resolves`,
      });
    }
  }

  const others = siblings.filter((r) => r.id !== opts?.excludeId);
  const sameDest = others.filter((r) => r.destinationCidr === candidate.destinationCidr);

  // exact duplicate (intent-independent of enabled/description)
  const dup = sameDest.find(
    (r) =>
      r.distance === candidate.distance &&
      (r.gateway ?? null) === (candidate.gateway ?? null) &&
      (r.interfaceName ?? null) === (candidate.interfaceName ?? null) &&
      r.blackhole === candidate.blackhole,
  );
  if (dup) {
    issues.push({
      code: "BR-ROUTE-DUP",
      kind: "conflict",
      field: "destinationCidr",
      message: `An identical route already exists${dup.name ? ` ("${dup.name}")` : ""} — same destination, distance, gateway and interface`,
    });
  }

  // ECMP set: same dest + same distance but a different gateway/interface → allowed
  const ecmp = sameDest.find((r) => r.distance === candidate.distance && !dup);
  if (ecmp) {
    issues.push({
      code: "BR-ROUTE-ECMP",
      kind: "info",
      message: `Joins an ECMP set — ${candidate.destinationCidr} already has a distance-${candidate.distance} route${ecmp.name ? ` ("${ecmp.name}")` : ""} via ${ecmp.gateway ?? ecmp.interfaceName ?? "iface"}`,
    });
  }

  // floating default guard: primary default is owned by the interface module
  if (candidate.destinationCidr === "0.0.0.0/0" && candidate.distance <= 1) {
    issues.push({
      code: "BR-ROUTE-DEFAULT-PRIMARY",
      kind: "conflict",
      field: "distance",
      message:
        "Static 0.0.0.0/0 with distance ≤ 1 would shadow the interface-managed primary default — use distance ≥ 2 for a floating backup default (or configure the default on the WAN interface)",
    });
  }

  return issues;
}

/** Hard issues (400): blackhole+gateway, recursive next-hop. */
export function hardRouteIssues(issues: RouteIssue[]): RouteIssue[] {
  return issues.filter((i) => i.kind === "invalid");
}

/** Conflicts (409 + force flow): duplicates, primary-default shadow. */
export function conflictRouteIssues(issues: RouteIssue[]): RouteIssue[] {
  return issues.filter((i) => i.kind === "conflict");
}

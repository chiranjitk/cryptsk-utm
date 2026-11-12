/**
 * Interface OS sync — drift detection + apply-plan generation.
 *
 * The console is the desired state (DB), /sys/class/net is the actual state
 * (host OS). diffIfaceOs() compares them field by field; buildApplyPlan()
 * emits the exact iproute2 commands that would converge the host onto the DB.
 *
 * Execution is gated: the apply endpoint only runs the plan when
 * CONSOLE_OS_APPLY=1 is set in the environment — everywhere else it is a
 * preview (plan-only). This module itself is side-effect free and pure
 * except for the RealInterface type import.
 *
 * buildApplyPlan/buildDeletePlan take an optional `hostDefaultDev` (the dev
 * of the host's current default route) so default-route mutation steps are
 * only generated for the interface that actually owns the route.
 */

import type { RealInterface } from "@/lib/host/proc";
import {
  readSecondaryIps,
  type IfaceRuleView,
} from "./iface-rules";

export interface OsDriftItem {
  field: string;
  db: string;
  os: string;
}

export interface OsDiff {
  managed: boolean;
  inSync: boolean;
  drift: OsDriftItem[];
}

function osUpState(os: RealInterface): string {
  return os.operState || "unknown";
}

/** Field-level diff between the DB row (desired) and the OS interface (actual). */
export function diffIfaceOs(view: IfaceRuleView, os: RealInterface | undefined): OsDiff {
  if (!os) return { managed: false, inSync: false, drift: [] };
  const drift: OsDriftItem[] = [];

  // admin state — OS reports "down" while the console expects the link up
  if (view.enabled && osUpState(os) === "down") {
    drift.push({ field: "admin", db: "enabled", os: "down" });
  }

  // MTU
  if (os.mtu != null && os.mtu !== view.mtu) {
    drift.push({ field: "mtu", db: String(view.mtu), os: String(os.mtu) });
  }

  // L3 addressing (only meaningful when the console carries a static primary)
  const ip = typeof view.config["ip"] === "string" ? (view.config["ip"] as string) : null;
  const prefix = typeof view.config["cidrPrefix"] === "number" ? (view.config["cidrPrefix"] as number) : null;
  if (view.mode === "l3" && ip && prefix != null) {
    if (!os.ipv4.includes(ip)) {
      drift.push({ field: "ip", db: `${ip}/${prefix}`, os: os.ipv4.join(", ") || "none" });
    } else {
      const expected = new Set([ip, ...readSecondaryIps(view.config).map((s) => s.ip)]);
      const extra = os.ipv4.filter((a) => !expected.has(a));
      if (extra.length > 0) {
        drift.push({ field: "ip-extra", db: ip, os: extra.join(", ") });
      }
    }
  }

  return { managed: true, inSync: drift.length === 0, drift };
}

// ── apply plan ──────────────────────────────────────────────────────────────

export interface OsPlanStep {
  cmd: string;
  summary: string;
}

export interface OsPlan {
  name: string;
  /** OS-side interface name (logical ifaces share their DB name) */
  osName: string | null;
  steps: OsPlanStep[];
}

function linkAdminSteps(name: string, view: IfaceRuleView, os: RealInterface | undefined): OsPlanStep[] {
  const steps: OsPlanStep[] = [];
  if (!view.enabled) {
    if (!os || osUpState(os) !== "down") {
      steps.push({ cmd: `ip link set ${name} down`, summary: "admin down (interface disabled in console)" });
    }
    return steps;
  }
  if (!os) {
    // freshly created links (bridges/bonds are born admin-down) — force up
    steps.push({ cmd: `ip link set ${name} up`, summary: "bring new interface up" });
    return steps;
  }
  if (osUpState(os) === "down") {
    steps.push({ cmd: `ip link set ${name} up`, summary: "bring interface up" });
  }
  return steps;
}

function addrSteps(
  name: string,
  view: IfaceRuleView,
  os: RealInterface | undefined,
  hostDefaultDev: string | null | undefined,
): OsPlanStep[] {
  const steps: OsPlanStep[] = [];
  if (view.mode !== "l3") return steps;

  const ip = typeof view.config["ip"] === "string" ? (view.config["ip"] as string) : null;
  const prefix = typeof view.config["cidrPrefix"] === "number" ? (view.config["cidrPrefix"] as number) : null;
  if (ip && prefix != null) {
    steps.push({
      cmd: `ip addr replace ${ip}/${prefix} dev ${name}`,
      summary: "primary IPv4 address",
    });
    for (const sec of readSecondaryIps(view.config)) {
      steps.push({ cmd: `ip addr replace ${sec.ip}/${sec.cidrPrefix} dev ${name}`, summary: `secondary ${sec.ip}` });
    }
    if (os) {
      const expected = new Set([ip, ...readSecondaryIps(view.config).map((s) => s.ip)]);
      for (const extra of os.ipv4) {
        if (!expected.has(extra)) {
          steps.push({ cmd: `ip addr del ${extra} dev ${name}`, summary: `remove unmanaged address ${extra}` });
        }
      }
    }
    // default-route ownership safety — `ip route replace default` rewrites the
    // host's ONLY default route. When another interface already owns it, the
    // step is suppressed (a second WAN must never silently hijack it).
    const gw = typeof view.config["gateway"] === "string" ? (view.config["gateway"] as string) : null;
    if (gw && (!hostDefaultDev || hostDefaultDev === name)) {
      steps.push({ cmd: `ip route replace default via ${gw} dev ${name}`, summary: `default route via ${gw}` });
    }
  }
  const mss = typeof view.config["mssClamp"] === "number" ? (view.config["mssClamp"] as number) : view.mssClamp;
  // advmss mutates the existing default route — same ownership rule applies
  // (undefined = route info not provided → legacy behavior; null = known none)
  if (typeof mss === "number" && (hostDefaultDev === undefined || hostDefaultDev === name)) {
    steps.push({
      cmd: `ip route change default dev ${name} advmss ${mss}`,
      summary: `TCP MSS clamp ${mss} (advmss)`,
    });
  }
  return steps;
}

/**
 * Build the iproute2 plan that converges the host onto the console row.
 * When `os` is undefined the interface is missing on the host → creation steps.
 */
export function buildApplyPlan(
  view: IfaceRuleView,
  os: RealInterface | undefined,
  hostDefaultDev?: string | null,
): OsPlan {
  const steps: OsPlanStep[] = [];
  const name = view.name;

  if (!os) {
    // creation — only logical interfaces can be created by the console
    switch (view.type) {
      case "vlan":
        steps.push({
          cmd: `ip link add link ${view.parentName ?? "PARENT?"} name ${name} type vlan id ${view.vlanId ?? 0}`,
          summary: `create VLAN ${view.vlanId} on ${view.parentName ?? "?"}`,
        });
        break;
      case "bridge": {
        steps.push({ cmd: `ip link add name ${name} type bridge`, summary: "create bridge" });
        const stp = view.config["stp"] === true;
        steps.push({ cmd: `ip link set dev ${name} type bridge stp_state ${stp ? 1 : 0}`, summary: `STP ${stp ? "on" : "off"}` });
        if (stp) {
          const mode = view.config["stpMode"] === "rstp" ? "mstp" : "stp";
          steps.push({ cmd: `ip link set dev ${name} type bridge stp_protocol ${mode}`, summary: `STP protocol ${mode}` });
          const prio = view.config["stpPriority"];
          if (typeof prio === "number") {
            steps.push({ cmd: `ip link set dev ${name} type bridge stp_priority ${prio}`, summary: `STP priority ${prio}` });
          }
          const fd = view.config["forwardDelay"];
          if (typeof fd === "number") {
            steps.push({ cmd: `ip link set dev ${name} type bridge forward_delay ${fd}`, summary: `forward delay ${fd}s` });
          }
        }
        if (view.config["igmpSnooping"] === true) {
          steps.push({ cmd: `ip link set dev ${name} type bridge mcast_snooping 1`, summary: "IGMP snooping on" });
        }
        break;
      }
      case "bond": {
        const mode = typeof view.config["mode"] === "string" ? (view.config["mode"] as string) : "active-backup";
        steps.push({ cmd: `ip link add name ${name} type bond mode ${mode}`, summary: `create bond (${mode})` });
        if (mode === "802.3ad") {
          const rate = view.config["lacpRate"] === "fast" ? "fast" : "slow";
          steps.push({ cmd: `ip link set dev ${name} type bond lacp_rate ${rate}`, summary: `LACP rate ${rate}` });
        }
        const miimon = view.config["miimon"];
        if (typeof miimon === "number" && miimon > 0) {
          steps.push({ cmd: `ip link set dev ${name} type bond miimon ${miimon}`, summary: `miimon ${miimon}ms` });
        }
        break;
      }
      case "loopback":
        steps.push({ cmd: `ip link add name ${name} type loopback`, summary: "create loopback" });
        break;
      default:
        // physical/tunnels cannot be conjured by the console
        break;
    }
  } else if (os.mtu != null && os.mtu !== view.mtu) {
    steps.push({ cmd: `ip link set ${name} mtu ${view.mtu}`, summary: `MTU ${os.mtu} -> ${view.mtu}` });
  }

  // members (bridge/bond)
  if (view.type === "bridge" || view.type === "bond") {
    const members = Array.isArray(view.config["members"])
      ? (view.config["members"] as unknown[]).filter((m): m is string => typeof m === "string")
      : [];
    for (const m of members) {
      steps.push({ cmd: `ip link set ${m} down`, summary: `${m} down before enslaving` });
      steps.push({ cmd: `ip link set ${m} master ${name}`, summary: `enslave ${m} to ${name}` });
      steps.push({ cmd: `ip link set ${m} up`, summary: `${m} up` });
    }
  }

  steps.push(...linkAdminSteps(name, view, os));
  steps.push(...addrSteps(name, view, os, hostDefaultDev));

  return { name, osName: os ? os.name : null, steps };
}

/**
 * Teardown plan for a deleted console interface. Only logical kernel links
 * (vlan/bridge/bond/loopback/tunnels) can be removed from the host — physical
 * ports stay (the kernel owns them), only the console record disappears.
 */
export function buildDeletePlan(view: IfaceRuleView, os: RealInterface | undefined): OsPlan {
  const steps: OsPlanStep[] = [];
  if (os && view.type !== "physical") {
    steps.push({ cmd: `ip link del ${view.name}`, summary: "remove interface from host" });
  }
  return { name: view.name, osName: os ? os.name : null, steps };
}

/** Compare a DB row against the OS list by name; null OS → unmanaged entry. */
export function osRowFor(ifaces: RealInterface[], name: string): RealInterface | undefined {
  return ifaces.find((i) => i.name === name);
}

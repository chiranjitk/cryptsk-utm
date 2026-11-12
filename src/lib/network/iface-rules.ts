/**
 * Interface business rules — PURE engine (no imports, runs in browser + server + tests).
 *
 * Every check returns a stable-coded issue so the UI can render live validation,
 * the API can enforce the same rules as 4xx errors, and the unit tests can pin
 * the contract. DB-dependent checks (unknown parents/members, mgmt-lockout
 * counting, reference conflicts) take the full interface list as input.
 *
 * Codes (stable, test-pinned):
 *   BR-NAME            interface name grammar
 *   BR-MTU-BOUNDS      MTU 68..9000
 *   BR-MTU-VLAN        VLAN MTU must not exceed parent MTU
 *   BR-MTU-PARENT      parent MTU must not drop below any VLAN child MTU
 *   BR-MTU-MEMBER      bridge/bond MTU must not exceed smallest member MTU
 *   BR-MTU-MASTER      member MTU must not drop below a master bridge/bond MTU
 *   BR-MSS             MSS clamp <= MTU-40
 *   BR-MSS-HINT        WAN role with MTU<1500 and no clamp (warning)
 *   BR-GW-SUBNET       gateway must sit inside the interface subnet
 *   BR-OVERLAP         L3 subnets must not overlap across interfaces
 *   BR-SECIP           secondary IP grammar / duplicates / count
 *   BR-WAN-ADDR        static WAN requires an IPv4 address
 *   BR-L2-L3           L2 mode carries no L3 addressing
 *   BR-MGMT-LOCKOUT    cannot disable/delete/demote the last enabled mgmt interface
 *   BR-MEMBER          bridge/bond membership rules
 *   BR-VLAN-PARENT     VLAN parent grammar (no vlan-over-vlan, enabled parent)
 *   BR-VLAN-UNIQ       VLAN ID uniqueness per parent
 *   BR-TUNNEL          tunnel endpoints must differ
 *   BR-LOOP-PREFIX     loopback /32 recommendation (warning)
 */

// ── view shape (mirrors the shaped row + parsed config JSON) ────────────────

export interface IfaceRuleView {
  id?: number;
  name: string;
  type: string; // physical | vlan | bridge | bond | loopback | gre | ipip
  mode: string; // l2 | l3
  role: string; // wan | lan | dmz | vpn | mgmt | unused
  mtu: number;
  mssClamp?: number | null;
  enabled: boolean;
  parentName?: string | null;
  vlanId?: number | null;
  config: Record<string, unknown>;
}

export interface IfaceIssue {
  code: string;
  field: string;
  severity: "error" | "warning";
  message: string;
}

export interface LintInput {
  self: IfaceRuleView;
  others: IfaceRuleView[];
  /** planned action driving the lockout rules */
  action?: "disable" | "delete";
  /** previous role when the role is being changed (update only) */
  roleFrom?: string | null;
}

// ── IPv4 math ───────────────────────────────────────────────────────────────

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isValidIpv4(v: string): boolean {
  return IPV4_RE.test(v.trim());
}

export function ipv4ToInt(ip: string): number | null {
  if (!IPV4_RE.test(ip)) return null;
  const o = ip.split(".").map(Number);
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

export function prefixToMask(prefix: number): number | null {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

export interface Subnet {
  ip: string;
  prefix: number;
}

export function networkOf(s: Subnet): number | null {
  const ip = ipv4ToInt(s.ip);
  const mask = prefixToMask(s.prefix);
  if (ip == null || mask == null) return null;
  return (ip & mask) >>> 0;
}

export function broadcastOf(s: Subnet): number | null {
  const net = networkOf(s);
  const mask = prefixToMask(s.prefix);
  if (net == null || mask == null) return null;
  return (net | (~mask >>> 0)) >>> 0;
}

export function ipInSubnet(ip: string, s: Subnet): boolean {
  const ipInt = ipv4ToInt(ip);
  const net = networkOf(s);
  const bcast = broadcastOf(s);
  if (ipInt == null || net == null || bcast == null) return false;
  return ipInt >= net && ipInt <= bcast;
}

export function subnetsOverlap(a: Subnet, b: Subnet): boolean {
  const an = networkOf(a);
  const ab = broadcastOf(a);
  const bn = networkOf(b);
  const bb = broadcastOf(b);
  if (an == null || ab == null || bn == null || bb == null) return false;
  return an <= bb && bn <= ab;
}

export function gatewayInSubnet(gateway: string, s: Subnet): boolean {
  return ipInSubnet(gateway, s);
}

/** MSS clamp suggestion: IPv4(20) + TCP(20) headers. */
export function suggestMssClamp(mtu: number): number | null {
  if (!Number.isInteger(mtu) || mtu < 68 || mtu > 9000) return null;
  return Math.min(1460, Math.max(536, mtu - 40));
}

// ── config JSON readers (tolerant — ADR-005) ────────────────────────────────

export interface SecondaryIp {
  ip: string;
  cidrPrefix: number;
}

export function readSecondaryIps(config: Record<string, unknown>): SecondaryIp[] {
  const v = config["secondaryIps"];
  if (!Array.isArray(v)) return [];
  return v
    .filter((x): x is Record<string, unknown> => typeof x === "object" && x !== null)
    .map((x) => ({ ip: String(x["ip"] ?? ""), cidrPrefix: Number(x["cidrPrefix"] ?? NaN) }))
    .filter((x) => isValidIpv4(x.ip) && Number.isInteger(x.cidrPrefix));
}

export function readMembers(config: Record<string, unknown>): string[] {
  const v = config["members"];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function cfgStr(config: Record<string, unknown>, key: string): string | null {
  const v = config[key];
  return typeof v === "string" && v.length > 0 ? v : null;
}

function cfgNum(config: Record<string, unknown>, key: string): number | null {
  const v = config[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Primary L3 subnet carried by the interface (null when unaddressed). */
export function primarySubnetOf(v: IfaceRuleView): Subnet | null {
  if (v.mode !== "l3") return null;
  const ip = cfgStr(v.config, "ip");
  const prefix = cfgNum(v.config, "cidrPrefix");
  if (ip && prefix != null && isValidIpv4(ip) && prefix >= 0 && prefix <= 32) return { ip, prefix };
  return null;
}

export function gatewayOf(v: IfaceRuleView): string | null {
  const g = cfgStr(v.config, "gateway");
  return g && isValidIpv4(g) ? g : null;
}

// ── rule engine ─────────────────────────────────────────────────────────────

const MEMBER_ELIGIBLE_TYPES = ["physical", "vlan"];
const VLAN_PARENT_TYPES = ["physical", "bridge", "bond"];

export function lintIface(input: LintInput): IfaceIssue[] {
  const { self, others, action, roleFrom } = input;
  const issues: IfaceIssue[] = [];
  const othersByName = new Map(others.map((o) => [o.name, o]));
  const primary = primarySubnetOf(self);
  const secondaries = readSecondaryIps(self.config);

  // ── BR-NAME ──
  if (!/^[a-z0-9-]{1,15}$/.test(self.name)) {
    issues.push({
      code: "BR-NAME",
      field: "name",
      severity: "error",
      message: "Name must be 1-15 chars of a-z, 0-9 or '-'",
    });
  }

  // ── BR-MTU-BOUNDS ──
  if (!Number.isInteger(self.mtu) || self.mtu < 68 || self.mtu > 9000) {
    issues.push({
      code: "BR-MTU-BOUNDS",
      field: "mtu",
      severity: "error",
      message: "MTU must be an integer between 68 and 9000",
    });
  }

  // ── BR-MSS ──
  if (self.mssClamp != null && self.mssClamp > self.mtu - 40) {
    issues.push({
      code: "BR-MSS",
      field: "mssClamp",
      severity: "error",
      message: `MSS clamp ${self.mssClamp} must be <= MTU-40 (${self.mtu - 40})`,
    });
  }
  if (self.role === "wan" && self.mtu < 1500 && self.mssClamp == null) {
    issues.push({
      code: "BR-MSS-HINT",
      field: "mssClamp",
      severity: "warning",
      message: "Set an MSS clamp for tunneling/PPPoE links (MTU < 1500 on a WAN)",
    });
  }

  // ── BR-GW-SUBNET ──
  const gw = gatewayOf(self);
  if (primary && gw && primary.prefix < 31 && !gatewayInSubnet(gw, primary)) {
    issues.push({
      code: "BR-GW-SUBNET",
      field: "gateway",
      severity: "error",
      message: `Gateway ${gw} is outside the interface subnet ${primary.ip}/${primary.prefix}`,
    });
  }

  // ── BR-OVERLAP (primary + secondaries vs every other L3 subnet) ──
  if (primary) {
    for (const o of others) {
      if (o.id != null && self.id != null && o.id === self.id) continue;
      if (o.name === self.name) continue;
      const oPrimary = primarySubnetOf(o);
      if (oPrimary && subnetsOverlap(primary, oPrimary)) {
        issues.push({
          code: "BR-OVERLAP",
          field: "ip",
          severity: "error",
          message: `Subnet ${primary.ip}/${primary.prefix} overlaps ${o.name} (${oPrimary.ip}/${oPrimary.prefix})`,
        });
        break;
      }
    }
  }
  for (const sec of secondaries) {
    const secSubnet: Subnet = { ip: sec.ip, prefix: sec.cidrPrefix };
    for (const o of others) {
      if (o.id != null && self.id != null && o.id === self.id) continue;
      if (o.name === self.name) continue;
      const oPrimary = primarySubnetOf(o);
      if (oPrimary && subnetsOverlap(secSubnet, oPrimary)) {
        issues.push({
          code: "BR-OVERLAP",
          field: "secondaryIps",
          severity: "error",
          message: `Secondary ${sec.ip}/${sec.cidrPrefix} overlaps ${o.name} (${oPrimary.ip}/${oPrimary.prefix})`,
        });
        break;
      }
    }
  }

  // ── BR-SECIP ──
  if (secondaries.length > 8) {
    issues.push({
      code: "BR-SECIP",
      field: "secondaryIps",
      severity: "error",
      message: "At most 8 secondary addresses per interface",
    });
  }
  const seenSec = new Set<string>();
  for (const sec of secondaries) {
    const key = `${sec.ip}/${sec.cidrPrefix}`;
    if (seenSec.has(key)) {
      issues.push({
        code: "BR-SECIP",
        field: "secondaryIps",
        severity: "error",
        message: `Duplicate secondary address ${key}`,
      });
    }
    seenSec.add(key);
    if (!Number.isInteger(sec.cidrPrefix) || sec.cidrPrefix < 1 || sec.cidrPrefix > 32) {
      issues.push({
        code: "BR-SECIP",
        field: "secondaryIps",
        severity: "error",
        message: `Secondary ${sec.ip} needs a prefix between 1 and 32`,
      });
    }
  }

  // ── BR-WAN-ADDR ──
  const wanType = cfgStr(self.config, "wanType");
  if (self.role === "wan" && self.mode === "l3" && wanType === "static" && !primary) {
    issues.push({
      code: "BR-WAN-ADDR",
      field: "ip",
      severity: "error",
      message: "Static WAN requires an IPv4 address",
    });
  }

  // ── BR-L2-L3 ──
  const l2Ip = cfgStr(self.config, "ip");
  if (self.mode === "l2" && l2Ip) {
    issues.push({
      code: "BR-L2-L3",
      field: "mode",
      severity: "error",
      message: "L2 mode carries no L3 addressing — strip the IP or switch to L3",
    });
  }

  // ── BR-MGMT-LOCKOUT ──
  const otherMgmt = others.filter((o) => o.role === "mgmt" && o.enabled && o.name !== self.name);
  // "disable" implies the interface is currently enabled (the service only sets
  // the action when transitioning enabled→disabled) — judge the CURRENT state
  const mgmtCurrentlyOn = action === "disable" ? true : self.enabled;
  const isLastMgmt = self.role === "mgmt" && mgmtCurrentlyOn && otherMgmt.length === 0;
  if ((action === "disable" || action === "delete") && isLastMgmt) {
    issues.push({
      code: "BR-MGMT-LOCKOUT",
      field: "enabled",
      severity: "error",
      message: `${self.name} is the last enabled management interface — ${
        action === "disable" ? "disabling" : "deleting"
      } it would lock out appliance administration`,
    });
  }
  if (roleFrom === "mgmt" && self.role !== "mgmt" && self.enabled && otherMgmt.length === 0) {
    issues.push({
      code: "BR-MGMT-LOCKOUT",
      field: "role",
      severity: "error",
      message: `${self.name} is the last enabled management interface — demote another interface to mgmt first`,
    });
  }

  // ── MTU chain ──
  if (self.type === "vlan") {
    const parentName = self.parentName ?? cfgStr(self.config, "parent");
    const parent = parentName ? othersByName.get(parentName) : undefined;
    if (parent && self.mtu > parent.mtu) {
      issues.push({
        code: "BR-MTU-VLAN",
        field: "mtu",
        severity: "error",
        message: `VLAN MTU ${self.mtu} exceeds parent ${parent.name} MTU ${parent.mtu}`,
      });
    }
  }
  if (self.type === "physical" || self.type === "bridge" || self.type === "bond") {
    for (const child of others) {
      if (child.type !== "vlan") continue;
      const childParent = child.parentName ?? cfgStr(child.config, "parent");
      if (childParent === self.name && child.mtu > self.mtu) {
        issues.push({
          code: "BR-MTU-PARENT",
          field: "mtu",
          severity: "error",
          message: `MTU ${self.mtu} is below VLAN child ${child.name} (MTU ${child.mtu})`,
        });
      }
    }
  }
  if (self.type === "bridge" || self.type === "bond") {
    const members = readMembers(self.config);
    const memberRows = members.map((m) => othersByName.get(m)).filter((x): x is IfaceRuleView => x != null);
    if (memberRows.length > 0) {
      const minMtu = Math.min(...memberRows.map((m) => m.mtu));
      if (self.mtu > minMtu) {
        issues.push({
          code: "BR-MTU-MEMBER",
          field: "mtu",
          severity: "error",
          message: `${self.type === "bridge" ? "Bridge" : "Bond"} MTU ${self.mtu} exceeds smallest member MTU ${minMtu}`,
        });
      }
    }
  }
  if (self.type === "physical" || self.type === "vlan") {
    for (const master of others) {
      if (master.type !== "bridge" && master.type !== "bond") continue;
      if (!readMembers(master.config).includes(self.name)) continue;
      if (master.mtu > self.mtu) {
        issues.push({
          code: "BR-MTU-MASTER",
          field: "mtu",
          severity: "error",
          message: `MTU ${self.mtu} is below ${master.type} ${master.name} (MTU ${master.mtu})`,
        });
      }
    }
  }

  // ── BR-MEMBER (bridge/bond membership) ──
  if (self.type === "bridge" || self.type === "bond") {
    const members = readMembers(self.config);
    const seen = new Set<string>();
    for (const m of members) {
      if (m === self.name) {
        issues.push({
          code: "BR-MEMBER",
          field: "members",
          severity: "error",
          message: `A ${self.type} cannot include itself`,
        });
        continue;
      }
      if (seen.has(m)) {
        issues.push({
          code: "BR-MEMBER",
          field: "members",
          severity: "error",
          message: `Member ${m} listed twice`,
        });
        continue;
      }
      seen.add(m);
      const row = othersByName.get(m);
      if (!row) {
        issues.push({
          code: "BR-MEMBER",
          field: "members",
          severity: "error",
          message: `Member ${m} does not exist`,
        });
        continue;
      }
      if (!MEMBER_ELIGIBLE_TYPES.includes(row.type)) {
        issues.push({
          code: "BR-MEMBER",
          field: "members",
          severity: "error",
          message: `Member ${m} is a ${row.type} — only physical or vlan ports can be enslaved`,
        });
      }
      const master = others.find(
        (o) => o.name !== self.name && (o.type === "bridge" || o.type === "bond") && readMembers(o.config).includes(m),
      );
      if (master) {
        issues.push({
          code: "BR-MEMBER",
          field: "members",
          severity: "error",
          message: `Member ${m} is already enslaved to ${master.name}`,
        });
      }
      const mPrimary = primarySubnetOf(row);
      if (mPrimary || cfgStr(row.config, "gateway") || cfgStr(row.config, "wanType")) {
        issues.push({
          code: "BR-MEMBER",
          field: "members",
          severity: "error",
          message: `Member ${m} carries L3 addressing — strip its IP/gateway first`,
        });
      }
    }
    if (self.type === "bridge" && members.length === 0) {
      issues.push({
        code: "BR-MEMBER",
        field: "members",
        severity: "error",
        message: "A bridge needs at least 1 member",
      });
    }
    if (self.type === "bond" && members.length < 2) {
      issues.push({
        code: "BR-MEMBER",
        field: "members",
        severity: "error",
        message: "A bond needs at least 2 members",
      });
    }
  }

  // ── BR-VLAN-PARENT / BR-VLAN-UNIQ ──
  if (self.type === "vlan") {
    const parentName = self.parentName ?? cfgStr(self.config, "parent");
    if (!parentName) {
      issues.push({
        code: "BR-VLAN-PARENT",
        field: "parent",
        severity: "error",
        message: "A parent interface is required for a VLAN",
      });
    } else {
      const parent = othersByName.get(parentName);
      if (!parent) {
        issues.push({
          code: "BR-VLAN-PARENT",
          field: "parent",
          severity: "error",
          message: `Parent ${parentName} does not exist`,
        });
      } else if (!VLAN_PARENT_TYPES.includes(parent.type)) {
        issues.push({
          code: "BR-VLAN-PARENT",
          field: "parent",
          severity: "error",
          message: `VLAN parent must be a physical, bridge or bond interface (not ${parent.type})`,
        });
      } else if (!parent.enabled) {
        issues.push({
          code: "BR-VLAN-PARENT",
          field: "parent",
          severity: "warning",
          message: `Parent ${parent.name} is disabled — the VLAN will stay down`,
        });
      }
      const clash = others.find(
        (o) =>
          o.id !== self.id &&
          o.type === "vlan" &&
          (o.parentName ?? cfgStr(o.config, "parent")) === parentName &&
          o.vlanId === self.vlanId,
      );
      if (clash) {
        issues.push({
          code: "BR-VLAN-UNIQ",
          field: "vlanId",
          severity: "error",
          message: `VLAN ID ${self.vlanId} is already used on ${parentName} (${clash.name})`,
        });
      }
    }
  }

  // ── BR-TUNNEL ──
  if (self.type === "gre" || self.type === "ipip") {
    const local = cfgStr(self.config, "local");
    const remote = cfgStr(self.config, "remote");
    if (local && remote && local === remote) {
      issues.push({
        code: "BR-TUNNEL",
        field: "remote",
        severity: "error",
        message: "Tunnel local and remote endpoints must differ",
      });
    }
  }

  // ── BR-LOOP-PREFIX ──
  if (self.type === "loopback") {
    const prefix = cfgNum(self.config, "cidrPrefix");
    if (prefix != null && prefix < 32) {
      issues.push({
        code: "BR-LOOP-PREFIX",
        field: "cidrPrefix",
        severity: "warning",
        message: "Loopbacks are conventionally a single /32 address",
      });
    }
  }

  return issues;
}

/** Group issues into {field: messages} maps for form rendering / API details. */
export function groupIssues(issues: IfaceIssue[]): {
  errors: Record<string, string[]>;
  warnings: Record<string, string[]>;
} {
  const errors: Record<string, string[]> = {};
  const warnings: Record<string, string[]> = {};
  for (const i of issues) {
    const bucket = i.severity === "error" ? errors : warnings;
    (bucket[i.field] ??= []).push(i.message);
  }
  return { errors, warnings };
}

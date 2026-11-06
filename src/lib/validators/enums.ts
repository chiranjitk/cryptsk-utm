/**
 * Canonical enum values (PROJECT_MEMORY §6) — zod is the single source of
 * allowed values at every edge. Extend per resource as modules M01+ land.
 */

import { z } from "zod";

export const userRoleSchema = z.enum([
  "super_admin", "tenant_admin", "security_admin", "network_admin",
  "soc_analyst", "helpdesk", "auditor", "api_service",
]);

export const firewallActionSchema = z.enum(["allow", "deny", "drop", "reject"]);
export const loggingLevelSchema = z.enum(["none", "summary", "detail"]);
export const serviceProtocolSchema = z.enum(["tcp", "udp", "icmp", "any"]);
export const natTypeSchema = z.enum(["snat", "dnat", "hairpin", "exempt"]);
export const ifaceTypeSchema = z.enum(["physical", "vlan", "bridge", "bond", "loopback", "gre", "ipip"]);
export const ifaceModeSchema = z.enum(["l2", "l3"]);
export const ifaceRoleSchema = z.enum(["wan", "lan", "dmz", "vpn", "mgmt", "unused"]);
export const wanTypeSchema = z.enum(["static", "dhcp", "pppoe"]);
export const wanPolicyModeSchema = z.enum(["priority", "failover", "load_balance"]);
export const probeTypeSchema = z.enum(["icmp", "tcp", "dns", "http"]);
export const vpnTypeSchema = z.enum(["wireguard_s2s", "wireguard_remote", "ipsec_s2s", "ipsec_remote", "openvpn"]);
export const vpnStatusSchema = z.enum(["up", "down", "connecting", "error"]);
export const ipsModeSchema = z.enum(["inline_drop", "inline_tap", "passive"]);
export const ipsActionSchema = z.enum(["alert", "drop", "reject", "bypass", "suppressed"]);
export const ipsSeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export const notificationSeveritySchema = z.enum(["info", "warning", "critical"]);
export const notificationTypeSchema = z.enum(["threat", "system", "vpn", "ha", "config"]);
export const dnsRecordTypeSchema = z.enum(["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR"]);
export const dhcpLeaseStateSchema = z.enum(["active", "expired", "released"]);
export const syslogProtocolSchema = z.enum(["udp", "tcp", "tls"]);
export const netflowVersionSchema = z.enum(["v5", "v9", "ipfix"]);
export const reportRangeSchema = z.enum(["daily", "weekly", "monthly"]);
export const reportFormatSchema = z.enum(["pdf", "html", "csv", "json"]);
export const webhookEventsSchema = z.enum(["alerts.new", "config.updated", "wan.status", "vpn.status", "sessions.update"]);
export const snmpVersionSchema = z.enum(["v2c", "v3"]);
export const directorySourceTypeSchema = z.enum(["ldap", "ad"]);
export const ipsPresetSchema = z.enum(["conservative", "balanced", "aggressive"]);
export const qosTemplateSchema = z.enum(["voip", "video", "gaming", "bulk", "custom"]);
export const haRoleSchema = z.enum(["disabled", "active", "standby"]);
export const identityMethodSchema = z.enum(["local", "radius", "captive_portal", "vpn"]);
export const auditResultSchema = z.enum(["success", "failure", "denied"]);
export const wanStateSchema = z.enum(["up", "degraded", "down", "unknown"]);

/** Shared pagination query shape (API_STANDARDS §6). */
export const paginationQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  sort: z.string().optional(),
  q: z.string().optional(),
});

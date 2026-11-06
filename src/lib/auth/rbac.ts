/**
 * RBAC — authoritative matrix from docs/07-SECURITY/AUTH_AND_RBAC.md §4.
 * Enforced ONLY here (called from lib/api/handler.ts); the UI merely mirrors it.
 * Where ENDPOINTS.md floors and this matrix disagree, THIS matrix wins.
 */

export const ROLES = [
  "super_admin",
  "tenant_admin",
  "security_admin",
  "network_admin",
  "soc_analyst",
  "helpdesk",
  "auditor",
  "api_service",
] as const;

export type Role = (typeof ROLES)[number];

export type CapabilityArea =
  | "dashboard"
  | "network"
  | "firewall"
  | "ips_policies"
  | "ips_events"
  | "vpn_config"
  | "vpn_sessions"
  | "dns_dhcp"
  | "identity"
  | "qos"
  | "logs"
  | "log_forwarding"
  | "reports"
  | "webhooks"
  | "firmware"
  | "audit"
  | "ha"
  | "system"
  | "backups"
  | "api_keys"
  | "notifications";

/** Interactive roles allowed per operation. `auditor`/`api_service` are handled specially below. */
const MATRIX: Record<CapabilityArea, { read: Role[]; write: Role[]; admin?: Role[] }> = {
  //               read                                              write (edit)                          admin
  dashboard: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst", "helpdesk"], write: [] },
  network: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "network_admin"] },
  firewall: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "security_admin"] },
  ips_policies: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "security_admin"] },
  ips_events: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "security_admin", "soc_analyst"] },
  vpn_config: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "network_admin"] },
  vpn_sessions: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst", "helpdesk"], write: ["super_admin", "tenant_admin", "security_admin", "soc_analyst"] },
  dns_dhcp: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "network_admin"] },
  identity: { read: ["super_admin", "tenant_admin", "security_admin"], write: ["super_admin", "tenant_admin", "security_admin"] },
  qos: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "network_admin"] },
  logs: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst", "helpdesk"], write: [] },
  log_forwarding: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "network_admin"] },
  reports: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "security_admin", "soc_analyst"] },
  webhooks: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "security_admin"] },
  firmware: { read: ["super_admin", "tenant_admin", "network_admin"], write: ["super_admin", "tenant_admin"] },
  audit: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: [] },
  ha: { read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst"], write: ["super_admin", "tenant_admin", "network_admin"] },
  system: { read: ["super_admin", "tenant_admin", "network_admin"], write: ["super_admin", "tenant_admin"], admin: ["super_admin", "tenant_admin"] },
  backups: { read: ["super_admin", "tenant_admin", "network_admin"], write: ["super_admin", "tenant_admin"], admin: ["super_admin", "tenant_admin"] },
  api_keys: { read: ["super_admin", "tenant_admin"], write: ["super_admin"] },
  notifications: {
    read: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst", "helpdesk"],
    write: ["super_admin", "tenant_admin", "security_admin", "network_admin", "soc_analyst", "helpdesk"],
  },
};

export interface AuthContext {
  kind: "user" | "key";
  userId?: number;
  username?: string;
  role: Role;
  tenantId: number;
  scopes?: string[]; // api_service only
}

export type Operation = "read" | "write" | "admin";

/** Matrix check for a single capability request. The matrix wins over coarse floors. */
export function can(auth: AuthContext, area: CapabilityArea, op: Operation): boolean {
  // auditor: every read passes; only mutation is notifications mark-read
  if (auth.role === "auditor") {
    if (op === "read") return true;
    return area === "notifications" && op === "write";
  }

  // api_service: strictly scoped by key scopes; admin endpoints need admin scope;
  // api-key administration and webhooks stay closed to machine keys (matrix: none)
  if (auth.role === "api_service") {
    const scopes = auth.scopes ?? [];
    if (area === "api_keys" || area === "webhooks") return false;
    if (op === "read") return scopes.includes("read");
    if (op === "write") return scopes.includes("write");
    if (op === "admin") return scopes.includes("admin");
    return false;
  }

  const entry = MATRIX[area];
  if (!entry) return false;
  if (op === "read") return entry.read.includes(auth.role);
  if (op === "write") return entry.write.includes(auth.role);
  return (entry.admin ?? []).includes(auth.role);
}

/** Human-readable label for UI display (M07 owns the full table). */
export function roleLabel(role: Role): string {
  const labels: Record<Role, string> = {
    super_admin: "Super Admin",
    tenant_admin: "Tenant Admin",
    security_admin: "Security Admin",
    network_admin: "Network Admin",
    soc_analyst: "SOC Analyst",
    helpdesk: "Helpdesk",
    auditor: "Auditor",
    api_service: "API Service",
  };
  return labels[role] ?? role;
}

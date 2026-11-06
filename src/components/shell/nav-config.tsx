"use client";

/**
 * View registry + sidebar navigation — LOCKED to PROJECT_MEMORY §8 (29 hash views).
 * The ONLY Next.js route is `/`; all navigation is client-side via window.location.hash.
 */

export type ViewDef = {
  path: string; // hash without '#'
  title: string;
  icon: string; // lucide icon name, resolved in sidebar
  placeholder?: string; // set = view not built yet (shows which module ships it)
};

export const VIEWS: ViewDef[] = [
  { path: "/dashboard", title: "Dashboard", icon: "LayoutDashboard" },
  { path: "/network/interfaces", title: "Interfaces", icon: "Network", placeholder: "M02" },
  { path: "/network/routing", title: "Routing", icon: "Route", placeholder: "M02" },
  { path: "/network/wan", title: "Multi-WAN", icon: "Globe", placeholder: "M02" },
  { path: "/firewall/rules", title: "Firewall Rules", icon: "ShieldCheck" },
  { path: "/firewall/nat", title: "NAT", icon: "ArrowLeftRight" },
  { path: "/firewall/objects", title: "Objects", icon: "Boxes" },
  { path: "/firewall/zones", title: "Zones", icon: "Landmark" },
  { path: "/ips/policies", title: "IPS Policies", icon: "Radar", placeholder: "M04" },
  { path: "/ips/events", title: "IPS Events", icon: "Siren", placeholder: "M04" },
  { path: "/vpn/configs", title: "VPN Configs", icon: "Lock", placeholder: "M05" },
  { path: "/vpn/sessions", title: "VPN Sessions", icon: "Users", placeholder: "M05" },
  { path: "/dns-dhcp/dns", title: "DNS Security", icon: "Globe2", placeholder: "M06" },
  { path: "/dns-dhcp/dhcp", title: "DHCP", icon: "Router", placeholder: "M06" },
  { path: "/identity/users", title: "Users & Groups", icon: "UserCog", placeholder: "M07" },
  { path: "/identity/sessions", title: "Identity Sessions", icon: "Fingerprint", placeholder: "M07" },
  { path: "/identity/portal", title: "Captive Portal", icon: "Wifi", placeholder: "M07" },
  { path: "/qos/policies", title: "QoS Policies", icon: "Gauge", placeholder: "M08" },
  { path: "/logs/firewall", title: "Firewall Logs", icon: "ScrollText", placeholder: "M09" },
  { path: "/logs/ips", title: "IPS Logs", icon: "FileWarning", placeholder: "M09" },
  { path: "/logs/audit", title: "Audit Log", icon: "History", placeholder: "M09" },
  { path: "/logs/live", title: "Live Tail", icon: "Activity", placeholder: "M09" },
  { path: "/logs/reports", title: "Reports", icon: "BarChart3", placeholder: "M09" },
  { path: "/ha", title: "High Availability", icon: "ServerCog", placeholder: "M10" },
  { path: "/system/settings", title: "System Settings", icon: "Settings", placeholder: "M10" },
  { path: "/system/backups", title: "Backups", icon: "DatabaseBackup", placeholder: "M10" },
  { path: "/system/api-keys", title: "API Platform", icon: "KeyRound", placeholder: "M11" },
];

export const SETUP_VIEW: ViewDef = { path: "/setup", title: "Setup Wizard", icon: "Sparkles", placeholder: "M10" };

export const NAV_GROUPS: Array<{ label: string; paths: string[] }> = [
  { label: "Overview", paths: ["/dashboard"] },
  { label: "Network", paths: ["/network/interfaces", "/network/routing", "/network/wan"] },
  { label: "Firewall", paths: ["/firewall/rules", "/firewall/nat", "/firewall/objects", "/firewall/zones"] },
  { label: "Intrusion Prevention", paths: ["/ips/policies", "/ips/events"] },
  { label: "VPN", paths: ["/vpn/configs", "/vpn/sessions"] },
  { label: "DNS & DHCP", paths: ["/dns-dhcp/dns", "/dns-dhcp/dhcp"] },
  { label: "Identity", paths: ["/identity/users", "/identity/sessions", "/identity/portal"] },
  { label: "QoS", paths: ["/qos/policies"] },
  { label: "Logs & Reports", paths: ["/logs/firewall", "/logs/ips", "/logs/audit", "/logs/live", "/logs/reports"] },
  { label: "System", paths: ["/ha", "/system/settings", "/system/backups", "/system/api-keys"] },
];

export function viewFor(path: string): ViewDef | undefined {
  const clean = path.startsWith("#") ? path.slice(1) : path;
  if (clean === SETUP_VIEW.path) return SETUP_VIEW;
  return VIEWS.find((v) => v.path === clean);
}

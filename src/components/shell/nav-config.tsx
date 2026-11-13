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
  { path: "/network/interfaces", title: "Interfaces", icon: "Network" },
  { path: "/network/routing", title: "Routing", icon: "Route" },
  { path: "/network/wan", title: "Multi-WAN", icon: "Globe" },
  { path: "/firewall/rules", title: "Firewall Rules", icon: "ShieldCheck" },
  { path: "/firewall/nat", title: "NAT", icon: "ArrowLeftRight" },
  { path: "/firewall/objects", title: "Objects", icon: "Boxes" },
  { path: "/firewall/zones", title: "Zones", icon: "Landmark" },
  { path: "/ips/policies", title: "IPS Policies", icon: "Radar" },
  { path: "/ips/events", title: "IPS Events", icon: "Siren" },
  { path: "/vpn/configs", title: "VPN Configs", icon: "Lock" },
  { path: "/vpn/sessions", title: "VPN Sessions", icon: "Users" },
  { path: "/dns-dhcp/dns", title: "DNS Security", icon: "Globe2" },
  { path: "/dns-dhcp/dhcp", title: "DHCP", icon: "Router" },
  { path: "/identity/users", title: "Users & Groups", icon: "UserCog" },
  { path: "/identity/sessions", title: "Identity Sessions", icon: "Fingerprint" },
  { path: "/identity/portal", title: "Captive Portal", icon: "Wifi" },
  { path: "/qos/policies", title: "QoS Policies", icon: "Gauge" },
  { path: "/logs/firewall", title: "Firewall Logs", icon: "ScrollText" },
  { path: "/logs/ips", title: "IPS Logs", icon: "FileWarning" },
  { path: "/logs/audit", title: "Audit Log", icon: "History" },
  { path: "/logs/live", title: "Live Tail", icon: "Activity" },
  { path: "/logs/reports", title: "Reports", icon: "BarChart3" },
  { path: "/ha", title: "High Availability", icon: "ServerCog" },
  { path: "/system/settings", title: "System Settings", icon: "Settings" },
  { path: "/system/backups", title: "Backups", icon: "DatabaseBackup" },
  { path: "/system/api-keys", title: "API Platform", icon: "KeyRound" },
  // ── Phase 2 (M12–M23) — Growth: enterprise features ──
  { path: "/logs/search", title: "Log Search", icon: "FileSearch" },
  { path: "/logs/compliance", title: "Compliance", icon: "FileCheck" },
  { path: "/threat-intel/feeds", title: "Threat Feeds", icon: "Rss" },
  { path: "/threat-intel/iocs", title: "IOCs", icon: "Bug" },
  { path: "/threat-intel/auto-block", title: "Auto-Block", icon: "ShieldBan" },
  { path: "/pki/authorities", title: "Certificate Authorities", icon: "Building2" },
  { path: "/pki/certificates", title: "Certificates", icon: "FileKey" },
  { path: "/web/ssl-inspection", title: "SSL Inspection", icon: "LockKeyhole" },
  { path: "/web/url-filter", title: "URL Filtering", icon: "Filter" },
  { path: "/web/waf", title: "WAF", icon: "ShieldHalf" },
  { path: "/web/app-control", title: "App Control", icon: "AppWindow" },
  { path: "/routing/dynamic", title: "BGP & OSPF", icon: "GitBranch" },
  { path: "/routing/sdwan", title: "SD-WAN", icon: "Share2" },
  { path: "/network/ipv6", title: "IPv6", icon: "Binary" },
  { path: "/email/security", title: "Email Security", icon: "MailWarning" },
  { path: "/identity/federation", title: "Federation (SSO)", icon: "BadgeCheck" },
  { path: "/identity/nac", title: "NAC & Profiling", icon: "ScanLine" },
];

export const SETUP_VIEW: ViewDef = { path: "/setup", title: "Setup Wizard", icon: "Sparkles" };

export const NAV_GROUPS: Array<{ label: string; paths: string[] }> = [
  { label: "Overview", paths: ["/dashboard"] },
  { label: "Network", paths: ["/network/interfaces", "/network/routing", "/network/wan"] },
  { label: "Firewall", paths: ["/firewall/rules", "/firewall/nat", "/firewall/objects", "/firewall/zones"] },
  { label: "Intrusion Prevention", paths: ["/ips/policies", "/ips/events"] },
  { label: "VPN", paths: ["/vpn/configs", "/vpn/sessions"] },
  { label: "DNS & DHCP", paths: ["/dns-dhcp/dns", "/dns-dhcp/dhcp"] },
  { label: "Identity", paths: ["/identity/users", "/identity/sessions", "/identity/portal", "/identity/federation", "/identity/nac"] },
  { label: "QoS", paths: ["/qos/policies"] },
  { label: "Logs & Reports", paths: ["/logs/firewall", "/logs/ips", "/logs/audit", "/logs/live", "/logs/search", "/logs/reports", "/logs/compliance"] },
  { label: "Threat Intelligence", paths: ["/threat-intel/feeds", "/threat-intel/iocs", "/threat-intel/auto-block"] },
  { label: "PKI", paths: ["/pki/authorities", "/pki/certificates"] },
  { label: "Web Security", paths: ["/web/ssl-inspection", "/web/url-filter", "/web/waf", "/web/app-control"] },
  { label: "Advanced Routing", paths: ["/routing/dynamic", "/routing/sdwan"] },
  { label: "System", paths: ["/ha", "/network/ipv6", "/email/security", "/system/settings", "/system/backups", "/system/api-keys"] },
];

export function viewFor(path: string): ViewDef | undefined {
  const clean = path.startsWith("#") ? path.slice(1) : path;
  if (clean === SETUP_VIEW.path) return SETUP_VIEW;
  return VIEWS.find((v) => v.path === clean);
}

#!/usr/bin/env node
// sweep-views.mjs — authenticate once, then GET every view-backing API endpoint.
// Reports: HTTP code, row count (array length / items length / object keys),
// payload bytes, and any simulated/mock markers found in the payload.
const BASE = "http://127.0.0.1:3000";

const eps = [
  "auth-settings",
  "address-groups", "address-objects",
  "api-keys",
  "app-control/catalog", "app-control/logs", "app-control/policies", "app-control/rules", "app-control/stats",
  "captive-portal", "captive-portal/vouchers",
  "config-versions",
  "dashboard/summary",
  "dhcp/leases", "dhcp/relay", "dhcp/reservations", "dhcp/subnets",
  "directory-sources",
  "dns/policies", "dns/query-logs", "dns/records", "dns/settings",
  "dynamic-routing/overview", "dynamic-routing/bfd-profiles", "dynamic-routing/bgp/neighbors",
  "dynamic-routing/community-lists", "dynamic-routing/ospf/interfaces", "dynamic-routing/ospf/settings",
  "dynamic-routing/prefix-lists", "dynamic-routing/route-maps",
  "email-security/gateways", "email-security/logs", "email-security/policy", "email-security/routing-rules", "email-security/stats",
  "firewall-rules",
  "ha/config", "ha/status",
  "identity/sessions",
  "identity-advanced/idps", "identity-advanced/coa-profiles", "identity-advanced/byod", "identity-advanced/nac-profiles",
  "interfaces",
  "ips/events", "ips/policies", "ips/rule-categories", "ips/update-settings",
  "ipv6/dhcpv6-servers", "ipv6/nat66-rules", "ipv6/prefix-delegation", "ipv6/settings", "ipv6/status",
  "logs/anonymization", "logs/audit", "logs/firewall", "logs/ips", "logs/netflow-targets",
  "logs/report-schedules", "logs/stats",
  "nat-rules",
  "network/app-catalog", "network/lldp-neighbors", "network/mac-table", "network/port-mirrors",
  "notifications",
  "pbr-rules",
  "pki/cas", "pki/certificates", "pki/certificates/expiring",
  "qos/policies", "qos/rules",
  "radius-profiles",
  "reports/runs",
  "routes",
  "schedule-objects",
  "sdwan/overlays", "sdwan/policies", "sdwan/sites", "sdwan/sla-profiles", "sdwan/stats",
  "service-groups", "service-objects",
  "ssl-inspection/bypass-rules", "ssl-inspection/policies", "ssl-inspection/stats",
  "system/backups", "system/firmware", "system/policy-templates", "system/settings", "system/ssh-keys", "system/status",
  "threat-intel/auto-block-rules", "threat-intel/feeds", "threat-intel/iocs", "threat-intel/stats",
  "url-filter/custom-lists", "url-filter/logs", "url-filter/policies", "url-filter/stats",
  "user-groups", "users",
  "vpn/configs", "vpn/sessions", "vpn/user-groups",
  "waf/logs", "waf/policies", "waf/vhosts", "waf/stats",
  "wan-policies",
  "webhooks",
  "zones",
];

async function j(url, opts = {}) {
  return fetch(BASE + url, { ...opts, signal: AbortSignal.timeout(15000) });
}

const login = await j("/api/v1/auth/login", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ username: "admin", password: "admin123" }),
});
if (!login.ok) {
  console.error("LOGIN FAILED " + login.status);
  process.exit(2);
}
const cookie = (login.headers.getSetCookie?.() ?? []).find((c) => c.startsWith("cryptsk_token="))?.split(";")[0];
const H = { cookie };

let pass = 0, fail = 0, flagged = 0;
const rows = [];
for (const ep of eps) {
  try {
    const res = await j("/api/v1/" + ep, { headers: H });
    const text = await res.text();
    let rowCount = "-";
    let shaped = false;
    try {
      const parsed = JSON.parse(text);
      shaped = parsed && typeof parsed === "object" && "data" in parsed;
      const d = parsed?.data;
      if (Array.isArray(d)) rowCount = d.length;
      else if (d && Array.isArray(d.items)) rowCount = d.items.length;
      else if (d && typeof d === "object") rowCount = Object.keys(d).length;
      else if (d !== undefined) rowCount = String(d).slice(0, 12);
    } catch {}
    const mock = /simulated|"mock"|sandbox-fake/i.test(text) ? " MOCK?" : "";
    const okFlag = res.ok && shaped ? "PASS" : "FAIL";
    if (okFlag === "PASS") pass++; else fail++;
    if (mock) flagged++;
    rows.push(`${okFlag}\t${ep}\t${res.status}\trows=${rowCount}\t${text.length}B${mock}`);
  } catch (e) {
    fail++;
    rows.push(`FAIL\t${ep}\tERR\t${e.message.slice(0, 40)}`);
  }
}
console.log(rows.join("\n"));
console.log(`\nSWEEP RESULT: ${pass} OK, ${fail} failed, ${flagged} mock-flagged, ${eps.length} total`);

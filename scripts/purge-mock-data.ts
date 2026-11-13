/**
 * purge-mock-data.ts (ADR-021) — removes ALL demo config + mock operational
 * rows from the SQLite database, leaving the honest production baseline:
 *
 *   KEEP: Tenant, User, UserGroup(+Member), SystemSetting, ConfigVersion,
 *         ApiKey, AuditLog (real console history), ThreatFeed (real feed URLs)
 *   DROP: every demo-created config object (interfaces/zones/objects/rules/…)
 *         and every mock operational row (logs/events/leases/sessions/…)
 *
 * Usage: bun scripts/purge-mock-data.ts [--dry-run]
 * Also flips system/setup.completed → false so the first-time wizard runs.
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const DRY = process.argv.includes("--dry-run");

/** children → parents (FK-safe deletion order) */
const PURGE_ORDER: Array<[string, keyof PrismaClient]> = [
  // 1. operational / telemetry (mock-generated)
  ["firewallLog", "firewallLog"],
  ["ipsEvent", "ipsEvent"],
  ["identitySession", "identitySession"],
  ["identityActivityEvent", "identityActivityEvent"],
  ["notification", "notification"],
  ["sslInspectionLog", "sslInspectionLog"],
  ["urlFilterLog", "urlFilterLog"],
  ["wafLog", "wafLog"],
  ["appControlLog", "appControlLog"],
  ["emailLog", "emailLog"],
  ["reportRun", "reportRun"],
  ["webhookDelivery", "webhookDelivery"],
  ["iocHit", "iocHit"],
  ["dhcpLease", "dhcpLease"],
  ["vpnSession", "vpnSession"],
  ["nacDevice", "nacDevice"],
  ["byodEnrollment", "byodEnrollment"],
  ["ribRoute", "ribRoute"],
  // 2. dependent config rows
  ["certRevocation", "certRevocation"],
  ["certificate", "certificate"],
  ["autoBlockRule", "autoBlockRule"],
  ["ioc", "ioc"],
  ["sslBypassRule", "sslBypassRule"],
  ["urlCategoryRule", "urlCategoryRule"],
  ["urlCustomList", "urlCustomList"],
  ["wafExclusion", "wafExclusion"],
  ["appControlRule", "appControlRule"],
  ["emailRoutingRule", "emailRoutingRule"],
  ["ospfInterface", "ospfInterface"],
  ["bgpNeighbor", "bgpNeighbor"],
  ["routeMap", "routeMap"],
  ["prefixList", "prefixList"],
  ["communityList", "communityList"],
  ["bfdProfile", "bfdProfile"],
  ["sdwanPath", "sdwanPath"],
  ["sdwanPolicy", "sdwanPolicy"],
  // 3. config parents
  ["captivePortalProfile", "captivePortalProfile"],
  ["directorySource", "directorySource"],
  ["radiusCoaProfile", "radiusCoaProfile"],
  ["radiusProfile", "radiusProfile"],
  ["nacProfile", "nacProfile"],
  ["federatedIdp", "federatedIdp"],
  ["sslInspectionPolicy", "sslInspectionPolicy"],
  ["urlFilterPolicy", "urlFilterPolicy"],
  ["wafVhost", "wafVhost"],
  ["wafPolicy", "wafPolicy"],
  ["appControlPolicy", "appControlPolicy"],
  ["emailGateway", "emailGateway"],
  ["emailPolicy", "emailPolicy"],
  ["certificateAuthority", "certificateAuthority"],
  ["slaProfile", "slaProfile"],
  ["sdwanOverlay", "sdwanOverlay"],
  ["sdwanSite", "sdwanSite"],
  ["ipv6Settings", "ipv6Settings"],
  ["nat66Rule", "nat66Rule"],
  ["dhcpv6Server", "dhcpv6Server"],
  ["vpnUserGroup", "vpnUserGroup"],
  ["vpnConfig", "vpnConfig"],
  ["syslogTarget", "syslogTarget"],
  ["netflowTarget", "netflowTarget"],
  ["webhook", "webhook"],
  ["reportSchedule", "reportSchedule"],
  ["savedLogSearch", "savedLogSearch"],
  ["complianceTemplate", "complianceTemplate"],
  ["anonymizationRule", "anonymizationRule"],
  ["sshKey", "sshKey"],
  ["ipsPolicy", "ipsPolicy"],
  ["dnsPolicy", "dnsPolicy"],
  ["dnsRecord", "dnsRecord"],
  ["dhcpReservation", "dhcpReservation"],
  ["dhcpSubnet", "dhcpSubnet"],
  ["qosRule", "qosRule"],
  ["qosPolicy", "qosPolicy"],
  ["haConfig", "haConfig"],
  ["scheduleObject", "scheduleObject"],
  ["serviceGroup", "serviceGroup"],
  ["serviceObject", "serviceObject"],
  ["addressGroup", "addressGroup"],
  ["addressObject", "addressObject"],
  ["natRule", "natRule"],
  ["firewallRule", "firewallRule"],
  ["pbrRule", "pbrRule"],
  ["portMirror", "portMirror"],
  ["staticRoute", "staticRoute"],
  ["wanPolicy", "wanPolicy"],
  ["networkInterface", "networkInterface"],
  ["zone", "zone"],
];

const KEEP = new Set([
  "tenant", "user", "userGroup", "userGroupMember", "systemSetting",
  "configVersion", "apiKey", "auditLog", "threatFeed", "webhookDelivery",
]);

async function main() {
  console.log(`Purging demo/mock data (ADR-021)${DRY ? " — DRY RUN" : ""}…`);
  const counts: Record<string, number> = {};
  const errors: string[] = [];

  for (const [label, model] of PURGE_ORDER) {
    if (KEEP.has(label)) continue;
    try {
      const delegate = prisma[model] as unknown as { deleteMany: (args?: unknown) => Promise<{ count: number }> };
      if (DRY) {
        const c = await delegate.count({});
        counts[label] = c;
      } else {
        const res = await delegate.deleteMany({});
        counts[label] = res.count;
      }
    } catch (err) {
      errors.push(`${label}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (!DRY) {
    // first-time wizard gate → false (matches production baseline)
    try {
      await prisma.systemSetting.upsert({
        where: { tenantId_category_key: { tenantId: 1, category: "system", key: "setup" } },
        update: { value: JSON.stringify({ completed: false }) },
        create: { tenantId: 1, category: "system", key: "setup", value: JSON.stringify({ completed: false }) },
      });
    } catch (err) {
      errors.push(`system/setup: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  console.log(JSON.stringify(counts, null, 2));
  if (errors.length) {
    console.error("Non-fatal errors:");
    for (const e of errors) console.error("  -", e);
  }
  const total = Object.values(counts).reduce((s, v) => s + v, 0);
  console.log(`Done. ${total} rows ${DRY ? "would be " : ""}purged.${errors.length ? ` ${errors.length} table(s) skipped.` : ""}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());

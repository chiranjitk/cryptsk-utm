/**
 * M12 — Enhanced Logging & Reporting seed (spec 2.13).
 * Idempotent upserts keyed on the module's @@unique([tenantId, name]) keys,
 * tenantId = 1. Orchestrated by prisma/seed-phase2.ts (M12 entry).
 */

import type { PrismaClient } from "@prisma/client";

export default async function seed(prisma: PrismaClient): Promise<string> {
  const tenantId = 1;

  // ── saved searches (2) ────────────────────────────────────────────────────
  await prisma.savedLogSearch.upsert({
    where: { tenantId_name: { tenantId, name: "Blocked inbound last 7d" } },
    update: {
      dataset: "firewall",
      queryText: "action:deny",
      filters: JSON.stringify({ action: "deny", sinceDays: "7" }),
    },
    create: {
      tenantId,
      name: "Blocked inbound last 7d",
      dataset: "firewall",
      queryText: "action:deny",
      filters: JSON.stringify({ action: "deny", sinceDays: "7" }),
    },
  });

  await prisma.savedLogSearch.upsert({
    where: { tenantId_name: { tenantId, name: "Critical IPS" } },
    update: {
      dataset: "ips",
      queryText: "",
      filters: JSON.stringify({ severity: "critical" }),
    },
    create: {
      tenantId,
      name: "Critical IPS",
      dataset: "ips",
      queryText: "",
      filters: JSON.stringify({ severity: "critical" }),
    },
  });

  // ── compliance templates (3) ──────────────────────────────────────────────
  const templates = [
    {
      name: "PCI-DSS v4 monthly review",
      framework: "PCI",
      sections: ["traffic", "threats", "audit"],
      range: "monthly",
    },
    {
      name: "HIPAA quarterly audit",
      framework: "HIPAA",
      sections: ["audit", "traffic"],
      range: "quarterly",
    },
    {
      name: "GDPR monthly privacy check",
      framework: "GDPR",
      sections: ["traffic", "audit"],
      range: "monthly",
    },
  ] as const;

  for (const t of templates) {
    await prisma.complianceTemplate.upsert({
      where: { tenantId_name: { tenantId, name: t.name } },
      update: {
        framework: t.framework,
        sections: JSON.stringify(t.sections),
        range: t.range,
      },
      create: {
        tenantId,
        name: t.name,
        framework: t.framework,
        sections: JSON.stringify(t.sections),
        range: t.range,
        enabled: true,
      },
    });
  }

  // ── anonymization rules (2) ───────────────────────────────────────────────
  await prisma.anonymizationRule.upsert({
    where: { tenantId_name: { tenantId, name: "Mask internal source IPs" } },
    update: { dataset: "firewall", field: "source_ip", strategy: "mask", enabled: true },
    create: {
      tenantId,
      name: "Mask internal source IPs",
      dataset: "firewall",
      field: "source_ip",
      strategy: "mask",
      enabled: true,
    },
  });

  await prisma.anonymizationRule.upsert({
    where: { tenantId_name: { tenantId, name: "Pseudonymize audit users" } },
    update: { dataset: "audit", field: "user_name", strategy: "pseudonymize", enabled: true },
    create: {
      tenantId,
      name: "Pseudonymize audit users",
      dataset: "audit",
      field: "user_name",
      strategy: "pseudonymize",
      enabled: true,
    },
  });

  return "M12: 2 saved searches, 3 compliance templates, 2 anonymization rules";
}

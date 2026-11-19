/**
 * CASB SaaS catalog defaults (Phase 4 §4.3) — the shipped baseline of the
 * most-demanded enterprise SaaS apps (spec note: start with the top vendors —
 * Google, Microsoft, Salesforce, Dropbox, Slack — then broaden). Each entry
 * carries the domains nDPI/SNI hints are matched against (plain entries are
 * suffix-matched, "*." entries match subdomains — see lib/casb/matcher.ts),
 * a category and a 0-100 risk score driving the sanctioned/shadow verdict.
 *
 * `ensureSaasCatalog` seeds the defaults for a tenant idempotently: rows the
 * operator renamed/edited are NOT clobbered, only missing defaults are
 * created — calling it twice never duplicates.
 */

import { db } from "@/lib/db";
import type { SaasAppCategory } from "@/lib/validators/casb";

// ── shipped defaults (13 entries, real domains) ─────────────────────────────

export interface SaasAppSeed {
  name: string;
  vendor: string;
  category: SaasAppCategory;
  domains: string[];
  riskScore: number;
}

export const DEFAULT_SAAS_APPS: SaasAppSeed[] = [
  {
    name: "Google Workspace",
    vendor: "Google",
    category: "collaboration",
    domains: ["google.com", "googledrive.com", "docs.google.com", "drive.google.com"],
    riskScore: 10,
  },
  {
    name: "Microsoft 365",
    vendor: "Microsoft",
    category: "productivity",
    domains: ["microsoft.com", "office.com", "onedrive.live.com", "sharepoint.com"],
    riskScore: 10,
  },
  {
    name: "Microsoft Teams",
    vendor: "Microsoft",
    category: "collaboration",
    domains: ["teams.microsoft.com"],
    riskScore: 10,
  },
  {
    name: "Salesforce",
    vendor: "Salesforce",
    category: "crm",
    domains: ["salesforce.com", "force.com"],
    riskScore: 15,
  },
  {
    name: "Dropbox",
    vendor: "Dropbox",
    category: "storage",
    domains: ["dropbox.com", "dropboxusercontent.com"],
    riskScore: 25,
  },
  {
    name: "Slack",
    vendor: "Salesforce",
    category: "collaboration",
    domains: ["slack.com", "slack-edge.com"],
    riskScore: 15,
  },
  {
    name: "Zoom",
    vendor: "Zoom",
    category: "collaboration",
    domains: ["zoom.us", "*.zoom.us"],
    riskScore: 15,
  },
  {
    name: "GitHub",
    vendor: "GitHub",
    category: "devops",
    domains: ["github.com", "githubusercontent.com", "github.io"],
    riskScore: 20,
  },
  {
    name: "Jira",
    vendor: "Atlassian",
    category: "devops",
    domains: ["atlassian.net", "atlassian.com"],
    riskScore: 15,
  },
  {
    name: "Box",
    vendor: "Box",
    category: "storage",
    domains: ["box.com", "boxcloud.com"],
    riskScore: 25,
  },
  {
    name: "Notion",
    vendor: "Notion",
    category: "productivity",
    domains: ["notion.so", "notion.site"],
    riskScore: 20,
  },
  {
    name: "AWS Console",
    vendor: "Amazon",
    category: "devops",
    domains: ["aws.amazon.com", "amazonaws.com"],
    riskScore: 30,
  },
  {
    name: "Personal Gmail",
    vendor: "Google",
    category: "other",
    domains: ["gmail.com", "mail.google.com"],
    riskScore: 60, // consumer mail alongside the sanctioned suite → shadow risk
  },
];

// ── idempotent seed ─────────────────────────────────────────────────────────

/**
 * Create every missing default for the tenant; existing rows are left
 * untouched (operator edits survive re-seeds). Returns the number of rows
 * CREATED by this call (0 when the catalog is already seeded).
 */
export async function ensureSaasCatalog(tenantId: number): Promise<number> {
  let created = 0;
  for (const app of DEFAULT_SAAS_APPS) {
    const existing = await db.saasAppCatalog.findFirst({
      where: { tenantId, name: app.name },
      select: { id: true },
    });
    if (existing) continue;
    await db.saasAppCatalog.create({
      data: {
        tenantId,
        name: app.name,
        vendor: app.vendor,
        category: app.category,
        domains: JSON.stringify(app.domains),
        riskScore: app.riskScore,
      },
    });
    created += 1;
  }
  return created;
}

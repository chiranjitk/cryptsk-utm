/**
 * QoS templates (M08 §5.1) — starter-rule seeds applied at CREATE time only.
 * After create, `template` is informational: editing rules never re-syncs the
 * template and changing it on an existing policy does not rewrite rules.
 * Percentages are of the NEW policy's bandwidthKbps and are resolved to kbps
 * by the service when seeding.
 *
 * matchApps are canonical app-catalog labels (GET /api/v1/network/app-catalog)
 * so every seeded rule passes the service matcher check (M08 §5.2).
 */

export type QosTemplateName = "voip" | "video" | "gaming" | "bulk" | "custom";

export interface QosTemplateSeedRule {
  name: string;
  priority: number; // 0 highest .. 7 lowest
  guaranteedPct: number | null; // % of bandwidthKbps
  maxPct: number | null; // % of bandwidthKbps
  dscpMark: number | null;
  matchApps: string[];
}

export interface QosTemplateDef {
  label: string;
  intent: string;
  defaultBandwidthKbps: number;
  rules: QosTemplateSeedRule[];
}

export const QOS_TEMPLATES: Record<QosTemplateName, QosTemplateDef> = {
  voip: {
    label: "VoIP",
    intent: "Protect call quality first",
    defaultBandwidthKbps: 10_000,
    rules: [
      // spec §5.1 lists sip+rtp; the static catalog ships "SIP" — "RTP" is not
      // a catalog label and would fail the §5.2 matcher check, so SIP only.
      { name: "Voice", priority: 0, guaranteedPct: 10, maxPct: 30, dscpMark: 46, matchApps: ["SIP"] },
    ],
  },
  video: {
    label: "Video",
    intent: "Cap bulk streaming, protect calls",
    defaultBandwidthKbps: 50_000,
    rules: [
      { name: "Conferencing", priority: 2, guaranteedPct: 30, maxPct: 70, dscpMark: 34, matchApps: ["Teams", "Zoom", "Skype"] },
      { name: "Streaming", priority: 5, guaranteedPct: null, maxPct: 50, dscpMark: 26, matchApps: ["YouTube", "Netflix", "Twitch"] },
    ],
  },
  gaming: {
    label: "Gaming",
    intent: "Low latency for game flows, starve downloads",
    defaultBandwidthKbps: 30_000,
    rules: [
      { name: "Game traffic", priority: 1, guaranteedPct: 15, maxPct: 50, dscpMark: 32, matchApps: ["Steam"] },
      { name: "Updates", priority: 7, guaranteedPct: null, maxPct: 20, dscpMark: 8, matchApps: ["Windows-Update"] },
    ],
  },
  bulk: {
    label: "Bulk",
    intent: "One fat, deprioritized lane",
    defaultBandwidthKbps: 100_000,
    rules: [
      // matcher-less = the policy's single catch-all class ("everything else")
      { name: "Backups", priority: 7, guaranteedPct: null, maxPct: 80, dscpMark: 8, matchApps: [] },
    ],
  },
  custom: {
    label: "Custom",
    intent: "Blank canvas — no starter rules",
    defaultBandwidthKbps: 50_000,
    rules: [],
  },
};

/** Well-known DSCP values for the rule-editor picker (M08 §4 table). */
export const DSCP_WELL_KNOWN: Array<{ value: number; name: string; use: string }> = [
  { value: 46, name: "EF", use: "Voice (RTP)" },
  { value: 34, name: "AF41", use: "Interactive video" },
  { value: 32, name: "CS4", use: "Real-time interactive / gaming" },
  { value: 26, name: "AF31", use: "Multimedia streaming" },
  { value: 24, name: "CS3", use: "Signaling" },
  { value: 18, name: "AF21", use: "High-throughput data" },
  { value: 8, name: "CS1", use: "Bulk / scavenger (backups, sync)" },
  { value: 0, name: "BE (CS0)", use: "Best effort (default)" },
];

export function dscpName(value: number): string | null {
  return DSCP_WELL_KNOWN.find((d) => d.value === value)?.name ?? null;
}

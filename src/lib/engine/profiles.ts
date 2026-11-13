/**
 * Mock traffic profiles (SIMULATION_LAYER §3 / DATA_LIFECYCLE §3).
 * Selected via env MOCK_PROFILE=office|hospitality|msp_branch (default office).
 * JSON-shaped on purpose — extend without touching engine code.
 */

export interface TrafficProfile {
  name: string;
  /** baseline kbps ranges per interface role */
  baselines: Record<string, [number, number]>;
  /** app mix weights (nDPI-ish labels) */
  appMix: Array<[string, number]>;
  /** fraction of generated flows that get blocked (rule matches) */
  blockRate: number;
  /** ips event probability per tick */
  ipsEventRate: number;
  /** severity distribution for generated ips events */
  severityMix: Array<[string, number]>;
  /** wan probe flap probability per tick (0 = stable) */
  wanFlapRate: number;
  /** dns-heavy behavior */
  dnsShare: number;
}

const APPS_OFFICE: Array<[string, number]> = [
  ["HTTPS", 38], ["Teams", 14], ["YouTube", 10], ["Windows-Update", 8],
  ["DNS", 8], ["Slack", 6], ["SIP", 5], ["Netflix", 4], ["SSH", 3],
  ["RDP", 2], ["BitTorrent", 1], ["Facebook", 1],
];

export const PROFILES: Record<string, TrafficProfile> = {
  office: {
    name: "office",
    baselines: {
      wan: [40000, 300000],
      lan: [20000, 150000],
      dmz: [5000, 40000],
      mgmt: [500, 8000],
      vpn: [5000, 60000],
      unused: [0, 0],
    },
    appMix: APPS_OFFICE,
    blockRate: 0.08,
    ipsEventRate: 0.35,
    severityMix: [["info", 30], ["low", 26], ["medium", 22], ["high", 14], ["critical", 8]],
    wanFlapRate: 0.002,
    dnsShare: 0.08,
  },
  hospitality: {
    name: "hospitality",
    baselines: {
      wan: [60000, 220000],
      lan: [30000, 120000],
      dmz: [5000, 30000],
      mgmt: [500, 6000],
      vpn: [2000, 20000],
      unused: [0, 0],
    },
    appMix: [["HTTPS", 52], ["YouTube", 16], ["Netflix", 10], ["DNS", 12], ["Instagram", 5], ["TikTok", 5]],
    blockRate: 0.16,
    ipsEventRate: 0.3,
    severityMix: [["info", 36], ["low", 28], ["medium", 20], ["high", 10], ["critical", 6]],
    wanFlapRate: 0.001,
    dnsShare: 0.14,
  },
  msp_branch: {
    name: "msp_branch",
    baselines: {
      wan: [30000, 180000],
      lan: [15000, 90000],
      dmz: [4000, 25000],
      mgmt: [500, 8000],
      vpn: [8000, 70000],
      unused: [0, 0],
    },
    appMix: APPS_OFFICE,
    blockRate: 0.12,
    ipsEventRate: 0.7,
    severityMix: [["info", 22], ["low", 22], ["medium", 24], ["high", 19], ["critical", 13]],
    wanFlapRate: 0.02,
    dnsShare: 0.08,
  },
};

export function getProfile(): TrafficProfile {
  const name = process.env.MOCK_PROFILE ?? "office";
  return PROFILES[name] ?? PROFILES.office;
}

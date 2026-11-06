/**
 * ET-style category catalog (M04 §4 category matrix) + preset bundles
 * (DATA_PLANE §3.1). Single source of truth for /api/v1/ips/rule-categories,
 * the generator (via lib/engine) and the seeded policies.
 */

export interface CategoryDef {
  name: string;
  label: string;
  /** typical base severity shown as a hint in the matrix */
  baseSeverity: "info" | "low" | "medium" | "high" | "critical";
  /** preprocessor family that must be on for the family to fire */
  family: "stream" | "http" | "tls" | "ssh" | "generic";
  sidBase: number;
  description: string;
}

export const CATEGORY_CATALOG: CategoryDef[] = [
  { name: "trojan", label: "Trojan activity", baseSeverity: "critical", family: "generic", sidBase: 2_024_000, description: "Known trojan C2 / beaconing signatures" },
  { name: "worm", label: "Worm propagation", baseSeverity: "critical", family: "generic", sidBase: 2_025_500, description: "Self-replicating malware spreading over the network" },
  { name: "botnet", label: "Botnet", baseSeverity: "critical", family: "generic", sidBase: 2_025_000, description: "Botnet C2 channels and DGA traffic" },
  { name: "exploit", label: "Exploit kit", baseSeverity: "critical", family: "http", sidBase: 2_032_000, description: "Client-side exploit kit landing pages" },
  { name: "malware", label: "Malware download", baseSeverity: "high", family: "http", sidBase: 2_030_000, description: "Executable downloads from flagged infrastructure" },
  { name: "phishing", label: "Phishing", baseSeverity: "high", family: "http", sidBase: 2_026_000, description: "Phishing kit URLs and credential-harvest pages" },
  { name: "c2", label: "C2 / threat-intel", baseSeverity: "high", family: "generic", sidBase: 2_027_000, description: "Command-and-control + feed-sourced known-bad IPs" },
  { name: "web_attack", label: "Web attack", baseSeverity: "high", family: "http", sidBase: 2_020_000, description: "Generic web attacks (LFI/RFI, command injection)" },
  { name: "sql_injection", label: "SQL injection", baseSeverity: "high", family: "http", sidBase: 2_022_000, description: "SQLi patterns in HTTP parameters" },
  { name: "xss", label: "Cross-site scripting", baseSeverity: "medium", family: "http", sidBase: 2_021_000, description: "Reflected/stored XSS payloads" },
  { name: "dos", label: "DoS / DDoS", baseSeverity: "high", family: "stream", sidBase: 2_100_000, description: "Denial-of-service flood patterns (rate escalates)" },
  { name: "scan", label: "Recon / scan", baseSeverity: "medium", family: "stream", sidBase: 2_010_000, description: "Port scans and host sweeps" },
  { name: "brute_force", label: "Brute force", baseSeverity: "medium", family: "generic", sidBase: 2_101_000, description: "Credential brute-force patterns (ssh/rdp/http-auth)" },
  { name: "info_leak", label: "Info leak", baseSeverity: "low", family: "http", sidBase: 2_200_000, description: "Sensitive data in transit (ids/passwords/tokens)" },
  { name: "policy", label: "Policy violation", baseSeverity: "info", family: "generic", sidBase: 2_210_000, description: "ET policy signatures (P2P, streaming, noncompliant apps)" },
];

const BY_NAME = new Map(CATEGORY_CATALOG.map((c) => [c.name, c]));

export function categoryDef(name: string): CategoryDef | undefined {
  return BY_NAME.get(name);
}

/** Simulated TI feed (M04 §5 — policy-level tiBlocklist only). */
export const TI_FEED_IPS = [
  "45.83.91.7", "185.220.101.34", "91.219.236.182", "5.188.206.11",
  "89.248.167.131", "193.32.162.44",
];

// ── presets (DATA_PLANE §3.1) ───────────────────────────────────────────────

export interface PresetBundle {
  key: "conservative" | "balanced" | "aggressive";
  mode: "inline_drop" | "inline_tap" | "passive";
  categories: Record<string, boolean>;
  summary: string;
}

function cats(on: string[]): Record<string, boolean> {
  const m: Record<string, boolean> = {};
  for (const c of CATEGORY_CATALOG) m[c.name] = on.includes(c.name);
  return m;
}

export const PRESETS: Record<PresetBundle["key"], PresetBundle> = {
  conservative: {
    key: "conservative",
    mode: "inline_tap",
    categories: cats(["trojan", "worm", "botnet", "exploit", "malware", "c2"]),
    summary: "High-confidence categories only; scans/policy off; alert-heavy, drops rarely. First weeks after deployment.",
  },
  balanced: {
    key: "balanced",
    mode: "inline_drop",
    categories: cats(CATEGORY_CATALOG.filter((c) => !["dos", "policy", "info_leak"].includes(c.name)).map((c) => c.name)),
    summary: "Most ET categories on, noisy policy categories off, inline drop on WAN-facing flows. Standard small enterprise.",
  },
  aggressive: {
    key: "aggressive",
    mode: "inline_drop",
    categories: cats(CATEGORY_CATALOG.map((c) => c.name)),
    summary: "All categories on including policy/scan, drop-enabled, tight thresholds. DMZ servers, incident response.",
  },
};

// ── shapes ──────────────────────────────────────────────────────────────────

export interface ExceptionRow {
  sid: number;
  source?: string | null;
  dest?: string | null;
  comment?: string | null;
}

export interface ThresholdRow {
  sid: number;
  track: "by_src" | "by_dst";
  count: number;
  seconds: number;
}

export interface PreprocessorMap {
  stream?: boolean;
  http?: boolean;
  tls?: boolean;
  ssh?: boolean;
}

export interface IpsPolicyDto {
  id: number;
  name: string;
  mode: "inline_drop" | "inline_tap" | "passive";
  enabled: boolean;
  ruleCategories: Record<string, boolean>;
  customRules: string[];
  exceptions: ExceptionRow[];
  thresholds: ThresholdRow[];
  preprocessors: PreprocessorMap;
  tiBlocklist: boolean;
  attachedRuleCount: number;
  attachedRuleNames: string[];
}

export function parseJson<T>(raw: string, fallback: T): T {
  try {
    const v = JSON.parse(raw) as T;
    return v ?? fallback;
  } catch {
    return fallback;
  }
}

export function categoriesOn(map: Record<string, boolean>): number {
  return Object.values(map).filter(Boolean).length;
}

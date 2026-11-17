/**
 * Pure endpoint profiling (Phase 3 §3.6) — fuses OUI lookups, hostname
 * patterns, DHCP vendor classes and optional nDPI protocol labels into a
 * {vendor, deviceType, osGuess, confidence} profile, flags rogue-looking
 * devices (unknown MAC + fresh firstSeen + unclassified) and computes NAC
 * risk scores. No DB / no I/O — everything here is unit-testable.
 */

import { lookupOui, normalizeMac, type OuiEntry } from "./oui";

export type { DeviceType, OuiEntry } from "./oui";
import type { DeviceType } from "./oui";

// ── hostname patterns (mission list + a few safe product aliases) ───────────

/**
 * Ordered first-match-wins. Patterns are deliberately conservative — a
 * substring hit is only a hint, never proof. "hp" requires a boundary
 * (start, separator or digit) so "php-dev" does NOT classify as a printer.
 */
const HOSTNAME_PATTERNS: Array<{ re: RegExp; deviceType: DeviceType }> = [
  { re: /(?:print|prn|epson|brother|canon|laser|pixma|officejet|jetdirect|(?:^|[-_])hp(?:[-_]|[0-9]|$))/, deviceType: "printer" },
  { re: /(?:cam|ipc|ipcam|cctv|hik|dahua|onvif|nvrip)/, deviceType: "camera" },
  { re: /(?:tv|tizen|webos|bravia|appletv|chromecast|firetv|shield|projector)/, deviceType: "iot" },
  { re: /(?:phone|iphone|ipad|android|pixel|galaxy|voip)/, deviceType: "mobile" },
  { re: /(?:esp|tasmota|shelly|sonoff|tuya|wemos|hue|sonos|raspberry|rpi|zigbee|plug|bulb|sensor|thermostat|nest)/, deviceType: "iot" },
  { re: /(?:desktop|laptop|macbook|thinkpad|notebook|workstation|ubuntu|fedora|(?:^|-)ws(?:-|$)|(?:^|-)pc(?:-|$))/, deviceType: "workstation" },
];

/** First hostname pattern that matches → device type, else null. */
export function deviceTypeFromHostname(hostname: string): DeviceType | null {
  const h = hostname.trim().toLowerCase();
  if (h.length === 0) return null;
  for (const pattern of HOSTNAME_PATTERNS) {
    if (pattern.re.test(h)) return pattern.deviceType;
  }
  return null;
}

// ── DHCP vendor-class signals ────────────────────────────────────────────────

/** Recognized DHCP vendor class strings → {deviceType, osGuess}. */
export function signalFromVendorClass(
  vendorClass: string,
): { deviceType: DeviceType; osGuess: string } | null {
  const vc = vendorClass.trim().toLowerCase();
  if (vc.length === 0) return null;
  if (vc.includes("android-dhcp")) return { deviceType: "mobile", osGuess: "Android" };
  if (vc.startsWith("msft")) return { deviceType: "workstation", osGuess: "Windows" };
  if (vc.startsWith("udhcp")) return { deviceType: "iot", osGuess: "embedded Linux" };
  return null;
}

// ── nDPI protocol-label signals (override when present) ─────────────────────

/** Well-known nDPI labels → device class (keys are lowercase). */
const NDPI_LABELS: Record<string, { deviceType: DeviceType; osGuess?: string }> = {
  airprint: { deviceType: "printer" },
  ipp: { deviceType: "printer" },
  lpd: { deviceType: "printer" },
  printing: { deviceType: "printer" },
  rtsp: { deviceType: "camera" },
  onvif: { deviceType: "camera" },
  hikvision: { deviceType: "camera" },
  dahua: { deviceType: "camera" },
  sip: { deviceType: "phone", osGuess: "VoIP firmware" },
  h323: { deviceType: "phone", osGuess: "VoIP firmware" },
  whatsapp: { deviceType: "mobile" },
  telegram: { deviceType: "mobile" },
  signal: { deviceType: "mobile" },
  apple: { deviceType: "mobile", osGuess: "iOS/macOS" },
  windowsupdate: { deviceType: "workstation", osGuess: "Windows" },
  netflix: { deviceType: "iot" },
  youtube: { deviceType: "iot" },
  spotify: { deviceType: "iot" },
  twitch: { deviceType: "iot" },
  synology: { deviceType: "iot", osGuess: "DSM (embedded Linux)" },
};

/** First nDPI label with a known mapping → its signal, else null. */
export function signalFromNdpi(
  labels: string[] | null | undefined,
): { deviceType: DeviceType; osGuess?: string } | null {
  if (!labels) return null;
  for (const raw of labels) {
    const hit = NDPI_LABELS[raw.trim().toLowerCase()];
    if (hit) return hit;
  }
  return null;
}

// ── signal fusion ────────────────────────────────────────────────────────────

export const SIGNAL_WEIGHTS = { oui: 45, hostname: 35, vendorClass: 25, ndpi: 60 } as const;

export interface ProfileSignals {
  mac: string;
  hostname?: string | null;
  dhcpVendorClass?: string | null;
  nDpiLabels?: string[] | null;
}

export interface DeviceProfile {
  vendor: string | null;
  deviceType: DeviceType;
  osGuess: string | null;
  /** 0-100 — summed weight of the signals agreeing with the final type. */
  confidence: number;
  /** e.g. ["oui:printer", "hostname:printer"] — which signals fired. */
  matchedSignals: string[];
}

interface Vote {
  source: keyof typeof SIGNAL_WEIGHTS;
  deviceType: DeviceType;
  weight: number;
  osGuess?: string;
}

/**
 * Fuse the available signals into a device profile.
 *
 * Precedence: nDPI labels override everything when present (deepest packet
 * visibility), otherwise the strongest signal wins (OUI 45 > hostname 35 >
 * vendor-class 25). Confidence sums the weights of the signals that AGREE
 * with the final type (capped at 100) — disagreeing signals lower it. With
 * no signals at all the profile stays honestly unknown at confidence 0.
 */
export function profileFromSignals(signals: ProfileSignals): DeviceProfile {
  const ouiHit: OuiEntry | null = lookupOui(signals.mac);

  const votes: Vote[] = [];
  if (ouiHit && ouiHit.deviceTypeHint !== "unknown") {
    votes.push({ source: "oui", deviceType: ouiHit.deviceTypeHint, weight: SIGNAL_WEIGHTS.oui, osGuess: ouiHit.osHint });
  }
  const hostType = signals.hostname ? deviceTypeFromHostname(signals.hostname) : null;
  if (hostType) {
    votes.push({ source: "hostname", deviceType: hostType, weight: SIGNAL_WEIGHTS.hostname });
  }
  const vendorClass = signals.dhcpVendorClass ? signalFromVendorClass(signals.dhcpVendorClass) : null;
  if (vendorClass) {
    votes.push({ source: "vendorClass", deviceType: vendorClass.deviceType, weight: SIGNAL_WEIGHTS.vendorClass, osGuess: vendorClass.osGuess });
  }
  const ndpi = signalFromNdpi(signals.nDpiLabels);
  if (ndpi) {
    votes.push({ source: "ndpi", deviceType: ndpi.deviceType, weight: SIGNAL_WEIGHTS.ndpi, osGuess: ndpi.osGuess });
  }

  // nDPI overrides; otherwise highest-weight vote wins (weights are distinct).
  const ndpiVote = votes.find((v) => v.source === "ndpi");
  const winner = ndpiVote ?? [...votes].sort((a, b) => b.weight - a.weight)[0] ?? null;

  const deviceType: DeviceType = winner ? winner.deviceType : "unknown";
  const agreeing = votes.filter((v) => v.deviceType === deviceType);
  const confidence = winner ? Math.min(100, agreeing.reduce((sum, v) => sum + v.weight, 0)) : 0;
  const osGuess = agreeing.map((v) => v.osGuess).find((os) => os != null && os !== "") ?? null;

  return {
    vendor: ouiHit?.vendor ?? null,
    deviceType,
    osGuess,
    confidence,
    matchedSignals: votes.map((v) => `${v.source}:${v.deviceType}`),
  };
}

// ── rogue detection ──────────────────────────────────────────────────────────

/** "Recent" window for rogue candidates — mission spec: firstSeen < 24h. */
export const ROGUE_WINDOW_MS = 24 * 60 * 60 * 1000;

export interface RogueCandidate {
  macAddress: string;
  firstSeen: Date | string;
  deviceType: DeviceType;
}

/**
 * Rogue candidate = MAC absent from the known set (e.g. every MAC the DHCP
 * server ever leased), device still unclassified AND first seen within the
 * last 24h. Anything classified, known or stale is NOT flagged.
 */
export function rogueCheck(
  device: RogueCandidate,
  knownMacs: Iterable<string>,
  now: Date = new Date(),
): boolean {
  if (device.deviceType !== "unknown") return false;
  const mac = normalizeMac(device.macAddress);
  if (mac === null) return false;
  for (const known of knownMacs) {
    if (normalizeMac(known) === mac) return false;
  }
  const ts = device.firstSeen instanceof Date ? device.firstSeen.getTime() : Date.parse(device.firstSeen);
  if (Number.isNaN(ts)) return false;
  return now.getTime() - ts < ROGUE_WINDOW_MS;
}

// ── risk scoring (mission formula) ───────────────────────────────────────────

/** Base score — mirrors the nac_devices.risk_score column default. */
export const RISK_BASE = 30;

/** Clamp to the documented 0-100 band (integer). */
export function clampRisk(score: number): number {
  return Math.min(100, Math.max(0, Math.round(score)));
}

export interface RiskInput {
  deviceType: DeviceType;
  quarantined: boolean;
  osGuess?: string | null;
}

/**
 * Deterministic risk score: base 30, +15 for iot/camera class (unpatchable
 * embedded attack surface), +20 for still-unknown devices, +30 while
 * quarantined, +10 when no OS fingerprint exists. Clamped to 0-100 so the
 * score can never run away on re-scan.
 */
export function riskScoreFor(input: RiskInput): number {
  let score = RISK_BASE;
  if (input.deviceType === "iot" || input.deviceType === "camera") score += 15;
  if (input.deviceType === "unknown") score += 20;
  if (input.quarantined) score += 30;
  if (input.osGuess == null || input.osGuess.trim() === "") score += 10;
  return clampRisk(score);
}

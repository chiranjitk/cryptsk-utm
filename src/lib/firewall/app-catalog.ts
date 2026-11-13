/**
 * Static nDPI app-label catalog (M03 §8 — appliance publishes the live catalog
 * in Phase 2+). Served by GET /api/v1/network/app-catalog; the Rules editor
 * Applications picker and server-side rule validation both consume it.
 * Includes the "unknown" label (restored REVIEW-4A) and every label used by
 * the mock traffic profiles so generated flows always match a catalog entry.
 */

export const APP_CATALOG: string[] = [
  "unknown",
  "HTTPS",
  "HTTP",
  "DNS",
  "TLS",
  "QUIC",
  "SSH",
  "RDP",
  "SIP",
  "NTP",
  "MQTT",
  "SMTP",
  "IMAP",
  "Teams",
  "Slack",
  "Zoom",
  "Skype",
  "WhatsApp",
  "Telegram",
  "YouTube",
  "Netflix",
  "Spotify",
  "Twitch",
  "Windows-Update",
  "BitTorrent",
  "Facebook",
  "Instagram",
  "TikTok",
  "Twitter",
  "Reddit",
  "Steam",
  "GMail",
];

const LOWER = new Map(APP_CATALOG.map((l) => [l.toLowerCase(), l]));

/** Normalize an incoming label to its canonical catalog spelling (case-insensitive). */
export function canonicalAppLabel(label: string): string | null {
  return LOWER.get(label.trim().toLowerCase()) ?? null;
}

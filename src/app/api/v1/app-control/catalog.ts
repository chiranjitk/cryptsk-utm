/**
 * M18 Application Control — static nDPI-style application catalog. Used by the
 * rule validation (appName must be a known label), the UI autocomplete/test
 * card and the simulated decision engine's known/unknown app branch. The
 * appliance (nDPI) classifies traffic for real; this list lets the sandbox
 * demo plausible per-app decisions.
 */

export type AppCategory =
  | "media"
  | "collaboration"
  | "remote"
  | "filesharing"
  | "social"
  | "gaming"
  | "devops";

/** All 7 categories in display order (schema-locked). */
export const APP_CATEGORIES: AppCategory[] = [
  "media",
  "collaboration",
  "remote",
  "filesharing",
  "social",
  "gaming",
  "devops",
];

export interface AppCatalogEntry {
  /** nDPI label — lowercase identifier used in AppControlRule.appName. */
  name: string;
  category: AppCategory;
  description: string;
}

/** 26 nDPI-style apps across the 7 locked categories. */
export const APP_CATALOG: readonly AppCatalogEntry[] = [
  // media
  { name: "youtube", category: "media", description: "YouTube video streaming" },
  { name: "netflix", category: "media", description: "Netflix on-demand video" },
  { name: "spotify", category: "media", description: "Spotify audio streaming" },
  { name: "twitch", category: "media", description: "Twitch live streaming" },
  // collaboration
  { name: "teams", category: "collaboration", description: "Microsoft Teams meetings & chat" },
  { name: "zoom", category: "collaboration", description: "Zoom video conferencing" },
  { name: "slack", category: "collaboration", description: "Slack workspace messaging" },
  { name: "webex", category: "collaboration", description: "Cisco Webex conferencing" },
  // remote
  { name: "ssh", category: "remote", description: "Secure Shell remote terminal" },
  { name: "rdp", category: "remote", description: "Remote Desktop Protocol" },
  { name: "vnc", category: "remote", description: "Virtual Network Computing" },
  { name: "teamviewer", category: "remote", description: "TeamViewer remote support" },
  // filesharing
  { name: "bittorrent", category: "filesharing", description: "BitTorrent peer-to-peer file sharing" },
  { name: "dropbox", category: "filesharing", description: "Dropbox cloud sync" },
  { name: "googledrive", category: "filesharing", description: "Google Drive file storage" },
  { name: "onedrive", category: "filesharing", description: "Microsoft OneDrive sync" },
  // social
  { name: "facebook", category: "social", description: "Facebook social network" },
  { name: "instagram", category: "social", description: "Instagram photo sharing" },
  { name: "tiktok", category: "social", description: "TikTok short video" },
  { name: "twitter", category: "social", description: "X (Twitter) microblogging" },
  // gaming
  { name: "steam", category: "gaming", description: "Steam game platform & downloads" },
  { name: "epicgames", category: "gaming", description: "Epic Games launcher & store" },
  { name: "xboxlive", category: "gaming", description: "Xbox Live gaming network" },
  // devops
  { name: "github", category: "devops", description: "GitHub code hosting" },
  { name: "gitlab", category: "devops", description: "GitLab code hosting & CI" },
  { name: "docker-registry", category: "devops", description: "Docker Registry image pulls" },
] as const;

const BY_NAME: ReadonlyMap<string, AppCatalogEntry> = new Map(APP_CATALOG.map((a) => [a.name, a]));

/** Catalog entry for an nDPI label, or undefined when unknown. */
export function catalogEntry(name: string): AppCatalogEntry | undefined {
  return BY_NAME.get(name.trim().toLowerCase());
}

/** True when the label is a known nDPI app. */
export function isKnownApp(name: string): boolean {
  return BY_NAME.has(name.trim().toLowerCase());
}

/** Category of a known app, or null when unknown. */
export function categoryOf(name: string): AppCategory | null {
  return BY_NAME.get(name.trim().toLowerCase())?.category ?? null;
}

/**
 * M16 URL Filtering — built-in sample domain→category catalog used ONLY by the
 * simulated /test decision engine (spec 2.3.4). The appliance (Squid + a real
 * commercial feed) enforces categories for real; this map lets the UI demo a
 * plausible decision for known hosts. Everything unmatched is "uncategorized"
 * and falls through to the policy default action.
 */

export type UrlFilterCategory =
  | "gambling"
  | "adult"
  | "social_media"
  | "malware"
  | "phishing"
  | "p2p"
  | "streaming"
  | "games"
  | "news"
  | "shopping"
  | "weapons"
  | "hate"
  | "custom";

/** All 13 web categories in display order (schema-locked). */
export const URL_CATEGORIES: UrlFilterCategory[] = [
  "gambling",
  "adult",
  "social_media",
  "malware",
  "phishing",
  "p2p",
  "streaming",
  "games",
  "news",
  "shopping",
  "weapons",
  "hate",
  "custom",
];

/** Categories the engine always blocks regardless of per-policy rule config. */
export const ALWAYS_BLOCKED: ReadonlySet<string> = new Set(["malware", "phishing"]);

/** Sample domain→category map (~2 entries per category, mixed real + sandbox hosts). */
export const SAMPLE_DOMAIN_CATEGORIES: Readonly<Record<string, UrlFilterCategory>> = {
  // gambling
  "gamble-site.net": "gambling",
  "bet-casino.io": "gambling",
  // adult
  "adult-content.example": "adult",
  "nsfw-portal.example": "adult",
  // social media
  "social.example": "social_media",
  "facebook.com": "social_media",
  "instagram.com": "social_media",
  // malware
  "malware-cdn.xyz": "malware",
  "trojan-distro.example": "malware",
  // phishing
  "phishing-login.example": "phishing",
  "secure-bank-verify.example": "phishing",
  // p2p
  "torrent-tracker.example": "p2p",
  "p2p-index.example": "p2p",
  // streaming
  "youtube.com": "streaming",
  "netflix.com": "streaming",
  "twitch.tv": "streaming",
  // games
  "gamehub.example": "games",
  "roblox.com": "games",
  // news
  "news-daily.example": "news",
  "bbc.com": "news",
  // shopping
  "shop-mart.example": "shopping",
  "ebay.com": "shopping",
  // weapons
  "arms-market.example": "weapons",
  "gun-auctions.example": "weapons",
  // hate
  "hate-forum.example": "hate",
  "extremist-board.example": "hate",
  // custom (org-defined productivity set)
  "github.com": "custom",
  "gitlab.com": "custom",
};

/** Hosts treated as search engines for the SafeSearch enforcement branch. */
export const SEARCH_ENGINE_DOMAINS: Readonly<string[]> = [
  "google.com",
  "bing.com",
  "duckduckgo.com",
  "search.brave.com",
  "yahoo.com",
];

/** Exact → longest-suffix match: www.youtube.com hits youtube.com. */
function matchSuffix(host: string, table: Readonly<string[]>): string | null {
  const h = host.toLowerCase().replace(/\.+$/, "");
  if (table.includes(h)) return h;
  const parts = h.split(".");
  for (let i = 1; i < parts.length - 1; i += 1) {
    const suffix = parts.slice(i).join(".");
    if (table.includes(suffix)) return suffix;
  }
  return null;
}

/** Category for a request host, or null when uncategorized. */
export function lookupCategory(host: string): UrlFilterCategory | null {
  const hit = matchSuffix(host, Object.keys(SAMPLE_DOMAIN_CATEGORIES));
  return hit !== null ? (SAMPLE_DOMAIN_CATEGORIES[hit] ?? null) : null;
}

/** True when the host is a known search engine (SafeSearch branch). */
export function isSearchEngine(host: string): boolean {
  return matchSuffix(host, SEARCH_ENGINE_DOMAINS) !== null;
}

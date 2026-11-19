/**
 * CASB hint matcher (Phase 4 §4.3) — PURE functions, no DB/network access.
 * An `appHint` is the nDPI label or SNI hostname guess carried on an
 * aggregated discovery row; `matchHint` attributes it to a catalog app by
 * DOMAIN SUFFIX matching:
 *   • plain entry "google.com"  → hint "docs.google.com" matches (suffix),
 *     as does the bare domain itself;
 *   • wildcard entry "*.zoom.us" → matches subdomains ("us02web.zoom.us")
 *     but NOT the bare "zoom.us" (that is the plain entry's job);
 *   • longest matching domain wins (most specific attribution).
 * `classifyVerdict` maps the match outcome to the discovery verdict:
 *   • no catalog match → "unknown"  (unattributed SaaS = the shadow-IT
 *     candidate surfaced for triage),
 *   • match with riskScore ≤ SANCTIONED_MAX_RISK → "sanctioned",
 *   • match with riskScore above it → "shadow" (in catalog but high-risk,
 *     e.g. consumer mail/storage next to the sanctioned suite).
 */

// ── shapes ──────────────────────────────────────────────────────────────────

/** Minimal catalog entry shape — DB rows are shaped into this by the service. */
export interface MatchCatalogEntry {
  id: number;
  name: string;
  vendor: string;
  category: string;
  domains: string[];
  riskScore: number;
}

export interface HintMatch {
  app: MatchCatalogEntry;
  /** the catalog domain entry that matched (wildcards verbatim, "*.zoom.us") */
  matchedDomain: string;
}

/**
 * riskScore above which a CATALOGED app is treated as shadow IT rather than
 * sanctioned (0-100 scale; 50 = the midpoint — consumer-grade apps ship 55+).
 */
export const SANCTIONED_MAX_RISK = 50;

// ── hint normalization ──────────────────────────────────────────────────────

/**
 * Reduce a raw hint to a bare lowercase hostname: strips scheme, userinfo,
 * port, path and trailing dot; returns "" when nothing host-like remains.
 * Pure string shaping — accepts nDPI labels and SNI guesses alike.
 */
export function normalizeHint(raw: string): string {
  let hint = (raw ?? "").trim().toLowerCase();
  if (!hint) return "";
  if (hint.includes("://")) {
    const after = hint.split("://", 2)[1] ?? "";
    hint = after.split("/", 1)[0] ?? "";
  } else if (hint.includes("/")) {
    hint = hint.split("/", 1)[0] ?? "";
  }
  hint = hint.split("@").pop() ?? ""; // drop userinfo (user@host)
  hint = hint.split(":", 1)[0] ?? ""; // drop port
  if (hint.endsWith(".")) hint = hint.slice(0, -1);
  return hint;
}

/**
 * Suffix-domain test: does `host` sit under `domain`?
 *   exact ("zoom.us" ≡ "zoom.us"), subdomain ("docs.google.com" under
 *   "google.com"); wildcards ("*.zoom.us") match any DEEPER host under
 *   "zoom.us" but not the bare parent domain.
 */
function hostUnderDomain(host: string, domain: string): boolean {
  if (domain.startsWith("*.")) {
    const parent = domain.slice(2);
    return host.endsWith(`.${parent}`);
  }
  return host === domain || host.endsWith(`.${domain}`);
}

// ── matching ────────────────────────────────────────────────────────────────

/**
 * Attribute `hint` to a catalog app. Winner = the LONGEST matched domain
 * (specificity: "docs.google.com" beats "google.com" when both entries
 * exist); length ties resolve to catalog order (first listed wins). Returns
 * null when no entry matches (unknown app).
 */
export function matchHint(rawHint: string, catalog: MatchCatalogEntry[]): HintMatch | null {
  const host = normalizeHint(rawHint);
  if (!host) return null;

  let best: HintMatch | null = null;
  let bestLength = -1;

  for (const app of catalog) {
    for (const domain of app.domains) {
      const entry = domain.trim().toLowerCase();
      if (!entry) continue;
      if (!hostUnderDomain(host, entry)) continue;
      // specificity: longer matched domain wins; strict '>' keeps the first
      // catalog entry on ties so default ordering stays deterministic
      const len = entry.replace("*.", "").length;
      if (len > bestLength) {
        bestLength = len;
        best = { app, matchedDomain: entry };
      }
    }
  }
  return best;
}

// ── verdict classification ──────────────────────────────────────────────────

export type SaasVerdictValue = "sanctioned" | "shadow" | "unknown";

/**
 * Verdict for one aggregated (clientIp, appHint) discovery:
 *   unknown (no catalog attribution) | sanctioned (cataloged, low risk) |
 *   shadow (cataloged but riskScore > SANCTIONED_MAX_RISK).
 */
export function classifyVerdict(match: HintMatch | null): SaasVerdictValue {
  if (!match) return "unknown";
  return match.app.riskScore > SANCTIONED_MAX_RISK ? "shadow" : "sanctioned";
}

/**
 * Pure GeoIP → nftables named-set renderer (spec §1.4).
 *
 * Turns per-country CIDR prefix maps (parsed by the geoip service from
 * admin-provided CSV sources) into nftables `set` fragments for the
 * console-firewall table:
 *
 *   set utm_geo_de { type ipv4_addr; flags interval; auto-merge; elements = { … } }
 *
 * Contract:
 *  • PURE — no fs, no DB, no exec; same inputs → byte-identical fragment and
 *    hash (elements are deduped, validated and network-sorted before render).
 *  • PERF GUARD — a country with more than GEO_SET_MAX_PREFIXES prefixes is
 *    skipped with a warning instead of emitting a mega-set (20k+ interval
 *    elements dominate nft apply/commit time and can stall convergence);
 *    callers surface the warning instead of silently pretending enforcement.
 *  • `flags interval; auto-merge` — the kernel merges overlapping/adjacent
 *    ranges itself, so the emitted prefixes need not be non-overlapping.
 */

import { createHash } from "node:crypto";

export const GEO_SET_PREFIX = "utm_geo_";
/** Perf guard: countries above this prefix count are skipped (documented). */
export const GEO_SET_MAX_PREFIXES = 20000;

const CIDR_RE = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/;
const ISO_CC_RE = /^[A-Za-z]{2}$/;

export interface GeoSetInfo {
  country: string;
  setName: string;
  prefixCount: number;
  skipped: boolean;
  skipReason: string | null;
}

export interface GeoRenderResult {
  /** nftables fragment — one `set …` line per emitted country */
  fragment: string;
  /** sha256 of the fragment (deterministic content hash) */
  sha256: string;
  /** per-country accounting (emitted and skipped) */
  sets: GeoSetInfo[];
  warnings: string[];
}

/** `DE` → `utm_geo_de`; non-ISO input is sanitized defensively. */
export function geoSetName(cc: string): string {
  return `${GEO_SET_PREFIX}${cc.toLowerCase().replace(/[^a-z0-9_]/g, "")}`;
}

function ipToInt(ip: string): number {
  const [a, b, c, d] = ip.split(".").map(Number);
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}

/** Valid IPv4 CIDR check (octet + bit range) — invalid entries are dropped. */
export function isValidV4Cidr(p: string): boolean {
  const m = p.match(CIDR_RE);
  if (!m) return false;
  const bits = Number(m[2]);
  if (bits > 32) return false;
  return m[1].split(".").every((o) => Number(o) <= 255);
}

/** Dedupe + validate + network-numeric sort — the determinism core. */
function normalizePrefixes(raw: string[]): { prefixes: string[]; invalid: number } {
  const seen = new Set<string>();
  const valid: Array<{ p: string; net: number; bits: number }> = [];
  let invalid = 0;
  for (const p of raw) {
    if (!isValidV4Cidr(p)) {
      invalid += 1;
      continue;
    }
    if (seen.has(p)) continue;
    seen.add(p);
    const [net, bits] = p.split("/");
    valid.push({ p, net: ipToInt(net), bits: Number(bits) });
  }
  valid.sort((a, b) => a.net - b.net || a.bits - b.bits || (a.p < b.p ? -1 : 1));
  return { prefixes: valid.map((v) => v.p), invalid };
}

/**
 * Render nftables named sets for the wanted countries. Deterministic:
 * countries are processed in sorted order, elements deduped/validated/sorted,
 * so identical inputs always produce an identical fragment and hash.
 */
export function renderGeoSets(prefixData: Record<string, string[]>, wantedCountries: string[]): GeoRenderResult {
  const warnings: string[] = [];
  const sets: GeoSetInfo[] = [];
  const lines: string[] = [];

  const wanted = [...new Set(wantedCountries.map((c) => c.trim().toUpperCase()))]
    .filter((c) => {
      if (ISO_CC_RE.test(c)) return true;
      warnings.push(`ignored non-ISO country key '${c}'`);
      return false;
    })
    .sort();

  for (const cc of wanted) {
    const raw = prefixData[cc] ?? [];
    if (raw.length === 0) {
      warnings.push(`country ${cc} has no prefixes in any loaded GeoIP source — no set emitted`);
      sets.push({ country: cc, setName: geoSetName(cc), prefixCount: 0, skipped: true, skipReason: "no prefixes" });
      continue;
    }
    if (raw.length > GEO_SET_MAX_PREFIXES) {
      warnings.push(
        `country ${cc} skipped: ${raw.length} prefixes exceed the ${GEO_SET_MAX_PREFIXES}-prefix set cap (perf guard — split the source or raise the cap consciously)`,
      );
      sets.push({
        country: cc,
        setName: geoSetName(cc),
        prefixCount: raw.length,
        skipped: true,
        skipReason: `exceeds ${GEO_SET_MAX_PREFIXES}-prefix cap`,
      });
      continue;
    }
    const { prefixes, invalid } = normalizePrefixes(raw);
    if (invalid > 0) warnings.push(`country ${cc}: dropped ${invalid} malformed/non-IPv4 prefix(es)`);
    if (prefixes.length === 0) {
      warnings.push(`country ${cc} had only malformed prefixes — no set emitted`);
      sets.push({ country: cc, setName: geoSetName(cc), prefixCount: 0, skipped: true, skipReason: "no valid prefixes" });
      continue;
    }
    const setName = geoSetName(cc);
    lines.push(`set ${setName} { type ipv4_addr; flags interval; auto-merge; elements = { ${prefixes.join(", ")} } }`);
    sets.push({ country: cc, setName, prefixCount: prefixes.length, skipped: false, skipReason: null });
  }

  const fragment = lines.join("\n");
  const sha256 = createHash("sha256").update(fragment).digest("hex");
  return { fragment, sha256, sets, warnings };
}

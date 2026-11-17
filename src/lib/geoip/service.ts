/**
 * GeoIP source service (spec §1.4) — DB-backed loader for country-prefix CSV
 * sources that feed nftables named sets (`utm_geo_*`).
 *
 * HONEST SCOPE NOTE: sources are admin-provided CSV files on the console host
 * — a GeoLite2 country CSV or an APNIC delegated list converted to lines of
 * `ISO_CODE,prefix`. NOTHING is bundled: no GeoLite2 binary, no mmdb reader
 * (the GeoipSource.kind column accepts "mmdb" for a future reader). The
 * console only parses what an operator points it at and records the result.
 *
 * Data flow:
 *   POST /geoip/sources {name, filePath}
 *     → loadSource(): read + parseGeoCsv + aggregate per country
 *     → GeoipSource row (status loaded, countries JSON, prefixCount)
 *   firewall apply (firewall-os)
 *     → getGeoResolver(): re-reads loaded sources (readPrefixes) and injects
 *       a (cc) => prefixes|null callback into the pure nft generator.
 *   GET /geoip/status
 *     → getSets() + renderGeoSets(): per-country set counts + hash preview.
 */

import fs from "node:fs/promises";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { renderGeoSets, GEO_SET_MAX_PREFIXES, type GeoSetInfo } from "./render";
import { isFqdnStale } from "@/lib/firewall/fqdn-resolver";

// ── CSV parsing (pure, exported for tests) ──────────────────────────────────

const ISO_CC_RE = /^[A-Za-z]{2}$/;
const CIDR_RE = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/;

export interface GeoCsvParseResult {
  /** upper-case ISO code → deduped IPv4 prefixes (input order preserved) */
  countries: Record<string, string[]>;
  /** accepted IPv4 prefixes (the only kind nftables ipv4_addr sets take) */
  v4Count: number;
  /** IPv6 prefixes: COUNTED but excluded (warned) — sets are ipv4_addr */
  v6Count: number;
  /** lines that were neither comment/blank nor parseable */
  badLines: number;
  warnings: string[];
}

function isValidV4Cidr(p: string): boolean {
  const m = p.match(CIDR_RE);
  if (!m) return false;
  if (Number(m[2]) > 32) return false;
  return m[1].split(".").every((o) => Number(o) <= 255);
}

/**
 * Parse a plain-text country CSV: lines of `ISO_CODE,prefix` (e.g.
 * `DE,185.10.0.0/16`). Tolerates `#` comment lines, blank lines and bad lines
 * (counted, never fatal as long as SOME prefixes parse). GeoLite2-style
 * `prefix,ISO_CODE` rows are tolerated by swapping obviously-swapped fields.
 */
export function parseGeoCsv(text: string): GeoCsvParseResult {
  const countries: Record<string, string[]> = {};
  const seen = new Set<string>();
  let v4Count = 0;
  let v6Count = 0;
  let badLines = 0;
  const warnings: string[] = [];

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;

    const fields = line.split(",").map((f) => f.trim());
    if (fields.length < 2) {
      badLines += 1;
      continue;
    }
    let code = fields[0];
    let prefix = fields[1];
    // tolerance: GeoLite2 network CSVs list `prefix,country` — swap when the
    // first field is clearly a CIDR and the second clearly an ISO code
    if (CIDR_RE.test(code) && ISO_CC_RE.test(prefix)) {
      [code, prefix] = [prefix, code];
    }
    if (!ISO_CC_RE.test(code)) {
      badLines += 1;
      continue;
    }
    const cc = code.toUpperCase();
    if (prefix.includes(":")) {
      v6Count += 1;
      continue; // ipv6 counted but warned — console sets are ipv4_addr
    }
    if (!isValidV4Cidr(prefix)) {
      badLines += 1;
      continue;
    }
    const key = `${cc}|${prefix}`;
    if (seen.has(key)) continue; // dedupe exact duplicates
    seen.add(key);
    (countries[cc] ??= []).push(prefix);
    v4Count += 1;
  }

  if (v6Count > 0) warnings.push(`${v6Count} IPv6 prefix(es) counted but excluded (sets are ipv4_addr only)`);
  if (badLines > 0) warnings.push(`${badLines} unparseable line(s) skipped (comments/blanks are fine, data lines must be ISO_CODE,prefix)`);
  return { countries, v4Count, v6Count, badLines, warnings };
}

// ── DTOs ────────────────────────────────────────────────────────────────────

export type GeoipSourceDTO = {
  id: number;
  name: string;
  kind: string; // csv | mmdb (mmdb is future — see header note)
  filePath: string;
  countries: string[];
  prefixCount: number;
  status: string; // pending | loaded | error
  error: string | null;
  updatedAt: string;
  createdAt: string;
};

function parseCountries(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function toSourceDTO(row: {
  id: number;
  name: string;
  kind: string;
  filePath: string;
  countries: string;
  prefixCount: number;
  status: string;
  error: string | null;
  updatedAt: Date;
  createdAt: Date;
}): GeoipSourceDTO {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    filePath: row.filePath,
    countries: parseCountries(row.countries),
    prefixCount: row.prefixCount,
    status: row.status,
    error: row.error,
    updatedAt: row.updatedAt.toISOString(),
    createdAt: row.createdAt.toISOString(),
  };
}

export interface GeoipLoadResult {
  source: GeoipSourceDTO;
  /** per-country accepted-prefix counts */
  countries: Array<{ country: string; prefixCount: number }>;
  v6Count: number;
  badLines: number;
  warnings: string[];
}

// ── source lifecycle ────────────────────────────────────────────────────────

export async function listSources(tenantId: number): Promise<GeoipSourceDTO[]> {
  const rows = await db.geoipSource.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toSourceDTO);
}

/**
 * Read + parse a CSV file and write/update the GeoipSource row (upserted by
 * name within the tenant). Parse/load failures mark the row status=error with
 * the message and throw a validation error so the API answers 400.
 */
export async function loadSource(
  tenantId: number,
  input: { name: string; filePath: string },
): Promise<GeoipLoadResult> {
  const name = input.name.trim();
  const filePath = input.filePath.trim();
  const existing = await db.geoipSource.findFirst({ where: { tenantId, name } });

  const fail = async (message: string): Promise<never> => {
    if (existing) {
      await db.geoipSource.update({
        where: { id: existing.id },
        data: { status: "error", error: message.slice(0, 1024), filePath, updatedAt: new Date() },
      });
    } else {
      await db.geoipSource.create({
        data: { tenantId, name, kind: "csv", filePath, status: "error", error: message.slice(0, 1024) },
      });
    }
    throw ApiError.validation(message);
  };

  let text: string;
  try {
    text = await fs.readFile(filePath, "utf8");
  } catch (err) {
    await fail(`Cannot read GeoIP source file '${filePath}': ${err instanceof Error ? err.message : "read error"}`);
    return undefined as never; // unreachable — fail always throws
  }

  const parsed = parseGeoCsv(text);
  if (parsed.v4Count === 0) {
    await fail(`GeoIP source '${filePath}' contains no usable IPv4 prefixes (${parsed.badLines} bad line(s), ${parsed.v6Count} IPv6)`);
    return undefined as never;
  }

  const countries = Object.keys(parsed.countries).sort();
  const data = {
    kind: "csv",
    filePath,
    countries: JSON.stringify(countries),
    prefixCount: parsed.v4Count,
    status: "loaded",
    error: null,
    updatedAt: new Date(),
  };
  const row = existing
    ? await db.geoipSource.update({ where: { id: existing.id }, data })
    : await db.geoipSource.create({ data: { tenantId, name, ...data } });

  return {
    source: toSourceDTO(row),
    countries: countries.map((cc) => ({ country: cc, prefixCount: parsed.countries[cc].length })),
    v6Count: parsed.v6Count,
    badLines: parsed.badLines,
    warnings: parsed.warnings,
  };
}

/**
 * Re-read a source file → { country → prefixes } (the DB stores only counts;
 * prefixes always come from a fresh file read so set rendering reflects the
 * file on disk, not a stale snapshot).
 */
export async function readPrefixes(
  filePath: string,
): Promise<{ prefixes: Record<string, string[]>; warnings: string[] }> {
  const text = await fs.readFile(filePath, "utf8");
  const parsed = parseGeoCsv(text);
  return { prefixes: parsed.countries, warnings: parsed.warnings };
}

export interface GeoipSets {
  /** merged (deduped) country → IPv4 prefixes across all loaded sources */
  prefixes: Record<string, string[]>;
  /** sorted union of country codes present */
  countries: string[];
  /** merged per-country prefix counts */
  counts: Record<string, number>;
  sources: GeoipSourceDTO[];
  warnings: string[];
}

/** Loaded GeoipSource data merged across sources — the firewall's view. */
export async function getSets(tenantId: number): Promise<GeoipSets> {
  const rows = await db.geoipSource.findMany({
    where: { tenantId, status: "loaded" },
    orderBy: { name: "asc" },
  });
  const prefixes: Record<string, string[]> = {};
  const warnings: string[] = [];
  const seen = new Set<string>();

  for (const row of rows) {
    try {
      const { prefixes: filePrefixes, warnings: fileWarnings } = await readPrefixes(row.filePath);
      for (const w of fileWarnings) warnings.push(`source '${row.name}': ${w}`);
      for (const [cc, list] of Object.entries(filePrefixes)) {
        const bucket = (prefixes[cc.toUpperCase()] ??= []);
        for (const p of list) {
          const key = `${cc}|${p}`;
          if (seen.has(key)) continue;
          seen.add(key);
          bucket.push(p);
        }
      }
    } catch (err) {
      // a source that was loaded once but whose file vanished on disk —
      // honest warning, the other sources still render
      warnings.push(`source '${row.name}' (${row.filePath}) could not be re-read: ${err instanceof Error ? err.message : "read error"}`);
    }
  }

  const countries = Object.keys(prefixes).sort();
  const counts: Record<string, number> = {};
  for (const cc of countries) counts[cc] = prefixes[cc].length;
  return {
    prefixes,
    countries,
    counts,
    sources: rows.map(toSourceDTO),
    warnings,
  };
}

/**
 * Build the GeoIP lookup callback injected into the pure nft generator.
 * Returns null when NO loaded sources exist (the generator then warns
 * "geo object skipped: no GeoIP source loaded" and keeps those rules
 * config-only — the strict under-matching contract).
 */
export async function getGeoResolver(
  tenantId: number,
): Promise<((cc: string) => string[] | null) | null> {
  const sets = await getSets(tenantId);
  if (sets.countries.length === 0) return null;
  return (cc: string) => {
    const list = sets.prefixes[String(cc).toUpperCase()];
    return list && list.length > 0 ? [...list] : null;
  };
}

export async function removeSource(tenantId: number, id: number): Promise<{ ok: true; removed: GeoipSourceDTO }> {
  const row = await db.geoipSource.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`GeoIP source ${id} not found`);
  await db.geoipSource.delete({ where: { id: row.id } });
  return { ok: true, removed: toSourceDTO(row) };
}

// ── status (GET /geoip/status — sources + set accounting + object health) ──

export interface GeoipStatus {
  sources: GeoipSourceDTO[];
  /** per-country named-set accounting from the pure renderer */
  sets: GeoSetInfo[];
  /** sha256 of the rendered geo-set fragment (drift fingerprint) */
  sha256: string | null;
  warnings: string[];
  cap: number;
  geoObjects: Array<{
    id: number;
    name: string;
    value: string;
    resolvable: boolean;
    prefixCount: number | null;
    capped: boolean;
  }>;
  fqdnObjects: Array<{
    id: number;
    name: string;
    value: string;
    ipCount: number;
    resolvedAt: string | null;
    stale: boolean;
  }>;
}

function parseResolvedIps(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

export async function getGeoipStatus(tenantId: number): Promise<GeoipStatus> {
  const [sets, geoRows, fqdnRows] = await Promise.all([
    getSets(tenantId),
    db.addressObject.findMany({ where: { tenantId, type: "geo" }, orderBy: { name: "asc" } }),
    db.addressObject.findMany({
      where: { tenantId, type: "fqdn" },
      orderBy: { name: "asc" },
      select: { id: true, name: true, value: true, resolvedIps: true, resolvedAt: true },
    }),
  ]);

  const rendered = sets.countries.length > 0 ? renderGeoSets(sets.prefixes, sets.countries) : null;
  const warnings = [...sets.warnings, ...(rendered?.warnings ?? [])];

  return {
    sources: sets.sources,
    sets: rendered?.sets ?? [],
    sha256: rendered?.sha256 ?? null,
    warnings,
    cap: GEO_SET_MAX_PREFIXES,
    geoObjects: geoRows.map((o) => {
      const cc = o.value.trim().toUpperCase();
      const count = sets.counts[cc];
      return {
        id: o.id,
        name: o.name,
        value: o.value,
        resolvable: count != null && count > 0,
        prefixCount: count ?? null,
        capped: count != null && count > GEO_SET_MAX_PREFIXES,
      };
    }),
    fqdnObjects: fqdnRows.map((o) => ({
      id: o.id,
      name: o.name,
      value: o.value,
      ipCount: parseResolvedIps(o.resolvedIps).length,
      resolvedAt: o.resolvedAt ? o.resolvedAt.toISOString() : null,
      stale: isFqdnStale(o.resolvedAt),
    })),
  };
}

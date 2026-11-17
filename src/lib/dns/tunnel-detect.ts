/**
 * DNS tunneling detection engine (Phase 3 §3.4) — PURE, rule-based, no DB and
 * no clock: every timestamp/threshold input is explicit so runs are
 * deterministic and unit-testable.
 *
 * Scope (heuristic by spec §3.4; AI DGA model explicitly deferred):
 *   • Shannon entropy over queried domain names (encoded tunnels / DGA-like
 *     domains carry high per-domain entropy),
 *   • unique-domain volume per client window (beaconing fans out),
 *   • longest single DNS label excluding the TLD (payload hidden in labels).
 *
 * Input rows mirror the DNS query-log source behind /api/v1/dns/query-logs —
 * that route serves the engine ring buffer (DnsQueryLogEntry), NOT a Prisma
 * model — but only clientIp/domain/ts are consumed here.
 */

// ── public shapes ───────────────────────────────────────────────────────────

export interface TunnelQueryInput {
  clientIp: string;
  domain: string;
  /** ISO timestamp; rows without a parseable ts are kept as-is by
   *  analyzeClientWindow and skipped by aggregateWindows (cannot be bucketed). */
  ts?: string;
}

export type TunnelVerdict = "clean" | "suspicious" | "likely_tunnel";

export interface WindowSpec {
  windowStart: Date;
  windowEnd: Date;
}

export interface ClientWindowStat {
  clientIp: string;
  windowStart: Date;
  windowEnd: Date;
  queryCount: number;
  uniqueDomains: number;
  /** longest single label excluding the TLD, across all queries (0 if none) */
  maxLabelLength: number;
  /** mean Shannon entropy across UNIQUE domains (volume must not skew entropy) */
  avgDomainEntropy: number;
  verdict: TunnelVerdict;
}

export interface WindowAggregate extends WindowSpec {
  clients: ClientWindowStat[];
}

export interface DomainCount {
  domain: string;
  count: number;
}

export interface LabelHit {
  label: string;
  domain: string;
  length: number;
}

/**
 * Rule thresholds (spec §3.4 — LOCKED values):
 *   suspicious    : entropy ≥ 3.5  OR uniqueDomains ≥ 25  OR maxLabelLength ≥ 45
 *   likely_tunnel : entropy ≥ 4.2  AND (uniqueDomains ≥ 40 OR queryCount ≥ 100)
 */
export const TUNNEL_THRESHOLDS = {
  suspicious: { entropy: 3.5, uniqueDomains: 25, maxLabelLength: 45 },
  likelyTunnel: { entropy: 4.2, uniqueDomains: 40, queryCount: 100 },
} as const;

// ── primitives ──────────────────────────────────────────────────────────────

/** Shannon entropy in bits/symbol: H = −Σ p·log2(p). Empty string → 0. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Labels of a domain with the TLD (rightmost label) removed. A single-label
 *  name has no separable TLD — it is kept whole. */
export function labelsExcludingTld(domain: string): string[] {
  const labels = domain.split(".").filter((l) => l.length > 0);
  return labels.length > 1 ? labels.slice(0, -1) : labels;
}

/** Longest single label excluding the TLD ("www.google.com" → 6 "google"). */
export function maxLabelLengthExcludingTld(domain: string): number {
  let max = 0;
  for (const label of labelsExcludingTld(domain)) max = Math.max(max, label.length);
  return max;
}

const round4 = (v: number): number => Math.round(v * 10_000) / 10_000;

/** Apply the LOCKED §3.4 thresholds to one client's window metrics. */
export function verdictFor(s: {
  queryCount: number;
  uniqueDomains: number;
  maxLabelLength: number;
  avgDomainEntropy: number;
}): TunnelVerdict {
  const t = TUNNEL_THRESHOLDS;
  if (
    s.avgDomainEntropy >= t.likelyTunnel.entropy &&
    (s.uniqueDomains >= t.likelyTunnel.uniqueDomains || s.queryCount >= t.likelyTunnel.queryCount)
  ) {
    return "likely_tunnel";
  }
  if (
    s.avgDomainEntropy >= t.suspicious.entropy ||
    s.uniqueDomains >= t.suspicious.uniqueDomains ||
    s.maxLabelLength >= t.suspicious.maxLabelLength
  ) {
    return "suspicious";
  }
  return "clean";
}

// ── per-client window analysis ──────────────────────────────────────────────

/**
 * Group queries by client inside one window and score each client.
 * Rows carrying a parseable ts outside [windowStart, windowEnd) are excluded
 * (half-open interval — end exclusive). Deterministic: clients sorted by IP.
 */
export function analyzeClientWindow(queries: TunnelQueryInput[], window: WindowSpec): ClientWindowStat[] {
  const startMs = window.windowStart.getTime();
  const endMs = window.windowEnd.getTime();
  const byClient = new Map<string, TunnelQueryInput[]>();
  for (const q of queries) {
    if (q.ts !== undefined) {
      const t = Date.parse(q.ts);
      if (Number.isFinite(t) && (t < startMs || t >= endMs)) continue;
    }
    const rows = byClient.get(q.clientIp);
    if (rows) rows.push(q);
    else byClient.set(q.clientIp, [q]);
  }
  return [...byClient.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([clientIp, rows]) => {
      const domains = new Set(rows.map((r) => r.domain));
      const entropySum = [...domains].reduce((sum, d) => sum + shannonEntropy(d), 0);
      const maxLabel = rows.reduce((m, r) => Math.max(m, maxLabelLengthExcludingTld(r.domain)), 0);
      const stat: ClientWindowStat = {
        clientIp,
        windowStart: window.windowStart,
        windowEnd: window.windowEnd,
        queryCount: rows.length,
        uniqueDomains: domains.size,
        maxLabelLength: maxLabel,
        avgDomainEntropy: domains.size === 0 ? 0 : round4(entropySum / domains.size),
        verdict: "clean",
      };
      return { ...stat, verdict: verdictFor(stat) };
    });
}

// ── fixed-window aggregation ────────────────────────────────────────────────

/**
 * Bucket queries into FIXED windows aligned to the epoch grid: windows are
 * windowMinutes long and start every stepMinutes (start = k·stepMs), never
 * anchored to the data — same input rows always yield the same windows.
 * With windowMinutes == stepMinutes this is plain tumbling; with
 * windowMinutes > stepMinutes windows overlap and a row contributes to every
 * window whose half-open range [start, start+windowMinutes) contains its ts.
 * Rows without a parseable ts are skipped. Output is sorted by windowStart.
 */
export function aggregateWindows(
  queries: TunnelQueryInput[],
  windowMinutes: number,
  stepMinutes: number,
): WindowAggregate[] {
  const windowMs = windowMinutes * 60_000;
  const stepMs = stepMinutes * 60_000;
  if (!(windowMs > 0) || !(stepMs > 0) || windowMs < stepMs) return [];

  // bucket rows on the step grid (bucketStart ≤ ts < bucketStart + stepMs)
  const buckets = new Map<number, TunnelQueryInput[]>();
  for (const q of queries) {
    const t = Date.parse(q.ts ?? "");
    if (!Number.isFinite(t)) continue;
    const bucketStart = Math.floor(t / stepMs) * stepMs;
    const rows = buckets.get(bucketStart);
    if (rows) rows.push(q);
    else buckets.set(bucketStart, [q]);
  }
  if (buckets.size === 0) return [];

  // a row at ts joins every window with start ≤ ts < start + windowMs;
  // candidate starts are bucketStart − k·stepMs (later k → earlier window, so
  // the scan can stop at the first window that ends at/before ts)
  const windows = new Map<number, TunnelQueryInput[]>();
  const maxSpan = Math.ceil(windowMs / stepMs);
  for (const [bucketStart, rows] of buckets) {
    for (const row of rows) {
      const t = Date.parse(row.ts ?? "");
      for (let k = 0; k < maxSpan; k++) {
        const start = bucketStart - k * stepMs;
        if (start + windowMs <= t) break;
        const rowsInWindow = windows.get(start);
        if (rowsInWindow) rowsInWindow.push(row);
        else windows.set(start, [row]);
      }
    }
  }

  return [...windows.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([start, rows]) => {
      const spec: WindowSpec = { windowStart: new Date(start), windowEnd: new Date(start + windowMs) };
      return { ...spec, clients: analyzeClientWindow(rows, spec) };
    });
}

// ── finding detail helpers ──────────────────────────────────────────────────

/**
 * Most-queried domains, count desc; ties broken by domain asc so the result
 * is deterministic regardless of row order.
 */
export function topDomains(queries: TunnelQueryInput[], limit: number): DomainCount[] {
  const counts = new Map<string, number>();
  for (const q of queries) counts.set(q.domain, (counts.get(q.domain) ?? 0) + 1);
  return [...counts.entries()]
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count || (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0))
    .slice(0, Math.max(0, limit));
}

/**
 * Longest non-TLD labels seen, one entry per unique domain (the longest label
 * is a property of the domain), length desc then label/domain asc.
 */
export function longestLabels(queries: TunnelQueryInput[], limit: number): LabelHit[] {
  const seen = new Map<string, LabelHit>();
  for (const q of queries) {
    const key = `${q.domain}`;
    if (seen.has(key)) continue;
    let best: LabelHit = { label: "", domain: q.domain, length: 0 };
    for (const label of labelsExcludingTld(q.domain)) {
      if (label.length > best.length) best = { label, domain: q.domain, length: label.length };
    }
    seen.set(key, best);
  }
  return [...seen.values()]
    .sort(
      (a, b) =>
        b.length - a.length ||
        (a.label < b.label ? -1 : a.label > b.label ? 1 : 0) ||
        (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0),
    )
    .slice(0, Math.max(0, limit));
}

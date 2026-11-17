/**
 * DLP detection engine (Phase 3 §3.3) — PURE core, no db import.
 *
 * Two matchers per SPEC.md §3.3 ("Regex pattern matching … Custom", "Keyword
 * matching … Custom (Go + Aho-Corasick)"):
 *   - keyword patterns compile into ONE Aho-Corasick automaton per scan and
 *     scan the text once (O(text + matches), independent of keyword count);
 *   - regex patterns compile at build time with a guarded `new RegExp` — an
 *     invalid expression records a build warning and never throws at scan
 *     time (a broken pattern must not take the whole scan down).
 *
 * Redaction contract (HARD CONSTRAINT — never store full sensitive text):
 * excerpts keep at most 16 context chars before + 16 after the hit; the
 * matched span itself is replaced by `█` repeated to the span's length; the
 * final excerpt is capped at 120 chars.
 */

// ── input/result shapes (plain data — service maps rows into these) ─────────

export type DlpSeverity = "low" | "medium" | "high" | "critical";
export type DlpCategory = "pii" | "financial" | "credentials" | "custom";

export interface DlpPatternInput {
  id: number;
  kind: "regex" | "keyword";
  /** regex source, or a comma-separated keyword list for kind=keyword */
  value: string;
  severity: DlpSeverity;
  category: DlpCategory;
}

export interface DlpMatch {
  patternId: number;
  severity: DlpSeverity;
  category: DlpCategory;
  /** redacted excerpt — matched span masked with █, ≤120 chars total */
  excerpt: string;
  /** match span [index, end) in the scanned text */
  index: number;
  end: number;
  kind: "regex" | "keyword";
}

export interface ScanPayloadInput {
  text: string;
  fileExtension?: string;
  patterns: DlpPatternInput[];
}

export interface ScanResult {
  matches: DlpMatch[];
  /** decided severity = max matched severity, null when nothing matched */
  severity: DlpSeverity | null;
  /** build-time problems (invalid regex sources) — never fatal */
  warnings: string[];
  /** caller-supplied extension, echoed so policy layers can apply fileTypes */
  fileExtension: string | null;
}

const SEVERITY_RANK: Record<DlpSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const CONTEXT_CHARS = 16;
const EXCERPT_CAP = 120;
/** safety valve — pathological inputs must not flood the result set */
const MAX_MATCHES = 100;

// ── Aho-Corasick (SPEC §3.3: keyword matching via Aho-Corasick) ─────────────

interface AcNode {
  /** edge label → child node index */
  next: Map<string, number>;
  /** suffix-failure link index */
  fail: number;
  /** keyword indices ending exactly at this node */
  out: number[];
}

interface Automaton {
  nodes: AcNode[];
  /** keyword i = terms[i] (already lower-cased) */
  terms: string[];
}

/**
 * Build the automaton: phase 1 builds the keyword trie, phase 2 computes
 * failure links breadth-first (classic Aho-Corasick, 1975). Output lists are
 * merged down the fail chain so every node directly reports all suffix hits.
 * Matching is case-insensitive by lowering keywords + text (ASCII-honest;
 * exotic Unicode case folding may shift offsets by a code point).
 */
function buildAhoCorasick(keywords: string[]): Automaton {
  const root: AcNode = { next: new Map(), fail: 0, out: [] };
  const nodes: AcNode[] = [root];
  const terms: string[] = [];

  for (const raw of keywords) {
    const kw = raw.toLowerCase();
    if (kw.length === 0 || terms.includes(kw)) continue; // dedupe identical terms
    terms.push(kw);
    let cur = 0;
    for (const ch of kw) {
      let next = nodes[cur].next.get(ch);
      if (next === undefined) {
        next = nodes.length;
        nodes.push({ next: new Map(), fail: 0, out: [] });
        nodes[cur].next.set(ch, next);
      }
      cur = next;
    }
    nodes[cur].out.push(terms.length - 1);
  }

  // BFS failure links — depth-1 nodes fail to root
  const queue: number[] = [];
  for (const child of nodes[0].next.values()) {
    nodes[child].fail = 0;
    queue.push(child);
  }
  for (let head = 0; head < queue.length; head++) {
    const u = queue[head];
    for (const [ch, v] of nodes[u].next) {
      let f = nodes[u].fail;
      while (f !== 0 && !nodes[f].next.has(ch)) f = nodes[f].fail;
      const fail = nodes[f].next.get(ch);
      nodes[v].fail = fail !== undefined && fail !== v ? fail : 0;
      nodes[v].out = [...nodes[v].out, ...nodes[nodes[v].fail].out];
      queue.push(v);
    }
  }
  return { nodes, terms };
}

export interface KeywordOwner {
  term: string;
  patternId: number;
  severity: DlpSeverity;
  category: DlpCategory;
}

/** Compile the keyword automaton for a scan — exported for tests/harnesses. */
export function buildKeywordAutomaton(patterns: DlpPatternInput[]): {
  automaton: Automaton;
  owners: KeywordOwner[];
} {
  const owners: KeywordOwner[] = [];
  const seen = new Set<string>();
  for (const p of patterns) {
    for (const term of splitKeywords(p.value)) {
      // dedupe identical terms — owners[] stays index-aligned with automaton.terms[]
      const key = term.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      owners.push({ term, patternId: p.id, severity: p.severity, category: p.category });
    }
  }
  return { automaton: buildAhoCorasick(owners.map((o) => o.term)), owners };
}

/** keyword pattern values are comma-separated keyword lists (SCHEMA §3.3). */
export function splitKeywords(value: string): string[] {
  return value
    .split(",")
    .map((k) => k.trim())
    .filter((k) => k.length > 0);
}

/** Run the automaton over the (lowered) text — yields [start, end) spans + owning term index. */
function scanAutomaton(
  automaton: Automaton,
  lowered: string,
): Array<{ termIdx: number; start: number; end: number }> {
  const hits: Array<{ termIdx: number; start: number; end: number }> = [];
  let cur = 0;
  for (let i = 0; i < lowered.length; i++) {
    const ch = lowered[i];
    while (cur !== 0 && !automaton.nodes[cur].next.has(ch)) cur = automaton.nodes[cur].fail;
    const next = automaton.nodes[cur].next.get(ch);
    cur = next !== undefined ? next : 0;
    for (const termIdx of automaton.nodes[cur].out) {
      const end = i + 1;
      const start = end - automaton.terms[termIdx].length;
      if (start >= 0) hits.push({ termIdx, start, end });
    }
  }
  return hits;
}

// ── redaction ───────────────────────────────────────────────────────────────

/**
 * Build the redacted excerpt: ≤16 chars before, the matched span fully
 * replaced by `█` (one per char — length preserved), ≤16 chars after, then
 * the whole excerpt capped at 120 chars.
 */
export function redactExcerpt(text: string, start: number, end: number): string {
  const from = Math.max(0, start - CONTEXT_CHARS);
  const to = Math.min(text.length, end + CONTEXT_CHARS);
  const before = text.slice(from, start);
  const after = text.slice(end, to);
  const masked = "\u2588".repeat(Math.max(0, end - start));
  return `${before}${masked}${after}`.slice(0, EXCERPT_CAP);
}

// ── regex patterns ──────────────────────────────────────────────────────────

interface CompiledRegex {
  patternId: number;
  severity: DlpSeverity;
  category: DlpCategory;
  re: RegExp;
}

/** Build regex matchers; invalid sources produce warnings, never throws. */
export function buildRegexMatchers(patterns: DlpPatternInput[], warnings: string[]): CompiledRegex[] {
  const compiled: CompiledRegex[] = [];
  for (const p of patterns) {
    try {
      // global + case-insensitive: every occurrence, case-tolerant
      compiled.push({ patternId: p.id, severity: p.severity, category: p.category, re: new RegExp(p.value, "gi") });
    } catch {
      warnings.push(`Pattern #${p.id} skipped: invalid regular expression "${p.value.slice(0, 64)}"`);
    }
  }
  return compiled;
}

// ── scan entry point ────────────────────────────────────────────────────────

const bySeverityDesc = (a: DlpMatch, b: DlpMatch): number => {
  const ra = SEVERITY_RANK[a.severity] ?? 0;
  const rb = SEVERITY_RANK[b.severity] ?? 0;
  if (ra !== rb) return rb - ra;
  return a.index - b.index;
};

export function maxSeverity(severities: Array<DlpSeverity | null | undefined>): DlpSeverity | null {
  let best: DlpSeverity | null = null;
  let rank = 0;
  for (const s of severities) {
    if (!s) continue;
    const r = SEVERITY_RANK[s] ?? 0;
    if (r > rank) {
      rank = r;
      best = s;
    }
  }
  return best;
}

/**
 * Scan a payload against the given patterns. Pure — no db, no fs, no clock.
 * Duplicate (patternId, span) hits collapse; the result list is severity-
 * ordered and capped at MAX_MATCHES entries.
 */
export function scanPayload(input: ScanPayloadInput): ScanResult {
  const warnings: string[] = [];
  const text = typeof input.text === "string" ? input.text : "";
  const lowered = text.toLowerCase();
  const matches: DlpMatch[] = [];
  const seen = new Set<string>();

  const keywordPatterns = input.patterns.filter((p) => p.kind === "keyword");
  const regexPatterns = input.patterns.filter((p) => p.kind !== "keyword"); // kind column defaults to regex

  if (keywordPatterns.length > 0 && text.length > 0) {
    const { automaton, owners } = buildKeywordAutomaton(keywordPatterns);
    for (const hit of scanAutomaton(automaton, lowered)) {
      const owner = owners[hit.termIdx];
      if (!owner) continue;
      const key = `k:${owner.patternId}:${hit.start}:${hit.end}`;
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push({
        patternId: owner.patternId,
        severity: owner.severity,
        category: owner.category,
        excerpt: redactExcerpt(text, hit.start, hit.end),
        index: hit.start,
        end: hit.end,
        kind: "keyword",
      });
    }
  }

  const regexMatchers = buildRegexMatchers(regexPatterns, warnings);
  for (const m of regexMatchers) {
    if (matches.length >= MAX_MATCHES) break;
    m.re.lastIndex = 0;
    let guard = 0;
    let res: RegExpExecArray | null;
    while ((res = m.re.exec(text)) !== null && guard++ < MAX_MATCHES) {
      const start = res.index;
      const len = res[0].length;
      if (len === 0) {
        // zero-width match — advance one char to keep the global scan moving
        m.re.lastIndex += 1;
        if (m.re.lastIndex > text.length) break;
        continue;
      }
      const end = start + len;
      const key = `r:${m.patternId}:${start}:${end}`;
      if (!seen.has(key)) {
        seen.add(key);
        matches.push({
          patternId: m.patternId,
          severity: m.severity,
          category: m.category,
          excerpt: redactExcerpt(text, start, end),
          index: start,
          end,
          kind: "regex",
        });
      }
    }
  }

  matches.sort(bySeverityDesc);
  return {
    matches: matches.slice(0, MAX_MATCHES),
    severity: maxSeverity(matches.map((m) => m.severity)),
    warnings,
    fileExtension: input.fileExtension?.trim() || null,
  };
}

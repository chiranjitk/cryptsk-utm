/**
 * WAF simulated OWASP CRS engine (M17 §2.4.4) — SANDBOX ONLY. A real
 * appliance evaluates ModSecurity/Coraza rules; here ~12 representative CRS
 * rules are pattern-matched against the request (url + payload,
 * case-insensitive), scored like the CRS anomaly-scoring mode and compared
 * against the policy's in-threshold. Geo-block and rate-limit behaviours are
 * simulated: geo via a payload sentinel `country=XX`, rate limit via an
 * in-memory 60s sliding window per policy.
 */

export type CrsCategory = "sqli" | "xss" | "lfi" | "rfi" | "rce" | "scanner" | "protocol";

export interface CrsRule {
  id: number;
  msg: string;
  category: CrsCategory;
  score: number;
  pattern: RegExp;
  /** Where the pattern applies — defaults to payload + url ("any"). */
  target?: "any" | "url" | "payload";
  /** Extra precondition (e.g. 920420 fires on parameter-less POST bodies). */
  when?: (req: CrsRequest) => boolean;
}

export interface CrsRequest {
  method: string;
  url: string;
  payload: string;
}

export interface CrsMatch {
  id: number;
  msg: string;
  category: CrsCategory;
  score: number;
}

// ── sample rule set (12 representative CRS rules) ───────────────────────────

export const CRS_RULES: readonly CrsRule[] = [
  {
    id: 942100,
    msg: "SQL Injection Attack Detected via libinjection (' OR 1=1)",
    category: "sqli",
    score: 5,
    pattern: /(?:'|%27)\s*(?:or|and)\s+1\s*=\s*1/i,
  },
  {
    id: 942140,
    msg: "SQL Injection Attack: UNION SELECT / information_schema probing",
    category: "sqli",
    score: 5,
    pattern: /\bunion[\s+]+(?:all[\s+]+)?select\b|\binformation_schema\b/i,
  },
  {
    id: 941100,
    msg: "XSS Attack Detected via libinjection (<script> tags, javascript: URIs)",
    category: "xss",
    score: 5,
    pattern: /<script\b|javascript\s*:/i,
  },
  {
    id: 941160,
    msg: "XSS Filter - Category 5: Disallowed HTML Attributes (onerror=, onload=)",
    category: "xss",
    score: 5,
    pattern: /<\s*(?:img|svg|iframe|body|input)\b[^>]*\bon\w+\s*=|\bon(?:error|load|click|mouseover)\s*=|document\.cookie/i,
  },
  {
    id: 930100,
    msg: "Path Traversal Attack (/../) Detected",
    category: "lfi",
    score: 5,
    pattern: /(?:\.\.[\\/]|%2e%2e(?:%2f|%5c|\/|\\))/i,
  },
  {
    id: 930120,
    msg: "OS File Access Attempt (/etc/passwd and friends)",
    category: "lfi",
    score: 5,
    pattern: /\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/environ|boot\.ini/i,
  },
  {
    id: 931100,
    msg: "Remote File Inclusion (RFI) Attack Detected (parameterised URL fetch)",
    category: "rfi",
    score: 5,
    pattern: /=\s*(?:https?|ftp):\/\/[^\s&]+/i,
  },
  {
    id: 932100,
    msg: "Unix Command Injection Detected (; cat /etc/passwd)",
    category: "rce",
    score: 5,
    pattern: /;\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh)\b|\|\s*(?:cat|id|whoami|nc)\b/i,
  },
  {
    id: 932150,
    msg: "Unix Shell Execution Injection ($( ), backticks, <?php)",
    category: "rce",
    score: 5,
    pattern: /\$\(\s*\w+[^)]*\)|`[^`]{2,}`|<\?php\b/i,
  },
  {
    id: 913100,
    msg: "Found User-Agent associated with security scanner (sqlmap, nikto, …)",
    category: "scanner",
    score: 5,
    pattern: /sqlmap|nikto|nmap|masscan|dirbuster|acunetix|nessus|wpscan/i,
  },
  {
    id: 920420,
    msg: "Request Missing a Content-Type Header (parameter-less POST body)",
    category: "protocol",
    score: 2,
    pattern: /[\s\S]*/, // any payload — real check is the `when` precondition
    target: "payload",
    when: (req) => bodyWithoutParams(req),
  },
  {
    id: 920440,
    msg: "URL File Extension is Restricted (.env/.bak/.conf/…)",
    category: "protocol",
    score: 3,
    pattern: /\.(?:env|bak|conf|ini|sql|old|log|git)(?:[?#]|$)/i,
    target: "url",
  },
] as const;

/** 920420 sandbox stand-in for a missing Content-Type header: the method
 *  carries a body whose payload declares neither k=v params nor JSON. */
function bodyWithoutParams(req: CrsRequest): boolean {
  if (req.method !== "POST" && req.method !== "PUT") return false;
  const p = req.payload.trim();
  return p.length > 0 && !p.includes("=") && !p.startsWith("{") && !p.startsWith("[");
}

// ── evaluation ──────────────────────────────────────────────────────────────

export interface PolicyEvalConfig {
  owaspCrsEnabled: boolean;
  paranoiaLevel: number;
  anomalyInThreshold: number;
  anomalyOutThreshold: number;
  learningMode: boolean;
  geoBlockCountries: string[];
  rateLimitRpm: number | null;
  rateLimitBurst: number | null;
  enabled: boolean;
}

export type BlockReason = "anomaly" | "geo" | "rate_limit";

export interface CrsEvalResult {
  action: "pass" | "log" | "block";
  reason: BlockReason | null;
  anomalyScore: number;
  threshold: number;
  matched: CrsMatch[];
  /** Short human explanation persisted on the summary WafLog row. */
  summary: string;
}

/** Simulated CRS anomaly-scoring evaluation. `policyId` feeds the rate-limit
 *  window; pass a non-positive id to skip rate-limit accounting. */
export function evaluateCrs(
  policy: PolicyEvalConfig,
  policyId: number,
  req: CrsRequest,
): CrsEvalResult {
  const matched: CrsMatch[] = [];

  if (policy.enabled && policy.owaspCrsEnabled) {
    for (const rule of CRS_RULES) {
      if (rule.when && !rule.when(req)) continue;
      const target = rule.target ?? "any";
      const haystack =
        target === "url" ? req.url : target === "payload" ? req.payload : `${req.payload}\n${req.url}`;
      if (rule.pattern.test(haystack)) {
        // PL ≥ 2 tightens protocol rules (+1) — sandbox PL-rule emulation
        const score = rule.category === "protocol" && policy.paranoiaLevel >= 2 ? rule.score + 1 : rule.score;
        matched.push({ id: rule.id, msg: rule.msg, category: rule.category, score });
      }
    }
  }

  const anomalyScore = matched.reduce((sum, m) => sum + m.score, 0);
  const threshold = policy.anomalyInThreshold;

  // ── geo-block simulation: payload sentinel `country=XX` against the list ──
  const geoHit = /country\s*=\s*([a-z]{2})/i.exec(req.payload)?.[1]?.toUpperCase() ?? null;
  const geoBlocked = geoHit !== null && policy.geoBlockCountries.includes(geoHit);

  // ── rate-limit simulation: >rpm invocations / 60s sliding window / policy ──
  const rateLimited =
    policy.rateLimitRpm !== null && policy.rateLimitRpm > 0 && isRateLimited(policyId, policy.rateLimitRpm);

  let action: CrsEvalResult["action"];
  let reason: BlockReason | null = null;
  if (geoBlocked) {
    action = "block";
    reason = "geo";
  } else if (rateLimited) {
    action = "block";
    reason = "rate_limit";
  } else if (anomalyScore >= threshold) {
    action = policy.learningMode ? "log" : "block"; // learning mode = log-only
    reason = "anomaly";
  } else if (anomalyScore > 0) {
    action = "log"; // CRS logs sub-threshold anomalies even without blocking
  } else {
    action = "pass";
  }

  const summary =
    reason === "geo"
      ? `geo-block hit (${geoHit} in [${policy.geoBlockCountries.join(",")}])`
      : reason === "rate_limit"
        ? `rate limit exceeded (>${policy.rateLimitRpm} rpm / 60s window)`
        : anomalyScore > 0
          ? `anomaly score ${anomalyScore} vs in-threshold ${threshold}`
          : "no rule matches";

  return { action, reason, anomalyScore, threshold, matched, summary };
}

// ── rate-limit simulation state (in-memory, resets on process reload) ───────

const RATE_WINDOW_MS = 60_000;
/** policyId → timestamps (ms) of test invocations inside the trailing window. */
const policyWindows = new Map<number, number[]>();

/** Records the invocation; returns true once the trailing-60s count exceeds `rpm`. */
export function isRateLimited(policyId: number, rpm: number): boolean {
  const now = Date.now();
  const stamps = (policyWindows.get(policyId) ?? []).filter((t) => now - t < RATE_WINDOW_MS);
  stamps.push(now);
  policyWindows.set(policyId, stamps);
  return stamps.length > Math.max(1, rpm);
}

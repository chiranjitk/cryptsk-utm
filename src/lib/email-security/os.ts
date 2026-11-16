/**
 * Email Security OS layer (M22 §2.8 — real appliance integration) — the PURE
 * core that bridges the console email config to the real Postfix + Rspamd
 * (+ ClamAV) stack on the Debian 13 appliance:
 *
 *   • renderMainCf          deterministic FULL-FILE /etc/postfix/main.cf
 *   • renderTransportMap    /etc/postfix/utm-transport (routing rules + gateways)
 *   • renderRspamd*         /etc/rspamd/local.d/*.conf + utm-attach.map
 *   • renderEmailFiles      the whole managed real estate + confHash
 *   • computeEmailDrift     console intent vs OS reality (hash + unit only)
 *   • buildEmailApplyPlan   step list (backup → stage → install → postmap →
 *                           validate → services → verify → state LAST)
 *   • emailStepGuarded      anchored whitelist — no other exec path
 *
 * MANAGED REAL ESTATE (full-file, keepalived/waf style — master.cf is NEVER
 * touched; the console only ever installs main.cf + utm-transport and the
 * rspamd local.d fragments below):
 *   /etc/postfix/main.cf                full file (backup-first)
 *   /etc/postfix/utm-transport          transport table (+ postmap → .db)
 *   /etc/rspamd/local.d/actions.conf    spam thresholds (add_header/reject)
 *   /etc/rspamd/local.d/phishing.conf   blockPhishing → action = reject
 *   /etc/rspamd/local.d/antivirus.conf  blockMalware → clamd 127.0.0.1:3310
 *   /etc/rspamd/local.d/spf.conf        spfVerify → enabled true/false
 *   /etc/rspamd/local.d/dkim.conf       dkimVerify → enabled true/false
 *   /etc/rspamd/local.d/dmarc.conf      dmarcPolicy → rspamd action
 *   /etc/rspamd/local.d/utm-attach.conf blocked-extension multimap
 *   /etc/rspamd/utm-attach.map          extension list (one per line)
 *
 * DETERMINISTIC POLICY MAPPINGS (documented in the rendered files too):
 *   message_size_limit = maxMessageSizeMb × 1024 × 1024
 *   actions.conf:  add_header = spamThreshold · reject = spamThreshold + 4
 *                  (rspamd 0–20 scale; the +4 margin keeps the add_header gate
 *                  strictly below reject — reject is never rendered below it)
 *   dmarc.conf:    none → no_action · quarantine → add_header · reject → reject
 *   tlsMode:       none → security_level none · starttls → may ·
 *                  wrapper → smtpd_tls_wrappermode=yes + security_level none
 *                  (wrapper performs the handshake itself; level stays none)
 *
 * HONEST LIMITATIONS (rendered as comments/warnings, not silently dropped):
 *   • listenPort ≠ 25 is NOT rendered — master.cf is a red line; the single
 *     smtpd listener from main.cf carries all gateways;
 *   • routing actions deliver/quarantine are NOT transport-mapped (deliver =
 *     postfix default handling, quarantine is a console-log verdict only);
 *   • quarantineRetentionDays is recorded in state.json only — the retention
 *     sweep is out of scope in v1;
 *   • milter_default_action = accept is fail-open BY DESIGN (a dead rspamd
 *     must not black-hole mail).
 *
 * This module is PURE (no exec/db/fs) — fs/exec/db live in os-service.ts.
 */

import { createHash } from "crypto";

// ── constants ───────────────────────────────────────────────────────────────

export const EMAIL_STATE_DIR = "/var/lib/console/email";
export const EMAIL_STATE_FILE = `${EMAIL_STATE_DIR}/state.json`;
/** backup-<ts>/ directories mirror the absolute managed path under them */
export const EMAIL_BACKUP_RE = /^backup-[\w.-]+$/;

export const POSTFIX_MAIN_CF = "/etc/postfix/main.cf";
export const POSTFIX_TRANSPORT = "/etc/postfix/utm-transport";
export const RSPAMD_LOCAL_D = "/etc/rspamd/local.d";
export const RSPAMD_ATTACH_MAP = "/etc/rspamd/utm-attach.map";

/** rspamd milter endpoint rendered into main.cf smtpd_milters. */
export const RSPAMD_MILTER = "inet:127.0.0.1:11332";
export const RSPAMD_MILTER_PORT = 11332;
/** rspamd web UI port — probed informationally, never enforced. */
export const RSPAMD_WEBUI_PORT = 11334;
export const SMTP_PORT = 25;
/** clamd scanner endpoint (antivirus.conf). */
export const CLAMD_SERVER = "127.0.0.1:3310";
export const CLAMD_PORT = 3310;

/** Port probe (informational): smtp listener + rspamd milter + rspamd webui. */
export const EMAIL_SS_PROBE = `ss -ltn '( sport = :25 or sport = :11332 or sport = :11334 )'`;

/** The complete console-owned managed real estate — install targets are pinned to this set. */
export const EMAIL_MANAGED_PATHS: readonly string[] = [
  POSTFIX_MAIN_CF,
  POSTFIX_TRANSPORT,
  `${RSPAMD_LOCAL_D}/actions.conf`,
  `${RSPAMD_LOCAL_D}/phishing.conf`,
  `${RSPAMD_LOCAL_D}/antivirus.conf`,
  `${RSPAMD_LOCAL_D}/spf.conf`,
  `${RSPAMD_LOCAL_D}/dkim.conf`,
  `${RSPAMD_LOCAL_D}/dmarc.conf`,
  `${RSPAMD_LOCAL_D}/utm-attach.conf`,
  RSPAMD_ATTACH_MAP,
];

/** Units the email module owns end-to-end (start/stop/verify). */
export const EMAIL_UNITS = ["postfix", "rspamd"] as const;

// ── shapes (resolved by os-service, consumed here purely) ──────────────────

export type GatewayModeOs = "proxy" | "relay";
export type TlsModeOs = "none" | "starttls" | "wrapper";
export type DmarcPolicyOs = "none" | "quarantine" | "reject";
export type RoutingActionOs = "deliver" | "relay" | "reject" | "quarantine";

export interface EmailGatewayOsShape {
  id: number;
  name: string;
  mode: GatewayModeOs;
  listenPort: number;
  relayDomains: string[];
  upstreamHost: string | null;
  tlsMode: TlsModeOs;
  enabled: boolean;
}

export interface EmailPolicyOsShape {
  spamThreshold: number;
  blockPhishing: boolean;
  blockMalware: boolean;
  scanArchives: boolean;
  maxMessageSizeMb: number;
  blockedExtensions: string[];
  spfVerify: boolean;
  dkimVerify: boolean;
  dmarcPolicy: DmarcPolicyOs;
  quarantineRetentionDays: number;
  enabled: boolean;
}

export interface EmailRuleOsShape {
  id: number;
  name: string;
  matchDomain: string;
  action: RoutingActionOs;
  targetHost: string | null;
  priority: number;
  enabled: boolean;
}

export interface EmailRenderInput {
  gateways: EmailGatewayOsShape[];
  policy: EmailPolicyOsShape;
  rules: EmailRuleOsShape[];
}

// ── hashing ─────────────────────────────────────────────────────────────────

/** Per-file hash — sha256, first 16 hex chars (state.json fileHashes value). */
export function emailHash(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

/** confHash — sha256[:16] over the CONCATENATED managed files, sorted by path. */
export function emailConfHash(contents: Array<{ path: string; content: string }>): string {
  const sorted = [...contents].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return createHash("sha256")
    .update(sorted.map((f) => f.content).join(""))
    .digest("hex")
    .slice(0, 16);
}

// ── sanitizers (defensive — the zod validators are the first line) ──────────

/** Domain/token safe for a bare postfix transport key or rspamd map line. */
export function safeEmailToken(v: string): string | null {
  const s = v.trim().toLowerCase();
  if (!s || s.length > 253) return null;
  return /^[\w.-]+$/.test(s) ? s : null;
}

/** Host safe for an smtp:[host] transport nexthop (no injection chars). */
export function safeTransportHost(v: string): string | null {
  const s = v.trim().toLowerCase();
  if (!s || s.length > 253) return null;
  return /^[a-z0-9._-]+$/.test(s) ? s : null;
}

/** matchDomain "@zip"/"@partner.com" → bare transport key ("zip"/"partner.com"). */
export function transportKeyFor(matchDomain: string): string | null {
  return safeEmailToken(matchDomain.replace(/^@/, ""));
}

/**
 * Hard red-line refusals — checked before ANY exec. A domain/host carrying
 * shell metacharacters would inject postfix transport or rspamd map syntax.
 * Returns null when nothing is refused.
 */
export function hardEmailRefusal(gateways: EmailGatewayOsShape[], rules: EmailRuleOsShape[]): string | null {
  for (const g of gateways) {
    if (!g.enabled) continue;
    for (const d of g.relayDomains) {
      if (!safeEmailToken(d)) {
        return `refused: gateway "${g.name}" (id ${g.id}) carries relay domain "${d}" that postfix cannot carry safely — fix the gateway first`;
      }
    }
    if (g.upstreamHost && !safeTransportHost(g.upstreamHost)) {
      return `refused: gateway "${g.name}" (id ${g.id}) has an upstreamHost that postfix cannot carry safely — fix the gateway first`;
    }
  }
  for (const r of rules) {
    if (!r.enabled) continue;
    if (!transportKeyFor(r.matchDomain)) {
      return `refused: routing rule "${r.name}" (id ${r.id}) matches a domain that postfix cannot carry safely — fix the rule first`;
    }
    if (r.action === "relay" && (!r.targetHost || !safeTransportHost(r.targetHost))) {
      return `refused: routing rule "${r.name}" (id ${r.id}) relays to a targetHost that postfix cannot carry safely — fix the rule first`;
    }
  }
  return null;
}

// ── renderers: postfix ──────────────────────────────────────────────────────

/** Dedupe + sort the relay domains of ENABLED gateways (deterministic order). */
export function collectRelayDomains(gateways: EmailGatewayOsShape[]): string[] {
  const seen = new Set<string>();
  for (const g of gateways) {
    if (!g.enabled) continue;
    for (const d of g.relayDomains) {
      const safe = safeEmailToken(d);
      if (safe) seen.add(safe);
    }
  }
  return [...seen].sort();
}

/**
 * smtpd_tls_security_level from tlsMode. wrapper renders wrappermode=yes and
 * keeps security_level none — the wrapper performs the TLS handshake at
 * connect, a security_level above none would double-gate the session.
 */
export function tlsSecurityLines(mode: TlsModeOs): string[] {
  switch (mode) {
    case "wrapper":
      return [
        "# tlsMode=wrapper — TLS wraps the connection from the start (implicit TLS);",
        "# security_level stays none because wrappermode performs the handshake itself.",
        "smtpd_tls_wrappermode = yes",
        "smtpd_tls_security_level = none",
      ];
    case "starttls":
      return ["# tlsMode=starttls — TLS offered via STARTTLS, plaintext allowed", "smtpd_tls_security_level = may"];
    case "none":
    default:
      return ["# tlsMode=none — TLS disabled in console policy", "smtpd_tls_security_level = none"];
  }
}

/** Full-file main.cf — deterministic, byte-stable for a given input. */
export function renderMainCf(
  policy: EmailPolicyOsShape,
  gateways: EmailGatewayOsShape[],
): { content: string; warnings: string[] } {
  const warnings: string[] = [];
  const enabled = gateways.filter((g) => g.enabled);
  const relayDomains = collectRelayDomains(gateways);

  const L: string[] = [];
  L.push("# Managed by the Cryptsk Console — email-security module (M22).");
  L.push("# FULL-FILE management: this file is overwritten on every console apply.");
  L.push("# The pre-apply original is backed up under /var/lib/console/email/backup-<ts>/.");
  L.push("# master.cf is NEVER touched by the console.");
  L.push("myhostname = utm-gateway");
  L.push("mydestination =");
  L.push("inet_interfaces = all");
  L.push("inet_protocols = ipv4");
  L.push(`message_size_limit = ${policy.maxMessageSizeMb * 1024 * 1024}`);
  L.push("smtpd_banner = $myhostname ESMTP");
  L.push("mynetworks = 127.0.0.0/8");
  L.push(`relay_domains = ${relayDomains.join(", ")}`);
  L.push("transport_maps = hash:/etc/postfix/utm-transport");
  L.push("# Rspamd milter — every message is scanned (spam/phishing/malware) pre-queue");
  L.push(`smtpd_milters = ${RSPAMD_MILTER}`);
  L.push("non_smtpd_milters = $smtpd_milters");
  L.push("# fail-open BY DESIGN: a dead rspamd must not black-hole mail");
  L.push("milter_default_action = accept");
  L.push(...tlsSecurityLines(enabled[0]?.tlsMode ?? "none"));
  L.push("smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination");
  const content = L.join("\n") + "\n";

  const tlsModes = new Set(enabled.map((g) => g.tlsMode));
  if (tlsModes.size > 1) {
    warnings.push(
      `gateways disagree on tlsMode (${[...tlsModes].join(", ")}) — main.cf renders the FIRST enabled gateway's mode (${enabled[0]?.tlsMode}); postfix has one global smtpd TLS policy`,
    );
  }
  const offPort = enabled.filter((g) => g.listenPort !== SMTP_PORT);
  if (offPort.length > 0) {
    warnings.push(
      `gateway(s) ${offPort.map((g) => `"${g.name}" (:${g.listenPort})`).join(", ")} listen on a non-25 port — master.cf is never touched by the console, so the single smtpd listener from main.cf (port ${SMTP_PORT}) carries all gateways`,
    );
  }
  if (!policy.enabled) {
    warnings.push("content policy is disabled in the console — values are still rendered; verdicts stay simulated-only until re-enabled");
  }
  return { content, warnings };
}

// ── transport map ───────────────────────────────────────────────────────────

export interface TransportEntry {
  domain: string;
  line: string;
  /** rule:<name> | gateway:<name> */
  source: string;
  kind: "relay" | "reject";
}

export interface RenderedTransport {
  content: string;
  entries: TransportEntry[];
  /** gateway ids whose relayDomains actually landed in the map */
  gatewayIds: number[];
  warnings: string[];
}

/**
 * /etc/postfix/utm-transport — routing rules first (explicit policy, priority
 * asc), then enabled gateways' relayDomains as defaults. First occurrence of a
 * domain wins; duplicates are warned. deliver/quarantine rules are rendered as
 * comment lines documenting the v1 limitation.
 */
export function renderTransportMap(
  gateways: EmailGatewayOsShape[],
  rules: EmailRuleOsShape[],
): RenderedTransport {
  const warnings: string[] = [];
  const entries: TransportEntry[] = [];
  const seen = new Set<string>();
  const gatewayIds = new Set<number>();

  const L: string[] = [];
  L.push("# Managed by the Cryptsk Console — email-security module (M22).");
  L.push(`# postmap'd to ${POSTFIX_TRANSPORT}.db on every console apply.`);
  L.push("# transport key → nexthop; routing rules first, gateway relay_domains after.");

  const activeRules = [...rules]
    .filter((r) => r.enabled)
    .sort((a, b) => a.priority - b.priority || a.id - b.id);
  for (const r of activeRules) {
    const key = transportKeyFor(r.matchDomain);
    if (!key) continue;
    if (r.action === "relay") {
      const host = r.targetHost ? safeTransportHost(r.targetHost) : null;
      if (!host) continue;
      if (seen.has(key)) {
        warnings.push(`routing rule "${r.name}" domain ${key} duplicates an earlier transport entry — first source wins`);
        continue;
      }
      seen.add(key);
      const line = `${key} smtp:[${host}]:${SMTP_PORT}`;
      entries.push({ domain: key, line, source: `rule:${r.name}`, kind: "relay" });
      L.push(line);
    } else if (r.action === "reject") {
      if (seen.has(key)) {
        warnings.push(`routing rule "${r.name}" domain ${key} duplicates an earlier transport entry — first source wins`);
        continue;
      }
      seen.add(key);
      const line = `${key} error:5.7.1 rejected by policy`;
      entries.push({ domain: key, line, source: `rule:${r.name}`, kind: "reject" });
      L.push(line);
    } else {
      // deliver | quarantine — honest limitation, kept as a comment
      L.push(`# rule "${r.name}" (${key}): action ${r.action} is NOT transport-mapped — v1 limitation:`);
      L.push(`#   deliver falls through to postfix's default handling, quarantine is a`);
      L.push(`#   console-log verdict only (no hold queue wired yet).`);
    }
  }

  for (const g of [...gateways].filter((x) => x.enabled).sort((a, b) => a.id - b.id)) {
    if (!g.upstreamHost) {
      if (g.relayDomains.length > 0) {
        warnings.push(
          `gateway "${g.name}" (${g.mode}) has relay domains but no upstreamHost — its domains are not transport-mapped`,
        );
      }
      continue;
    }
    const host = safeTransportHost(g.upstreamHost);
    if (!host) continue;
    let mapped = 0;
    for (const d of g.relayDomains) {
      const key = safeEmailToken(d);
      if (!key) continue;
      if (seen.has(key)) {
        warnings.push(`gateway "${g.name}" relay domain ${key} duplicates an earlier transport entry — first source wins`);
        continue;
      }
      seen.add(key);
      const line = `${key} smtp:[${host}]:${SMTP_PORT}`;
      entries.push({ domain: key, line, source: `gateway:${g.name}`, kind: "relay" });
      L.push(line);
      mapped += 1;
    }
    if (mapped > 0) gatewayIds.add(g.id);
  }

  if (entries.length === 0) {
    L.push("# (empty — no relay/reject routing rules and no gateway relay domains)");
  }
  return { content: L.join("\n") + "\n", entries, gatewayIds: [...gatewayIds].sort(), warnings };
}

// ── renderers: rspamd local.d fragments ─────────────────────────────────────

const RSPAMD_HEADER = "# Managed by the Cryptsk Console — email-security module (M22).";

/** Format a threshold without a trailing ".0" (6 → "6", 6.5 → "6.5"). */
function fmtScore(n: number): string {
  return String(Math.round(n * 100) / 100);
}

/**
 * actions.conf — deterministic console mapping (rspamd 0–20 score scale):
 *   add_header = spamThreshold · reject = spamThreshold + 4.
 */
export function renderRspamdActions(policy: EmailPolicyOsShape): string {
  const addHeader = policy.spamThreshold;
  const reject = policy.spamThreshold + 4;
  return [
    RSPAMD_HEADER,
    "# Console mapping (deterministic, rspamd 0–20 score scale):",
    "#   add_header = spamThreshold",
    "#   reject     = spamThreshold + 4  (margin above the add_header gate)",
    "# greylist and other actions keep their rspamd defaults.",
    `add_header = ${fmtScore(addHeader)};`,
    `reject = ${fmtScore(reject)};`,
    "",
  ].join("\n");
}

/** phishing.conf — blockPhishing=true forces reject on phishing symbols. */
export function renderRspamdPhishing(policy: EmailPolicyOsShape): string {
  if (!policy.blockPhishing) {
    return [
      RSPAMD_HEADER,
      "# blockPhishing=false — phishing symbols still fire, but no forced reject;",
      "# scores flow through the actions.conf thresholds instead.",
      "",
    ].join("\n");
  }
  return [
    RSPAMD_HEADER,
    "# blockPhishing=true — phishing detections are rejected outright.",
    "phishing {",
    "    action = reject;",
    "}",
    "",
  ].join("\n");
}

/** antivirus.conf — blockMalware=true points the clamd scanner at 3310. */
export function renderRspamdAntivirus(policy: EmailPolicyOsShape): string {
  if (!policy.blockMalware) {
    return [
      RSPAMD_HEADER,
      "# blockMalware=false — no clamd scanner configured by the console;",
      "# malware scanning is inactive (attachment extension blocking still applies).",
      "",
    ].join("\n");
  }
  return [
    RSPAMD_HEADER,
    "# blockMalware=true — ClamAV daemon on loopback (clamav-daemon unit).",
    policy.scanArchives
      ? "# scanArchives=true — clamd archive limits keep rspamd defaults (documented in console)."
      : "# scanArchives=false — archive payload scanning is not forced by the console.",
    "clamd {",
    `    servers = "${CLAMD_SERVER}";`,
    "}",
    "",
  ].join("\n");
}

function renderModuleEnabled(name: string, enabled: boolean, note: string): string {
  return [RSPAMD_HEADER, note, `${name} {`, `    enabled = ${enabled};`, "}", ""].join("\n");
}

export function renderRspamdSpf(policy: EmailPolicyOsShape): string {
  return renderModuleEnabled("spf", policy.spfVerify, `# spfVerify=${policy.spfVerify} — sender policy framework checks in rspamd.`);
}

export function renderRspamdDkim(policy: EmailPolicyOsShape): string {
  return renderModuleEnabled("dkim", policy.dkimVerify, `# dkimVerify=${policy.dkimVerify} — DKIM signature verification in rspamd.`);
}

/** dmarc.conf — console dmarcPolicy → rspamd action (none→no_action, quarantine→add_header, reject→reject). */
export function renderRspamdDmarc(policy: EmailPolicyOsShape): string {
  const action = policy.dmarcPolicy === "reject" ? "reject" : policy.dmarcPolicy === "quarantine" ? "add_header" : "no_action";
  return [
    RSPAMD_HEADER,
    `# console dmarcPolicy=${policy.dmarcPolicy} → rspamd action ${action}`,
    "# (quarantine maps to add_header: rspamd holds no quarantine queue;",
    "#  the console mail log is the quarantine surface in v1)",
    "dmarc {",
    `    action = ${action};`,
    "}",
    "",
  ].join("\n");
}

/** utm-attach.conf — blocked-extension multimap (reject + UTM_BLOCKED_EXT symbol). */
export function renderRspamdAttachConf(policy: EmailPolicyOsShape): string {
  const exts = policy.blockedExtensions;
  if (exts.length === 0) {
    return [
      RSPAMD_HEADER,
      "# blockedExtensions is empty — multimap rendered but matches nothing.",
      "",
    ].join("\n");
  }
  return [
    RSPAMD_HEADER,
    "# blocked attachment extensions (map below) → reject with UTM_BLOCKED_EXT.",
    "utm_attach {",
    '    type = "filename";',
    '    filter = "extension";',
    `    map = "${RSPAMD_ATTACH_MAP}";`,
    '    action = "reject";',
    '    symbol = "UTM_BLOCKED_EXT";',
    "}",
    "",
  ].join("\n");
}

/** utm-attach.map — one lowercase extension per line, sorted, deduped. */
export function renderRspamdAttachMap(policy: EmailPolicyOsShape): string {
  const exts = [...new Set(policy.blockedExtensions.map((e) => e.trim().toLowerCase()).filter((e) => /^[\w-]{1,10}$/.test(e)))].sort();
  return [
    "# Managed by the Cryptsk Console — blocked attachment extensions (one per line).",
    ...exts,
    "",
  ].join("\n");
}

// ── full managed real estate ────────────────────────────────────────────────

export type EmailFileKind = "postfix" | "rspamd";

export interface EmailFilePlan {
  path: string;
  content: string;
  /** stage path under EMAIL_STATE_DIR (installed via `install -m 0644`) */
  stage: string;
  kind: EmailFileKind;
}

export interface RenderedGateway {
  id: number;
  name: string;
  mode: GatewayModeOs;
  listenPort: number;
  relayDomains: string[];
  upstreamHost: string | null;
  tlsMode: TlsModeOs;
  enabled: boolean;
  /** sha256-16 of the gateway's rendered identity (status rows) */
  renderHash: string;
  /** transport lines this gateway contributed */
  transportLines: string[];
}

export interface RenderedEmail {
  files: EmailFilePlan[];
  entries: TransportEntry[];
  gateways: RenderedGateway[];
  rules: EmailRuleOsShape[];
  /** null when nothing is enabled (teardown — no files rendered) */
  confHash: string | null;
  fileHashes: Record<string, string>;
  warnings: string[];
  /** no enabled gateways → teardown plan (stop units), no files rendered */
  empty: boolean;
}

/** Render the complete managed real estate. Same input → byte-identical output. */
export function renderEmailFiles(input: EmailRenderInput): RenderedEmail {
  const warnings: string[] = [];
  const enabled = input.gateways.filter((g) => g.enabled);
  const empty = enabled.length === 0;

  if (empty) {
    for (const g of input.gateways.filter((g) => !g.enabled)) {
      warnings.push(`gateway "${g.name}" is disabled — postfix/rspamd will be STOPPED on apply (teardown)`);
    }
    return { files: [], entries: [], gateways: [], rules: input.rules, confHash: null, fileHashes: {}, warnings, empty: true };
  }

  const main = renderMainCf(input.policy, input.gateways);
  const transport = renderTransportMap(input.gateways, input.rules);
  warnings.push(...main.warnings, ...transport.warnings);
  warnings.push(
    `quarantine retention (${input.policy.quarantineRetentionDays} d) is recorded in state.json only — the retention sweep is out of scope in v1`,
  );

  const rspamdFiles: Array<[string, string]> = [
    [`${RSPAMD_LOCAL_D}/actions.conf`, renderRspamdActions(input.policy)],
    [`${RSPAMD_LOCAL_D}/phishing.conf`, renderRspamdPhishing(input.policy)],
    [`${RSPAMD_LOCAL_D}/antivirus.conf`, renderRspamdAntivirus(input.policy)],
    [`${RSPAMD_LOCAL_D}/spf.conf`, renderRspamdSpf(input.policy)],
    [`${RSPAMD_LOCAL_D}/dkim.conf`, renderRspamdDkim(input.policy)],
    [`${RSPAMD_LOCAL_D}/dmarc.conf`, renderRspamdDmarc(input.policy)],
    [`${RSPAMD_LOCAL_D}/utm-attach.conf`, renderRspamdAttachConf(input.policy)],
    [RSPAMD_ATTACH_MAP, renderRspamdAttachMap(input.policy)],
  ];

  const files: EmailFilePlan[] = [
    { path: POSTFIX_MAIN_CF, content: main.content, stage: `${EMAIL_STATE_DIR}/stage-main.cf`, kind: "postfix" },
    { path: POSTFIX_TRANSPORT, content: transport.content, stage: `${EMAIL_STATE_DIR}/stage-utm-transport`, kind: "postfix" },
    ...rspamdFiles.map(([p, content]) => ({
      path: p,
      content,
      stage: `${EMAIL_STATE_DIR}/stage-${p.split("/").pop()}`,
      kind: "rspamd" as EmailFileKind,
    })),
  ];

  const fileHashes: Record<string, string> = {};
  for (const f of files) fileHashes[f.path] = emailHash(f.content);

  const transportByGateway = new Map<number, string[]>();
  for (const e of transport.entries) {
    if (!e.source.startsWith("gateway:")) continue;
    const g = input.gateways.find((x) => x.name === e.source.slice("gateway:".length));
    if (g) transportByGateway.set(g.id, [...(transportByGateway.get(g.id) ?? []), e.line]);
  }
  const gateways: RenderedGateway[] = input.gateways.map((g) => ({
    ...g,
    renderHash: emailHash(
      JSON.stringify({
        id: g.id,
        mode: g.mode,
        listenPort: g.listenPort,
        relayDomains: g.relayDomains,
        upstreamHost: g.upstreamHost,
        tlsMode: g.tlsMode,
        enabled: g.enabled,
      }),
    ),
    transportLines: transportByGateway.get(g.id) ?? [],
  }));

  return {
    files,
    entries: transport.entries,
    gateways,
    rules: input.rules,
    confHash: emailConfHash(files.map((f) => ({ path: f.path, content: f.content }))),
    fileHashes,
    warnings,
    empty: false,
  };
}

// ── drift ───────────────────────────────────────────────────────────────────

export interface EmailDrift {
  /** null when the OS facts cannot decide (tools missing) */
  inSync: boolean | null;
  managedByConsole: boolean;
  driftReasons: string[];
}

export interface EmailDriftInput {
  enabledGatewayCount: number;
  renderedHash: string | null;
  /** sha256-16 over the managed files CURRENTLY on disk (null when none) */
  onDiskHash: string | null;
  /** last applied hash from state.json */
  stateHash: string | null;
  postfixActive: boolean | null;
  rspamdActive: boolean | null;
}

/**
 * inSync flips ONLY on (a) file hashes vs last applied state and (b) unit
 * states — ports are transient and informational, they never flip inSync.
 */
export function computeEmailDrift(input: EmailDriftInput): EmailDrift {
  const reasons: string[] = [];
  const managedByConsole = Boolean(input.stateHash && input.onDiskHash && input.stateHash === input.onDiskHash);

  if (input.enabledGatewayCount === 0) {
    if (input.postfixActive === true) reasons.push("postfix is active but no gateway is enabled — Apply stops the mail stack");
    if (input.rspamdActive === true) reasons.push("rspamd is active but no gateway is enabled — Apply stops the mail stack");
    const unknown = input.postfixActive == null || input.rspamdActive == null;
    return { inSync: reasons.length > 0 ? false : unknown ? null : true, managedByConsole, driftReasons: reasons };
  }

  if (input.onDiskHash == null) {
    reasons.push("managed files not deployed — apply to OS");
  } else if (!managedByConsole) {
    reasons.push("managed files changed outside the console (hash ≠ last applied)");
  } else if (input.stateHash !== input.renderedHash) {
    reasons.push("console config changed since last apply — apply to OS");
  }
  if (input.postfixActive !== true) reasons.push(`postfix unit is ${input.postfixActive === false ? "not active" : "unknown"} — expected active`);
  if (input.rspamdActive !== true) reasons.push(`rspamd unit is ${input.rspamdActive === false ? "not active" : "unknown"} — expected active`);

  return { inSync: reasons.length === 0, managedByConsole, driftReasons: reasons };
}

// ── apply plan ──────────────────────────────────────────────────────────────

export type EmailStepKind =
  | "dir"
  | "backup"
  | "stage"
  | "install"
  | "cleanup"
  | "postmap"
  | "validate"
  | "service"
  | "verify"
  | "probe"
  | "writefile";

export interface EmailPlanStep {
  step: string;
  /** "" for stage/verify-hash/writefile (fs ops resolved at exec time) */
  cmd: string;
  kind: EmailStepKind;
  /** probes — failure recorded, never aborts */
  optional?: boolean;
}

export interface EmailApplyPlan {
  mode: "plan" | "exec";
  steps: EmailPlanStep[];
  files: EmailFilePlan[];
  backupDir: string;
  /** null when empty (teardown) */
  confHash: string | null;
  fileHashes: Record<string, string>;
  gatewayIds: number[];
  stateContent: string;
  warnings: string[];
  empty: boolean;
  /** every non-fs step passed the whitelist */
  guarded: boolean;
  refused: string | null;
}

/**
 * Convergence plan (mirrors logs/qos ordering, task-specified sequence):
 *   backup → stage files → install → postmap → rspamadm configtest →
 *   postfix check → enable/restart rspamd → start/reload postfix →
 *   verify (units active + ports probe + re-hash) → state.json LAST.
 * Failure after install auto-restores backups + postmap + service restarts
 * (enforced by the executor in os-service.ts).
 * NO enabled gateway → stop postfix + rspamd (disable path) + warning.
 */
export function buildEmailApplyPlan(input: {
  gateways: EmailGatewayOsShape[];
  policy: EmailPolicyOsShape;
  rules: EmailRuleOsShape[];
  /** managed paths currently present on disk (drive the backup steps) */
  onDiskPaths: string[];
  postfixState: string | null;
  rspamdState: string | null;
  mode: "plan" | "exec";
  ts: string;
}): EmailApplyPlan {
  const { gateways, policy, rules, onDiskPaths, postfixState, rspamdState, mode, ts } = input;

  // refusal surfaces separately — nothing is executed when it fires
  const refused = hardEmailRefusal(gateways, rules);
  const rendered = renderEmailFiles({ gateways, policy, rules });
  const backupDir = `${EMAIL_STATE_DIR}/backup-${ts}`;

  const steps: EmailPlanStep[] = [{ step: "state dir", cmd: `mkdir -p ${EMAIL_STATE_DIR}`, kind: "dir" }];

  if (!rendered.empty) {
    // 1) backup every managed file present on disk (pre-apply state)
    const present = new Set(onDiskPaths);
    for (const p of EMAIL_MANAGED_PATHS) {
      if (present.has(p)) {
        steps.push({ step: `backup ${p.split("/").pop()}`, cmd: `cp ${p} ${backupDir}${p}`, kind: "backup" });
      }
    }
    // 2) stage rendered files (fs) + 3) install into the managed paths
    for (const f of rendered.files) {
      steps.push({ step: `stage ${f.path.split("/").pop()}`, cmd: "", kind: "stage" });
    }
    for (const f of rendered.files) {
      steps.push({ step: `install ${f.path.split("/").pop()}`, cmd: `install -m 0644 ${f.stage} ${f.path}`, kind: "install" });
    }
    steps.push({
      step: "cleanup stage files",
      cmd: `rm -f ${rendered.files.map((f) => f.stage).join(" ")}`,
      kind: "cleanup",
    });
    // 4) transport db + 5) validation AFTER install (validate the live tree)
    steps.push({ step: "postmap transport", cmd: `postmap ${POSTFIX_TRANSPORT}`, kind: "postmap" });
    steps.push({ step: "rspamadm configtest", cmd: "rspamadm configtest", kind: "validate" });
    steps.push({ step: "postfix check", cmd: "postfix check", kind: "validate" });
    // 6) services: rspamd first (the milter must be up before postfix queues through it)
    steps.push({
      step: rspamdState === "active" ? "restart rspamd" : "enable rspamd",
      cmd: rspamdState === "active" ? "systemctl restart rspamd" : "systemctl enable --now rspamd",
      kind: "service",
    });
    steps.push({
      step: postfixState === "active" ? "reload postfix" : "start postfix",
      cmd: postfixState === "active" ? "systemctl reload postfix" : "systemctl start postfix",
      kind: "service",
    });
    // 7) verify
    steps.push({ step: "verify rspamd unit", cmd: "systemctl is-active rspamd", kind: "verify" });
    steps.push({ step: "verify postfix unit", cmd: "systemctl is-active postfix", kind: "verify" });
    steps.push({ step: "probe listeners", cmd: EMAIL_SS_PROBE, kind: "probe", optional: true });
    steps.push({ step: "verify managed file hashes", cmd: "", kind: "verify" });
  } else {
    // teardown: no gateways → stop the mail stack (disable), no files rendered
    steps.push({ step: "stop postfix", cmd: "systemctl stop postfix", kind: "service" });
    steps.push({ step: "stop rspamd", cmd: "systemctl stop rspamd", kind: "service" });
    steps.push({ step: "probe listeners", cmd: EMAIL_SS_PROBE, kind: "probe", optional: true });
  }

  // state.json is the LAST step — only written when every verify passed
  steps.push({ step: "save state file", cmd: "", kind: "writefile" });

  const appliedAt = new Date().toISOString();
  const enabledIds = rendered.gateways.filter((g) => g.enabled).map((g) => g.id);
  const stateContent = JSON.stringify(
    {
      confHash: rendered.confHash,
      fileHashes: rendered.fileHashes,
      gatewayIds: enabledIds,
      appliedAt,
      ...(rendered.empty ? { stopped: true } : {}),
    },
    null,
    2,
  );

  return {
    mode,
    steps,
    files: rendered.files,
    backupDir,
    confHash: rendered.confHash,
    fileHashes: rendered.fileHashes,
    gatewayIds: enabledIds,
    stateContent,
    warnings: rendered.warnings,
    empty: rendered.empty,
    guarded: steps.every((s) => s.cmd === "" || emailStepGuarded(s.cmd)),
    refused,
  };
}

// ── command whitelist ───────────────────────────────────────────────────────

/**
 * EXACT/anchored whitelist — anything else (pipes, `;`, `&&`, other units,
 * master.cf, reboots) fails. fs ops (stage/verify-hash/writefile/restore) are
 * pinned to EMAIL_STATE_DIR + EMAIL_MANAGED_PATHS in code, not shell.
 */
export function emailStepGuarded(cmd: string): boolean {
  const c = cmd.trim();
  if (!c) return false;
  if (c === `mkdir -p ${EMAIL_STATE_DIR}`) return true;
  if (c === `postmap ${POSTFIX_TRANSPORT}`) return true;
  if (c === "postfix check") return true;
  if (c === "rspamadm configtest") return true;
  if (c === EMAIL_SS_PROBE) return true;
  // service lifecycle — rspamd/postfix only, start|stop|restart|reload|enable/disable
  if (/^systemctl (enable --now|disable --now|start|restart|reload|stop) (rspamd|postfix)$/.test(c)) return true;
  if (/^systemctl is-active (rspamd|postfix)$/.test(c)) return true;
  // install: stage file under EMAIL_STATE_DIR → a managed path (never master.cf)
  const inst = /^install -m 0644 (\S+) (\S+)$/.exec(c);
  if (inst) {
    const [, src, dst] = inst;
    return src.startsWith(`${EMAIL_STATE_DIR}/stage-`) && EMAIL_MANAGED_PATHS.includes(dst);
  }
  // backup cp: managed path → backupDir + the SAME absolute path
  const cp = /^cp (\S+) (\S+)$/.exec(c);
  if (cp) {
    const [, src, dst] = cp;
    return (
      EMAIL_MANAGED_PATHS.includes(src) &&
      dst.startsWith(`${EMAIL_STATE_DIR}/backup-`) &&
      dst.endsWith(src) &&
      !dst.includes("..")
    );
  }
  // stage cleanup
  if (/^rm -f \/var\/lib\/console\/email\/stage-[\w.-]+( \/var\/lib\/console\/email\/stage-[\w.-]+)*$/.test(c)) return true;
  return false;
}

/** Runtime check: backup dirs live in EMAIL_STATE_DIR and match backup-<ts>. */
export function isEmailBackupDir(dir: string): boolean {
  if (!dir.startsWith(`${EMAIL_STATE_DIR}/`)) return false;
  if (dir.includes("..")) return false;
  return EMAIL_BACKUP_RE.test(dir.split("/").pop() ?? "");
}

// ── ss probe parsing (ground truth format from iproute2) ────────────────────

/**
 * Parse `ss -ltn` output for LISTEN ports. Returns one boolean per requested
 * port — informational only, never flips inSync.
 */
export function parseSsPorts(stdout: string, ports: number[]): Record<number, boolean> {
  const out: Record<number, boolean> = {};
  for (const p of ports) {
    const re = new RegExp(`:${p}(\\s|$)`, "m");
    out[p] = re.test(stdout);
  }
  return out;
}

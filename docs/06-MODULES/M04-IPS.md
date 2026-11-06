# M04 — IPS / IDS

> TL;DR: Suricata-style intrusion prevention: policy editor (mode, ET category matrix, custom rules, exceptions, thresholds) plus the live event explorer with suppression and a shortcut to firewall block rules. Views `#/ips/policies`, `#/ips/events`.

Related: [PROJECT_MEMORY](../00-PROJECT-MEMORY/PROJECT_MEMORY.md) (§6 enums, §7.2, §7.3) · [SCHEMA](../03-DATABASE/SCHEMA.md) (IpsPolicy/IpsEvent) · [ER_DIAGRAM](../03-DATABASE/ER_DIAGRAM.md) §2 (IpsPolicy RESTRICT) · [ENDPOINTS](../04-API/ENDPOINTS.md) · [UI_DESIGN_SYSTEM](../05-FRONTEND/UI_DESIGN_SYSTEM.md) · [PAGE_MAP](../05-FRONTEND/PAGE_MAP.md) · [SIMULATION_LAYER](../02-ARCHITECTURE/SIMULATION_LAYER.md) §3/§5/§6 (generator) · M03 (policy attach + block-rule creation) · M09 (IPS log view)

---

## 1. Purpose & Scope (Phase 1)

M04 gives the security admin detection control and visibility: IPS policies decide **how** traffic is inspected (inline blocking vs. detect-only) and **which** Emerging Threats-style categories are enabled; the events view turns the resulting `ips_events` stream into a triage workflow (filter → inspect → suppress or block at the firewall).

Derived from upstream spec §1.6 (IPS/IDS) Phase 1 table — **fully covered per the owner zero-loss ruling (REVIEW-4A)**:

| Upstream Phase 1 feature | Console Phase 1 decision |
|---|---|
| Modes inline_drop / inline_tap / passive, ET rule set, category enable/disable, exceptions (SID), bypass (source/dest), custom Suricata rules, threshold tuning, event suppression | IN — this spec |
| IPS Policy Profiles (conservative/balanced/aggressive presets) | IN — one-click presets via `POST /api/v1/ips/policies/apply-preset` (category bundle + mode per preset, DATA_PLANE §3.1); seeded `BALANCED` remains the default policy (restored REVIEW-4A) |
| Auto rule updates (suricata-update scheduling) | IN — `GET/PUT /api/v1/ips/update-settings` (enabled, interval daily/weekly, time, last/next run) rendered in the Rule Updates card on `#/ips/policies`; engine simulates the update cycle (restored REVIEW-4A) |
| Anomaly detection (preprocessors) | IN — `preprocessors` JSON toggles on the policy (`stream`/`http`/`tls`/`ssh`, default all on); deep stream-reassembly/decoding tuning stays Phase 2 per the spec's own cut list (restored REVIEW-4A) |
| Threat intelligence correlation (block known bad IPs from feeds) | IN — policy-level `tiBlocklist` toggle: feed-sourced bad IPs are dropped at IPS level (generator emits `category = "c2"`/`malware` drops for feed IPs). Full feed ingestion/IOC management is spec §2.11 Phase 2 — not a deferral, the spec's own phase assignment (restored REVIEW-4A) |
| Bypass rules (skip IPS for source/dest) | IN — `exceptions` `sid: 0` = any-SID capture-level bypass (ADR-017) |

**Appliance deployment note:** Suricata runs inline via nftables NFQUEUE — the generator emits a `queue num 1-4 fanout bypass` verdict on the forward chain for flows whose firewall rule attaches an IPS profile (DATA_PLANE §1). `inline_drop` enforces the drop verdict; `inline_tap` accepts but alerts (detect-only); `passive` runs as IDS on a mirror/SPAN tap via af-packet — never in the forwarding path. IDS vs IPS: only `inline_drop` blocks traffic; the other two modes are detect-only.

## 2. Data Model

Reference: [SCHEMA](../03-DATABASE/SCHEMA.md) §3/§4.

| Model | Fields used here | Notes |
|---|---|---|
| `IpsPolicy` | `name`, `mode` (`inline_drop\|inline_tap\|passive`, default `inline_drop`), `enabled`, `ruleCategories` JSON `{[category: string]: boolean}`, `customRules` JSON array of raw suricata rule strings, `exceptions` JSON `[{sid: number, source?: string, dest?: string, comment?: string}]`, `thresholds` JSON `[{sid: number, track: "by_src"\|"by_dst", count: number, seconds: number}]`, `preprocessors` JSON `{stream?, http?, tls?, ssh?}`, `tiBlocklist` boolean | unique `(tenantId, name)`; hard FK from `FirewallRule.ipsPolicyId` → delete **RESTRICT** (409 while attached) |
| `IpsEvent` | `timestamp`, `srcIp`, `srcPort`, `dstIp`, `dstPort`, `action` (`alert\|drop\|reject\|bypass\|suppressed`), `sid` (string, ET-style e.g. `2xxxxxx`), `severity` (`info\|low\|medium\|high\|critical`), `category` (e.g. `trojan`, `web_attack`, `scan`), `message`, `suppressedUntil?` | indexed `(tenantId, timestamp)` + `(tenantId, severity)`; no config FKs — `sid`/category are plain strings |
| `FirewallRule.ipsPolicyId` | attach point | managed in M03's RuleEditor; M04 only displays the attached-rule count |

Integrity: categories come from the server's category catalog (next section); `ruleCategories` keys not in the catalog are ignored by the generator. Events survive policy deletion by design (no FK, ER_DIAGRAM §2 note).

## 3. API Surface

| METHOD | Path | Purpose | Triggering UI action |
|---|---|---|---|
| GET | `/api/v1/ips/policies` | list policies (+ attached-rule count) | `#/ips/policies` load |
| POST | `/api/v1/ips/policies` | create policy | "New policy" dialog |
| PUT | `/api/v1/ips/policies/{id}` | update policy | policy editor save / enable toggle |
| DELETE | `/api/v1/ips/policies/{id}` | delete policy | row delete → `409 CONFLICT` when attached to rules |
| GET | `/api/v1/ips/rule-categories` | ET category list + enabled state | category matrix in editor |
| GET | `/api/v1/ips/events` | filtered event list | `#/ips/events` load + filter changes |
| POST | `/api/v1/ips/events/{id}/suppress` | `{duration: "24h"\|"7d"\|"forever"}` | row suppress menu |
| POST | `/api/v1/ips/policies/apply-preset` | `{preset: "conservative"\|"balanced"\|"aggressive", name?}` → create/replace a policy from the preset bundle | "Apply preset" dropdown → preset dialog |
| GET | `/api/v1/ips/update-settings` | auto-update scheduler config | "Rule Updates" card load |
| PUT | `/api/v1/ips/update-settings` | save scheduler (enabled, interval, time) | "Rule Updates" card save |

Query params on `GET /api/v1/ips/events` (locked set: `?severity=&sid=&q=&since=&until=&category=&page=`): severity chip value, exact `sid`, free-text `q` (matches `message`/ip fields), time range `since`/`until` ISO, `category` (see §8 mirroring note), `page`/`limit` pagination.

Expected error cases:

| Case | Result |
|---|---|
| Delete policy attached to ≥ 1 firewall rule | `409 CONFLICT` with referencing rule names (RESTRICT) |
| Duplicate policy name | `409 CONFLICT` |
| `customRules` failing loose syntax check | `400 VALIDATION_ERROR` with line numbers |
| `thresholds`/`exceptions` entry with missing/invalid `sid` | `400 VALIDATION_ERROR` |
| Suppress on nonexistent event | `404 NOT_FOUND` |
| Invalid `duration` value | `400 VALIDATION_ERROR` (enum: `24h`, `7d`, `forever`) |
| Unknown `preset` value | `400 VALIDATION_ERROR` (enum: `conservative`, `balanced`, `aggressive`) |
| `preprocessors` key outside `stream\|http\|tls\|ssh` | `400 VALIDATION_ERROR` |

## 4. Views & Interactions

### `#/ips/policies`

- **Policy list:** name, mode badge, enabled switch, "categories on: k/10", custom rules count, attached rules count (link → `#/firewall/rules?search=<policy name>`), actions (edit, duplicate, delete).
- **Preset dropdown ("Apply preset"):** Conservative / Balanced / Aggressive → preset dialog shows the category bundle + mode that will be applied (per DATA_PLANE §3.1) and either creates a new policy (name input, default preset name) or replaces the selected policy's category map + mode after confirm. Audited + `config:updated {section: "ips"}`.
- **Rule Updates card** (below the list): enabled switch, interval radio (`daily`/`weekly`), time input, `lastUpdateAt` / `nextUpdateAt` readouts, "Run update now" button (simulated: bumps `lastUpdateAt`, toast "ET rules updated"). Persists to the `ips/auto_update` SystemSetting.
- **Policy editor dialog:**
  - **Mode selector** with explanation panel (radio cards): `inline_drop` — inline, matching traffic is **dropped** (events carry `action = drop`); `inline_tap` — inline copy, detect-only (events `action = alert`); `passive` — off-path IDS on a mirror/span, detect-only (events `action = alert`). Panel states plainly: only `inline_drop` blocks traffic.
  - **Category matrix:** rows per category from `/ips/rule-categories` (~10, e.g. `malware`, `trojan`, `web_attack`, `scan`, `exploit`, `policy`, `dos`, `botnet` — exact list served by the endpoint), each with toggle + severity-distribution hint; master "all on/off" switch. State mirrors `ruleCategories` JSON.
  - **Custom rules** textarea: raw suricata rule syntax, one per line, loosely validated (non-empty, starts with a known action keyword, contains `sid:`); helper text; error list per line on save.
  - **Exceptions table:** sid (number; `0` = any-SID capture bypass, labeled "bypass (any SID)"), optional source/dest (ip or cidr), comment; add-row + remove; corresponds to threshold.config-style suppressions.
  - **Thresholds table:** sid, `track` (`by_src`/`by_dst`), `count`, `seconds`; helper text "alert at most `count` events per `seconds` per tracked host".
  - **Anomaly detection (preprocessors) section:** four switches — `stream` reassembly, `http` inspector, `tls` inspector, `ssh` inspector (default all on); caption "Suricata anomaly-detection engines applied for this policy; deep stream/decoding tuning is a Phase-2 item".
  - **Threat-intel blocklist switch:** `tiBlocklist` — "drop traffic to/from known-bad feed IPs (ET-compatible free feeds)"; when on, the generator emits feed-IP `drop` events (category `c2`/`malware`).
  - Enable switch mirrors `enabled`; save → PUT.
- Empty state: no policies → EmptyState + "New policy"; seed guarantees two (`BALANCED`, `STRICT_WEB`).

### `#/ips/events`

- **Filter bar:** severity chips (`critical`, `high`, `medium`, `low`, `info` — multi-select maps to `?severity=` calls or server list), category select (see §8 gap), time range presets (1 h / 24 h / 7 d → `since`/`until`), search input (`q`), sid search.
- **Table** (server-paginated): timestamp, severity badge (info=zinc, low=zinc, medium=amber, high=rose, critical=rose bold), category chip, sid (mono), action badge (`alert`=amber, `drop`/`reject`=rose-600, `bypass`=zinc, `suppressed`=muted), src → dst (ip:port), message (truncated).
- **Row actions:** Suppress menu (`24h` / `7d` / `forever`) → POST suppress → row re-renders with `action = suppressed` chip and `suppressedUntil` tooltip; "Block source" → opens M03 RuleEditor prefilled (see §5).
- **Detail side panel** (click row): full event fields, raw message, suppressed-until, related actions: Suppress, "Create firewall block rule" (prefills RuleEditor: name `IPS block sid <sid>`, srcAddr = new temp address object for `srcIp/32`, action `drop`, comment referencing the event id).
- Loading = table skeleton; empty = EmptyState ("No events match the current filters").

## 5. Business Logic & Validation

- **Mode semantics (simulated):** `inline_drop` → the `ips-events` generator emits rows with `action = drop` for enabled-category hits, and correlated `firewall_logs` rows with `action = drop` appear for the same flows (SIMULATION_LAYER §3 ips row + §6 contract); `inline_tap` and `passive` → events only (`action = alert`), no correlated drops. `passive` additionally labels traffic as mirror-sourced in the editor explainer.
- **Category gating:** generator only emits events for categories enabled in the **attached, enabled** policy for that flow's path; with no policy attached (rule without `ipsPolicyId`), the engine-level default policy (first enabled policy by seed order) applies in simulation — documented so tests are deterministic.
- **Severity mapping:** each category carries a base severity (e.g. `malware`/`trojan` → `high`/`critical`, `scan`/`policy` → `low`/`medium`); `dos` bursts escalate with rate. Exact mapping lives with the generator contract (SIMULATION_LAYER §6: sid ranges 2xxxxxx web, 20xxxxx malware, 21xxxxx scan…).
- **Exceptions evaluation:** event is not emitted (or downgraded to `bypass`) when `sid` matches and optional `source`/`dest` CIDR contains the flow endpoint — matching Suricata `suppress` (threshold.config) semantics. `sid: 0` entries render as nftables `skip queue` rules ahead of the queue rule (ADR-017).
- **TI blocklist:** when the attached policy has `tiBlocklist = true`, feed-sourced source IPs (a small built-in simulated feed list) produce `drop` events with category `c2`/`malware` plus correlated `firewall_logs` drops; appliance-side the feed sync populates an nftables set consumed before the queue rule.
- **Preprocessors:** toggles gate which anomaly inspectors the simulated engine "runs"; disabling `http`/`tls` suppresses their event families in the generator mix. Recorded config only (no real preprocessing, SIMULATION_LAYER §9).
- **Thresholds:** per `sid` + `track` key, at most `count` alerts per `seconds` window; further hits within the window are recorded with `action = suppressed` rather than dropped from existence (preserves forensic completeness).
- **Suppression action:** `POST /suppress` sets `suppressedUntil = now + duration` on the event (and marks `action = suppressed`); `forever` clears `suppressedUntil` to `null` with `action = "suppressed"` carrying the permanence — this convention is pinned in ENDPOINTS.md (§3 example). While suppressed, the generator tags repeat hits with `action = suppressed`.
- **Zod validation:** `mode`/`severity`/`action`/`track` from locked enums (PROJECT_MEMORY §6); `sid` positive int in exceptions/thresholds (string on events, ET ranges); `count` 1–10 000; `seconds` 1–86 400; custom rules loose-checked as above (real signature validation is explicitly out of simulation scope, SIMULATION_LAYER §9).
- **applyConfig("ips")** on every policy mutation: audit + `config_versions` snapshot (section `ips`) + `config:updated` broadcast; the generator picks up enabled categories/mode immediately.

## 6. Realtime

| Event | UI reaction |
|---|---|
| `logs:tail` | `kind = "ips"` entries prepend to `#/ips/events` table (and the detail panel live-region) **only when they pass the active filters**; capped in-memory buffer of 50 live rows on top of the paginated query |
| `config:updated` | `section = ips` → invalidate `ips-policies`, `ips-rule-categories` queries |
| `alerts:new` | `notification.type = "threat"` → unread badge bump; link target `#/ips/events?severity=critical` |

Subscribe `{ channels: ["logs", "alerts"] }` while either view is mounted.

## 7. Acceptance Criteria (checklist)

- Given the category endpoint returns ~10 categories, when the editor opens, then the matrix shows exactly those rows with persisted toggle states from `ruleCategories`.
- Given policy mode `inline_drop`, when a matching event is generated, then a correlated `firewall_logs` row with `action = drop` exists for the same flow (check `#/logs/firewall` within the same tick window).
- Given mode switched to `inline_tap` and saved, when new events arrive, then `action = alert` and no new correlated drop rows appear.
- Given category `scan` disabled, when the generator runs 20 ticks, then no new `scan` events appear in `#/ips/events`.
- Given an exception for `sid = 2010001, source = 10.0.0.0/24`, when a matching flow occurs, then no `alert` row is emitted for it (or it is labeled `bypass`).
- Given threshold `sid = 21xxxxx, track = by_src, count = 2, seconds = 60`, when 5 hits arrive from one source in 60 s, then exactly 2 are `alert` and the rest are `suppressed`.
- Given Suppress → `7d` on an event, when the request returns, then `suppressedUntil` is 7 days ahead and the row shows the suppressed chip.
- Given "Create firewall block rule" clicked in the detail panel, when RuleEditor opens, then name/action/src fields are prefilled from the event and saving lands in `#/firewall/rules` at the end position.
- Given "Apply preset → Aggressive" is chosen with name `AGGRESSIVE-DR`, when confirmed, then a policy with all categories on + `inline_drop` mode exists and the audit row names the preset.
- Given the Rule Updates card set to weekly 03:00, when saved, then `GET /ips/update-settings` echoes the schedule and `nextUpdateAt` is recomputed; "Run update now" bumps `lastUpdateAt`.
- Given `preprocessors.http = false` on the attached policy, when the generator runs, then no `web_attack` family events appear (inspector off).
- Given `tiBlocklist = true`, when the generator emits feed-IP traffic, then `drop` events with category `c2` appear and correlated firewall drops exist.
- Given a custom rule line missing `sid:`, when saving, then a per-line validation error blocks the save.
- Given policy `BALANCED` attached to 3 rules, when Delete is attempted, then `409 CONFLICT` lists the 3 rule names.
- Given filters severity=`critical` + 24 h, when loading, then the request carries `?severity=critical&since=<-24h>` and pagination meta is honored (server-side, no client filtering of pages).
- Given `config:updated {section: "ips"}`, when received on `#/ips/policies`, then the policy list refetches and any open editor shows a stale-data banner instead of silently overwriting.

## 8. Open Questions & Risks

- **IPS bypass vs exception (RESOLVED — ADR-017):** `sid: 0` in `exceptions` means "any SID" (SID-less capture-level bypass); the generator renders such entries as nftables `skip queue` rules ahead of the Suricata queue rule. SCHEMA.md §4 and ENDPOINTS.md are aligned; UI must label these "bypass (any SID)".
- **`?category=` mirroring (RESOLVED):** ENDPOINTS.md §5 now carries `?category=` on `/api/v1/ips/events` (matches PROJECT_MEMORY §7.2 locked param list).
- **`forever` sentinel (RESOLVED):** ENDPOINTS.md pins the convention — `duration: "forever"` → `suppressedUntil = null` + `action = "suppressed"`; §5 above matches.
- **Default-policy rule (RESOLVED — ADR-017):** traffic on rules without `ipsPolicyId` is evaluated by the first enabled policy by seed order (`id` ascending) — pinned in ENDPOINTS.md §5.
- ~~**Presets / auto-update / preprocessors / TI correlation deferred**~~ RESOLVED (REVIEW-4A): restored in this spec. TI stays policy-level blocklist only — feed ingestion/IOC management is spec §2.11 Phase 2 (the spec's own assignment, not a deferral).
- **Suppress vs. threshold interplay:** both produce `action = suppressed`; the events table cannot currently distinguish admin suppression from threshold rate-limiting (distinguishable only via `suppressedUntil` presence). Acceptable for Phase 1; revisit if analysts complain.
- Custom suricata rules are stored/echoed but never meaningfully evaluated — risk of user expectation mismatch; editor must carry the "loosely validated, signature logic simulated" disclaimer.

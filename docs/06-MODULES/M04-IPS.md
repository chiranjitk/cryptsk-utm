# M04 — IPS / IDS

> TL;DR: Suricata-style intrusion prevention: policy editor (mode, ET category matrix, custom rules, exceptions, thresholds) plus the live event explorer with suppression and a shortcut to firewall block rules. Views `#/ips/policies`, `#/ips/events`.

Related: [PROJECT_MEMORY](../00-PROJECT-MEMORY/PROJECT_MEMORY.md) (§6 enums, §7.2, §7.3) · [SCHEMA](../03-DATABASE/SCHEMA.md) (IpsPolicy/IpsEvent) · [ER_DIAGRAM](../03-DATABASE/ER_DIAGRAM.md) §2 (IpsPolicy RESTRICT) · [ENDPOINTS](../04-API/ENDPOINTS.md) · [UI_DESIGN_SYSTEM](../05-FRONTEND/UI_DESIGN_SYSTEM.md) · [PAGE_MAP](../05-FRONTEND/PAGE_MAP.md) · [SIMULATION_LAYER](../02-ARCHITECTURE/SIMULATION_LAYER.md) §3/§5/§6 (generator) · M03 (policy attach + block-rule creation) · M09 (IPS log view)

---

## 1. Purpose & Scope (Phase 1)

M04 gives the security admin detection control and visibility: IPS policies decide **how** traffic is inspected (inline blocking vs. detect-only) and **which** Emerging Threats-style categories are enabled; the events view turns the resulting `ips_events` stream into a triage workflow (filter → inspect → suppress or block at the firewall).

Derived from upstream spec §1.6 (IPS/IDS) Phase 1 table, **trimmed to console Phase 1**:

| Upstream Phase 1 feature | Console Phase 1 decision |
|---|---|
| Modes inline_drop / inline_tap / passive, ET rule set, category enable/disable, exceptions (SID), bypass (source/dest), custom Suricata rules, threshold tuning, event suppression | IN — this spec |
| IPS Policy Profiles (conservative/balanced/aggressive presets) | OUT as one-click presets; Phase 1 is manual category toggles (preset = a seeded policy, e.g. `BALANCED`). Deferred to [ROADMAP](../01-PRODUCT/ROADMAP.md) |
| Auto rule updates (suricata-update scheduling) | OUT of console Phase 1 (build decision, ROADMAP §5) — category set is static in Phase 1 (served by `/ips/rule-categories`); no update-scheduler UI |
| Anomaly detection (preprocessor tuning) | OUT — no preprocessor UI in Phase 1 |
| Threat intelligence correlation / feed sync | OUT — Phase 2 (`2.11 Threat Intelligence`) |
| Bypass rules (skip IPS for source/dest) | Partial — `exceptions` entries are SID-keyed (SCHEMA §4 requires `sid`), so they express "disable SID X for this traffic", not a SID-less capture-level bypass; appliance-side, true traffic bypass is an nftables "skip queue" rule. Flagged in §8 (spec §1.6 lists bypass rules as Phase 1) |

**Appliance deployment note:** Suricata runs inline via nftables NFQUEUE — the generator emits a `queue num 1-4 fanout bypass` verdict on the forward chain for flows whose firewall rule attaches an IPS profile (DATA_PLANE §1). `inline_drop` enforces the drop verdict; `inline_tap` accepts but alerts (detect-only); `passive` runs as IDS on a mirror/SPAN tap via af-packet — never in the forwarding path. IDS vs IPS: only `inline_drop` blocks traffic; the other two modes are detect-only.

## 2. Data Model

Reference: [SCHEMA](../03-DATABASE/SCHEMA.md) §3/§4.

| Model | Fields used here | Notes |
|---|---|---|
| `IpsPolicy` | `name`, `mode` (`inline_drop\|inline_tap\|passive`, default `inline_drop`), `enabled`, `ruleCategories` JSON `{[category: string]: boolean}`, `customRules` JSON array of raw suricata rule strings, `exceptions` JSON `[{sid: number, source?: string, dest?: string, comment?: string}]`, `thresholds` JSON `[{sid: number, track: "by_src"\|"by_dst", count: number, seconds: number}]` | unique `(tenantId, name)`; hard FK from `FirewallRule.ipsPolicyId` → delete **RESTRICT** (409 while attached) |
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

## 4. Views & Interactions

### `#/ips/policies`

- **Policy list:** name, mode badge, enabled switch, "categories on: k/10", custom rules count, attached rules count (link → `#/firewall/rules?search=<policy name>`), actions (edit, duplicate, delete).
- **Policy editor dialog:**
  - **Mode selector** with explanation panel (radio cards): `inline_drop` — inline, matching traffic is **dropped** (events carry `action = drop`); `inline_tap` — inline copy, detect-only (events `action = alert`); `passive` — off-path IDS on a mirror/span, detect-only (events `action = alert`). Panel states plainly: only `inline_drop` blocks traffic.
  - **Category matrix:** rows per category from `/ips/rule-categories` (~10, e.g. `malware`, `trojan`, `web_attack`, `scan`, `exploit`, `policy`, `dos`, `botnet` — exact list served by the endpoint), each with toggle + severity-distribution hint; master "all on/off" switch. State mirrors `ruleCategories` JSON.
  - **Custom rules** textarea: raw suricata rule syntax, one per line, loosely validated (non-empty, starts with a known action keyword, contains `sid:`); helper text; error list per line on save.
  - **Exceptions table:** sid (number), optional source/dest (ip or cidr), comment; add-row + remove; corresponds to threshold.config-style suppressions.
  - **Thresholds table:** sid, `track` (`by_src`/`by_dst`), `count`, `seconds`; helper text "alert at most `count` events per `seconds` per tracked host".
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
- **Exceptions evaluation:** event is not emitted (or downgraded to `bypass`) when `sid` matches and optional `source`/`dest` CIDR contains the flow endpoint — matching Suricata `suppress` (threshold.config) semantics. Capture-level bypass (skip inspection for a flow regardless of SID) is not expressible with the SID-keyed shape — see §8.
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
- Given a custom rule line missing `sid:`, when saving, then a per-line validation error blocks the save.
- Given policy `BALANCED` attached to 3 rules, when Delete is attempted, then `409 CONFLICT` lists the 3 rule names.
- Given filters severity=`critical` + 24 h, when loading, then the request carries `?severity=critical&since=<-24h>` and pagination meta is honored (server-side, no client filtering of pages).
- Given `config:updated {section: "ips"}`, when received on `#/ips/policies`, then the policy list refetches and any open editor shows a stale-data banner instead of silently overwriting.

## 8. Open Questions & Risks

- **IPS bypass vs exception (RESOLVED — ADR-017):** `sid: 0` in `exceptions` means "any SID" (SID-less capture-level bypass); the generator renders such entries as nftables `skip queue` rules ahead of the Suricata queue rule. SCHEMA.md §4 and ENDPOINTS.md are aligned; UI must label these "bypass (any SID)".
- **`?category=` mirroring (RESOLVED):** ENDPOINTS.md §5 now carries `?category=` on `/api/v1/ips/events` (matches PROJECT_MEMORY §7.2 locked param list).
- **`forever` sentinel (RESOLVED):** ENDPOINTS.md pins the convention — `duration: "forever"` → `suppressedUntil = null` + `action = "suppressed"`; §5 above matches.
- **Default-policy rule (RESOLVED — ADR-017):** traffic on rules without `ipsPolicyId` is evaluated by the first enabled policy by seed order (`id` ascending) — pinned in ENDPOINTS.md §5.
- **Suppress vs. threshold interplay:** both produce `action = suppressed`; the events table cannot currently distinguish admin suppression from threshold rate-limiting (distinguishable only via `suppressedUntil` presence). Acceptable for Phase 1; revisit if analysts complain.
- Custom suricata rules are stored/echoed but never meaningfully evaluated — risk of user expectation mismatch; editor must carry the "loosely validated, signature logic simulated" disclaimer.

# M09 — Logging & Reporting

> TL;DR: Searchable firewall/IPS/audit log views with server-side pagination, a realtime live
> tail over the socket, and aggregate traffic/threat reports from `/logs/stats`. Retention is
> capped by the lifecycle job; scheduled PDF reports are explicitly out of Phase 1.

Related: ../00-PROJECT-MEMORY/PROJECT_MEMORY.md (§7.2 API, §7.3 realtime, §8 views, §9 tokens) ·
../03-DATABASE/SCHEMA.md (FirewallLog, IpsEvent, AuditLog) · ../03-DATABASE/DATA_LIFECYCLE.md §4 (retention) ·
../02-ARCHITECTURE/SIMULATION_LAYER.md (generators) · ../04-API/ENDPOINTS.md · ../04-API/API_STANDARDS.md ·
../05-FRONTEND/UI_DESIGN_SYSTEM.md · ../05-FRONTEND/PAGE_MAP.md · ../05-FRONTEND/STATE_AND_DATA_FLOW.md ·
../01-PRODUCT/ROADMAP.md · siblings: M04-IPS.md (suppress endpoint), M10-SYSTEM.md (notifications center), M03-FIREWALL.md (rule names)

---

## 1. Purpose & Scope (Phase 1)

This module is the console's window into what happened: filterable firewall flow logs, IPS
events, an append-only audit trail of admin actions, a realtime live tail, and basic traffic/
threat reports built on aggregate queries. It consumes the MockEngine-generated log streams
(SIMULATION_LAYER §4/§6) and the retention job's guarantees (DATA_LIFECYCLE §4).

**In scope (Phase 1):**

| Area | Contents |
|---|---|
| Firewall logs | Filtered, server-paginated table; row detail drawer with full fields; CSV export of the current filter |
| IPS logs | Severity/category filters; suppressed badge; links to M04 suppress flow |
| Audit log | Actor, `object.verb` action, object type/id/name, result, before/after JSON in a detail drawer |
| Live tail | `#/logs/live` over the `logs:tail` socket event; kind filter, pause/resume, autoscroll, 500-row in-memory buffer, severity coloring |
| Reports | `#/logs/reports`: range picker 1h/24h/7d; cards + charts from `/logs/stats` (traffic trend, top apps, top talkers, threat mix, action mix); print-friendly layout |

**Out of scope (deferred — see ../01-PRODUCT/ROADMAP.md):** syslog forwarding and log
forwarding reliability buffers (upstream Ready, no Phase-1 endpoint; the seed's logging
`syslog` toggle is display-only), NetFlow/IPFIX export targets, scheduled reports
(daily/weekly/monthly) and PDF/HTML report formats (Phase 1 is on-screen + browser print
only), full-text search backends (ClickHouse/Meilisearch), compliance/executive templates,
log integrity hash-chaining, anonymization, CEF/LEEF export — all on the upstream Phase-2
list. Editing IPS exceptions lives in M04; this module only renders event data.

---

## 2. Data Model

From ../03-DATABASE/SCHEMA.md §3 (append-heavy tables; no config FKs — `ruleName`/`appName`
are denormalized strings on purpose so rows survive rule deletion, SCHEMA §5).

| Model | Fields used here | Notes |
|---|---|---|
| `FirewallLog` | `timestamp`, `srcIp/srcPort`, `dstIp/dstPort`, `protocol` (`tcp\|udp\|icmp`), `action` (`allow\|deny\|drop\|reject`), `ruleName?`, `appName?` (nDPI label), `bytes`, `packets`, `userName?` | Index `(tenantId, timestamp)` + `srcIp`/`dstIp`; cap 50 000 rows (retention) |
| `IpsEvent` | `timestamp`, `srcIp/srcPort`, `dstIp/dstPort`, `action` (`alert\|drop\|reject\|bypass\|suppressed`), `sid?`, `severity` (`info\|low\|medium\|high\|critical`), `category?` (e.g. trojan, web_attack, scan, policy), `message?`, `suppressedUntil?` | Cap 5 000 rows; `suppressed` action/suppressedUntil render the suppressed badge |
| `AuditLog` | `createdAt`, `userId?`/`username?`, `sourceIp?`, `action` (e.g. `login`, `rule.create`, `iface.update`, `config.apply`), `objectType`, `objectId?`, `objectName?`, `beforeState?`/`afterState?` (JSON strings), `result` (`success\|failure\|denied`) | Append-only (ADR-011); cap 20 000 rows; never purged by `--reset` (DATA_LIFECYCLE §5) |

Growth expectations (ER_DIAGRAM §5): firewall_logs ~1–3 rows/tick, ips_events 0–1/tick —
hence server-side pagination everywhere; the client never receives unbounded arrays.

---

## 3. API Surface

Paths verbatim from PROJECT_MEMORY §7.2. Pagination `?page=&limit=&sort=-timestamp` →
`meta: { page, limit, total, totalPages }` (§7.1). Time filters take ISO datetimes.

| METHOD | Path | Purpose | Triggering UI action |
|---|---|---|---|
| GET | `/api/v1/logs/firewall` | Firewall log page; filters `?q=&action=&src=&dst=&since=&until=&page=` | Open `#/logs/firewall`, change any filter, paginate |
| GET | `/api/v1/logs/ips` | IPS event page; filters `?severity=&category=&page=` (+ `?q=`, `?since=`, `?until=` standard filters) | Open `#/logs/ips`, filter chips |
| GET | `/api/v1/logs/audit` | Audit page; filters `?user=&objectType=&page=` (+ `?q=`, `?since=`, `?until=`, `?result=`) | Open `#/logs/audit`, filter |
| GET | `/api/v1/logs/stats` | Aggregates for reports; `?range=1h\|24h\|7d` | Open `#/logs/reports`, change range |
| GET | `/api/v1/logs/firewall/export` | CSV of the current filter (same params as `/logs/firewall`, no `page`) | "Export CSV" button on `#/logs/firewall` |
| POST | `/api/v1/ips/events/{id}/suppress` | *(owned by M04)* Body `{ duration: "24h"\|"7d"\|"forever" }` | "Suppress" action on an IPS row in `#/logs/ips` (reuses M04 endpoint; do not duplicate) |

The export endpoint is part of the locked surface (PROJECT_MEMORY §7.2 + ENDPOINTS.md §11);
it streams `text/csv` of the matching rows capped at 10 000 (most recent first; response
header `X-Row-Cap` reports the cap). IPS export intentionally does **not** ship in Phase 1.
**Expected error cases:** `VALIDATION_ERROR` 400 (bad ISO dates, unknown `action`/`severity`
enum value, `until < since`); `RATE_LIMITED` 429 if export is hammered (export counts
against the standard limit, ../04-API/API_STANDARDS.md); `UNAUTHORIZED` 401. Log endpoints
are read-only — no other mutations exist on these tables.

---

## 4. Views & Interactions

Five hash views (LOCKED §8). All tables use the shared `DataTable` (@tanstack/react-table)
with **server-side pagination** (PROJECT_MEMORY §13 gotcha: never load 5k rows client-side);
states per ../05-FRONTEND/UI_DESIGN_SYSTEM.md (skeletons, EmptyState, error + Retry).

### `#/logs/firewall`

- **Filter bar:** free-text `q` (matches src/dst/user/rule/app), action Select
  (`allow|deny|drop|reject`), src and dst IP inputs, since/until datetime pickers, "Export
  CSV" button (exports the *current* filter via `GET /api/v1/logs/firewall/export`, §3),
  active-filter count chip.
- **Table columns:** timestamp (sortable, default `sort=-timestamp`), src `ip:port`, dst
  `ip:port`, protocol badge, action badge — `allow` emerald, `deny`/`drop` rose-600,
  `reject` orange-500 (UI_DESIGN_SYSTEM §2.3) — appName, ruleName, bytes (humanized), user.
  Row click → **detail drawer** with every field incl. ports, packets, userName, and the raw id.
- **States:** EmptyState ("No flows match this filter"); loading skeleton rows; error card.
  A subtle banner shows retention: "Rolling 50 000-row window (DATA_LIFECYCLE §4)".

### `#/logs/ips`

- **Filter bar:** severity multi-chips (5 enum values), category Select (distinct categories
  observed — from the category list the generator emits), `q`, since/until.
- **Table:** timestamp, severity badge (color map §5.4), action badge (`suppressed` renders
  zinc "suppressed" badge; `drop` rose; `alert` amber), sid (mono), category, message, src →
  dst. Row detail drawer shows all fields incl. `suppressedUntil` when present.
- **Row action:** "Suppress" → M04's suppress dialog (duration 24h/7d/forever) — the endpoint
  belongs to M04; this view only reuses it. Suppressed rows show the badge and, until
  `suppressedUntil`, still appear in listings.

### `#/logs/audit`

- **Filter bar:** user Select (users list), objectType Select (distinct types), result chips
  (`success|failure|denied`), `q`, since/until.
- **Table:** timestamp, username (avatar-initials + fallback for deleted users), action
  rendered as `object.verb` chip (e.g. `firewall_rule.create`), objectType, objectName,
  result badge — `success` emerald, `failure` rose solid, `denied` rose outline — sourceIp.
- **Detail drawer:** full row; `beforeState`/`afterState` rendered side-by-side through
  `JsonFieldViewer` (monospace, collapsible, JSON-string columns parsed; masked fields stay
  masked because the API never wrote them in clear — see M07 §5.3 masking rule).

### `#/logs/live`

- **Controls:** kind filter chips (`firewall` / `ips` / both), Pause/Resume button,
  autoscroll toggle (default on), buffer counter ("N / 500"), Clear buffer.
- **Mechanics:** subscribes to the `logs:tail` socket event; each entry is prepended (newest
  top) into an **in-memory ring buffer capped at 500 rows** (client-side; independent of the
  engine's server-side buffers). Pause stops *rendering* (buffer keeps counting so the user
  sees how much was missed); Resume flush-renders. Autoscroll off freezes the viewport while
  new rows accumulate above.
- **Rendering:** single-line entries — timestamp (mono), kind chip, severity/action badge
  colored per §5.4, src → dst summary, app/sid, message tail. Firehose feels like ~1–3
  rows/s (SIMULATION_LAYER §4); virtualize the list if profiling shows jank.
- **States:** socket disconnected → amber "Live updates paused — reconnecting" banner
  (reconnect handled by the shared socket hook); buffer full → oldest rows silently dropped
  (counter shows 500 / 500).

### `#/logs/reports`

- **Range picker:** segmented control `1h | 24h | 7d` → `GET /api/v1/logs/stats?range=…`.
- **Cards row:** total flows (sum of action series), blocked % (`(deny+drop+reject) / total`),
  critical+high events (`ipsBySeverity`), peak bucket — each with a delta vs the previous
  equal-length window (computed client-side from a second stats call if needed).
- **Charts** (recharts via `components/charts/`, palette ADR-013 — emerald/teal/amber/rose/
  orange/violet/zinc, never indigo/blue), from the LOCKED `/logs/stats` payload
  (ENDPOINTS.md §11: `{ range, from, to, bucketMinutes, series: [{key, points: [{ts, count}]}],
  ipsBySeverity: [{key, count}] }`):
  - **Action trend** — stacked area of the per-action series (`allow`/`deny`/`drop`/`reject`)
    over the range's time buckets.
  - **Action mix** — donut of total counts per action across the window.
  - **Threat mix** — donut/bar of `ipsBySeverity` counts.
  - Top apps / top talkers over a range are **not** in the locked `/logs/stats` payload — the
    dashboard's 24 h `topApps`/`topTalkers` (from `/dashboard/summary`) are the Phase-1 view of
    that data; extending `/logs/stats` is a Phase 2 expansion (see §8).
- **Print-friendly layout:** a "Print" button triggers `window.print()`; a print stylesheet
  (page CSS, not a route) collapses filter bars and sidebars, forces light theme and
  black-on-white tables. Marked as the Phase-1 substitute for scheduled PDFs.
- **States:** per-card skeleton; empty range → EmptyState per chart ("No events in this
  window") rather than zeroed axes.

---

## 5. Business Logic & Validation

### 5.1 Filtering & pagination contract
- All list views: every filter is part of the TanStack Query key (`[logs, 'firewall', filters]`)
  so cache invalidation is correct (PROJECT_MEMORY §13); `page` resets to 1 on any filter
  change; `limit` default 25, max 100.
- `since`/`until` are ISO-8601 UTC; the client converts from the user's locale via date-fns
  (PROJECT_MEMORY §13 time rule). `until < since` → client-side validation error before fetch.
- Free-text `q` is a server-side substring match (case-insensitive) over the columns listed
  per view; the console never filters full pages client-side.

### 5.2 Audit semantics (ADR-011)
- Every mutating API call appends an audit row (actor, action `object.verb`, before/after)
  — enforced centrally in `lib/api/handler.ts`; this module only *reads* them. Result values:
  `success` | `failure` | `denied`. Login attempts, RBAC denials, and config applies all
  surface here; `config.apply` entries are what drive `config:updated` on the realtime
  service (SIMULATION_LAYER §7).
- Before/after JSON must never contain secrets (password hashes, sharedSecrets, TOTP seeds)
  — writers redact at the handler layer; the viewer renders whatever is stored as-is.

### 5.3 Retention & volume (DATA_LIFECYCLE §4)
- Caps: `firewall_logs` 50 000, `ips_events` 5 000, `audit_log` 20 000 rows (batch-deleted
  oldest-first by the retention job every 500 ticks); `notifications` pruned separately
  (M10). Expired DHCP leases are kept 7 days (M06). Retention overrides live in
  `system_settings` category `logging` — edited in M10, consumed here only as banner copy.
- Log tables have **no FKs to config tables**: `ruleName`/`appName` are denormalized strings,
  so filtering by rule still works after the rule is deleted (SCHEMA §5).

### 5.4 Severity & action color map (consistent across views; tokens per §9)

Canonical source: UI_DESIGN_SYSTEM §2.3/§2.4. This table restates it for quick reference:

| Value | Badge color |
|---|---|
| `critical` | rose-600 (solid) |
| `high` | rose-500 (outline) |
| `medium` | orange-500 |
| `low` | amber-500 |
| `info` | violet-500 |
| `warning` (notifications only) | amber-500 |
| `allow` / `success` / `active` | emerald-500 |
| `deny` / `drop` | rose-600 |
| `reject` | orange-500 |
| `failure` | rose-600 (solid) |
| `denied` / blocked | rose-600 (outline) |

(Color is never the sole signal — every badge pairs a glyph + text label.)

### 5.5 Where the data comes from (simulation honesty)
- Firewall/IPS rows are generated per 2 s tick by the firewall-logs / ips-events generators
  (SIMULATION_LAYER §6) with realistic zone subnets, ET-style sids, and rule-consistent
  actions; backfilled ~5 000 + ~300 rows over 30 days at seed (DATA_LIFECYCLE §2). The live
  tail shows the *same* stream pushed through the ring buffer → realtime-service →
  `logs:tail` (SIMULATION_LAYER §7) — a row seen live may not exist in `GET /logs/firewall`
  pages yet if retention/pagination windows differ; that is expected and must not be
  "fixed" by client-side dedupe.

---

## 6. Realtime

| Event (§7.3, verbatim) | Reaction in this module |
|---|---|
| `logs:tail` `{ kind: "firewall"\|"ips", entry: FirewallLog \| IpsEvent }` | `#/logs/live` appends into the 500-row buffer per the kind filter; other log views MAY show a subtle "new rows" pill prompting refetch (no auto-refetch churn) |
| `alerts:new` `{ notification: Notification }` | Drives the topbar bell unread badge (notification center = M10); `#/logs/live` does not consume it |
| `config:updated` | Not consumed here directly (log tables are not config); report view refetches on range change only |
| `metrics:tick`, `sessions:update`, `wan:status` | Not consumed here |

Subscription control stays `subscribe { channels: ["logs","alerts"] }` while a live-tail
consumer is mounted; unsubscribes on unmount (../05-FRONTEND/STATE_AND_DATA_FLOW.md).

---

## 7. Acceptance Criteria (checklist)

- [ ] `#/logs/firewall` paginates server-side: changing page issues a new request with `page`/`limit`, and `meta.totalPages` drives the paginator.
- [ ] Every filter (`q`, `action`, `src`, `dst`, `since`, `until`) reaches the API verbatim and resets `page` to 1; `until < since` is blocked client-side.
- [ ] Row detail drawer shows all FirewallLog fields for the clicked row.
- [ ] "Export CSV" downloads a CSV matching the current filter, capped at 10 000 rows, and the UI communicates the cap when hit.
- [ ] `#/logs/ips` severity/category filters work; rows with `action: "suppressed"` (or live `suppressedUntil`) render the suppressed badge.
- [ ] "Suppress" in `#/logs/ips` reuses M04's endpoint with durations 24h/7d/forever and the row updates without full reload.
- [ ] `#/logs/audit` filters by user/objectType/result; the detail drawer renders `beforeState`/`afterState` via JsonFieldViewer with added/removed visual distinction.
- [ ] Audit rows for deleted users still render a username string (no crash on null `userId`).
- [ ] `#/logs/live` streams entries from `logs:tail` within ~1 s of generation; kind filter, pause/resume, autoscroll, and the 500-row cap all behave as specified.
- [ ] Pausing keeps counting missed rows and Resume renders them; the buffer never exceeds 500 entries.
- [ ] Disabling the realtime mini-service shows the amber "Live updates paused" banner on `#/logs/live` and the view recovers on reconnect.
- [ ] `#/logs/reports` honors the 1h/24h/7d picker, renders the five aggregates from `/logs/stats`, and all charts use only the locked palette.
- [ ] Print layout removes shell chrome and prints legibly in light theme (browser print preview check).
- [ ] Severity/action badges match the §5.4 color map on every view; no indigo/blue anywhere.
- [ ] `bun run lint` passes; no new Next.js routes; no client-side filtering of unbounded log arrays.

---

## 8. Open Questions & Risks

- ~~**CSV export endpoint is a PROPOSED EXPANSION**~~ RESOLVED: `GET /api/v1/logs/firewall/export` is locked (PROJECT_MEMORY §7.2 + ENDPOINTS.md §11). IPS export stays out of Phase 1 scope.
- ~~**`/logs/stats` payload shape is sketched, not locked**~~ RESOLVED: ENDPOINTS.md §11 pins the shape (`series` + `ipsBySeverity`); §4 reports are built on it. If product wants range-scoped top apps/talkers, extend `/logs/stats` via the normal expand-never-rename process.
- Retention override keys (`system_settings` category `logging`) are named in DATA_LIFECYCLE §4 but not itemized; M10 must fix exact key names when building settings.
- Live tail is client-side buffered only (500 rows); the server ring buffer (2 000 log entries, SIMULATION_LAYER §4) is not browsable — out of contract, noted as future work.
- Dashboard/report cards computing "delta vs previous window" need a second stats call; confirm acceptable load or extend `range` semantics in ENDPOINTS.md.
- Firewall `q` matching across `userName` can leak user-activity patterns to roles without identity read rights — verify the RBAC matrix (../07-SECURITY/AUTH_AND_RBAC.md) treats logs/audit consistently.

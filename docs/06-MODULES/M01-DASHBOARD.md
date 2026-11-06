# M01 — Dashboard

> TL;DR: The landing view (#/dashboard) gives a 30-second answer to "is the network healthy, what is happening right now, and what needs attention?" — live throughput, sessions, WAN/VPN status, threat feed, and quick actions, all fed by `GET /api/v1/dashboard/summary` plus the realtime `metrics:tick` stream.

Related: [PROJECT_MEMORY](../00-PROJECT-MEMORY/PROJECT_MEMORY.md) (§7.2 API, §7.3 events, §8 view map, §9 tokens) · [SCHEMA](../03-DATABASE/SCHEMA.md) · [ENDPOINTS](../04-API/ENDPOINTS.md) · [PAGE_MAP](../05-FRONTEND/PAGE_MAP.md) · [UI_DESIGN_SYSTEM](../05-FRONTEND/UI_DESIGN_SYSTEM.md) · [SIMULATION_LAYER](../02-ARCHITECTURE/SIMULATION_LAYER.md) · M02 (WAN detail) · M04 (IPS events) · M05 (VPN detail) · M09 (logs) · M10 (system)

---

## 1. Purpose & Scope (Phase 1)

The Dashboard is the operator's default view after login. It aggregates live telemetry and recent security events into a single screen: throughput per direction with sparklines, active conntrack sessions, alert counts, system health gauges, WAN link strip, VPN tunnel list, and a high-severity threat feed. It is a **read-mostly** module — the only writes are quick actions (create backup; restart service via the audited `POST /api/v1/system/services/{name}/restart` endpoint — simulated apply, REVIEW-4A).

Explicitly **OUT of scope in Phase 1** (per upstream spec §1.1 and [ROADMAP](../01-PRODUCT/ROADMAP.md)):

| Excluded feature | Deferred to |
|---|---|
| AI risk score | Phase 3 |
| Threat heatmap | Phase 2 |
| Security posture score | Phase 3 |
| Historical report generation (PDF etc.) | M09/`#/logs/reports` owns reports, not the dashboard |
| Configurable dashboard widgets/layouts | Phase 2+ |

Everything in this spec derives from upstream spec §1.1 "Dashboard" feature table; no features were trimmed beyond the exclusions the spec itself declares.

## 2. Data Model

The dashboard owns no config tables. It is an aggregation layer over:

| Source (model / stream) | Fields used | Notes |
|---|---|---|
| `GET /dashboard/summary` response | health, throughput, sessions, alerts24h, topApps, topTalkers, wanStatus, vpnStatus | verbatim payload contract from PROJECT_MEMORY §7.2 |
| MockEngine ring buffer via `metrics:tick` | `ifaces[].rxKbps/txKbps`, `cpuPct`, `memPct`, `conntrackCount`, `ts` | in-process ring buffer, last 500 ticks (SIMULATION_LAYER §4) |
| `FirewallLog` (via `/logs/stats`) | `appName`, `srcIp`, `bytes` aggregates | top apps / top talkers beyond the live window |
| `IpsEvent` | `severity` (`high`/`critical`), `timestamp`, `message`, `srcIp`, `category` | threat feed, last 24 h |
| `WanPolicy` | `state` (`up`/`degraded`/`down`/`unknown`), `interfaceName` | WAN strip |
| `VpnConfig` | `status` (`up`/`down`/`connecting`/`error`), `name`, `type` | tunnel list |
| `Notification` | `isRead`, `severity`, `createdAt` | unread alert counter |
| `SystemSetting` | n/a (read indirectly via `/system/status`) | — |

No logical (JSON-array) references are involved in this module.

## 3. API Surface

| METHOD | Path | Purpose | Triggering UI action |
|---|---|---|---|
| GET | `/api/v1/dashboard/summary` | health, throughput, sessions, alerts24h, topApps, topTalkers, wanStatus, vpnStatus | view load; refetch on `config:updated` + every 30 s |
| GET | `/api/v1/system/status` | cpu/ram/disk/temp/uptime/services; services array also powers the restart menu | gauges + system health card; refetch every 30 s; "Restart service" quick action posts to `/system/services/{name}/restart` (§3) |
| GET | `/api/v1/logs/stats` | chart aggregates `?range=1h\|24h\|7d` | traffic chart when range switched off "live" |
| GET | `/api/v1/ips/events` | threat feed rows | feed load: parallel `?severity=high&since=<-24h>&limit=10` + `?severity=critical&since=<-24h>&limit=10`, merged newest-first |
| GET | `/api/v1/notifications` | unread alert badge (`?unread=true`) | view load + on `alerts:new` |
| POST | `/api/v1/system/backups` | create backup (quick action) | "Create backup" button → navigates/toasts per M10 |
| POST | `/api/v1/system/services/{name}/restart` | restart a running service (quick action; audited, simulated) | "Restart service" menu item |

Query params used: `?range=` on `/logs/stats`; `?severity=&since=&limit=` (pagination `page/limit` per §7.1) on `/ips/events`; `?unread=` on `/notifications`.

Expected error cases: any of the above failing → per-card error state (retry button), never a blank dashboard; 401 → AuthGate redirect (global, not module-specific).

## 4. Views & Interactions

View: `#/dashboard` (single view, no tabs). Layout regions per [PAGE_MAP](../05-FRONTEND/PAGE_MAP.md):

| Region | Content | Components |
|---|---|---|
| Header strip | overall health badge (healthy/degraded/critical), uptime, quick actions | `StatusBadge`, DropdownMenu |
| KPI cards row (4 cards) | throughput rx + tx (value + `Sparkline` from ring buffer), active sessions (conntrack count), alerts 24 h (high+critical count, rose when > 0), unread notifications | Card, Sparkline |
| Traffic chart | area chart rx/tx; default "live" = last 60 ticks (2 s cadence ≈ 2 min window); range switch buttons Live / 1 h / 24 h | recharts AreaChart via `ui/chart.tsx` wrapper; series colors emerald (rx) + teal (tx) — never blue |
| Top 10 apps | donut chart (or horizontal bar list on narrow screens) from `topApps` | recharts PieChart, token palette §9 |
| Top 10 talkers | table (ip, app label, bytes rx/tx) or bar list | DataTable |
| WAN strip | one badge per WAN iface (`wan0`, `wan1`): up / degraded / down + probe target tooltip | StatusBadge map: up=emerald, degraded=amber, down=rose |
| VPN tunnel list | name, type, status badge, last status message | StatusBadge: up=emerald, connecting=amber, down=zinc, error=rose |
| Threat feed | last 24 h `ips_events` with severity high/critical: time, severity chip, category, src → dst, message; click → deep link `#/ips/events?q=<sid>` | list with `max-h-96 overflow-y-auto`, EmptyState when none |
| System health | gauges CPU / RAM / disk (ring gauges), temp readout, services line (running count from `/system/status`) | Gauge components, amber > 80 %, rose > 95 % |

User actions:
- Range switch (Live / 1 h / 24 h) on the traffic chart.
- Quick action "Create backup" → `POST /api/v1/system/backups` → success toast + link `#/system/backups`.
- Quick action "Restart service" (menu of running services from `/system/status`) → `POST /api/v1/system/services/{name}/restart` (audited, tenant_admin floor, simulated ~2 s apply → service `status: running` again; `config:updated {section: "system"}` broadcast) → toast. (Endpoint restored in REVIEW-4A — no longer a client-side stub.)
- Click on WAN badge → `#/network/wan`; tunnel row → `#/vpn/configs`; feed row → `#/ips/events`; alerts card → `#/ips/events?severity=critical`.

States: skeleton cards while summary loads; per-card error state with retry; EmptyState variants: "No high-severity events in the last 24 hours" (feed), "No VPN tunnels configured" (tunnel list, with link to `#/vpn/configs`).

## 5. Business Logic & Validation

- **Live window:** `metrics:tick` arrives every 2 s; the client keeps a rolling array of the last 60 ticks (≈ 2 min) and recomputes the area chart on each tick. The server ring buffer holds 500 ticks; a fresh page load backfills the chart from `/dashboard/summary` throughput history (simulated adapter serves it from the same buffer).
- **Range switch:** 1 h / 24 h series come from `/logs/stats?range=1h|24h` pre-aggregated buckets (DB-backed), not from the ring buffer — the buffer only spans ~17 min.
- **Alerts 24 h:** count of `ips_events` where `severity` ∈ {`high`, `critical`} and `timestamp` ≥ now−24 h (server-computed in `/dashboard/summary`; the feed duplicates the query client-side for rows).
- **Health classification (client-side, simple thresholds):** CPU/mem/disk `> 95` → critical, `> 80` → degraded (amber), else healthy; any WAN iface `down` while another WAN policy exists → at minimum "degraded" banner; any `vpn_configs.status = error` → degraded.
- **Top apps / talkers:** server aggregates `firewall_logs` by `app_name` / `src_ip` with byte sums over 24 h (pattern per ER_DIAGRAM §4). Dashboard only renders.
- **Restart service stub:** purely client-side simulation (no API call exists in the locked surface): validates the service name against the `services` array of `/system/status`, runs a ~2 s spinner, shows a "restarted (simulated)" toast. No DB write, no MockEngine state change. See §8.
- **Backup action:** plain `POST /api/v1/system/backups` (full behavior owned by M10); dashboard only triggers and toasts.
- **Simulated data:** all series are MockEngine output (SIMULATION_LAYER §4, §6): per-role baselines (wan 40k–300k kbps, lan 20k–150k), bursty CPU, conntrack 5k–50k. Determinism via `MOCK_SEED`.

## 6. Realtime

| Event | UI reaction |
|---|---|
| `metrics:tick` | push tick into rolling buffer; update throughput cards + sparklines, live area chart, CPU/RAM gauge values, conntrack count |
| `wan:status` | `{iface, state}` → update WAN strip badge; toast on `down` (rose) |
| `alerts:new` | `{notification}` → increment unread badge; if `type = threat` prepend matching row to threat feed (fetch by id or reuse payload) |
| `sessions:update` | `kind = "vpn"` → refresh tunnel session counts (cheap refetch of `/dashboard/summary` debounced 2 s) |
| `config:updated` | invalidate `dashboard` + `system` query keys (refetch summary) |

Subscribe with `{ channels: ["metrics", "alerts"] }` on view mount; unsubscribe on unmount. Connect string: `io("/?XTransformPort=3003")` (§11.6).

## 7. Acceptance Criteria (checklist)

- Given a fresh login, when `#/dashboard` renders, then all cards show data (no zeros-until-tick flash) because summary backfills from the ring buffer/DB.
- Given `metrics:tick` every 2 s, when 10 ticks pass, then the live chart shows 10 new points and the sparkline slides without layout shift.
- Given range switch to 24 h, when data loads, then the chart switches source to `/logs/stats?range=24h` buckets and the x-axis is hourly.
- Given a seeded WAN policy with `state = down`, when the dashboard loads, then the WAN strip shows a rose "down" badge for that interface.
- Given `wan:status {iface: "wan0", state: "degraded"}` arrives, when processed, then the badge turns amber without a full refetch.
- Given 0 high/critical events in 24 h, when the feed renders, then the EmptyState message is shown, not an empty table shell.
- Given a new `alerts:new` threat notification, when it arrives, then the alerts-24h count increments by 1 and the feed prepends the row.
- Given CPU tick of 97, when the gauge renders, then the gauge is rose and the header health badge shows "critical".
- Given "Create backup" clicked, when the POST succeeds, then a toast appears and `#/system/backups` lists the new backup.
- Given "Restart service" chosen for a running service name, when confirmed, then `POST /api/v1/system/services/{name}/restart` is issued (audited) and after ~2 s the service shows `running` again in the health strip.
- Given any per-card fetch failure, when it occurs, then only that card shows an error + retry while other cards keep rendering.
- Given the session cookie expires, when any dashboard fetch 401s, then AuthGate takes over (no stacked error toasts).

## 8. Open Questions & Risks

- ~~**No restart endpoint in the locked surface**~~ RESOLVED (REVIEW-4A): `POST /api/v1/system/services/{name}/restart` is in PROJECT_MEMORY §7.2 (simulated restart, audited).
- **Severity >= high filter:** `/ips/events` `?severity=` takes a single value; the feed needs two parallel calls (high + critical). A `severity=gte:high` extension would simplify — flag to ENDPOINTS.md owner.
- **Throughput history on first load:** `/dashboard/summary` payload is not shape-pinned for history series (ring-buffer backfill). ENDPOINTS.md must pin the exact summary JSON shape before M01 build.
- Chart re-render cost: 60-point area chart updating every 2 s is fine, but sparklines in 4 cards + gauges must reuse one socket subscription (no per-card connections).

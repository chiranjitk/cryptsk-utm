# UI Design System — Cryptsk Console

> **TL;DR:** An enterprise, light-first, dense-but-breathable security-operations console
> built from the existing shadcn/ui set in `src/components/ui`. Colors are LOCKED: neutrals
> are **zinc** and **solid primary buttons are neutral zinc** (`bg-zinc-700 text-white
> hover:bg-zinc-800` — the as-built ADR-019 rev-2/rev-3 ruling, 161 call sites; brand hue
> survives only in the logo glyph, focus ring `--primary`, links and the `--chart-1` series).
> **Red discipline (ADR-019 rev 2, owner directive after the rev-1 blanket sweep looked like
> an alarm; rev 3, 2026-11-13, resolves the red-vs-zinc primary question by ratifying the
> as-built zinc): red/rose appear ONLY as danger semantics — deny/drop/block/critical/
> destructive — plus the locked brand surfaces above. Informational and decorative accents
> (header icons, info chips, data meters, count badges, upload/secondary chart series) are
> neutral zinc.** Emerald remains reserved ONLY for true health semantics (up/online/healthy
> dots + badges). Charts lead with neutral series and use at most ONE brand-red series.
> No custom color names — only shadcn semantic variables and the small registry of shared
> components defined in §5.

Related: [PROJECT_MEMORY §8–9 (view map + tokens, LOCKED)](../00-PROJECT-MEMORY/PROJECT_MEMORY.md) ·
[DECISIONS.md (ADRs)](../00-PROJECT-MEMORY/DECISIONS.md) ·
[PAGE_MAP.md (every view)](./PAGE_MAP.md) ·
[STATE_AND_DATA_FLOW.md (data layer)](./STATE_AND_DATA_FLOW.md) ·
[ARCHITECTURE.md](../02-ARCHITECTURE/ARCHITECTURE.md)

---

## 1. Brand & Feel

- **Product character:** security-operations console for a UTM/NGFW appliance. The UI must
  read as calm, precise, high-signal — the operator scans it many times a day under stress.
- **Theme:** light is the default (`next-themes`, `defaultTheme="light"`, `class` strategy on
  `<html>` — enterprise white surfaces per ADR-019); dark theme is fully supported and must
  never break contrast. Every custom style is written with dark-mode variants where needed.
- **Density:** dense but breathable — data tables and log views are compact
  (`text-sm`, row height ~36–40px), while page scaffolds keep generous section rhythm
  (`space-y-4`/`space-y-6`). Never cram two data tables side by side below `lg`.
- **Icons:** lucide-react only (bundled with shadcn). One glyph size language: `size-4`
  inline, `size-5` in buttons/nav. Never mix other icon sets.
- **Logo:** `BrandLogo` SVG mark (`components/shell/brand-logo.tsx`) — rounded hexagon
  badge + defense-in-depth inner hex outline + ring keyhole, gradient `#ef4444 → #c81e1e
  (55%) → #7f1d1d` (v3, 2026-11-09). Mirrored by `src/app/icon.svg` (favicon) and
  `public/logo.svg`. No image assets.
- **Voice:** short, factual labels ("Block", "Suppress 24h", "Force probe"). Sentence case
  everywhere; no exclamation marks; toasts state what happened, not enthusiasm.

## 2. Color System (LOCKED — ADR-019, supersedes the ADR-013 palette)

**Hard rule: NO emerald/teal as brand or UI-chrome color — any `emerald-*`/`teal-*` class
used for buttons, active nav, badges, charts, or decorative accents is a bug.** Emerald is
reserved exclusively for health semantics (§2.4 up/healthy rows).

**Hard rule 2 (rev 3 — zinc primary, as-built ruling 2026-11-13; ADR-019 rev-2 compliant):
PRIMARY ACTIONS ARE NEUTRAL ZINC.** Solid primary buttons render `bg-zinc-700 text-white
hover:bg-zinc-800` (canonical app-wide — 161 call sites at ratification); the active sidebar
item is a zinc tint (`bg-zinc-600/10`), not red. RED IS NOT A PAINT JOB: `red-*`/`rose-*`
appear ONLY as (1) the retained brand surfaces — logo glyph, focus ring (`--primary`), brand
links, `--chart-1` series — and (2) danger semantics: deny/drop/block/reject-adjacent danger
labels, destructive confirmations, critical severity, security warnings. Everything
informational or decorative — section-header icons, tinted icon chips, info chips/badges, count
pills, data meters/progress fills, upload/secondary chart series — is **zinc** (`bg-zinc-500/10
text-zinc-600 dark:text-zinc-300` family). Rose stays reserved for destructive/critical;
`info` uses neutral zinc. Rationale: in a security console red must keep its alarm value —
the 2026-11-09 rev-1 blanket red sweep destroyed that and was owner-rejected, and rev-2's
"red primary buttons" never shipped (the codebase standardized on zinc primaries during R1–R9
while rev 2's doc text was left behind). Rev 3 closes that doc/code conflict by ratifying the
zinc reality; §2.5 keeps red-700 as the first chart series so brand red still has one home.

### 2.1 Base palette roles

| Role | Token / class | Notes |
|---|---|---|
| Neutrals (bg, surfaces, borders, text) | `zinc-50…zinc-950` | light base white, sidebar white w/ faint warm tint (`--sidebar` token), dark cards `zinc-900` |
| Brand primary | zinc-700 buttons (`bg-zinc-700 hover:bg-zinc-800 text-white`) | primary buttons + active nav tint are zinc (rev 3); brand hue = logo glyph, focus ring `--primary`, links, `--chart-1` |
| Accent (charts secondary, TX/upload) | zinc-500 (`#71717a`) | secondary series, TX labels/legend — NOT red (rev 2) |
| Destructive | rose-600 | delete confirms, destructive buttons (`--destructive`) |

### 2.2 Semantic meanings → tokens (canonical mapping)

| Meaning | Color | Typical surface |
|---|---|---|
| Allow rule, success toast, permitted | zinc soft (neutral-permit) | soft badge — calm permit; red is danger-only (rev 2) |
| UP/online/healthy state (true health only) | emerald-600 | soft badge, green dot — the ONLY allowed emerald usage |
| Degraded / warning / "needs attention" | amber-500 | soft badge, gauge >80% |
| Secondary warning (distinct from amber when both shown) | orange-500 | reject action, medium severity |
| Block / deny / critical / failure | rose-600 | solid badge, destructive button, gauge >95% |
| Informational series / neutral-info | zinc-500 | info severity, 6th chart series |
| Disabled / inactive / standby | zinc (muted) | outline badge, muted switch |

### 2.3 Rule-action matrix (canonical — used by StatusBadge)

| `firewall_rules.action` | Variant | Class recipe | Icon |
|---|---|---|---|
| `allow` | zinc soft | `border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300` | `ShieldCheck` |
| `deny` | rose solid | `border-transparent bg-rose-600 text-white` | `Ban` |
| `drop` | rose outline | `border-rose-600/60 bg-transparent text-rose-500` | `CircleX` |
| `reject` | orange soft | `border-orange-500/40 bg-orange-500/10 text-orange-500` | `CircleMinus` |

The same four variants serve `ips_events.action` (`alert`=amber soft, `drop`=rose,
`reject`=orange, `bypass`/`suppressed`=zinc) and `nat_rules.type` uses plain zinc chips.

### 2.4 Status matrix (canonical)

| Value | Variant | Icon | Used by |
|---|---|---|---|
| `up` / `active` / `healthy` / `success` | emerald soft (health-only) | `CircleCheck` | interfaces, WAN, VPN, leases, HA role, audit result |
| `degraded` / `warn` / `expired` / `standby` | amber soft | `CircleAlert` | WAN probes, gauges >80%, DHCP leases, HA standby |
| `connecting` | amber soft + pulsing dot | `LoaderCircle` | VPN tunnels |
| `down` (WAN, interface link) | rose solid | `CircleX` | WAN strip, interface table |
| `down` (VPN tunnel) | zinc outline | `CircleOff` | VPN list (not an incident, just not established) |
| `error` / `failure` / `critical` | rose solid | `TriangleAlert` | VPN error, audit failure, severity critical |
| `high` | rose outline | `TriangleAlert` | severity scale |
| `medium` | orange soft | `CircleAlert` | severity scale |
| `low` | amber outline | `CircleMinus` | severity scale |
| `info` | zinc soft | `Info` | severity scale, informational toasts |
| `disabled` / `unused` / `passive` | zinc outline | `CircleDashed` | toggles off, HA disabled, IPS passive mode |

Severity ladder (LOCKED enum): `info` < `low` < `medium` < `high` < `critical` → zinc,
amber, orange, rose, rose-solid. This 5-level scale is the `ips_events.severity` enum
(PROJECT_MEMORY §6); `notifications.severity` uses its own 3-level scale
(`info|warning|critical` — zinc, amber, rose). Color is never the sole signal — every
badge pairs a glyph + text label (see §9).

### 2.5 Chart palette (LOCKED order)

Defined once as CSS variables in `globals.css` (`--chart-1`…`--chart-7`), consumed by
`ChartContainer` config as `var(--chart-N)`. Never hardcode chart hexes in components.

| Slot | Color | Hex (light) |
|---|---|---|
| `--chart-1` | red-700 (the ONLY brand-red series) | `#b91c1c` |
| `--chart-2` | zinc-500 | `#71717a` |
| `--chart-3` | amber-500 | `#f59e0b` |
| `--chart-4` | rose-500 | `#f43f5e` |
| `--chart-5` | orange-500 | `#f97316` |
| `--chart-6` | zinc-400 | `#a1a1aa` |
| `--chart-7` | slate-500 | `#64748b` |

Series pick slots strictly in order (1st series = brand red, 2nd = zinc, …). Named series
keep a fixed slot everywhere (**throughput rx/download = red-700, tx/upload = zinc-500** —
rev 2: the second series is neutral so the chart never reads as an alarm) for cross-view
muscle memory. The concrete implementation lives in `src/components/charts/palette.tsx`
(`PALETTE` — mirrors this table; dark mode uses the `.dark` `--chart-*` variables).

## 3. Theme Tokens (Tailwind 4 + shadcn variables)

Theme is implemented the standard shadcn Tailwind-v4 way: semantic CSS variables in
`src/app/globals.css` under `:root` (light) and `.dark` (dark, the default), mapped via
`@theme inline` to Tailwind utilities (`bg-background`, `text-muted-foreground`, …).

Rules:

1. **Only semantic shadcn variable names.** No `--emerald`, `--brand-green`, no custom
   color tokens beyond `--chart-1…7`. Components say `bg-primary`, never `bg-emerald-500`
   for themed surfaces (status badges are the exception — they are state, not theme).
2. **Radius:** keep the shadcn default `--radius`; do not restyle the design system.
3. Dark is applied by `next-themes` (class strategy); `suppressHydrationWarning` on `<html>`.

| Variable | Dark (default) | Light |
|---|---|---|
| `--background` | zinc-950 `#09090b` | white `#ffffff` |
| `--foreground` | zinc-50 `#fafafa` | zinc-950 `#09090b` |
| `--card` | zinc-900 `#18181b` | white |
| `--card-foreground` | zinc-50 | zinc-950 |
| `--popover` | zinc-900 | white |
| `--primary` | emerald-500 `#10b981` | emerald-600 `#059669` |
| `--primary-foreground` | zinc-950 (dark text on emerald) | white |
| `--secondary` | zinc-800 `#27272a` | zinc-100 `#f4f4f5` |
| `--muted` | zinc-800/60 | zinc-100 |
| `--muted-foreground` | zinc-400 `#a1a1aa` | zinc-500 `#71717a` |
| `--accent` | zinc-800 (hover surfaces) | zinc-100 |
| `--destructive` | rose-600 `#e11d48` | rose-600 |
| `--border` | zinc-800 `#27272a` | zinc-200 `#e4e4e7` |
| `--input` | zinc-800 | zinc-200 |
| `--ring` | emerald-500 | emerald-600 |
| `--chart-1…7` | see §2.5 | see §2.5 |

Teal is intentional **not** a theme variable: it appears only in charts (`--chart-2`) and
status chips, so it cannot leak into buttons or nav.

## 4. Typography & Spacing

- **Font:** the default shadcn/Tailwind sans stack (no custom webfont). Monospace
  (`font-mono`) for IPs, CIDRs, MACs, port lists, JSON, config previews, and hash paths.
- **Scale:** page title `text-lg font-semibold` (this is the view `h1`), card titles
  `text-sm font-medium`, body `text-sm`, table/meta `text-xs`. Metrics value
  `text-2xl font-semibold tabular-nums`.
- **Numbers:** `tabular-nums` on every metric, counter, byte rate, hit count, timestamp
  column — digits must not jitter on live updates.
- **Page padding:** view content `p-4` (mobile) → `p-6` (lg+). Grids `gap-4`, sections
  `gap-6`. Cards use `p-4` (compact KPI) or `p-6` (forms, detail panes). These two
  spacings are the only approved card paddings.
- **Table density:** default rows `py-2`; log/event tables may use `py-1.5 text-xs` with a
  `Pagination` footer. Long lists scroll inside the card: `max-h-96 overflow-y-auto` with
  the custom slim scrollbar styles from `globals.css` (PROJECT_MEMORY §9).
- **Timestamps:** store UTC, render with `date-fns` in user locale (`HH:mm:ss` for live
  views, `MMM d, HH:mm` for history).

## 5. Component Patterns (canonical shared registry)

All custom patterns live in `src/components/shared/` (kebab-case files per naming rules)
and are composed **only** from existing `src/components/ui` primitives. These names are
canonical — code must use them as-is.

| Component (file) | Built from | One-liner |
|---|---|---|
| `PageScaffold` (page-scaffold.tsx) | div, Button | view header + actions + content rhythm |
| `StatusBadge` (status-badge.tsx) | Badge | the only way to render a state value |
| `DataTable` (data-table.tsx) | @tanstack/react-table + Table + Pagination | server-paginated, sortable tables |
| `ObjectPicker` (object-picker.tsx) | Dialog + Command + Collapsible | pick address/service objects & groups |
| `RuleEditor` (rule-editor.tsx) | Sheet + Form | create/edit firewall, NAT, QoS rules |
| `EmptyState` (empty-state.tsx) | icon + Button | friendly zero-data |
| `ErrorState` (error-state.tsx) | Alert + Button | inline failure + retry |
| `SkeletonTable` (skeleton-table.tsx) | Table + Skeleton | loading placeholder for tables |
| `ConfirmDialog` (confirm-dialog.tsx) | AlertDialog | destructive confirmations |
| `MetricCard` (metric-card.tsx) | Card + Sparkline | KPI card with delta + sparkline |
| `Sparkline` (sparkline.tsx) | recharts Area (ChartContainer) | tiny inline trend, no axes |
| `Gauge` (gauge.tsx) | recharts RadialBar (ChartContainer) | CPU/RAM/disk ring gauges |
| `JsonFieldViewer` (json-field-viewer.tsx) | Collapsible + pre | collapsible monospace JSON |
| `FormSection` (form-section.tsx) | Form primitives | label + control + hint grouping |

### 5.1 PageScaffold

Props: `{ title, description?, actions?: ReactNode, children }`. Renders the view `h1`
title left, `actions` row right (wraps on mobile), then content in `space-y-4`. Every
view starts with it — no bespoke headers. Views with tabs render `TabsList` directly
under the scaffold header (see PAGE_MAP tabbed views).

### 5.2 StatusBadge

Props: `{ value: string, map?: Record<string, Variant>, size?: "sm" }`. One registry
(§2.3/§2.4) resolves variant + icon; unknown values fall back to zinc. Always renders
icon + text (never color alone). If a new enum value appears, extend the registry — never
inline badge classes in a view. Fire action chips, VPN/WAN states, severities, HA roles,
lease states, audit results all go through it.

### 5.3 DataTable

Generic `DataTable<TData>` over `@tanstack/react-table` + `ui/table`:

- Server pagination is the default for logs/events/sessions: props
  `{ pageMeta, onPageChange }` render `Pagination` (`?page=&limit=25` per API standards).
- Column sorting maps to `?sort=-timestamp` style params (client sends, server sorts).
- Built-in states: `isLoading` → `SkeletonTable` rows; empty → `EmptyState` slot.
- Filter bar (`DataTableToolbar`): `Input` free-text (`?q=`), `Select`/`DropdownMenu`
  field filters (`?severity=`, `?action=`, date range via `Calendar`/`Popover`).
- Row click opens detail (`Sheet` for logs/sessions, `Dialog` for objects); row actions
  live in a `DropdownMenu` (kebab) to keep the table clean.
- Client-side tables (small config lists ≤ 100 rows, e.g. zones) may skip pagination but
  keep the same wrapper.

### 5.4 ObjectPicker

Dialog-based picker for firewall/NAT/QoS rule fields. Tabs or sections for Address
Objects / Address Groups / Services / Service Groups; groups expand via `Collapsible` to
show members; `Command` input filters; multi-select with checkmarks and a selected-count
footer. Props: `{ kind: "address" | "service", mode: "single" | "multi", value: number[],
onChange }`. Renders selected objects as removable chips in the parent form.

### 5.5 RuleEditor

Sheet (side right, `sm:max-w-xl`) used by firewall rules, NAT rules, and QoS rules with
per-module field sets. Built on `FormSection` + `ObjectPicker` + zod schemas from
`src/lib/validators/`. Sections: General (name, description, enabled `Switch`); Match
(source/destination zone `Select`, source/destination `ObjectPicker`, service
`ObjectPicker`, schedule); Action (RadioGroup — the four firewall actions with their
StatusBadge colors); Extras (logging `none|summary|detail`, connection limit, rate limit,
SYN-flood threshold where applicable). A "Validate" affordance calls
`POST /api/v1/firewall-rules/validate` and renders shadow/conflict warnings as an inline
amber `Alert` before save. Footer: Cancel + Save (never a floating action button).

### 5.6 EmptyState / ErrorState / SkeletonTable

- `EmptyState { icon, title, description?, action? }` — centered in the card, one-liner
  plus a single CTA ("Create rule", "Add subnet"). Mandatory for every zero-data list.
- `ErrorState { error, onRetry? }` — `Alert` variant destructive showing
  `error.code` + `error.message` and a retry Button. Used per card/table, never as a
  full-page dead end.
- `SkeletonTable { rows?, cols? }` — `Table` shell with `Skeleton` rows; the only loading
  state for tables. Skeleton the **layout** (cards keep their size) to avoid jumps.

### 5.7 ConfirmDialog + Toasts (sonner)

- `ConfirmDialog` wraps `AlertDialog`: `{ title, description, confirmLabel, destructive?,
  onConfirm, loading? }`. Destructive confirms use the destructive button variant and
  restate the object name in the description ("Delete rule 'Block SMB' ?").
- Toasts via sonner (`import { toast } from "sonner"`; global `<Toaster>` from
  `ui/sonner.tsx` in the root layout): `toast.success` on every successful mutation,
  `toast.error` with `{ description: error.code }` on mutation failure, `toast.info` for
  informational socket events, `toast.warning` for socket disconnect/reconnect. Queries
  never toast (views render `ErrorState` instead). Max one toast per action — do not
  stack success + refetch toasts.

### 5.8 MetricCard + Sparkline + Gauge

- `MetricCard { label, value, unit?, delta?, icon?, sparkline?, loading?, tone? }` —
  Card `p-4`; label `text-xs text-muted-foreground uppercase tracking-wide`; value
  `text-2xl tabular-nums`; optional delta chip (arrow + `+12%`, colored emerald/rose by
  `tone: "good" | "bad"`); optional `Sparkline`. Loading renders skeleton in place.
- `Sparkline { data: number[], color?: "chart-1"…"chart-7" }` — ~40px-high recharts Area
  with zero axes; default slot `--chart-1`.
- `Gauge { label, pct, unit? }` — ring gauge (recharts RadialBar in `ChartContainer`),
  thresholds: amber >80, rose >95, else emerald (mirrors M01 health rules).

### 5.9 JsonFieldViewer

`{ value: unknown, label?, defaultOpen?, maxHeight? }` — Collapsible with chevron; body
is `pre font-mono text-xs` inside a zinc-bordered rounded box, `max-h-96
overflow-y-auto`, pretty-printed, with a copy Button. Required for: NAT/pool JSON,
Suricata payload snippets, audit before/after diffs, config-version snapshots, raw log
payload columns. Never render raw JSON blobs as plain text (PROJECT_MEMORY §13).

### 5.10 FormSection

`{ title?, description?, children, columns?: 1 | 2 }` — groups related `FormField`s with
`gap-4`, renders an optional muted description, and standardizes `FormItem` spacing.
Every form in the console (login, rule editor, settings, objects) uses `FormSection` +
react-hook-form + zodResolver; see STATE_AND_DATA_FLOW §6.

### 5.11 CommandPalette (shell-level, app-shell.tsx)

Global `Cmd/Ctrl+K` palette built on `ui/command.tsx` (cmdk inside a Radix Dialog, via
`CommandDialog`). Scope rules:

- Items: every hash-navigation destination from `nav-config.tsx`, grouped by `NAV_GROUPS`
  heading, plus a "Preferences" group with a **Toggle dark mode** command (next-themes).
  Navigation = set `window.location.hash` (never pushState — the shell listens to
  `hashchange`).
- Keyboard contract: `Cmd/Ctrl+K` toggles (listener bound only while the shell is
  mounted — not on `#/login` or the setup wizard), `Esc` closes, `↑/↓` move the
  selection, `Enter` navigates/runs; the input autofocuses on open.
- Discoverability: a topbar trigger (Search icon + "Search…" + `kbd` platform hint —
  `⌘K` on Apple platforms via a hydration-safe `useSyncExternalStore` probe, `Ctrl+K`
  elsewhere) sits left of the theme toggle. This is the ONLY global search UI; do not
  add per-view search overlays that duplicate it.
- The sr-only `DialogHeader` (title + description) must stay INSIDE `DialogContent` in
  `ui/command.tsx` so the "Command Palette" heading does not leak into the page heading
  outline while the dialog is closed.

### 5.12 Realtime status dot (shell-level, app-shell.tsx topbar)

A `role="status"` dot in the topbar (right of the Live/Simulated badge) reflecting the
transport state of the socket.io singleton — derived via `useRealtimeStatus()`
(`src/lib/realtime.ts`), which only attaches listeners to the EXISTING `getSocket()`
singleton and never opens a second connection. States (§2.4 semantics — emerald is true
health only): **connected** = emerald-500, **connecting** and **reconnecting**
(disconnect with auto-retry active) = amber-500 (reconnecting pulses), **offline**
(initial handshake failing) = rose-500. Screen-reader text via `aria-label`
("Realtime stream …") + native `title` tooltip; no visible text label — the topbar is
density-critical.

### 5.13 Topbar section label

The topbar `h1` renders `Section / View Title` where Section is the `NAV_GROUPS` label
containing the current `routePath` (derived in `app-shell.tsx`). Keeps orientation on
mobile where the sidebar is hidden; mirrors PAGE_MAP §5's "Group / View" promise for
non-tabbed views.

### 5.14 Table density + row flash (module tables, fw-ui.tsx)

- `DensityToggle` / `useTableDensity(key)` (M03 firewall views, reusable): comfortable |
  compact persisted per table under `fw-density:<key>` in localStorage; hydration-safe via
  `useSyncExternalStore` (server snapshot "comfortable"). Compact trims cell padding
  (`py-1 px-1.5`, `text-xs`) and MAY hide optional columns (the firewall rules table hides
  Sched/Guard/Hits); the trigger is an outline button with icon + label (`h-11 lg:h-8`,
  aria-label, `hidden sm:inline` label).
- Row flash (`ROW_FLASH_CLASS` = `fw-row-flash`, keyframes in `globals.css`): a ~1.5 s
  neutral zinc tint on a table row whose optimistic mutation just landed (firewall/NAT rule
  toggle). Pure CSS animation so it does not fight dnd-kit's inline transform transitions;
  the global `prefers-reduced-motion` block neutralizes it. Optimistic mechanics (rollback +
  toast) are unchanged — this is feedback, not state.

### 5.15 IPS/TI triage atoms (R3 — ips-ui.tsx, ti-ui.tsx, events/feeds/iocs/auto-block views)

- **IPS severity filter chips + timeline legend** (`SEVERITY_TONE`, ips-ui.tsx): the events
  severity chips reuse the M04 §4 badge recipes when active (critical = rose solid, high =
  rose soft, medium = amber, low/info = zinc) so the chips double as the legend of the
  compact "Last 24 h by severity" stacked bar (client-bucketed from the existing paginated
  `/api/v1/ips/events` — capped at the most recent 500, noted inline). Chart hexes:
  critical `#e11d48`, high `#fb7185`, medium `#f59e0b`, low `#a1a1aa`, info `#d4d4d8`
  (zinc/amber/rose only — no blue).
- **Suppression is confirm-first** (`SuppressMenu`, ips-ui.tsx): the 24h/7d/forever dropdown
  opens a dialog restating sid/category/message + a computed window ("until …") before the
  POST. The dialog states plainly that the audit log records the duration and a reason note
  is not persisted (the suppress endpoint's request shape is locked, M04 §3). Suppressed
  rows render at 60% opacity; a "hide suppressed" filter chip + an honest "n suppressed
  hidden on this page" footer note cover the triage pass. Live-tail rows (synthetic ids)
  have the Suppress trigger disabled.
- **Threat-intel feed freshness badge** (`FreshnessBadge`, ti-ui.tsx): data-recency badge
  per feed card — fresh (<24 h) = emerald dot (the module's ONLY emerald, sanctioned by the
  §2 health-only rule), aging (<7 d) = amber, stale (≥7 d) = rose, never synced = rose;
  sync error keeps rose via a "sync error" state. Sync OUTCOME (ok/error pill) stays on the
  separate `SyncStatusPill` (zinc). Replaces the module's old "no emerald at all" comment.
- **IOC bulk disable + copy** (iocs-view.tsx): per-row Checkbox column (select-all header
  with indeterminate state), a `role="toolbar"` selection bar with a sequential
  disable-to-progress button ("Disabling i/n…") against the EXISTING per-IOC
  `POST /iocs/{id}/disable` (no bulk endpoint was invented), and a copy-to-clipboard icon
  button per value cell (clipboard + toast). Selection is a Map of DTOs so it survives
  paging; disabling skips already-disabled rows and reports them in the toast.
- **Auto-block summary strip + row flash** (auto-block-view.tsx): a 5-cell stat strip
  (Rules / Enabled / Auto-feed / Manual / Hits) client-computed over the loaded rules —
  same `Card p-4` recipe as the feeds `StatsStrip` — and the §5.14 `ROW_FLASH_CLASS` on the
  toggled rule row (flashId + timer ref, event-context only).

### 5.16 VPN/SD-WAN round-4 atoms (R4 — vpn-ui/vpn-api consumers, sdwan-view.tsx)

- **Session connect-duration** (vpn-api.ts `fmtElapsed` + sessions-view.tsx "Uptime"
  column): `<1m` / `12m` / `5h 07m` / `3d 04:12` (days use `H:MM`), rendered as
  "up for …" in mono `tabular-nums` with the absolute connect time in the `title`. A 60 s
  clock heartbeat keeps labels fresh between the 15 s refetch. Disconnected sessions render
  "—" (VpnSession has no `disconnectedAt` — no invented duration) with an honest tooltip.
- **Bundle-download pending state** (configs-view.tsx RowMenu): the "Download client
  bundle" item keeps its dropdown open (`onSelect` `preventDefault`), swaps icon→spinner +
  "Preparing bundle…" while the POST is in flight, closes on settle; success/failure toasts
  unchanged. One pending slot per config id, disabled while pending.
- **Editor validation parity** (sdwan-view.tsx `INVALID_CLS` + `FieldErrorText`): the SD-WAN
  policy and SLA-profile editors validate per-field at submit — rose ring
  (`border-rose-500 ring-1 ring-rose-500/40 focus-visible:ring-rose-500`), `aria-invalid` +
  `aria-describedby` error id, `text-[11px] text-rose-600 dark:text-rose-400` error text,
  scroll-to + focus on the FIRST invalid control, per-field errors clear on edit, and Save
  is no longer silently disabled on an empty name (errors are explained instead). The
  overlay/site/path editors keep the single-message line (deferred).
- **Wide-table responsive pattern**: any card table wider than its column gets
  `overflow-auto` (not just `overflow-y-auto`) on the scroll container + a `min-w-[…]` on
  the Table so mobile scrolls horizontally instead of squishing (vpn sessions
  `min-w-[880px]`, sdwan sites 680 / policies 720→600 compact / SLA 420→360 compact);
  mono IP cells add `block min-w-0 max-w-44 truncate` + native `title`.

### 5.17 Network round-5 atoms (R5 — net-ui.tsx consumers: interfaces/routing/wan views)

- **Diagnostics output block** (`DiagOutputBlock`, net-ui.tsx): vendor-style tool output —
  optional summary chips row (`role="status"`), a `n lines · m chars` count with a Copy
  button (`copyText()` clipboard helper toasts on success/failure), then the raw tool output
  in a `max-h-56 overflow-auto` mono `<pre role="region">` with `whitespace-pre-wrap
  break-words`. Used by all four diagnostics tools AND the per-row "Ping gateway" dialog —
  one recipe everywhere raw command output renders.
- **Recent-target chips** (`useRecentTargets(key)` + `RecentTargetChips`): per-tool
  localStorage (`net-diag-recent:<ping|traceroute|dns|tcp>`, cap 4) written from the
  mutation's `onSuccess` via the stable `pushRecentTarget` store fn — completed runs only;
  hydration-safe via `useSyncExternalStore` (server snapshot = empty). Chips are 44px
  touch targets (`h-11 lg:h-7`), mono, truncating at `max-w-44`.
- **Derived-table freshness + provenance** (`LastUpdatedLabel` + `DataSourceBadge` +
  `useNowTick`): "updated Ns ago" beside every Refresh button on the LLDP/MAC/host-ports/ARP
  cards (10 s shared ticker, hydration-safe); `DataSourceBadge` renders emerald "live"
  (host lldpd) vs zinc "simulated" (engine generator) per the meta.source flag — provenance
  is never implied, it is stated next to the data.
- **Kernel-sync badges** (`RouteOsBadge` / `PbrKernelBadge` / `MirrorKernelBadge`): emerald
  "in kernel", amber "drifted"/"config-only", rose "not installed", zinc "off"/"kernel n/a"
  — a config row's kernel truth is always a badge, never a footnote.
- **Interfaces OS-apply staged feedback** (`ApplyPlanRunning` + `ApplyPlanStages` in
  interfaces-view.tsx): the "Preview apply plan" dialog opens WHILE the POST is in flight
  (spinning strip, `role="status"`, same recipe as firewall `ApplyStagesRunning` §R2), then
  maps the EXISTING `POST /interfaces/apply` response honestly onto three stages — Guards
  (gate/tool/protection; rose when the target was rejected), Plan (n convergence steps from
  `plans[]`, zinc-dashed "zero steps" when in sync), Kernel (exec results from `results[]`;
  "not touched (preview only)" when the gate is off). Failure stderr renders as break-words
  mono under the failing step. Endpoint shape unchanged (single-interface by design — no
  bulk path was invented).
- **Per-field editor validation parity** (`INVALID_CLS` + `FieldErrorText`): exported from
  net-ui for the network editors (route CIDR/gateway/distance, WAN probe target/interval/
  timeout/thresholds) — same rose-ring recipe as §5.16.
- **Density parity keys**: `net-static-routes`, `net-pbr-rules`, `net-lldp`, `net-mac`
  (independent per table, `fw-density:<key>` storage, §5.14 mechanics).

### 5.18 Logging round-6 atoms (R6 — logs views: search/firewall/ips/audit/live/reports)

- **Time-range preset chips** (search-view): `15m / 1h / 24h / 7d / Custom` in a
  `role="group"`; clicking a preset pins `since` as an ISO string in STATE at click time
  (never computed during render — a ticking value would destabilize the TanStack query key
  and refetch every render) and clears the day inputs; "Custom" lights up whenever the
  explicit date inputs drive the range. Query timing ("`N events total · 34 ms query`")
  is measured around the queryFn fetch with a ref — a client-perceived round-trip, not a
  server metric.
- **Action chips with window counts** (firewall-logs-view): `allow/deny/drop/reject` chips
  replace the action Select; counts are 24 h sums from the LOCKED `/logs/stats` payload
  (`["logs","stats","24h"]` — shared cache with the reports tab) and are window-level, NOT
  filter-scoped (same honest pattern as the R3 events-view severity chips); chips render
  count-less while stats load. 44 px on mobile (`h-11 lg:h-7` chip recipe).
- **Severity chip tone parity** (ips-logs-view): active severity chips take the M04
  `SEVERITY_TONE.chip` recipe (imported from ips-ui) instead of the generic zinc chip, so
  `#/logs/ips` and `#/ips/events` speak the same severity color language; the table badges
  keep the locked M09 §5.4 map (logs-ui `SeverityBadge`).
- **Confirm-first suppression in M09** (ips-logs-view): the row + detail-sheet "Suppress"
  action now mounts M04's `SuppressMenu` (ips-ui) instead of a bare 3-button duration
  dialog — dropdown → confirm dialog (sid/severity/window preview) → POST; `onSuppressed`
  patches the page cache locally (computed `suppressedUntil`) exactly as the M09
  acceptance requires. The search view's local severity badge was DELETED in favor of the
  locked logs-ui one (tone drift fix: high orange → rose-500 outline per §5.4).
- **Relative last-run + per-row run spinner** (reports Scheduled tab): `fmtAgo` (fmtElapsed
  pattern, local) renders "just now / 12m / 5h 07m / 3d 04:12 ago" with the absolute time
  in the `title`; a 60 s `setInterval` heartbeat (R4 sessions-view pattern) keeps labels
  fresh — NOT a `Date.now()` `useSyncExternalStore` snapshot, whose uncached getSnapshot
  can trip React's maximum-update-depth guard when renders straddle a millisecond boundary.
  "Run now" spins only the clicked row (`runPendingId`); §5.14 `ROW_FLASH_CLASS` fires on
  schedule + syslog + NetFlow enable/disable toggles.
- **Paused overlay + jump-to-newest** (live-tail): while paused, an amber floating pill on
  the stream ("Paused — N new lines buffered", `role="status"`) mirrors the Resume button
  counter; a "Newest" button appears when `scrollTop` leaves the newest position (list is
  newest-TOP, so "newest" = top) and smooth-scrolls back.
- **Wide-table min-content containment**: any grid-item card that wraps a `min-w-[…]` table
  MUST carry `min-w-0` (and keep the `overflow-x-auto` on an inner wrapper or itself) —
  otherwise the table's min-content width propagates through the auto-sized grid track and
  the PAGE scrolls horizontally at 390 px. Density keys: `logs-firewall`, `logs-ips`,
  `logs-audit`, `logs-compliance`, `logs-reports-scheduled`, `logs-reports-forwarding`
  (the last two shared per tab — one toggle controls all tables in it).
- **Recharts inline-px containment** (reports tab, R6 pass 2): a ResponsiveContainer writes
  its measured width as an INLINE PX width on the inner wrapper once mounted — inside a
  grid-item card that inline width becomes the card's min-content and inflates the whole
  grid track (the page then stays wide even after the layout above it shrinks). Every
  chart card must carry `min-w-0` on the Card AND `overflow-hidden` on the CardContent so
  a stale measurement clips instead of widening the page; the ResizeObserver then re-measures
  at the real width. Same rule as above, one level deeper: charts need it even where tables
  don't (verified: reports tab scrollWidth 505 → 390 at 390 px purely from this fix).
- **Filter-bar wrapping rule**: a `flex flex-wrap` filter bar's min-content is its WIDEST
  CHILD — any grouped row inside it (`chips + Clear + export + density`) must itself be
  `flex flex-wrap`, or the group's combined min-content overflows the page at 390 px even
  though the parent bar "can wrap" (audit-view: result chips group + Export CSV).
- **Export button + CSV tooltip recipe** (firewall + audit views): spinner-while-in-flight
  (`exporting` state, `Loader2 animate-spin`, disabled), shadcn Tooltip listing the exact
  CSV columns + the 10 000-row cap + what is deliberately NOT exported (audit: the
  before/after JSON states stay in the row drawer), success toast with the row count and an
  honest cap message when `rows >= 10000`.
- **Cross-view deep-link pivots** (R6 pass 3): log detail drawers launch a filtered sibling
  view by setting `window.location.hash` to `view?param=value` — `#/logs/search?q=<ip>`
  (firewall drawer src/dst buttons) and `#/ips/events?sid=<sid>` (IPS drawer triage pivot;
  events-view also widens its default 24 h window to "all time" when a sid is deep-linked).
  The receiving view reads the param ONE-SHOT via a lazy `useState(readXDeepLink)`
  initializer (rules-view `?search=` pattern) — never in an effect or during render —
  because the shell keys each view by routePath so navigation remounts it; closing the
  source drawer before setting the hash avoids the Radix backdrop flashing over the next view.
- **Mobile saved-search chips** (search view, R6 pass 3): the saved-searches rail is
  `hidden lg:block`, so below lg it must have a companion — a `lg:hidden flex flex-wrap`
  chip row (only when saved searches exist) where each chip is a 44 px pill split into an
  apply button (`min-w-0 truncate`) and a bordered w-11 delete button reusing the shared
  ConfirmDialog. Same data, same mutations, no duplicate state — the chips and the rail
  render from the one saved-searches query.

### 5.19 Identity & DNS/DHCP round-7 atoms (R7 — identity views, dhcp-view)

- **Relative last-login** (users-view): `fmtElapsed` (§5.16 pattern, local) renders
  "never" for `lastLoginAt: null` and "`<1m` / `12m` / `5h 07m` / `3d 04:12` ago" in mono
  `tabular-nums` with the absolute timestamp in the `title`; a 60 s `setInterval`
  heartbeat keeps labels fresh (R4 sessions pattern — never a `Date.now()`
  `useSyncExternalStore` snapshot).
- **Identity editor validation parity** (users-view, portal-view): the user editor,
  reset-password, group editor and voucher generator validate per-field at submit with
  the §5.16 recipe — local `INVALID_CLS` rose ring, `FieldErrorText` (`role="alert"`),
  `aria-invalid` + `aria-describedby`, scroll-to + focus FIRST invalid, per-field errors
  clear on edit, and Save is no longer silently disabled on empty required fields
  (errors are explained instead). The user editor / reset-password fetch the live auth
  policy (`auth-settings`, 30 s staleTime) so the client-side password pre-check mirrors
  the configured minLength/complexity — the server stays authoritative and its
  `fieldErrors` merge into the same bag on 400.
- **"N active now" summary chip** (sessions-view): an emerald pulsing-dot chip
  (`role="status"`, `tabular-nums`) beside the live badge — rendered ONLY when
  `method === "all"` and the search box is empty, because otherwise the loaded row count
  is filter-scoped and the chip would lie about the tenant-wide active count.
- **Voucher search + named revoke** (portal-view): a code search input filters the
  masked list client-side (state chips + search compose in the same `rows` memo, CSV
  export exports the filtered set); the revoke ConfirmDialog titles the masked code
  ("Revoke voucher …5M45?") instead of the anonymous "Revoke this voucher?".
- **RADIUS reveal copy + visible countdown** (identity-panels): the revealed shared
  secret row gains a copy icon button (net-ui `copyText`, 44 px mobile hit area) and a
  `role="status"` "auto-hides in Ns" countdown; the 15 s auto-hide is driven by the
  reveal timestamp + a 1 s tick heartbeat (setState only inside the interval callback —
  the `set-state-in-effect` lint rule forbids synchronous setState in the effect body).
  "Hide secret" still clears immediately.
- **DHCP tab counts** (dhcp-view): the Reservations/Leases tab triggers render count
  badges from the SAME query keys the tabs use (`["dhcp","reservations"]`,
  `["dhcp","subnets"]` — TanStack dedupes, zero extra requests); leases show the sum of
  `activeLeaseCount` labeled "N active" because that is exactly what the field measures.
  Counts render only once the data is loaded (no fake 0s).
- **Subnet pool utilization bar** (dhcp-view): per IPv4 subnet card — pool size derived
  client-side from `rangeStart`/`rangeEnd` (uint32 math, `ipv4ToInt`), fill =
  `activeLeaseCount / poolSize` as an `h-1.5` rounded bar with `role="progressbar"`
  (aria min/max/now + label), emerald < 60 %, amber ≥ 60 %, rose ≥ 85 %; a 2 % minimum
  width keeps a bar visible when only a couple of leases are out. IPv6 cards render
  nothing (config-only in simulation — the honest label stays).
- **44 px touch pass on identity/DHCP row controls**: row kebabs, expire/revoke icon
  buttons, group edit/delete, RADIUS/Directory Test buttons and the method/state/voucher
  filter chips are `h-11 lg:h-8 lg:h-7` (mobile hit area, desktop density preserved);
  sessions/leases/voucher tables got `min-w-[860px]/[820px]/[560px]` inside their
  existing `overflow-x-auto` wrappers (§5.16 wide-table pattern).

### 5.20 System/PKI/HA round-8 atoms (R8 — system-view, backups/api-keys views, ha-view, certificates-view)

- **Confirm-first service restart** (system-view HealthStripCard): the per-service chip
  button only OPENS a ConfirmDialog naming the service — consequence copy differs by data
  plane (host: "systemctl restart issued… brief packet-processing blips"; simulated:
  "~2 s apply… on a real appliance the unit would reload"). While the POST is in flight
  the initiating chip's icon swaps to a spinner (`restart.isPending && restart.variables
  === svc.name` — per-service pending, siblings stay clickable). M10 §5.6 dangerous-action
  rule: restart joins restore/revoke/upgrade in the confirm-first set.
- **Typed-version firmware upgrade** (system-view UpgradeDialog): destructive AlertDialog
  gated on typing the TARGET version string (the same recipe as the backups typed-RESTORE
  gate); description carries the safety-backup + control-plane-blip copy; Cancel clears the
  typed buffer. Rollback confirm names the previous history version when known (`history[
  history.length - 2]` — the endpoint restores the previous entry). Restores the M10 §5.6
  "typed confirmation for upgrades" rule that the UI had dropped.
- **SSH fingerprint copy + add-key validation parity + named remove** (system-view
  SshKeysCard): fingerprint cell is a truncating mono `code` (native `title`) + copy icon
  button (net-ui `copyText`, "Fingerprint copied" toast, `h-11 w-11 lg:h-7 lg:w-7`); the
  add dialog validates per-field at submit mirroring the server zod grammar (name 1–64,
  publicKey OpenSSH line regex + private-key rejection, both mirrored from validators
  system.ts) — `INVALID_CLS` rose ring, `role="alert"` text, `aria-invalid/describedby`,
  focus first invalid, errors clear on edit, server fieldErrors merge into the same bag;
  Save is no longer silently disabled on empty fields. Remove confirm names the key AND
  its fingerprint ("sessions authenticated with it stop working").
- **Backup search + age chips** (backups-view): id/note/type search filters the snapshot
  table client-side with its own honest empty state ("No backups match the search" +
  Clear); Created cell stacks the absolute time with an AgeBadge — <24 h emerald, 1–6 d
  zinc, ≥7 d amber (rotate reminder), absolute timestamp in the `title`. Create-dialog
  note field dropped its silent `maxLength` truncation for a submit pre-check (≤200,
  same grammar as `backupCreateSchema`) — silent truncation hides the limit, the error
  explains it.
- **API-key created-relative** (api-keys-view): Created column renders `fmtRelative` with
  the absolute timestamp in the `title` (Last used already did); keys + webhooks tables
  gained `overflow-x-auto` + `min-w-[820px]/[900px]` and a 44 px row-control pass.
  The show-once reveal dialog stays as shipped (§5.6 locked show-once pattern — an
  auto-hide countdown would weaken the "saved it" gate, NOT added).
- **HA editor validation parity** (ha-view): per-field client pre-checks at submit mirror
  `haConfigSchema` — priority 1–255 integer, virtualIp IPv4-CIDR shape when non-empty,
  peerIp IPv4 shape, failAfterSec 3–3600, holdDownSec 0–86400 AND ≥ failAfterSec, enabled
  ⇒ role ≠ disabled + peerIp present; same `INVALID_CLS`/`role="alert"`/focus-first-
  invalid/clear-on-edit recipe as §5.16, server fieldErrors merge on 400, Save enabled
  (errors are explained, not silently blocked). Tracked-interface chips are `h-11 lg:h-7`.
- **PKI expiring highlight strip** (certificates-view): when `GET /pki/certificates/
  expiring?days=30` returns rows, a zinc `role="region"` strip renders under the filter
  card — days-left chips sorted soonest-first, tone rose ≤7 d / amber 8–30 d, chip label
  `name · Nd` (truncate + tabular-nums), click sets the "Expiring ≤30d" filter; strip is
  hidden when none (honest-empty). Cert table got `overflow-auto` + `min-w-[880px]` and
  44 px kebab/chip pass. ExpiryPill thresholds stay 30/90 (§ existing recipe — strip tones
  are the mission-specified urgency scale, not a Pill change).

### 5.21 Content-security round-9 atoms (R9 — url-filter/app-control/ssl/waf/email views)

- **Log action chips** (url-filter LogsCard): the action Select became R6-style filter
  chips (`all + LOG_ACTIONS`, `role="group"`, `h-11 lg:h-7`, active chip reuses the
  module's `DECISION_CLS` tone) with window-level 24h counts from the SHARED
  `["url-filter","stats"]` key — count-less while stats load, never filter-scoped.
- **Log search** (url-filter + app-control): url-filter search is server-side (the logs
  endpoint already accepted `?q=` free-text — the UI now exposes it in the query key);
  app-control has no free-text param so its search filters the loaded 25-row window
  client-side, and its footer/empty state say so honestly ("n of m loaded entries match")
  with a Clear action on the filter-aware EmptyBlock.
- **Rule-toggle ROW_FLASH** (§5.14): app-control rules table (toggle/action/bandwidth
  mutations flash `variables.id`), ssl bypass-rules table, email routing-rules table and
  the email RELEASED mail-log row — flashId + one-shot timer ref per component, exact
  `ROW_FLASH_CLASS` recipe (reduced-motion neutralized globally).
- **Category chips from loaded rules** (app-control RulesTable): client-derived unique
  nDPI categories render as chips ONLY when >1 exists; filtered table gets its own honest
  "No rules in category …" EmptyBlock + Clear; count line switches to "n of m rules".
- **Bypass-rules search** (ssl-inspection): matchValue/reason filter on the selected
  policy's rules with a "n of m" badge, per-filter empty line + Clear (honest — the
  no-rules dashed state is unchanged when the policy truly has none).
- **WAF payload preview** (waf log table): rows with `payloadSnippet` render a `payload`
  pill (aria-expanded) that expands a full-width detail row — DiagOutputBlock-style mono
  `<pre role="region">` (`max-h-56 overflow-auto whitespace-pre-wrap break-words`) with a
  `n chars` label and net-ui `copyText` Copy button (§5.17 recipe). Fragments keep row
  keys stable; the message cell became a min-w-0 flex (truncate + pill, anti-overflow).
- **Exclusion editor validation parity** (waf): per-field submit pre-checks mirroring the
  server grammar (matchValue 1–256 required, ruleId positive int when scope=rule_id),
  `INVALID_CLS`/`FieldErrorText`/aria-invalid/describedby/focus-first-invalid/
  clear-on-edit imported from net-ui; Save no longer silently disabled (errors explained).
- **Confirm-first quarantine release** (email MailLogCard): Release opens a ConfirmDialog
  naming the message ("Release \"<subject>\"?") with from → to consequence copy; the
  released row flashes on settle (§5.6 dangerous-action rule — release re-delivers mail).
- **Density parity + wide tables**: `DensityToggle`/`useTableDensity` on the url-filter,
  app-control (rules + logs), ssl (bypass + logs), waf (logs) and email mail-log tables
  (`fw-density:<key>` mechanics, `[&_th/_td]` compact selectors per §5.14/R6); every
  content-security table now scrolls horizontally inside `overflow-auto` +
  `min-w-[420–920px]`; icon-only row controls are `h-11 w-11 lg:h-7 lg:w-7`.
- **Vhost status pills** (waf): disabled vhosts get a rose "disabled" badge and the card
  dims (opacity-70) — status is visible without hunting for the switch position.

### 5.22 Cross-cutting round-10 amendments (R10 — regression sweep)

- **Firewall rules filter chips hit the 44 px recipe** (rules-view, closes the R2 deferral):
  the zone/tag pill buttons and the chip-row "Clear all" button moved to the R6 chip recipe
  `inline-flex h-11 items-center rounded-full border px-2.5 text-xs lg:h-7 lg:py-1`; the
  row kebab is `h-11 w-11 lg:h-8 lg:w-8`.
- **Email gateways/routing reach density parity** (email-security-view, closes the R9
  note): `DensityToggle` + `useTableDensity("email-gateways"|"email-routing")` with the
  shared `[&_th/_td]` compact selectors, `overflow-auto` + `min-w` (860/760 px) wrappers,
  and §5.14 `ROW_FLASH_CLASS` on the gateway enable toggle (routing already had it).
- **Reports chart palette re-pointed to the locked §2.5/§2.3/§5.15 recipes**
  (reports-view): the legacy `CHART` constant carried real teal-500/emerald-500 hexes and
  painted `allow`/`medium` series in brand red — replaced with the §5.15 severity tones
  (critical rose-600, high rose-400, medium amber, low/info zinc) and the §2.3 action
  mapping (allow = zinc calm-permit, deny rose-600, drop rose-500, reject orange).
- **Primary-button law ratified as zinc** (§2 hard rule 2 rev 3): `bg-zinc-700 text-white
  hover:bg-zinc-800` is the canonical primary recipe; red/rose are danger-only plus the
  retained brand surfaces (logo glyph, focus ring, links, `--chart-1`). No code sweep —
  the ~161 zinc call sites were already the de-facto standard.

## 6. States

| State | Rule |
|---|---|
| Loading | `Skeleton`/`SkeletonTable`/skeleton cards matching final layout. Never page-level spinners; spinners only inside Buttons (`isPending`) and MetricCard deltas. |
| Empty | `EmptyState` with icon + one-liner + CTA. An empty table shell is a bug. |
| Error | `ErrorState` inline per card/table + retry; keep sibling content alive. 401 is handled globally (logout → `#/login`), never by per-view error UI. |
| Disabled | Disabled controls get a `Tooltip` explaining why ("Physical interfaces cannot be deleted"). Never hide a control the user is allowed to see. |
| Partial | Lists with live streams (logs/live) mark stale rows at 50% opacity instead of removing them. |

## 7. Interaction & Motion

- framer-motion, subtle only: view fade/rise 150–200ms ease-out on hash change;
  list stagger 20ms/item capped at ~10 items; 150–250ms range everywhere (PROJECT_MEMORY
  §9). Radix already animates dialogs/sheets — do not double-animate.
- Respect `prefers-reduced-motion`: gate transforms behind `useReducedMotion()`; reduced
  users get opacity-only transitions.
- Every clickable row, card link, and icon button has a visible hover state
  (`hover:bg-accent` or underline) and `focus-visible` ring (brand `--ring`).
- Touch targets: min 44px on mobile controls (table row actions become icon buttons with
  `size-11` hit area on small screens).
- Optimistic UI is allowed exactly where STATE_AND_DATA_FLOW §5 says (rule toggle, dnd
  reorder); everything else waits for the server response.

## 8. Charts (recharts via `ui/chart.tsx`)

- Always wrap in `ChartContainer` with a `ChartConfig`; series colors come from
  `var(--chart-N)`; tooltip = `ChartTooltip` + `ChartTooltipContent` (dark-styled by the
  wrapper); legend = `ChartLegendContent` where more than one series exists.
- Chart types (fixed vocabulary):
  - **Throughput:** stacked `AreaChart`, rx = `--chart-1` (brand red-700), tx =
    `--chart-2` (zinc-500 — rev 2: the second series is neutral so the chart never
    reads as an alarm), 2s `metrics:tick` cadence, x-axis `HH:mm` via date-fns.
  - **Top talkers:** horizontal `BarChart` (single series, `--chart-2`), IP/app labels
    truncated with `Tooltip` full value.
  - **Application share:** donut (`PieChart` with `innerRadius`), palette slots in
    §2.5 order, legend right (top on mobile).
  - **Latency/probe:** `LineChart` (`--chart-3`), threshold bands amber/rose.
  - **Health:** `Gauge` rings (§5.8).
- Axes use compact units: Kbps/Mbps/Gbps for rates, K/M for counts; `tickLine=false`,
  dashed zinc grid. No legends in dialogs; charts live in cards/pages, not modals.
- Never introduce blue/indigo for "internet" or "default" series — the palette is
  exhaustive because 7 slots are always enough for Phase 1 series counts.

## 9. Accessibility

- Landmarks: `header` (topbar), `nav` (sidebar), `main` (content region), one `h1` per
  view (provided by `PageScaffold`).
- Every icon-only control (topbar bell, theme toggle, row kebab) has `aria-label`.
- Dialogs/sheets: Radix focus trap + `Esc` + return focus are inherited; provide
  `DialogTitle`/`DialogDescription` always (no `aria-hidden` warnings).
- Tabs and menus: rely on Radix keyboard behavior; never intercept arrow keys.
- Color never sole signal: badges = icon + text (§2.3/§2.4); chart series also differ by
  label in legend/tooltip; severity also encoded by badge text.
- Contrast: text uses zinc-400+ on dark zinc-950/900 and zinc-500+ on light; emerald text
  is emerald-500 on dark, emerald-600+ on light (§3). Test light theme before shipping a
  view — dark-only styling is a bug.
- Charts: `ChartContainer` gets an `aria-label` ("Throughput, last 2 minutes"); provide a
  textual summary in the card description where the number matters (sessions, alerts).

## 10. Do / Don't

**Do**

- DO use `StatusBadge` for every state value, from the shared registry.
- DO use shadcn semantic variables (`bg-card`, `text-muted-foreground`) for themed UI.
- DO keep every view inside `PageScaffold` with `p-4/p-6`, `gap-4/6` rhythm.
- DO paginate logs/events server-side and show `meta.totalPages`.
- DO pair icons + text on badges, and `tabular-nums` on all metrics.
- DO give zero-data lists an `EmptyState` with a CTA.
- DO write dark and light styles together, and verify both.
- DO use lucide icons at `size-4`/`size-5` and lucide only.

**Don't**

- DON'T use indigo or blue anywhere — not in components, charts, or examples.
- DON'T hardcode hex colors in components (chart hexes live only in `--chart-N` vars).
- DON'T create new Next.js routes — views are hash paths in the `viewRegistry`.
- DON'T put charts inside dialogs; charts belong in cards/pages.
- DON'T invent new shared primitives when a `ui/*` component exists.
- DON'T render raw JSON without `JsonFieldViewer`.
- DON'T use spinners for lists/tables — skeleton the layout.
- DON'T exceed 250ms animations or ignore `prefers-reduced-motion`.

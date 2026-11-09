# UI Design System — Cryptsk Console

> **TL;DR:** An enterprise, light-first, dense-but-breathable security-operations console
> built from the existing shadcn/ui set in `src/components/ui`. Colors are LOCKED: neutrals
> are **zinc**, brand primary is **dark red** (red-800 light / red-500 dark — white surfaces
> + red chrome — ADR-019 rev, owner-directed 2026-11-09). **Red discipline (ADR-019 rev 2,
> owner directive after the rev-1 blanket sweep looked like an alarm): red is reserved for
> (1) brand surfaces — primary buttons, active nav, focus ring, logo, links — and (2) danger
> semantics — deny/drop/block/critical/destructive. Informational and decorative accents
> (header icons, info chips, data meters, count badges, upload/secondary chart series) are
> neutral zinc.** Emerald remains reserved ONLY for true health semantics (up/online/healthy
> dots + badges); rose stays destructive/critical. Charts lead with neutral series and use
> at most ONE brand-red series. No custom color names — only shadcn semantic variables and
> the small registry of shared components defined in §5.

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

**Hard rule 2 (rev 2 — red discipline): RED IS NOT A PAINT JOB.** Red (`red-*`) appears ONLY
as (1) brand surfaces: solid primary buttons (`bg-red-700 text-white`), active sidebar item,
focus ring, logo glyph, brand links; and (2) danger semantics: deny/drop/block/reject-adjacent
danger labels, destructive confirmations, security warnings. Everything informational or
decorative — section-header icons, tinted icon chips, info chips/badges, count pills, data
meters/progress fills, upload/secondary chart series — is **zinc** (`bg-zinc-500/10
text-zinc-600 dark:text-zinc-300` family). Rose stays reserved for destructive/critical;
`info` uses neutral zinc. Rationale: in a security console red must keep its alarm value —
the 2026-11-09 rev-1 blanket red sweep destroyed that and was owner-rejected.

### 2.1 Base palette roles

| Role | Token / class | Notes |
|---|---|---|
| Neutrals (bg, surfaces, borders, text) | `zinc-50…zinc-950` | light base white, sidebar white w/ faint warm tint (`--sidebar` token), dark cards `zinc-900` |
| Brand primary | red (`red-800` light / `red-500` dark) | primary buttons, active nav, focus ring, logo glyph, links |
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
  (`hover:bg-accent` or underline) and `focus-visible` ring (emerald `--ring`).
- Touch targets: min 44px on mobile controls (table row actions become icon buttons with
  `size-11` hit area on small screens).
- Optimistic UI is allowed exactly where STATE_AND_DATA_FLOW §5 says (rule toggle, dnd
  reorder); everything else waits for the server response.

## 8. Charts (recharts via `ui/chart.tsx`)

- Always wrap in `ChartContainer` with a `ChartConfig`; series colors come from
  `var(--chart-N)`; tooltip = `ChartTooltip` + `ChartTooltipContent` (dark-styled by the
  wrapper); legend = `ChartLegendContent` where more than one series exists.
- Chart types (fixed vocabulary):
  - **Throughput:** stacked `AreaChart`, rx = `--chart-1` (emerald), tx = `--chart-2`
    (teal), 2s `metrics:tick` cadence, x-axis `HH:mm` via date-fns.
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

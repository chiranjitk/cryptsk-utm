# M10 — System, HA & Notifications

> TL;DR: Appliance lifecycle from the console: HA pair status/config (Keepalived semantics,
> simulated peer), system settings, backup/restore with typed confirmation, API-key
> management, the topbar notification center, and the config-version diff viewer. Every
> action here is audited (ADR-011).

Related: ../00-PROJECT-MEMORY/PROJECT_MEMORY.md (§6 enums, §7.2 API, §7.3 realtime, §8 views) ·
../07-SECURITY/AUTH_AND_RBAC.md (role gates) · ../03-DATABASE/SCHEMA.md · ../03-DATABASE/ER_DIAGRAM.md ·
../03-DATABASE/DATA_LIFECYCLE.md (seed/reset/retention keys) · ../02-ARCHITECTURE/SIMULATION_LAYER.md §5 (HA state machine) ·
../04-API/ENDPOINTS.md · ../04-API/API_STANDARDS.md · ../05-FRONTEND/UI_DESIGN_SYSTEM.md · ../05-FRONTEND/PAGE_MAP.md ·
../05-FRONTEND/STATE_AND_DATA_FLOW.md · ../01-PRODUCT/ROADMAP.md ·
siblings: M09-LOGGING.md (audit view of this module's actions), M11-API-PLATFORM.md (scope matrix for keys)

---

## 1. Purpose & Scope (Phase 1)

This module covers the appliance-level surfaces that are not traffic-facing: high-availability
pairing (config + simulated status), general system settings, backup/restore, API keys for
machine access, the notification center, and configuration versioning with a visual diff.
It is the most permission-sensitive module: nearly every action is admin-gated and audited.

**In scope (Phase 1):**

| Area | Contents |
|---|---|
| HA | Config editor (enabled, role `disabled\|active\|standby`, priority, VIP CIDR, iface, peer IP, sync-config toggle, failAfter/holdDown seconds); status panel with simulated peer heartbeat; failover/failback explanation |
| System settings | General (hostname, timezone), notifications prefs, logging retention overrides, advanced toggles; appliance health strip from `/system/status` |
| Config versions | Version list per section + **side-by-side diff viewer** (added emerald / removed rose) — hosted inside `#/system/settings` (no dedicated hash route is LOCKED) |
| Backups | Snapshot list (created/size/type `config\|full`), create, download JSON, restore with typed confirmation |
| API keys | Create (name + scopes), show-secret-once dialog with copy, list (prefix, lastUsedAt, expiresAt, revoked), revoke |
| Notifications | Topbar bell, unread badge via `alerts:new`, list + mark-read |

**Out of scope (deferred — see ../01-PRODUCT/ROADMAP.md):** firmware upgrade/rollback
(SIMULATION_LAYER §3 notes "upgrade" would be a no-op status message — there is no Phase-1
endpoint, so nothing is built), SNMP v2c/v3, SSH key management, NTP server configuration
(timezone only in Phase 1), first-time setup wizard, default policy templates, system
hardening toggle, license management, change-approval workflow, secrets vault, HA
conntrackd session sync / VPN tunnel failover / bidirectional rsync sync (syncConfig is a
simulated toggle only), disk encryption. Multi-tenant administration UI is out (sandbox has
exactly one tenant, ADR-009).

---

## 2. Data Model

From ../03-DATABASE/SCHEMA.md §3 (names verbatim).

| Model | Fields used here | Notes |
|---|---|---|
| `HaConfig` | `enabled`, `role` (`disabled\|active\|standby`), `priority` (default 100; **higher wins** master election, Keepalived semantics — per SCHEMA), `virtualIp?` (CIDR), `ifaceName`, `peerIp?`, `syncConfig` (default true), `failAfterSec` (default 10), `holdDownSec` (default 60) | Singleton row per tenant (seed: disabled + a `standby` sample, DATA_LIFECYCLE §2.4) |
| `SystemSetting` | `category` (`general\|auth\|logging\|notifications\|dns\|advanced`), `key`, `value` (JSON) | `@@unique([tenantId, category, key])`; auth category is edited by M07 (`auth-settings`), `dns` by M06 (resolver settings) |
| `ConfigVersion` | `version`, `section` (`firewall\|nat\|interfaces\|routing\|dns\|dhcp\|vpn\|ips\|qos\|ha\|identity\|system`), `configSnapshot` (JSON string), `changeSummary?`, `createdBy?` → username, `createdAt` | `@@unique([tenantId, section, version])`; written on every significant apply (ADR-011) |
| `ApiKey` | `name`, `prefix` (unique, `"ck_"` + 8 chars), `hashedKey` (sha256 of full key), `scopes` (JSON: `["read"]` \| `["read","write"]` \| `["read","write","admin"]`), `lastUsedAt?`, `expiresAt?`, `revoked`, `createdAt` | Full key is **never** stored or re-shown; lifecycle rules in M11 |
| `Notification` | `type` (`threat\|system\|vpn\|ha\|config`), `severity`, `title`, `message?`, `sourceModule?`, `isRead`, `createdAt` | Severity enum per PROJECT_MEMORY §6 (dedicated `notifications.severity` row): `info\|warning\|critical` — matches the SCHEMA.md comment and the spec; the 5-level scale is `ips_events`-only. Index `(tenantId, isRead, createdAt)`; pruned read+>7 d beyond 500 rows (DATA_LIFECYCLE §4) |

**Non-table data (mechanism, not new models):** backups are **not** a Prisma model. In
sandbox mode a backup is a JSON file written under `db/backups/` (`{id, createdAt, sizeBytes,
type, payload}`), listed/read/restored by the system endpoints; SIMULATION_LAYER §3
(`system` row): "backup/restore copies snapshots". A `full` backup additionally embeds the
seedable volatile-table dump; a `config` backup carries config tables only. HA runtime state
(peer reachability, last failover) lives in the SimulatedAdapter/MockEngine, not the DB.

---

## 3. API Surface

Paths verbatim from PROJECT_MEMORY §7.2. Envelope/errors per ../04-API/API_STANDARDS.md.

| METHOD | Path | Purpose | Triggering UI action |
|---|---|---|---|
| GET | `/api/v1/ha/status` | Local + peer state (simulated): local role, peer reachability/heartbeat, last failover | Open `#/ha`; poll on view + after config saves |
| GET | `/api/v1/ha/config` | Read HA config | Open `#/ha` |
| PUT | `/api/v1/ha/config` | Save HA config | HA editor "Save" |
| GET | `/api/v1/system/status` | cpu/ram/disk/temp/uptime/services | Health strip on `#/system/settings` |
| GET | `/api/v1/system/settings` | Read all settings groups | Open `#/system/settings` |
| PUT | `/api/v1/system/settings` | Save settings (batch of `{category, key, value}`) | Any settings card "Save" |
| GET | `/api/v1/system/backups` | List backup snapshots | Open `#/system/backups` |
| POST | `/api/v1/system/backups` | Create backup (body `{ type: "config"\|"full", note? }`) | "Create backup" button |
| POST | `/api/v1/system/backups/{id}/restore` | Restore snapshot (typed confirmation in UI) | Restore action → ConfirmDialog |
| GET | `/api/v1/notifications` | List notifications (`?unread=true`, `?type=`, `?page=`) | Open bell popover / notification center |
| POST | `/api/v1/notifications/{id}/read` | Mark one as read (`{ isRead: true }` implied) | Row/popover "Mark read" |
| GET | `/api/v1/config-versions` | List versions (`?section=`, `?page=`) | "Config history" panel on `#/system/settings` |
| GET | `/api/v1/config-versions/{id}` | One version incl. `configSnapshot` | Select version pair in diff viewer |
| GET | `/api/v1/api-keys` | List keys (prefix + metadata only, never the secret) | Open `#/system/api-keys` |
| POST | `/api/v1/api-keys` | Create key (name, scopes, optional expiry) → response contains the **full key exactly once** | "New API key" dialog submit |
| DELETE | `/api/v1/api-keys/{id}` | Revoke key (sets `revoked = true`) | Row action "Revoke" (ConfirmDialog) |
| GET | `/api/v1/system/backups/{id}/download` | Download the backup JSON (file download; `config` and `full` payloads) | "Download" row action |
| POST | `/api/v1/notifications/read-all` | Convenience "mark all read" in the bell popover (audited) | "Mark all read" button |

**Expected error cases:** `VALIDATION_ERROR` 400 (VIP not valid CIDR, peerIp invalid, priority
outside 1–255, failAfterSec < 3, holdDownSec < failAfterSec, bad settings JSON, scopes value
outside the three allowed arrays); `CONFLICT` 409 (restoring onto a newer schema version —
simulated check on `type: "full"`); `NOT_FOUND` 404 (unknown backup/version/key id);
`FORBIDDEN` 403 (non-admin attempting admin-only surfaces per AUTH_AND_RBAC). Restores and
key revocation additionally require typed confirmation client-side (§4) — the API itself
accepts a plain POST; the type-to-confirm is a UI gate plus a `ConfirmDialog`.

---

## 4. Views & Interactions

Four hash views (LOCKED §8) plus the topbar notification center. Layouts per
../05-FRONTEND/PAGE_MAP.md; components per ../05-FRONTEND/UI_DESIGN_SYSTEM.md. **Audit rule:
every mutation on this module writes an `audit_log` row and a `config_versions` snapshot
where applicable (ADR-011)** — the UI never hides this; destructive dialogs name it.

### `#/ha`

- **Layout:** two cards. (1) **Status panel:** local role badge (`active` emerald /
  `standby` amber / `disabled` zinc), VIP + iface, peer IP with reachability dot (emerald =
  heartbeat seen, rose = lost), last heartbeat time ("x s ago"), last failover timestamp and
  count, hold-down countdown when in hold-down. (2) **Config editor** (admin-gated): enabled
  switch; role Select (`disabled|active|standby`); priority number (1–255, help text "higher
  wins master election (Keepalived semantics)"); `virtualIp` CIDR input; `ifaceName` Select; `peerIp` input;
  `syncConfig` switch ("sync configuration to peer — simulated in Phase 1"); `failAfterSec`
  and `holdDownSec` numbers with validation `holdDownSec ≥ failAfterSec`.
- **Failover/failback explanation panel** (collapsible, under the status card): plain-language
  Keepalived/VRRP semantics — peer exchanges heartbeat advertisements; silence beyond
  `failAfterSec` promotes the standby; a hold-down of `holdDownSec` delays failback to the
  preferred node to avoid flapping; VIP floats to the master; config sync copies applied
  sections when `syncConfig` is on. The state machine itself is **not redrawn here — see
  SIMULATION_LAYER §5** (HA peer: `standby ⇄ active` on heartbeat loss after `failAfter`,
  hold-down before failback).
- **States:** simulated peer toggle — the sandbox peer is fictional; status text labels
  reachability "simulated heartbeat". Loading skeletons; disabled HA → editor + muted status
  card ("HA is disabled").

### `#/system/settings`

- **Layout:** stacked cards. (1) **Appliance health strip** (from `/system/status`): cpu %,
  ram %, disk %, temp, uptime, services list with emerald/rose dots. (2) **General:**
  hostname (3–63 chars, DNS-safe), timezone Select (IANA names, default from seed
  `Asia/Calcutta`). (3) **Notifications prefs:** email toggle + recipient (display-only in
  Phase 1 — no mailer exists; label it), in-console severity threshold Select. (4) **Logging
  retention overrides:** per-table day/row overrides matching DATA_LIFECYCLE §4 keys
  (`firewall_logs`, `ips_events`, `audit_log` caps + days); hint text shows current caps.
  (5) **Advanced toggles:** diagnostics verbosity, mock-profile label (read-only — set via
  `MOCK_PROFILE` env, DATA_LIFECYCLE §3), "allow API-key access" master switch.
  (6) **Config history + diff viewer** (see below).
- **Save model:** each card saves its own group via `PUT /api/v1/system/settings` with a
  batch array of `{category, key, value}` (categories verbatim: `general`, `logging`,
  `notifications`, `advanced`); toast + audit + config snapshot (section `system`).
- **Config history panel:** section Select (12 LOCKED section values) + paginated version
  list (version, `changeSummary`, author username, createdAt). Selecting **two versions of
  the same section** opens the **diff viewer**: side-by-side snapshot panes (left = older,
  right = newer) with unified JSON diff lines — added lines tinted emerald, removed rose,
  unchanged zinc; `JsonFieldViewer` for single-snapshot inspection; "Restore this version"
  shortcut routes to the backups flow semantics (audit + broadcast), admin-gated.

### `#/system/backups`

- **Layout:** table of snapshots: id, createdAt, type badge (`config` teal / `full` violet),
  size (humanized), note, actions (Download, Restore, Delete-local-file where the sandbox
  exposes it). Header actions: "Create backup" (type Select + note) and "Refresh".
- **Restore flow (strict):** row "Restore" → ConfirmDialog in destructive style (rose) that
  requires **typing `RESTORE`** to enable the confirm button; dialog text states: what will
  be overwritten (config snapshot reload; `full` also resets volatile tables), that the
  action is audited, and that a safety backup is created first. Confirm →
  `POST /api/v1/system/backups/{id}/restore` → simulated restore = config snapshot reload +
  audit row + `config:updated` broadcast → toast "Restore complete".
- **Download:** `GET /api/v1/system/backups/{id}/download` returns the JSON file (locked
  surface, ENDPOINTS.md §13); filename `cryptsk-backup-<id>.json`.
- **States:** EmptyState ("No backups yet — create your first"); restore-in-progress button
  spinner; error card on failure.

### `#/system/api-keys`

- **Layout:** table: name, prefix (mono, `ck_` + 8 chars), scopes badges (`read` zinc /
  `write` amber / `admin` rose), `lastUsedAt` ("never" when null), `expiresAt` (or "never"),
  `revoked` badge, createdAt. Header: "New API key".
- **Create dialog:** name; scopes choice among the three LOCKED arrays (radio: `read` /
  `read+write` / `read+write+admin`, with one-line capability text per M11 §3); optional
  expiry datetime. Submit → **show-secret-once dialog**: the full `ck_…` key in a mono box
  with "Copy" button, a warning ("This secret is shown once and cannot be recovered"), and a
  required "I saved it" checkbox before closing. Only `prefix` ever appears again anywhere.
- **Revoke:** row action → ConfirmDialog ("Clients using this key immediately receive 401");
  DELETE sets `revoked = true` (row stays for history, M11 §5).
- **States:** EmptyState with security note; masked `lastUsedAt` refresh after machine calls.

### Notification center (topbar bell, part of this module)

- **Bell + unread badge:** badge count = `GET /api/v1/notifications?unread=true` total;
  increments live on `alerts:new` (§6); badge colors: `critical` rose, `warning` amber, else
  zinc count chip.
- **Popover / panel:** list of latest notifications — type icon (lucide per type), severity
  badge per M09 §5.4 map, title, message, sourceModule, relative createdAt; unread rows tinted;
  row click = mark read (`POST …/read`) + optional deep link per `sourceModule` (e.g. type
  `vpn` → `#/vpn/configs`).
- **States:** EmptyState ("You're all caught up"); "Mark all read" via
  `POST /api/v1/notifications/read-all`;
  pruned history (500-row cap) noted in the panel footer.

---

## 5. Business Logic & Validation

### 5.1 HA semantics (simulated)
- Config validation: `role` enum; `priority` 1–255; `virtualIp` valid CIDR on `ifaceName`;
  `peerIp` valid IPv4 ≠ any local iface IP; `holdDownSec ≥ failAfterSec`; enabling HA
  requires role ≠ `disabled` and a peer IP (else `VALIDATION_ERROR`).
- Runtime (SimulatedAdapter, SIMULATION_LAYER §5): peer heartbeat is fictional; if the UI
  (or a demo helper) stops the heartbeat, the standby promotes after `failAfterSec` and the
  view reflects `active`; failback to the higher-preference node waits `holdDownSec`.
  `priority` higher-wins per SCHEMA (Keepalived semantics — the corrected model).
- `syncConfig: true` is cosmetic in sandbox (no peer exists); the config apply loop already
  snapshots + broadcasts locally (ADR-011, SIMULATION_LAYER §7).

### 5.2 Settings & retention
- `PUT /api/v1/system/settings` upserts rows atomically (tx) keyed
  `(tenantId, category, key)`; values are zod-validated JSON per key (SCHEMA §4: "free JSON
  per settings schema (M10)" — this §4 table + §5.2 define those shapes).
- Retention override keys (authoritative list here): `retention.firewall_logs.days`,
  `retention.ips_events.days`, `retention.audit_log.days`, plus row caps
  `retention.<table>.max_rows`; the retention job (DATA_LIFECYCLE §4) reads them per tick
  batch. Overrides only *tighten or extend within hard ceilings* (hard caps: 50k/5k/20k).
- Hostname change propagates to the topbar/health strip after `config:updated`.

### 5.3 Backups & restore
- Create: `POST` writes the snapshot file, audited (`backup.create`), returns the list row.
  `type: "full"` additionally snapshots volatile tables (per DATA_LIFECYCLE §5 semantics).
- Restore (simulated): reloads config tables from the snapshot through the **same validation
  pipeline** (zod + adapter apply) — it is not a raw SQL overwrite (ADR-011 consequence:
  rollback = restore snapshot through validation); writes `audit_log` (`backup.restore`)
  and broadcasts `config:updated { section: "all" }` so every view refetches (sentinel
  value; flagged in §8). A safety backup is auto-created before restore (listed in the table).
- Version/snapshot growth: `config_versions` is never pruned by the retention job
  (DATA_LIFECYCLE §4 note) — the diff viewer can always reach v1.

### 5.4 API keys (lifecycle details in M11)
- `hashedKey = sha256(full_key)`; `prefix` (`ck_` + 8 chars) is the only lookup/search key
  stored in clear. The full key exists only in the POST response (one-time reveal dialog).
- `scopes` accepts exactly: `["read"]`, `["read","write"]`, `["read","write","admin"]`
  (SCHEMA §4). `DELETE` = soft revoke (`revoked = true`), audited; revoked/expired keys fail
  auth with `401 UNAUTHORIZED`.
- `lastUsedAt` updates on each successful key-authenticated request (throttled write, e.g.
  at most once per minute per key) — machine-usage visibility without write amplification.

### 5.5 Notifications
- `alerts:new` payload rows are persisted by the engine as `Notification` rows; `isRead` is
  the only mutable field in Phase 1 (no delete/dismiss endpoint — pruning is automatic).
- Severity enum is the dedicated `notifications.severity` row of PROJECT_MEMORY §6:
  `info|warning|critical` (3-level — matches SCHEMA.md and the spec; the 5-level scale is
  `ips_events`-only).

---

## 6. Realtime

| Event (§7.3, verbatim) | Reaction in this module |
|---|---|
| `alerts:new` `{ notification: Notification }` | Bell unread badge increments; popover list prepends the row; a toast fires for `severity: "critical"` only |
| `config:updated` `{ section }` | Invalidate matching query keys; after restore (section `"all"`) invalidate **all** queries; HA view refetches `/ha/status` on section `ha` |
| `metrics:tick` | Optional: feed the health strip's cpu/mem values between `/system/status` polls |
| `logs:tail`, `sessions:update`, `wan:status` | Not consumed here (M09 / M07 / M02) |

---

## 7. Acceptance Criteria (checklist)

- [ ] `#/ha` renders status + editor; role enum offers exactly `disabled|active|standby`; validation rejects `holdDownSec < failAfterSec` and malformed VIP/peerIp.
- [ ] HA status shows local role, simulated peer reachability dot, last heartbeat age, and last failover; the explanation panel describes Keepalived semantics and links SIMULATION_LAYER §5 instead of a new diagram.
- [ ] Saving HA config produces audit + `config_versions` (section `ha`) + `config:updated`, and the status panel refetches.
- [ ] `#/system/settings` saves each card as a `{category,key,value}` batch; hostname/timezone changes reflect after refetch; retention overrides show current hard caps.
- [ ] Health strip renders cpu/ram/disk/temp/uptime/services from `/system/status`.
- [ ] Config history lists versions per section; picking two versions renders a side-by-side diff with emerald added / rose removed lines; single snapshots open in JsonFieldViewer.
- [ ] Backup create produces a list row (created/size/type); download via `GET /api/v1/system/backups/{id}/download` returns valid JSON.
- [ ] Restore requires typing `RESTORE`; after confirm the UI shows the audit entry, a safety backup row, and all views refetch via `config:updated`.
- [ ] API-key create shows the full secret exactly once with working Copy and the "I saved it" gate; afterwards only the prefix is visible anywhere (list, audit, DB export).
- [ ] Key scopes are restricted to the three LOCKED arrays; expiry and revoke work; revoked keys fail with 401 on next use and `lastUsedAt` updates on successful machine calls.
- [ ] Bell unread badge increments from `alerts:new` without polling; clicking marks read; "Mark all read" (`POST /api/v1/notifications/read-all`) clears the badge.
- [ ] Notification severity badges follow the `info|warning|critical` map (no 5-level `ips_events` values rendered here).
- [ ] Every mutation in this module is audited with actor + before/after (spot-check via `#/logs/audit`).
- [ ] `bun run lint` passes; no new Next.js routes; destructive actions all use the destructive ConfirmDialog pattern.

---

## 8. Open Questions & Risks

- **Backups have no Prisma model by design** (filesystem JSON under `db/backups/`, SCHEMA.md §6 Pseudo-Resources); if the build team prefers DB rows, SCHEMA.md must change in the same task — do not silently invent a `Backup` table.
- **Restore broadcast sentinel:** `config:updated { section: "all" }` is proposed here; the realtime service and client cache-invalidation logic must agree on the sentinel (or emit one event per restored section).
- ~~**Notification severity enum conflict**~~ RESOLVED: PROJECT_MEMORY §6 has a dedicated `notifications.severity` row — `info|warning|critical` (matches SCHEMA.md and the spec); the 5-level scale is `ips_events`-only.
- ~~**HA priority direction**~~ RESOLVED: higher wins (Keepalived semantics) — SCHEMA.md and this doc agree; no adapter mapping needed.
- Key `lastUsedAt` throttling (1/min/key) trades freshness for write volume; if demos need exact metering, move to a per-request update behind a feature flag.

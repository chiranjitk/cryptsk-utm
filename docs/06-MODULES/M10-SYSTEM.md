# M10 — System, HA & Notifications

> TL;DR: Appliance lifecycle from the console: HA pair status/config (Keepalived semantics,
> simulated peer, session-sync + tracked interfaces), system settings (NTP, SNMP, hardening,
> resource-alert thresholds), backup/restore with typed confirmation, simulated firmware
> upgrade/rollback, SSH keys, first-time setup wizard, policy templates, API-key + webhook
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
pairing (config + simulated status), general system settings, backup/restore, firmware
upgrade/rollback, NTP/SNMP/hardening, SSH keys, the first-time setup wizard, default policy
templates, API keys + webhook registration for machine access, the notification center, and
configuration versioning with a visual diff. It is the most permission-sensitive module:
nearly every action is admin-gated and audited.

Derived from upstream spec §1.13 (HA) and §1.14 (System) Phase 1 tables — **fully covered per
the owner zero-loss ruling (REVIEW-4A); the former console deferrals are restored**:

| Upstream Phase 1 feature | Console Phase 1 decision |
|---|---|
| Active/Passive failover, VIP management, split-brain prevention, graceful failback (hold-down) | IN — `#/ha` status + config editor (priority **higher wins**, Keepalived semantics) |
| Configuration sync (bidirectional) | IN — `syncConfig` toggle (simulated copy-on-apply in sandbox; appliance: rsync + PG replication) (restored REVIEW-4A) |
| HA link monitoring | IN — `trackedInterfaces` (JSON array of iface names; Keepalived `track_interface`) (restored REVIEW-4A) |
| Firewall session sync (conntrackd) | IN — `sessionSync` toggle on `HaConfig` (restored REVIEW-4A) |
| VPN tunnel failover | IN — covered by the HA pair (VIP floats; StrongSwan/Keepalived semantics in the explanation panel) |
| HA cluster health dashboard | IN — `#/ha` status panel (simulated peer heartbeat) |
| Backup / restore | IN — snapshots (type `config\|full`), create/download/restore with typed `RESTORE` confirmation |
| Firmware upgrade / rollback | IN — `GET /system/firmware` + check/upgrade/rollback endpoints; simulated staged upgrade with a mandatory safety backup (spec: apt + systemd appliance-side) (restored REVIEW-4A) |
| Configuration versioning + diff viewer | IN — `config_versions` + side-by-side diff in `#/system/settings` |
| CLI (management) | IN via the spec's own alternative "SSH + API": management access = SSH (keys managed here) + the REST API; no bespoke CLI binary is built in Phase 1 |
| REST API / WebSocket / JWT / RBAC / Audit trail | IN — platform guarantees owned by M11 / 07-SECURITY / M09 |
| Admin MFA (TOTP) | IN — M07 (enroll + enforce) |
| NTP configuration | IN — settings card (`general/ntp`: servers, sync state) (restored REVIEW-4A) |
| SNMP v2c/v3 | IN — settings card (`advanced/snmp`: version, community masked / v3 user+protocols, port, allowlist) (restored REVIEW-4A) |
| SSH key management | IN — `#/system/settings` SSH keys card + `SshKey` CRUD (public keys only, fingerprint derived) (restored REVIEW-4A) |
| First-time setup wizard | IN — `#/setup` (view 29; gate on `SystemSetting` `setup.completed`) (restored REVIEW-4A) |
| Default policy templates (per vertical) | IN — template catalog + apply (office/hospitality/MSP-branch starter bundles) (restored REVIEW-4A) |
| System hardening toggle | IN — settings card (`advanced/hardening`: SSH password auth off, mgmt allowlist, stop-unused services) (restored REVIEW-4A) |
| Health check endpoints | IN — `GET /api/v1/system/status` (uptime + per-service status + resource levels) is the Phase-1 health surface used by the health strip and external monitors |
| Resource alerts (CPU, RAM, disk, temp) | IN — `notifications/thresholds` settings + engine-emitted warning/critical notifications via `alerts:new` (restored REVIEW-4A) |
| Quick action: restart service (spec §1.1 dashboard) | IN — `POST /api/v1/system/services/{name}/restart` (audited, simulated; M01 quick action) (restored REVIEW-4A) |
| License management | OUT — the spec's own §1.14 cut list assigns it to Phase 2 ("need business model first"); not a console deferral. Community tier runs unlicensed with no feature gates |

**Out of scope (spec's own phase assignments or drops — not deferrals):** change-approval
workflow, secrets vault, LUKS disk encryption, Secure Boot (hardware-level), service isolation
via containers (systemd first) — all on the spec §1.14 cut list; HA Active/Active + IPS state
sync (spec Phase 3); license management (spec Phase 2, above). Multi-tenant administration UI
is out (sandbox has exactly one tenant, ADR-009).

---

## 2. Data Model

From ../03-DATABASE/SCHEMA.md §3 (names verbatim).

| Model | Fields used here | Notes |
|---|---|---|
| `HaConfig` | `enabled`, `role` (`disabled\|active\|standby`), `priority` (default 100; **higher wins** master election, Keepalived semantics — per SCHEMA), `virtualIp?` (CIDR), `ifaceName`, `peerIp?`, `syncConfig` (default true), `sessionSync` (default true — conntrackd firewall-session replication), `trackedInterfaces` (JSON array of iface names — Keepalived link monitoring), `failAfterSec` (default 10), `holdDownSec` (default 60) | Singleton row per tenant (seed: disabled + a `standby` sample, DATA_LIFECYCLE §2.4) |
| `SystemSetting` | `category` (`general\|auth\|logging\|notifications\|dns\|dhcp\|ips\|advanced`), `key`, `value` (JSON) | `@@unique([tenantId, category, key])`; auth category is edited by M07 (`auth-settings`), `dns` by M06 (resolver settings), `dhcp`/`ips` by M06/M04 (relay, auto-update). Keys owned here: `general/hostname`, `general/timezone`, `general/ntp` `{enabled, servers[], synced, lastSyncAt?}`, `general/setup.completed`, `advanced/snmp`, `advanced/hardening`, `advanced/firmware`, `notifications/thresholds`, `logging/retention.*`, `advanced/*` toggles |
| `ConfigVersion` | `version`, `section` (`firewall\|nat\|interfaces\|routing\|dns\|dhcp\|vpn\|ips\|qos\|ha\|identity\|system`), `configSnapshot` (JSON string), `changeSummary?`, `createdBy?` → username, `createdAt` | `@@unique([tenantId, section, version])`; written on every significant apply (ADR-011) |
| `ApiKey` | `name`, `prefix` (unique, `"ck_"` + 8 chars), `hashedKey` (sha256 of full key), `scopes` (JSON: `["read"]` \| `["read","write"]` \| `["read","write","admin"]`), `lastUsedAt?`, `expiresAt?`, `revoked`, `createdAt` | Full key is **never** stored or re-shown; lifecycle rules in M11 |
| `Notification` | `type` (`threat\|system\|vpn\|ha\|config`), `severity`, `title`, `message?`, `sourceModule?`, `isRead`, `createdAt` | Severity enum per PROJECT_MEMORY §6 (dedicated `notifications.severity` row): `info\|warning\|critical` — matches the SCHEMA.md comment and the spec; the 5-level scale is `ips_events`-only. Index `(tenantId, isRead, createdAt)`; pruned read+>7 d beyond 500 rows (DATA_LIFECYCLE §4). Resource alerts land here as `type: "system"` rows when a threshold is crossed |
| `SshKey` | `name`, `publicKey` (OpenSSH `authorized_keys` line), `fingerprint?` (sha256, derived server-side), `addedBy?` (username), `enabled`, `createdAt` | Management-plane SSH keys only (console/appliance admin access); private keys are never uploaded or stored |

**Non-table data (mechanism, not new models):** backups are **not** a Prisma model. In
sandbox mode a backup is a JSON file written under `db/backups/` (`{id, createdAt, sizeBytes,
type, payload}`), listed/read/restored by the system endpoints; SIMULATION_LAYER §3
(`system` row): "backup/restore copies snapshots; firmware upgrade is a simulated staged
apply". A `full` backup additionally embeds the seedable volatile-table dump; a `config`
backup carries config tables only. HA runtime state (peer reachability, last failover, BFD
adjacency) and firmware state (`advanced/firmware` setting: current, channel, available,
history) live in the SimulatedAdapter/MockEngine + `SystemSetting` rows, not in dedicated
tables (SCHEMA.md §6).

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
| POST | `/api/v1/system/services/{name}/restart` | Restart a running service (simulated ~2 s apply, audited) | Dashboard "Restart service" quick action (M01) |
| GET | `/api/v1/system/firmware` | Firmware state: current, channel `stable`, lastCheckAt, available?, history | Firmware card on `#/system/settings` |
| POST | `/api/v1/system/firmware/check` | Simulated update check (sets `available`) | "Check for updates" button |
| POST | `/api/v1/system/firmware/upgrade` | Staged upgrade — safety backup first, then version bump + history entry (simulated) | "Upgrade now" (ConfirmDialog states the safety backup) |
| POST | `/api/v1/system/firmware/rollback` | Roll back to the previous version in history (simulated) | "Roll back" (ConfirmDialog) |
| GET | `/api/v1/system/policy-templates` | Per-vertical default policy templates (catalog) | Templates card on `#/setup` and `#/system/settings` |
| POST | `/api/v1/system/policy-templates/{id}/apply` | Apply a template's starter config (audited; snapshot `section: "all"`) | "Apply template" (ConfirmDialog: overwrites matching sections) |
| GET | `/api/v1/system/ssh-keys` | List SSH management keys (public material + fingerprint only) | SSH keys card on `#/system/settings` |
| POST | `/api/v1/system/ssh-keys` | Add SSH public key (fingerprint derived server-side) | "Add key" dialog submit |
| DELETE | `/api/v1/system/ssh-keys/{id}` | Remove SSH key | Row action "Remove" (ConfirmDialog) |
| POST | `/api/v1/system/setup/complete` | Mark the first-time-setup wizard done (sets `SystemSetting` `setup.completed = true`) | Wizard "Finish" button |

**Expected error cases:** `VALIDATION_ERROR` 400 (VIP not valid CIDR, peerIp invalid, priority
outside 1–255, failAfterSec < 3, holdDownSec < failAfterSec, bad settings JSON, scopes value
outside the three allowed arrays, SSH key line not parseable as an OpenSSH public key, NTP
server not a valid host/IP, SNMP community/port invalid); `CONFLICT` 409 (restoring onto a
newer schema version — simulated check on `type: "full"`; upgrade while another staged upgrade
is in flight); `NOT_FOUND` 404 (unknown backup/version/key/service name/template id);
`FORBIDDEN` 403 (non-admin attempting admin-only surfaces per AUTH_AND_RBAC — firmware,
restart, templates, setup are `tenant_admin`-floor; templates catalog is readable at
`soc_analyst`). Restores, upgrades, and key revocation additionally require typed
confirmation client-side (§4) — the API itself accepts a plain POST; the type-to-confirm is a
UI gate plus a `ConfirmDialog`.

---

## 4. Views & Interactions

Four shell hash views (LOCKED §8) plus the `#/setup` wizard (view 29 — renders **instead of**
the shell while setup is incomplete, same gate pattern as AuthGate) and the topbar
notification center. Layouts per ../05-FRONTEND/PAGE_MAP.md; components per
../05-FRONTEND/UI_DESIGN_SYSTEM.md. **Audit rule: every mutation on this module writes an
`audit_log` row and a `config_versions` snapshot where applicable (ADR-011)** — the UI never
hides this; destructive dialogs name it.

### `#/ha`

- **Layout:** two cards. (1) **Status panel:** local role badge (`active` emerald /
  `standby` amber / `disabled` zinc), VIP + iface, peer IP with reachability dot (emerald =
  heartbeat seen, rose = lost), last heartbeat time ("x s ago"), last failover timestamp and
  count, hold-down countdown when in hold-down, per-tracked-interface state chips
  (`trackedInterfaces[]` — any tracked iface down pins the local node out of master
  election, Keepalived `track_interface` semantics), and session-sync chip (`configSynced` /
  `sessionSynced` from the status payload).
  (2) **Config editor** (admin-gated): enabled switch; role Select (`disabled|active|standby`); priority
  number (1–255, help text "higher wins master election (Keepalived semantics)"); `virtualIp` CIDR input;
  `ifaceName` Select; `peerIp` input; `syncConfig` switch ("sync configuration to peer —
  simulated in Phase 1"); `sessionSync` switch ("replicate firewall sessions via conntrackd
  — simulated in Phase 1"); `trackedInterfaces` multiselect (iface names);
  `failAfterSec` and `holdDownSec` numbers with validation `holdDownSec ≥ failAfterSec`.
- **Failover/failback explanation panel** (collapsible, under the status card): plain-language
  Keepalived/VRRP semantics — peer exchanges heartbeat advertisements; silence beyond
  `failAfterSec` promotes the standby; a hold-down of `holdDownSec` delays failback to the
  preferred node to avoid flapping; VIP floats to the master; any tracked interface failure
  demotes the node regardless of priority (link monitoring); `sessionSync` mirrors conntrack
  entries via conntrackd so established flows survive failover (and VPN tunnels ride the
  floating VIP — StrongSwan + Keepalived tunnel failover). Config sync copies applied sections
  when `syncConfig` is on. The state machine itself is **not redrawn here — see
  SIMULATION_LAYER §5** (HA peer: `standby ⇄ active` on heartbeat loss after `failAfter`,
  hold-down before failback).
- **States:** simulated peer toggle — the sandbox peer is fictional; status text labels
  reachability "simulated heartbeat". Loading skeletons; disabled HA → editor + muted status
  card ("HA is disabled").

### `#/system/settings`

- **Layout:** stacked cards. (1) **Appliance health strip** (from `/system/status`): cpu %,
  ram %, disk %, temp, uptime, services list with emerald/rose dots; resource-threshold
  breach turns the matching gauge amber/rose and emits a notification (§5.5).
  (2) **General:** hostname (3–63 chars, DNS-safe), timezone Select (IANA names, default from
  seed `Asia/Calcutta`). (3) **System time (NTP):** enabled switch, NTP server list
  (add/remove, host/IP validated), read-only sync state (`synced` dot + `lastSyncAt`,
  engine-maintained; label "simulated sync in sandbox"). (4) **SNMP:** enabled switch;
  version radio (`v2c` / `v3`); v2c → community string (write-only, rendered masked after
  save); v3 → user + auth protocol (`sha|sha256`) + privacy protocol (`aes|des`); port
  (default 161); `allowedIps` allowlist (0 entries = unrestricted, amber hint). (5)
  **Hardening:** `sshPasswordAuth` switch (off = key-only SSH), `managementAllowlist`
  (IP/CIDR list for mgmt-plane access), `stopUnusedServices` switch; hint text names the
  appliance effects (sshd_config, nftables mgmt allowlist, systemd disable) and "recorded
  only in sandbox". (6) **Firmware:** current version + channel chip (`stable`);
  "Check for updates" (sets `available`); "Upgrade now" ConfirmDialog ("a safety backup is
  created first — see `#/system/backups`"); "Roll back" when `history` has ≥ 2 entries;
  history table (version, appliedAt). (7) **SSH keys:** table (name, fingerprint mono,
  addedBy, createdAt) + add dialog (name + `authorized_keys`-line textarea, parse-validated)
  + remove ConfirmDialog. (8) **Notifications prefs:** email toggle + recipient (display-only
  in Phase 1 — no mailer exists; label it), in-console severity threshold Select, and
  **resource-alert thresholds** (cpuPct/memPct/diskPct/tempC number inputs — engine compares
  per tick and emits warning/critical notifications, §5.5). (9) **Logging retention
  overrides:** per-table day/row overrides matching DATA_LIFECYCLE §4 keys (`firewall_logs`,
  `ips_events`, `audit_log` caps + days); hint text shows current caps. (10) **Advanced
  toggles:** diagnostics verbosity, mock-profile label (read-only — set via `MOCK_PROFILE`
  env, DATA_LIFECYCLE §3), "allow API-key access" master switch. (11) **Policy templates**
  card: vertical template cards (office / hospitality / MSP-branch) with per-section summary;
  "Apply" ConfirmDialog warns that matching sections are overwritten; apply →
  `POST /system/policy-templates/{id}/apply` → audit + `config:updated` fan-out (snapshot
  `section: "all"`). (12) **Config history + diff viewer** (see below).
- **Save model:** each card saves its own group via `PUT /api/v1/system/settings` with a
  batch array of `{category, key, value}` (categories verbatim: `general`, `logging`,
  `notifications`, `advanced`); toast + audit + config snapshot (section `system`). Firmware
  check/upgrade/rollback and template-apply use their dedicated endpoints, not the settings
  batch (they compose several writes + a safety backup inside one audited operation).
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

### `#/system/api-keys` — 2 tabs: API Keys | Webhooks

- **Tab 1 — API keys:** table: name, prefix (mono, `ck_` + 8 chars), scopes badges (`read` zinc /
  `write` amber / `admin` rose), `lastUsedAt` ("never" when null), `expiresAt` (or "never"),
  `revoked` badge, createdAt. Header: "New API key".
- **Create dialog:** name; scopes choice among the three LOCKED arrays (radio: `read` /
  `read+write` / `read+write+admin`, with one-line capability text per M11 §3); optional
  expiry datetime. Submit → **show-secret-once dialog**: the full `ck_…` key in a mono box
  with "Copy" button, a warning ("This secret is shown once and cannot be recovered"), and a
  required "I saved it" checkbox before closing. Only `prefix` ever appears again anywhere.
- **Revoke:** row action → ConfirmDialog ("Clients using this key immediately receive 401");
  DELETE sets `revoked = true` (row stays for history, M11 §5).
- **Tab 2 — Webhooks** (spec §1.15, restored REVIEW-4A; delivery simulated in sandbox — M11
  owns the semantics): table: name, url (mono, truncated), events chips, enabled switch,
  last delivery (relative time + lastStatus chip), failureCount (amber when > 0); row actions
  edit, "Send test", delete. Create/edit dialog: name, url (https only, zod URL validation),
  events multiselect (the five locked `webhooks.events` values — PROJECT_MEMORY §6), optional
  HMAC secret (write-only; omit-to-keep on edit; never returned by GET). "Send test" →
  `POST /api/v1/webhooks/{id}/test` → simulated delivery result toast (`{ok, status,
  latencyMs}`) and the row's `lastDeliveryAt`/`lastStatus` refresh. Registration is
  interactive-admin-only (machine keys get none — ENDPOINTS §14).
- **States:** EmptyState with security note; masked `lastUsedAt` refresh after machine calls;
  webhook list EmptyState ("No webhooks — register a callback endpoint").

### `#/setup` — first-time setup wizard (view 29, restored REVIEW-4A)

- **Gate:** rendered **instead of the shell** while `SystemSetting` (`general`,
  `setup.completed`) is `false` — same pattern as `AuthGate` (no sidebar/topbar leak, not in
  the sidebar registry, not reachable by deep link once completed — unknown hash after
  completion falls through to the normal redirect rules). PROJECT_MEMORY §8 lists it as
  view 29.
- **Steps (linear, Progress header, back/next per step):**
  1. **Welcome** — product wordmark, admin password change prompt (must differ from the seed
     default), timezone confirm.
  2. **WAN** — pick/verify the WAN interface + `wanType` (static/dhcp/pppoe fields per M02);
     writes the interface config, not a new resource.
  3. **LAN / DHCP** — LAN iface + subnet/pool defaults (creates/updates a `DhcpSubnet`).
  4. **Policy template** — pick a vertical template (same catalog as `#/system/settings`) or
     skip; applying runs the same audited template-apply endpoint.
  5. **Finish** — summary; "Finish setup" → `POST /api/v1/system/setup/complete` →
     `setup.completed = true` → shell renders (landing `#/dashboard`).
- **States:** every step saves through the regular module endpoints (M02/M03/M06 interfaces —
  this view only orchestrates them, it defines no new data); Cancel returns to the wizard at
  the same step; skipping setup is possible only by completing it (the gate is hard in
  Phase 1 — flagged in §8 as a demo convenience risk).

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
  snapshots + broadcasts locally (ADR-011, SIMULATION_LAYER §7). `sessionSync: true` behaves
  the same way (conntrackd is a no-op without a peer) — both toggles render their
  "simulated in Phase 1" labels.

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

### 5.5 Notifications & resource alerts
- `alerts:new` payload rows are persisted by the engine as `Notification` rows; `isRead` is
  the only mutable field in Phase 1 (no delete/dismiss endpoint — pruning is automatic).
- Severity enum is the dedicated `notifications.severity` row of PROJECT_MEMORY §6:
  `info|warning|critical` (3-level — matches SCHEMA.md and the spec; the 5-level scale is
  `ips_events`-only).
- **Resource alerts (spec §1.14, restored REVIEW-4A):** the MockEngine compares each tick's
  `cpuPct/memPct/diskPct/tempC` against the `notifications/thresholds` setting (seed: cpu 90,
  mem 90, disk 85, temp 80 — DATA_LIFECYCLE §2.5). Crossing a threshold emits one
  `Notification` (`type: "system"`, `warning` on first crossing, `critical` beyond +10 pp or
  sustained 5 min) with `sourceModule: "system"`; re-entering normal range emits an `info`
  recovery row. Alerts are edge-triggered (no per-tick spam): one open notification per
  metric until it recovers.

### 5.6 Firmware (simulated)
- State lives in the `advanced/firmware` `SystemSetting` (SCHEMA.md §4):
  `{current, channel: "stable", lastCheckAt?, available?, history[]}`; no Prisma model.
- **Check:** POST sets `available` (simulated catalogue offers e.g. `1.0.1` when
  `MOCK_PROFILE` allows; deterministic per seed) + `lastCheckAt`.
- **Upgrade (staged, simulated):** creates a safety `config`-type backup first (visible in
  `#/system/backups`), then bumps `current` → `available`, appends `{version, appliedAt}` to
  `history`, writes `audit_log` (`firmware.upgrade`), and broadcasts `config:updated
  {section: "system"}`. Appliance reality (CONTROL_PLANE §6): apt + systemd staged apply with
  per-service health checks and automatic rollback — the console contract (one audited POST,
  state visible after) is identical.
- **Rollback:** restores the previous `history` entry as `current` (simulated; appliance:
  previous versioned backup + package set). 409 when history has < 2 entries or an upgrade is
  already staged.
- HA note: upgrades on an HA pair follow the standby-first ordering in CONTROL_PLANE §6 —
  the sandbox has no peer, so the wizard text is display-only.

### 5.7 NTP, SNMP, hardening (settings-backed, restored REVIEW-4A)
- **NTP** (`general/ntp`): `{enabled, servers[], synced, lastSyncAt?}`; zod validates each
  server as host/IP; the engine flips `synced` true after the first tick following an enabled
  save (simulated reachability). Appliance: chrony/systemd-timesyncd rendering.
- **SNMP** (`advanced/snmp`): version radio `v2c|v3` (locked enum `snmp.version`); v2c
  `community` is **write-only and masked on read** (same masking rule as RADIUS
  sharedSecret, M07 §5.3); v3 exposes user + auth/priv protocol choices; `allowedIps` entries
  validated as IP/CIDR. Appliance renders `snmpd.conf`; sandbox records config only.
- **Hardening** (`advanced/hardening`): `{sshPasswordAuth, managementAllowlist[],
  stopUnusedServices}`; disabling `sshPasswordAuth` shows an inline warning ("ensure at least
  one SSH key exists — see below") linking the SSH keys card. Appliance effects: sshd_config,
  nftables mgmt-plane allowlist, systemd masking of unused services; sandbox records only.
- **SSH keys:** `publicKey` must parse as an OpenSSH public-key line (zod + shape check);
  `fingerprint` = sha256 of the key material, derived server-side (never client-supplied);
  private keys are rejected. DELETE removes the `authorized_keys` entry appliance-side and is
  audited.

### 5.8 Setup wizard & policy templates
- `setup.completed` is a normal `SystemSetting` row — the gate is a read of that row at
  shell-mount (cached per session; `config:updated {section: "system"}` re-evaluates it).
- **Templates:** `GET /system/policy-templates` returns a static catalog (per vertical:
  office / hospitality / MSP-branch) whose payload bundles starter rows for firewall/NAT/
  IPS/DNS/QoS sections. `POST …/apply` runs each section's normal create/update pipeline in
  one transaction, writes ONE `config_versions` snapshot with `section: "all"` (sentinel),
  and broadcasts `config:updated {section: "all"}` (same sentinel semantics as restore, §5.3
  — flagged in §8). Template ids are stable strings (`tpl-office`); applying twice is
  idempotent-by-replace for named seed rows, additive otherwise.

---

## 6. Realtime

| Event (§7.3, verbatim) | Reaction in this module |
|---|---|
| `alerts:new` `{ notification: Notification }` | Bell unread badge increments; popover list prepends the row; a toast fires for `severity: "critical"` only. Resource-alert and firmware/restore notifications arrive here (types `system` / `ha` / `config`) |
| `config:updated` `{ section }` | Invalidate matching query keys; after restore or template-apply (section `"all"`) invalidate **all** queries and re-evaluate the `setup.completed` gate; HA view refetches `/ha/status` on section `ha`; settings cards refetch on section `system` |
| `metrics:tick` | Feeds the health strip's cpu/mem values between `/system/status` polls; the threshold engine consumes the same values server-side (§5.5) |
| `logs:tail`, `sessions:update`, `wan:status` | Not consumed here (M09 / M07 / M02) |

---

## 7. Acceptance Criteria (checklist)

- [ ] `#/ha` renders status + editor; role enum offers exactly `disabled|active|standby`; validation rejects `holdDownSec < failAfterSec` and malformed VIP/peerIp.
- [ ] HA status shows local role, simulated peer reachability dot, last heartbeat age, last failover, tracked-interface state chips, and sync chips; the explanation panel describes Keepalived/conntrackd semantics and links SIMULATION_LAYER §5 instead of a new diagram.
- [ ] `sessionSync` and `trackedInterfaces` save with the HA config (`PUT /ha/config`), and a down tracked interface is reflected in the status chips (simulated).
- [ ] `#/system/settings` saves each card as a `{category,key,value}` batch; hostname/timezone changes reflect after refetch; retention overrides show current hard caps.
- [ ] NTP card saves `general/ntp` and shows the simulated `synced` state + `lastSyncAt`; server list add/remove validates each entry.
- [ ] SNMP card enforces the `v2c|v3` radio; the v2c community renders masked after save (write-only); v3 shows auth/priv protocol selects; `allowedIps` rejects malformed entries.
- [ ] Hardening card persists the three keys; turning `sshPasswordAuth` off with zero SSH keys shows the inline warning linking the SSH keys card.
- [ ] Firmware card: "Check for updates" sets `available` + `lastCheckAt`; "Upgrade now" creates a safety backup row before the version bump, appends a history entry, and is audited; "Roll back" restores the previous history entry (409 with < 2 entries).
- [ ] SSH keys: an `authorized_keys`-style line saves with a server-derived fingerprint; a private-key blob is rejected `400`; delete is audited.
- [ ] Policy templates: catalog renders per vertical; apply is audited, snapshots `section: "all"`, and every view refetches via the `config:updated` sentinel.
- [ ] `#/setup` renders instead of the shell while `setup.completed` is false; finishing runs `POST /system/setup/complete` and the shell renders on the next gate check.
- [ ] Resource alerts: pushing a metric past its threshold (demo helper or profile) produces exactly one `system` notification per metric until recovery; severity follows the 3-level map.
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
- **Restore / template-apply broadcast sentinel:** `config:updated { section: "all" }` is proposed here (restore and template-apply both use it); the realtime service and client cache-invalidation logic must agree on the sentinel (or emit one event per restored section).
- **Setup wizard gate is hard** (no "skip for now"): demo environments always pass through the wizard once; acceptable for onboarding fidelity, but a `SETUP_SKIP=1` env escape hatch may be wanted for CI screenshots — decide at build time, do not weaken the gate silently.
- **Firmware simulation depth:** the sandbox version bump is instant; consider a ~5 s staged spinner to teach the appliance's staged-apply UX. No contract impact (single audited POST either way).
- **SNMP community masking** reuses the fixed-length `"••••••••"` literal (M07 §5.3 rule); ensure the settings PUT ignores that literal on save (omit-to-keep semantics), same as directory-source bindPassword.
- ~~**Notification severity enum conflict**~~ RESOLVED: PROJECT_MEMORY §6 has a dedicated `notifications.severity` row — `info|warning|critical` (matches SCHEMA.md and the spec); the 5-level scale is `ips_events`-only.
- ~~**HA priority direction**~~ RESOLVED: higher wins (Keepalived semantics) — SCHEMA.md and this doc agree; no adapter mapping needed.
- ~~**Firmware upgrade/rollback, NTP, SNMP, SSH keys, wizard, templates, hardening deferred**~~ RESOLVED (REVIEW-4A): all restored per the owner zero-loss ruling — endpoints in PROJECT_MEMORY §7.2, shapes in SCHEMA.md §4, view surfaces in §4 above.
- Key `lastUsedAt` throttling (1/min/key) trades freshness for write volume; if demos need exact metering, move to a per-request update behind a feature flag.

# M07 — Identity & Access

> TL;DR: Console users, groups, auth policy, RADIUS profiles, captive portal + guest vouchers,
> and the live IP→user identity session map. Secret fields (sharedSecret/totpSecret) are never
> returned in clear by the API; reveal is an explicit, audited, role-gated endpoint.

Related: ../00-PROJECT-MEMORY/PROJECT_MEMORY.md (§6 enums, §7.2 API, §7.3 realtime, §8 views) ·
../07-SECURITY/AUTH_AND_RBAC.md (role matrix — authoritative) · ../03-DATABASE/SCHEMA.md ·
../03-DATABASE/ER_DIAGRAM.md · ../02-ARCHITECTURE/SIMULATION_LAYER.md · ../04-API/ENDPOINTS.md ·
../04-API/API_STANDARDS.md · ../05-FRONTEND/UI_DESIGN_SYSTEM.md · ../05-FRONTEND/PAGE_MAP.md ·
../05-FRONTEND/STATE_AND_DATA_FLOW.md · ../01-PRODUCT/ROADMAP.md ·
siblings: M08-QOS.md (per-user shaping consumers), M09-LOGGING.md (audit view), M10-SYSTEM.md (api-keys UI)

---

## 1. Purpose & Scope (Phase 1)

This module manages *who* is on the network and *who* may use the console: local users with
the 8-role RBAC enum, user groups, the auth policy that login/password flows enforce, RADIUS
profiles for external authentication, the captive portal (click-through / credentials /
voucher) with guest voucher generation, and the live identity session map that feeds
user-based firewall rules (M03) and per-user QoS (M08).

**In scope (Phase 1):**

| Area | Contents |
|---|---|
| Users | CRUD (username, email, role from the 8-value enum, `isActive` toggle), password set/reset honoring auth policy, last login display |
| User groups | CRUD + member multiselect (join table semantics) |
| Auth settings | Password policy (min length, complexity, expiry), lockout (attempts, window), session lifetime; TOTP **stub only** (§5.6) |
| RADIUS profiles | CRUD (serverIp, authPort, sharedSecret **masked**, timeoutSec, retries) + simulated test-connection |
| Captive portal | Single profile editor (enabled, mode `clickthrough\|credentials\|voucher`, interface, session timeout, bandwidth cap, redirect URL, voucher TTL) |
| Vouchers | Generation dialog (N time-limited codes, shown once, CSV download), voucher list with state |
| Identity sessions | Live ip→user map with method badges `local/radius/captive_portal/vpn`, started/last seen, expire action |

**Out of scope (deferred — see ../01-PRODUCT/ROADMAP.md):** AD/LDAP sync (upstream Ready, no
Phase-1 contract), SSO/SAML/OIDC/Kerberos (spec cut to Phase 2), RADIUS CoA and Dynamic VLAN
(Phase 2), concurrent session limits, user activity timeline (Phase 2), real TOTP enrollment
and login MFA challenge (Phase 2 — stub noted in §5.6), voucher persistence across restarts
(§8), 802.1X/MAB flows.

---

## 2. Data Model

From ../03-DATABASE/SCHEMA.md §3 (names verbatim).

| Model | Fields used here | Notes |
|---|---|---|
| `User` | `username`, `passwordHash` (bcrypt, never exported), `role` (8-value enum, PROJECT_MEMORY §6), `email?`, `totpSecret?` (**never serialized**), `isActive`, `lastLoginAt?` | `@@unique([tenantId, username])`; deleting a user SET NULLs `audit_log.userId` (username string kept) and cascades group memberships |
| `UserGroup` | `name`, `description?` | `@@unique([tenantId, name])` |
| `UserGroupMember` | `groupId` + `userId` (composite PK) | Both FKs `onDelete: Cascade` — membership rows only |
| `SystemSetting` (category `auth`) | Password policy, lockout, session lifetime, TOTP flag (JSON, shape §5.5) | Seed: lockout 5 attempts / 15 min (DATA_LIFECYCLE §2.5) |
| `RadiusProfile` | `name`, `serverIp`, `authPort` (default 1812), `sharedSecret` (**masked in API responses**), `timeoutSec` (default 3), `retries` (default 2) | `@@unique([tenantId, name])` |
| `CaptivePortalProfile` | `name`, `enabled` (default false), `mode` (`clickthrough\|credentials\|voucher`), `interfaceName`, `sessionTimeoutMin` (default 240), `bandwidthKbps?`, `redirectUrl?`, `voucherTtlHours` (default 24) | Single active profile per tenant in Phase 1 (list endpoint returns the profile) |
| `IdentitySession` | `userName`, `sourceIp` (**unique per tenant** — one session per IP), `method` (`local\|radius\|captive_portal\|vpn`), `deviceMac?`, `startedAt`, `lastSeen`, `state` (`active\|expired`) | Index `(tenantId, state)`; ~15 seeded, churns per tick (ER_DIAGRAM §5) |

**Non-table data (mechanism, not new models):** guest **vouchers** have no Prisma model by
design (SCHEMA.md §6 Pseudo-Resources) — Phase 1 keeps them in the MockEngine in-memory
store behind the locked voucher endpoints in §3 (persistence trade-off flagged in §8).

---

## 3. API Surface

Paths verbatim from PROJECT_MEMORY §7.2. Envelope/errors per ../04-API/API_STANDARDS.md.

| METHOD | Path | Purpose | Triggering UI action |
|---|---|---|---|
| GET | `/api/v1/users` | List users (`?q=`, `?role=`, `?groupId=`) | Open `#/identity/users` |
| POST | `/api/v1/users` | Create user (password required, policy-checked) | "Add User" dialog submit |
| PUT | `/api/v1/users/{id}` | Update user; optional `password` key = set/reset password | User dialog submit; "Reset password" action |
| DELETE | `/api/v1/users/{id}` | Delete user (self-delete and last-admin denied) | Row action "Delete" (ConfirmDialog) |
| GET | `/api/v1/user-groups` | List groups incl. member ids | Open groups card on `#/identity/users` |
| POST | `/api/v1/user-groups` | Create group | "Add Group" dialog |
| PUT | `/api/v1/user-groups/{id}` | Update group incl. `memberIds` (replace-all semantics) | Group dialog submit |
| DELETE | `/api/v1/user-groups/{id}` | Delete group (memberships cascade, users untouched) | Row action "Delete" |
| GET | `/api/v1/auth-settings` | Read auth policy | Open Auth Settings card |
| PUT | `/api/v1/auth-settings` | Save auth policy | Auth Settings card "Save" |
| GET | `/api/v1/radius-profiles` | List profiles (sharedSecret masked) | Open RADIUS card |
| POST | `/api/v1/radius-profiles` | Create profile | RADIUS dialog submit |
| PUT | `/api/v1/radius-profiles/{id}` | Update profile (omit `sharedSecret` to keep) | RADIUS dialog submit |
| DELETE | `/api/v1/radius-profiles/{id}` | Delete profile | Row action "Delete" |
| GET | `/api/v1/captive-portal` | Read portal profile | Open `#/identity/portal` |
| PUT | `/api/v1/captive-portal` | Save portal profile | Portal "Save" |
| POST | `/api/v1/radius-profiles/{id}/test` | Simulated test-connection → `{ok, latencyMs}` | RADIUS card "Test" button |
| POST | `/api/v1/radius-profiles/{id}/reveal` | Reveal `sharedSecret` (super_admin/tenant_admin; **audited**; rate-limited) | "Reveal secret" action |
| GET | `/api/v1/identity/sessions` | Live ip→user sessions (`?method=`, `?state=active`) | Open `#/identity/sessions` |
| POST | `/api/v1/identity/sessions/{id}/expire` | Admin expire → `state: "expired"` + `sessions:update {kind:"identity"}` | Row action "Expire" |
| GET | `/api/v1/captive-portal/vouchers` | List vouchers (code masked to last 4 chars) | Vouchers card load |
| POST | `/api/v1/captive-portal/vouchers` | Body `{ count: 1–500, ttlHours?, bandwidthKbps? }` → batch-create codes; **response is the only time the full codes are returned** | "Generate vouchers" dialog |
| DELETE | `/api/v1/captive-portal/vouchers/{id}` | Revoke one voucher | Voucher row "Revoke" |

**Expected error cases:** `VALIDATION_ERROR` 400 (weak password vs auth policy — error
`details` names the failed rule; bad email/mac/IPv4; role outside enum); `CONFLICT` 409
(duplicate username, duplicate group/profile name, deleting the last enabled `super_admin`/
`tenant_admin` user, self-delete); `FORBIDDEN` 403 (non-privileged reveal attempt, RBAC deny);
`UNAUTHORIZED` 401; lockout returns `401 UNAUTHORIZED` with `error.code = "UNAUTHORIZED"` and
`details.lockedUntil` (login is owned by the auth module; policy comes from here).

---

## 4. Views & Interactions

Three hash views (LOCKED §8). Layout/components per ../05-FRONTEND/PAGE_MAP.md and
../05-FRONTEND/UI_DESIGN_SYSTEM.md; forms via react-hook-form + zod; all mutations audited.

### `#/identity/users`

- **Layout:** two-column on xl — left: Users `DataTable` (username, email, role badge, active
  badge, groups chips, lastLoginAt); right (or top bar): "User Groups" card (group list with
  member count, add/edit/delete).
- **User editor dialog:** username, email, role Select, isActive switch, groups multiselect,
  password fields (set on create; "Reset password" generates or accepts a new one). TOTP row:
  `Not enrolled` + disabled button **"Enroll TOTP (Phase 2)"** — explicit stub, do not fake
  enrollment.
- **Role descriptions table** (shown as help text next to the role Select; matrix authority:
  ../07-SECURITY/AUTH_AND_RBAC.md):

| Role | Phase-1 description |
|---|---|
| `super_admin` | Everything, including HA, backup/restore, API keys, auth settings, user management |
| `tenant_admin` | Full configuration of the tenant's security/network stack; no appliance-level system keys |
| `security_admin` | Firewall, NAT, objects, IPS policies + events, VPN session operations, logs and threat response (authority: ../07-SECURITY/AUTH_AND_RBAC.md §4) |
| `network_admin` | Interfaces, routing, WAN, DHCP, DNS, QoS, HA, VPN configuration |
| `soc_analyst` | Read security telemetry; live tail; suppress IPS events |
| `helpdesk` | Read identity sessions and VPN sessions; mark notifications read; no configuration or user changes |
| `auditor` | Read-only everywhere, including audit log |
| `api_service` | Machine-account marker role (API keys act through scopes, not this role's UI) |

- **User Groups card:** name, description, members multiselect (users list); save = `PUT` with
  `memberIds` (replace-all; service diffs into `UserGroupMember` rows).
- **States:** skeletons; EmptyState for groups ("Create your first group"); delete-user
  ConfirmDialog lists dependent effects (group memberships removed, audit preserved as
  former-username).

### `#/identity/sessions`

- **Layout:** full-width live `DataTable`: sourceIp (mono), userName, method badge — `local`
  (emerald), `radius` (teal), `captive_portal` (amber), `vpn` (violet) — deviceMac, startedAt,
  lastSeen ("x s ago", ticking), state badge. Filter chips by `method`; `?state=active` default.
- **Data:** `GET /api/v1/identity/sessions` + `sessions:update` socket deltas (§6).
- **Row action:** "Expire" on active sessions (proposed endpoint, §3) with ConfirmDialog.
- **Empty/error:** empty map → EmptyState "No active identity sessions"; socket
  disconnected → amber banner "Live updates paused" with reconnect state from the socket hook.

### `#/identity/portal`

- **Layout:** stacked cards. (1) **Portal settings** form: enabled switch; mode Select with
  explanatory caption per mode; interface Select; sessionTimeoutMin; bandwidthKbps (optional,
  hint "applies a per-guest cap via QoS"); redirectUrl (URL validation); voucherTtlHours.
  (2) **Guest vouchers** card (visible always; generate disabled unless mode = `voucher`).
- **Voucher generation dialog:** count (1–500), TTL override (defaults to profile
  `voucherTtlHours`), optional bandwidth cap. Submit → `POST /api/v1/captive-portal/vouchers` →
  **one-time reveal dialog**: full codes list, "Copy all" and "Download CSV"
  (columns: `code,expiresAt`); after closing, codes are never shown whole again.
- **Voucher table:** code (masked `…last4`), state badge (`unused` emerald / `used` zinc /
  `expired` amber), createdAt, expiresAt, usedAt. Filters by state; CSV export of the
  *masked* list allowed.
- **Guest self-registration note** (simulated): in `credentials` mode the MockEngine
  occasionally "self-registers" a guest and opens an `IdentitySession` with
  `method: "captive_portal"` (SIMULATION_LAYER §6 sessions generator); a `notifications`
  row of type `system` may be emitted at low rate. This is display-only behavior — there is
  no guest-facing portal UI in Phase 1.
- **States:** portal disabled → amber inline banner "Captive portal is disabled" above cards;
  voucher list EmptyState with "Generate vouchers" CTA.

---

## 5. Business Logic & Validation

### 5.1 Users & groups
- Username `^[a-z0-9._-]{3,32}$`; email zod-validated when present; `role` from the §6 enum.
- Password set/reset travels as `password` on POST/PUT, is bcrypt-hashed server-side, and is
  **never** echoed back nor written to `audit_log` (before/after JSON must redact
  `passwordHash` and `totpSecret` — masking rule, ADR-011).
- Delete guardrails: cannot delete self; cannot delete the last enabled user with role
  `super_admin` or `tenant_admin` → `409 CONFLICT`.
- Group membership: PUT replaces the member set atomically (tx: delete-missing, create-new).

### 5.2 Auth settings enforcement (GET/PUT `/api/v1/auth-settings`)
- JSON shape (zod): `{ password: { minLength: 8–64, requireComplexity: boolean, expiryDays: 0–365 },
  lockout: { maxAttempts: 3–10, windowMin: 5–60 }, sessionLifetimeHours: 1–24 }`.
  Seed: complexity on, expiry 90 d, lockout 5 / 15 min, session 8 h (matches ADR-007 JWT).
  No `totpRequired` key in Phase 1 — an enforce-TOTP switch is a Phase 2 addition
  (../07-SECURITY/AUTH_AND_RBAC.md §6; the schema column `User.totpSecret` already exists).
- `PUT` validates the *current* users against the new password policy? No — policy applies to
  new/changed passwords only; expiry is checked at login (simulated).
- Login flow consumes this policy (lockout counters, expiry) — mechanics in
  ../07-SECURITY/AUTH_AND_RBAC.md; this module only owns the editor.

### 5.3 RADIUS profiles & masking (STRICT)
- `sharedSecret` is write-only through POST/PUT; **every** read returns the masked literal
  `"••••••••"` (fixed-length; do not leak length). Reveal only via
  `POST /api/v1/radius-profiles/{id}/reveal`, gated to `super_admin`/`tenant_admin`, audited
  with `result` and `sourceIp`, never included in list endpoints.
- PUT semantics: omitting `sharedSecret` keeps the stored value (the masked string sent back
  must be ignored by the server).
- Test-connection (simulated): SimulatedAdapter answers `ok: true` with seeded jitter
  latency 5–40 ms for syntactically valid targets, and `ok: false` for invalid/undroutable IPs
  (e.g. documentation ranges marked dead in the profile). No RADIUS packets exist in sandbox
  (SIMULATION_LAYER §9).

### 5.4 Captive portal & vouchers
- Profile is singleton per tenant: `PUT` upserts the single row; `enabled=false` stops
  simulated portal sessions.
- Voucher codes: `cks-XXXX-XXXX` (Crockford base32, server-generated, unique among live
  vouchers); TTL = generation-time `ttlHours` (falls back to profile); states: `unused` →
  `used` (first simulated portal login) / `expired` (TTL or profile change). Simulated
  portal logins consume `unused` vouchers at a low rate while `mode = "voucher"`.
- In-memory store caveat: vouchers do not survive process restart; the UI must label the
  card "Volatile in sandbox" — flagged in §8.

### 5.5 Identity sessions (simulated)
- Generated by the sessions generator (SIMULATION_LAYER §6): pool of users × methods, IPs
  from LAN/guest/VPN pools; `@@unique([tenantId, sourceIp])` means a new login from the same
  IP replaces the prior session; `lastSeen` bumps per tick while active; sessions age to
  `expired` after the portal/session timeout.
- `method` values are exactly the locked enum: `local`, `radius`, `captive_portal`, `vpn`.
- Admin expire (`POST /api/v1/identity/sessions/{id}/expire`) sets `state: "expired"` and
  emits `sessions:update`.

### 5.6 TOTP stub (say it plainly)
- `User.totpSecret` exists in the schema but Phase 1 has **no enroll, no verify, no login
  challenge**. The users table renders a placeholder row ("Not enrolled", disabled Phase-2
  button). `totpSecret` is excluded from every API response; no enforce-TOTP switch is
  exposed in `auth-settings` in Phase 1 (AUTH_AND_RBAC §6).

---

## 6. Realtime

| Event (§7.3, verbatim) | Reaction in this module |
|---|---|
| `sessions:update` `{ kind: "identity", diff: [...] }` | `#/identity/sessions` merges the diff into the live table (new/updated/expired rows) without a full refetch; badge counts update |
| `config:updated` | `config:updated` carries `section`; mutations here broadcast `section: "identity"` (the locked ConfigSection — ARCHITECTURE §5, STATE_AND_DATA_FLOW §2) → invalidate `['users', …]`, `['user-groups', …]`, `['radius-profiles', …]`, `['auth-settings', …]`, `['captive-portal', …]`, `['identity-sessions', …]` |
| `alerts:new` | Not consumed here (topbar notification center — M10) |
| `logs:tail`, `metrics:tick`, `wan:status` | Not consumed here |

Socket connect remains `io("/?XTransformPort=3003")` with `subscribe { channels: [...] }`;
sessions view subscribes to `alerts`-free channels per ../05-FRONTEND/STATE_AND_DATA_FLOW.md.

---

## 7. Acceptance Criteria (checklist)

- [ ] Users CRUD works end-to-end; role Select offers exactly the 8 enum values with the descriptions table as help text.
- [ ] Creating a user with a password violating the auth policy returns `VALIDATION_ERROR` whose `details` name the failed rules; the dialog shows them inline.
- [ ] "Reset password" is denied to `helpdesk` with `403 FORBIDDEN` (RBAC matrix: only tenant_admin/super_admin may mutate users; helpdesk is read-only here).
- [ ] Self-delete and last-admin delete are refused with `409 CONFLICT` and a human-readable message.
- [ ] Group editor multiselect saves via replace-all `memberIds`; membership chips on the users table update after `config:updated`.
- [ ] `GET /api/v1/radius-profiles` returns `sharedSecret: "••••••••"` everywhere; no list/detail response ever contains the clear secret.
- [ ] Reveal endpoint is reachable only for super_admin/tenant_admin, is audited, and the UI requires a second click ("Reveal secret") with auto-hide after 15 s.
- [ ] Test-connection returns the simulated `{ ok, latencyMs }` and renders success (emerald) / failure (rose) states.
- [ ] Portal editor validates redirectUrl and enforces mode-conditional voucher UI; saving broadcasts `config:updated` and snapshots a config version.
- [ ] Voucher generation of N codes shows each code exactly once, supports Copy all and CSV download; the list afterwards shows masked codes with correct state badges.
- [ ] `#/identity/sessions` shows the live map, updates from `sessions:update` diffs within one tick, and method badges use the four locked enum values.
- [ ] Expire action on a session calls `POST /api/v1/identity/sessions/{id}/expire` and the row flips to `expired` without reload.
- [ ] TOTP is visibly a stub (disabled control labeled Phase 2) and `totpSecret` never appears in any network response.
- [ ] Audit rows for user/password mutations contain no `passwordHash`/`totpSecret` values in before/after JSON.
- [ ] `bun run lint` passes; only hash navigation changes (no new Next.js routes).

---

## 8. Open Questions & Risks

- **Voucher storage is in-memory by design (Phase 1).** SCHEMA.md §6 Pseudo-Resources and AUTH_AND_RBAC §7 record the decision: MockEngine store, volatile across restarts, durable `captive_portal_vouchers` table deferred to Phase 2 (spec lists it under "Phase 2+ tables — add when needed"). Mirror any persistence change in SCHEMA.md + ENDPOINTS.md.
- ~~**Password reset transport**~~ RESOLVED: `password` inside `PUT /api/v1/users/{id}` is the documented contract (ENDPOINTS.md §9); no dedicated password endpoint in Phase 1.
- ~~**Reveal/test/expire/vouchers are PROPOSED EXPANSIONS**~~ RESOLVED: all of them are in the LOCKED surface now (PROJECT_MEMORY §7.2 + ENDPOINTS.md §9); §3 lists them as first-class endpoints.
- ~~**Identity `config:updated` section naming**~~ RESOLVED: section `identity` is locked (ARCHITECTURE §5 ConfigSection union, STATE_AND_DATA_FLOW §2 invalidation table).
- Masking constant `"••••••••"` must not leak real length; ensure server masks, never the client.
- Session replace-on-same-IP (`@@unique([tenantId, sourceIp])`) can surprise in demos where VPN and LAN identities collide; the sessions view should surface the replaced session in the audit/notifications trail if product wants history.

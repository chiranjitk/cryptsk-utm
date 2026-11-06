# M11 — API Platform

> TL;DR: The console-as-platform rules: API-key lifecycle and scope matrix, rate limiting,
> machine-client conventions (envelope, pagination, error contract), usage auditing,
> webhook registrations (simulated delivery in sandbox — the machine-facing change
> notifications), and the generated OpenAPI artifact. No dedicated UI view — keys and
> webhooks are managed in `#/system/api-keys` (M10); no swagger UI bundle ships in Phase 1.

Related: ../00-PROJECT-MEMORY/PROJECT_MEMORY.md (§7 API contract — LOCKED) · ../04-API/API_STANDARDS.md (authoritative standards) ·
../04-API/ENDPOINTS.md (full catalog) · ../07-SECURITY/AUTH_AND_RBAC.md (role matrix) · ../03-DATABASE/SCHEMA.md (ApiKey) ·
../05-FRONTEND/STATE_AND_DATA_FLOW.md (how the console itself consumes the API) · ../01-PRODUCT/ROADMAP.md ·
../02-ARCHITECTURE/ARCHITECTURE.md · siblings: M10-SYSTEM.md (key management UI), M03-FIREWALL.md (example resource)

---

## 1. Purpose & Scope (Phase 1)

Every console feature is API-first (ADR-002): the UI talks only to `/api/v1/…` route
handlers. This module defines the *platform* guarantees that make the same API usable by
machines: authentication modes (session cookie vs API key), scope enforcement, rate limits,
the response envelope and error contract, pagination, and audit of machine access.

Derived from upstream spec §1.15 (API) Phase 1 table — **fully covered per the owner
zero-loss ruling (REVIEW-4A)**:

| Upstream Phase 1 feature | Console Phase 1 decision |
|---|---|
| REST API (all features) | IN — every feature is a `/api/v1` route handler (ADR-002) |
| API versioning (`/api/v1/`) | IN — path-segment versioning, LOCKED (API_STANDARDS §1) |
| OpenAPI/Swagger docs | IN — `GET /api/v1/openapi.json` (OpenAPI 3.1 artifact generated from the zod validators + the §7.2 route table); the upstream `swaggo` row targets the Go appliance API — the console generates from zod. Human-readable docs = ENDPOINTS.md; **no swagger UI bundle** ships in Phase 1 (restored REVIEW-4A) |
| API key management (create, revoke, scope) | IN — `#/system/api-keys` + `ck_` bearer keys with the three LOCKED scope arrays |
| API rate limiting | IN — per-key 60/min, per-session 300/min, token bucket, `429` + `Retry-After` (§5.2 / API_STANDARDS §9) |
| API pagination | IN — offset/page pagination (LOCKED deviation from the spec's "cursor-based" note; API_STANDARDS §6 reserves cursors for Phase 2 at appliance log volumes) |
| API batch operations | IN — batch-style endpoints in the LOCKED surface: `POST /firewall-rules/import` (batch create), `/firewall-rules/reorder` + `/nat-rules/reorder` (batch reposition), `POST /captive-portal/vouchers` (batch generate), `POST /notifications/read-all` (batch update). A generic batch endpoint is **not** part of the contract |
| API request/response logging (audit) | IN — every mutation audited in `audit_log` by the shared handler; machine calls attributed to the key name (§5.3) |
| Webhook support (event callbacks) | IN — registration CRUD + HMAC secret + simulated delivery test (spec-Phase-1 product feature; **console ships stubs** per ROADMAP §5: sandbox marks deliveries instead of performing real HTTP; the appliance sender signs payloads with the secret) (restored REVIEW-4A) |
| API change notifications (WebSocket push) | IN — for **console** clients via the locked socket events (§7.3); for **machine** clients the notification channel is webhooks (above) + REST polling — the socket event set stays console-facing, so no new realtime event is introduced (see §6) |

**Out of scope (spec's own assignments or locked deviations — not deferrals):** API
sandbox/test console + idempotency keys (upstream Phase 2), GraphQL (dropped upstream), a
swagger UI bundle (docs stay ENDPOINTS.md + the openapi.json artifact), a generic batch
endpoint (the locked per-resource batch endpoints above cover §1.15's "batch operations").

---

## 2. Data Model

Only two models are platform-owned (SCHEMA.md §3): `ApiKey` and `Webhook`.

| Field | Meaning |
|---|---|
| `name` | Human label shown in lists and audit attribution |
| `prefix` | Unique `"ck_"` + 8 chars; stored in clear for lookup/display; the only surviving trace of the key |
| `hashedKey` | `sha256(full_key)`; lookup is by prefix then constant-time hash compare |
| `scopes` | JSON array — exactly one of `["read"]`, `["read","write"]`, `["read","write","admin"]` (SCHEMA §4) |
| `lastUsedAt` | Updated on successful key-authenticated requests (throttled ~1/min/key, M10 §5.4) |
| `expiresAt` | Optional; expired keys authenticate as `401 UNAUTHORIZED` |
| `revoked` | Soft-delete flag set by `DELETE /api/v1/api-keys/{id}`; revoked keys fail 401; the row remains for audit |
| `Webhook` | `name` (unique per tenant), `url` (https only), `events` (JSON array of the locked `webhooks.events` values), `secret?` (HMAC, write-only/masked), `enabled`, `lastDeliveryAt?`, `lastStatus?` (simulated), `failureCount`, `createdAt` | Registration row; delivery is simulated in sandbox (realtime-service marks fields), real signed HTTP happens appliance-side (§5.6) |

Key generation: `ck_` + 32+ URL-safe random chars (server-side CSPRNG); the full key is
returned **only** in the POST response and shown once in the M10 dialog. Sessions (cookie
`cryptsk_token`, JWT 8 h, ADR-007) are the *interactive* auth mode and are owned by the auth
module (../07-SECURITY/AUTH_AND_RBAC.md); this module only defines how keys differ from
sessions (§5.4).

---

## 3. API Surface

Key-management endpoints are LOCKED in PROJECT_MEMORY §7.2:

| METHOD | Path | Purpose | Triggering UI action |
|---|---|---|---|
| GET | `/api/v1/api-keys` | List keys (prefix, scopes, `lastUsedAt`, `expiresAt`, `revoked`, `createdAt`) — never the secret | Open `#/system/api-keys` (M10) |
| POST | `/api/v1/api-keys` | Create key; response carries the full key exactly once | "New API key" dialog (M10) |
| DELETE | `/api/v1/api-keys/{id}` | Revoke (soft) | "Revoke" row action (M10) |
| GET | `/api/v1/webhooks` | List registrations (`secret` masked, never returned) | Webhooks tab on `#/system/api-keys` (M10) |
| POST | `/api/v1/webhooks` | Register `{name, url, events, secret?}` | "Add webhook" dialog (M10) |
| PUT | `/api/v1/webhooks/{id}` | Update (omit `secret` to keep stored value) | Webhook editor save (M10) |
| DELETE | `/api/v1/webhooks/{id}` | Delete registration | Row delete action (M10) |
| POST | `/api/v1/webhooks/{id}/test` | Simulated delivery → `{ok, status, latencyMs}`; updates `lastDeliveryAt`/`lastStatus` | "Send test" row action (M10) |
| GET | `/api/v1/openapi.json` | OpenAPI 3.1 artifact (machine-readable docs) | Machine clients / curl |

Role floors (ENDPOINTS §14): webhooks are `security_admin`-floor for everything and
**interactive admins only — machine keys get none** (mirroring api-key create/revoke);
`GET /openapi.json` is `helpdesk`-floor (any authenticated principal).

Platform rules that apply to **every** other endpoint (full catalog:
../04-API/ENDPOINTS.md; standards: ../04-API/API_STANDARDS.md):

### 3.1 Scope matrix (what each scope may call)

| Scope | Allowed calls |
|---|---|
| `read` | All `GET` endpoints (lists, details, stats, logs, status) |
| `write` | `read` + `POST`/`PUT`/`PATCH` on configuration and operational resources: zones, objects, firewall/NAT rules, IPS policies/suppression, VPN, DNS, DHCP, QoS, WAN, notification mark-read |
| `admin` | `write` + identity/system mutations: `users` (create/update/delete, password reset), `user-groups`, `auth-settings`, `radius-profiles`, `captive-portal`, `ha/config`, `system/settings`, `system/backups` (create/restore), `config-versions` restore-flows |

Method-class notes: `DELETE` requires `write` for config resources but `admin` for backups;
**api-key create/revoke is denied to machine keys entirely** (AUTH_AND_RBAC §4 — keys cannot
manage keys; only an interactive `super_admin` session can). Any endpoint not listed defaults
to `read` for GET and `write` for mutations. Insufficient scope → `403 FORBIDDEN` with
`error.code = "FORBIDDEN"` (never 401 — the key authenticated fine). The authoritative
per-route matrix lives in ../07-SECURITY/AUTH_AND_RBAC.md; this table is the API-key
projection of it and must be kept consistent.

### 3.2 Expected error cases (platform-wide)

`VALIDATION_ERROR` 400 · `UNAUTHORIZED` 401 (missing/invalid/expired/revoked credential) ·
`FORBIDDEN` 403 (valid credential, insufficient scope/role) · `NOT_FOUND` 404 · `CONFLICT`
409 · `RATE_LIMITED` 429 · `INTERNAL` 500 — all in the error envelope (§5.4).

---

## 4. Views & Interactions

**No dedicated hash view in Phase 1** (view map §8 has no `#/api` entry, by design).

| Surface | Where it lives | Notes |
|---|---|---|
| Key management UI | `#/system/api-keys` tab "API Keys" — owned by M10 (create dialog with one-time secret reveal + copy, list with prefix/`lastUsedAt`/`expiresAt`/revoked, revoke ConfirmDialog) | This module defines the behavior; M10 renders it |
| Webhook registration UI | `#/system/api-keys` tab "Webhooks" — owned by M10 (CRUD, events multiselect, masked secret, "Send test") | Behavior defined here (§5.6); M10 renders it |
| Machine-client docs | This document (§5) + ../04-API/ENDPOINTS.md + `GET /api/v1/openapi.json` | The openapi.json artifact is generated from zod (§4.2); ENDPOINTS.md is the human catalog |

### 4.1 What NOT to build (negative requirements)

No `#/api` or `#/developers` view and **no swagger UI bundle** — absent by decision (§1).
The `openapi.json` **route itself is in the LOCKED surface** (ENDPOINTS §14) — do not remove
it, do not hand-write its content (it must be generated). Grep-verifiable in acceptance
criteria §7.

### 4.2 OpenAPI / documentation strategy

`GET /api/v1/openapi.json` (restored REVIEW-4A — the spec §1.15 "OpenAPI/Swagger docs" row)
serves a build-time-generated **OpenAPI 3.1 artifact**:

1. **Source of truth:** the zod validators in `src/lib/validators/` + the LOCKED route table
   in PROJECT_MEMORY §7.2 (single definition; no hand-written parallel spec to drift).
2. **Generation:** a build-time script compiles zod schemas → OpenAPI 3.1 (zod-to-json-schema
   pipeline) and emits the static artifact the route serves. The generation must fail the
   build if a route handler diverges from §7.2 (paths are LOCKED — expand, never rename).
3. **Human-readable docs** remain ENDPOINTS.md (kept in the same task as any route change);
   no interactive swagger UI ships in Phase 1.
4. Machine-client documentation = this module + ENDPOINTS.md + the artifact; all three update
   in the same task per the doc rules.

---

## 5. Business Logic & Validation

### 5.1 Key lifecycle rules

- Create: `name` required (1–64 chars; convention: prefix machine integrations with `bot-`),
  `scopes` restricted to the three LOCKED arrays, `expiresAt` optional future datetime.
  Response (flat, per ENDPOINTS.md §13): `{ "data": { …ApiKey row sans `hashedKey`…, "key": "ck_…full once…" } }`.
- Reveal: the full key exists only in that response; the M10 dialog gates closing behind an
  "I saved it" checkbox; `hashedKey` (sha256) is the only stored form.
- Revoke: `DELETE` sets `revoked = true` (soft), audited; the list keeps showing the row
  with a `revoked` badge — history is the point.
- Expiry: `expiresAt < now` fails auth with `401 UNAUTHORIZED` at request time — no cron.
- Update of scopes after creation: **not supported in Phase 1** (no PUT endpoint in §7.2) —
  create a new key instead; document this in the M10 dialog helper text.

### 5.2 Rate limiting (defaults — from API_STANDARDS §9, the authority)

| Subject | Sustained | Burst | On exceed |
|---|---|---|---|
| API key | 60 requests/min | short bursts allowed (token bucket) | `429 RATE_LIMITED`, `Retry-After` header (seconds) |
| Session (console UI) | 300 requests/min | short bursts above the average allowed (token bucket) | same |
| Login endpoint | 5 attempts/min per (username, source IP) | — | same (plus lockout policy from auth-settings, M07) |

- Counters are in-memory per process in sandbox (no Redis — ADR-010); appliance mode moves
  them to Redis. Semantics (headers, error shape) stay identical.
- Limit headers on every response: `X-RateLimit-Limit`, `X-RateLimit-Remaining`
  (informational; `Retry-After` only on 429).
- Exports (`/logs/firewall/export`, M09) count against the same budget.

### 5.3 Usage audit (machine attribution)

- Successful key auth updates `ApiKey.lastUsedAt` (throttled ~1/min/key).
- Every mutation performed with a key writes `audit_log` exactly like a user action:
  `username` = the key's `name`, `sourceIp` = client IP, `result` per outcome
  (`success`/`failure`/`denied`). Scope-denied calls are audited as `denied`; rate-limited
  requests are **not** audited (noise control).

### 5.4 Envelope, errors, pagination (recap + pointers)

- Envelope (LOCKED §7.1): success `{ "data": …, "meta"?: … }`; error
  `{ "error": { "code", "message", "details"? } }`. Full rules: ../04-API/API_STANDARDS.md.
- Error codes: `VALIDATION_ERROR` 400 · `UNAUTHORIZED` 401 · `FORBIDDEN` 403 ·
  `NOT_FOUND` 404 · `CONFLICT` 409 · `RATE_LIMITED` 429 · `INTERNAL` 500.
- Pagination: `?page=1&limit=25&sort=-timestamp` → `meta: { page, limit, total, totalPages }`.
  **Deviation vs upstream:** the product spec's 1.15 table says "cursor-based pagination";
  the Phase-1 build uses offset/page pagination as LOCKED here — cursor pagination is a
  Phase-2 consideration only (record in ROADMAP when revisited).
- Filtering: `?q=` free text + field filters (`?severity=critical&since=ISO&until=ISO`).

### 5.5 Quickstart (curl)

Examples use **relative paths only** (sandbox rule §11.5: no absolute URLs / no ports in
hostnames). At runtime a machine client prefixes its console origin, e.g.
`https://console.example.local/api/v1/…`.

```bash
# A) Interactive login (session cookie jar)
curl -c jar.txt -X POST /api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
# → 200 {"data":{"user":{"id":1,"username":"admin","role":"super_admin", …}}}
# Subsequent calls: curl -b jar.txt …

# B) Machine client with an API key (no cookie)
curl -H "Authorization: Bearer ck_s3cr3t…" "/api/v1/firewall-rules?page=1&limit=25&sort=position"
# → 200 {"data":[ …rules… ],"meta":{"page":1,"limit":25,"total":12,"totalPages":1}}

# C) Create a firewall rule with a write-scope key
curl -X POST /api/v1/firewall-rules \
  -H "Authorization: Bearer ck_s3cr3t…" \
  -H "Content-Type: application/json" \
  -d '{"name":"Block guest SMB","action":"deny","logging":"summary"}'
# → 201 {"data":{"id":13,"name":"Block guest SMB","action":"deny", …}}
#     (unspecified fields take schema defaults; audit row written; config:updated broadcast)

# D) Scope denial is a 403, not a 401
curl -X POST /api/v1/firewall-rules -H "Authorization: Bearer ck_readonly…" \
  -H "Content-Type: application/json" -d '{"name":"x","action":"allow"}'
# → 403 {"error":{"code":"FORBIDDEN","message":"Key scope 'read' does not allow this action"}}

# E) Rate limited
# → 429 {"error":{"code":"RATE_LIMITED","message":"Too many requests"}} + Retry-After: 30
```

Client rules of thumb: never log the full key; branch on `error.code`, not messages;
respect `Retry-After`; expect identical shapes for key and session auth (no dual API).

### 5.6 Webhooks (registration + simulated delivery — restored REVIEW-4A)

- **Registration:** `POST /api/v1/webhooks` takes `{name, url, events, secret?}`; `url` must
  be **https**; `events` is a JSON array drawn exactly from the locked `webhooks.events` enum
  (PROJECT_MEMORY §6): `alerts.new`, `config.updated`, `wan.status`, `vpn.status`,
  `sessions.update` — the dot-form of the console realtime events. `logs.tail` is deliberately
  excluded to protect log volume. `secret` (HMAC) is write-only: set on POST, omitted on PUT
  to keep, never returned by GET (same masking rule as RADIUS sharedSecret, M07 §5.3).
- **Delivery (sandbox = simulated stub):** the realtime-service does **not** perform real
  HTTP. When a matching event fires, it marks the registration (`lastDeliveryAt`, `lastStatus`
  e.g. `"200"`/`"timeout"`, `failureCount`) with seeded outcomes; "Send test" runs one marked
  delivery and returns `{ok, status, latencyMs}`. The **appliance** sender performs real
  signed POSTs (HMAC-SHA256 header using the registration secret) — ROADMAP records this
  stub-vs-real nuance; no contract change is needed when the real sender lands.
- **Payloads:** mirror the §7.3 event payloads (`{notification}` / `{section}` / `{iface,
  state}` …) wrapped as `{event, ts, data}` so consumers can branch on `event`.
- **Error cases:** `409 CONFLICT` duplicate webhook name (unique per tenant); `400`
  VALIDATION_ERROR invalid `url` (https enforced) or an event outside the enum; `404`
  unknown id; `403 FORBIDDEN` machine keys (registration is interactive-admin-only,
  ENDPOINTS §14). Deliveries are never audited per-attempt (noise); registration mutations
  are audited.

---

## 6. Realtime

| Concern | Phase-1 position |
|---|---|
| Socket events for machine clients | **None.** The LOCKED event set (`metrics:tick`, `logs:tail`, `alerts:new`, `sessions:update`, `wan:status`, `vpn:status`, `config:updated`, §7.3) is console-facing only; machine clients consume **webhooks** (dot-form subset: `alerts.new`, `config.updated`, `wan.status`, `vpn.status`, `sessions.update` — §5.6) and poll the REST API. No new socket event was needed by any restored feature — the 7-event set is unchanged |
| Webhooks / event callbacks | **In Phase 1 as simulated stubs** (§5.6, ROADMAP nuance): registration UI + marked deliveries in sandbox; real HMAC-signed sender is appliance-side. Do not add a second sender or a delivery-retry engine in the console |
| `config:updated` | Console-side cache invalidation trigger (../05-FRONTEND/STATE_AND_DATA_FLOW.md §2); the `config.updated` webhook carries the same `{section}` payload for machine consumers |
| Appliance-mode transport | Realtime stays socket.io → appliance mode swaps to Redis pub/sub → Go → WebSocket with the same event names (ADR-008/ADR-010) — transparent to this module; the webhook sender joins the appliance side without a console contract change |

---

## 7. Acceptance Criteria (checklist)

- [ ] `POST /api/v1/api-keys` returns the full key exactly once; it is nowhere retrievable afterwards (list/detail/audit/DB all show `prefix` only).
- [ ] `hashedKey` is sha256 of the full key; a DB inspect never reveals a usable secret.
- [ ] A `read`-scope key succeeds on `GET /api/v1/firewall-rules` and receives `403 FORBIDDEN` on `POST` (not `401`).
- [ ] A `write`-scope key can create/update config resources but receives `403` on `POST /api/v1/api-keys` and on backup restore (admin-only).
- [ ] Revoked keys get `401 UNAUTHORIZED` on the next call; `expiresAt` in the past behaves identically without any job running.
- [ ] `DELETE /api/v1/api-keys/{id}` soft-revokes (`revoked = true`), keeps the row visible in the M10 list with a revoked badge, and is audited.
- [ ] Key scopes are restricted to the three LOCKED arrays; scope updates after creation are not offered (no PUT endpoint).
- [ ] `lastUsedAt` updates after a successful key call and is visible in `#/system/api-keys`.
- [ ] Machine mutations write `audit_log` rows attributed to the key name with `sourceIp` and correct `result`; denied-scope attempts are audited as `denied`; 429s are not audited.
- [ ] Exceeding the key rate limit returns `429 RATE_LIMITED` with `Retry-After` and the standard error envelope; limit headers are present on normal responses.
- [ ] Every error response matches `{ "error": { "code", "message", "details"? } }` with codes from the LOCKED set — spot-check 400/401/403/404/409/429.
- [ ] List endpoints return `meta: { page, limit, total, totalPages }` for `?page=&limit=&sort=` requests.
- [ ] Key-authenticated and session-authenticated calls return identical envelopes and shapes for the same resource (no dual API surface).
- [ ] `GET /api/v1/openapi.json` returns a parseable OpenAPI 3.1 document whose paths match the §7.2 route table exactly (no extra, no missing); the artifact is build-generated, not hand-maintained.
- [ ] Webhook registration: https-only URL enforced `400`; events outside the five locked values rejected `400`; duplicate name `409`; `secret` never appears in any GET/list response.
- [ ] "Send test" returns `{ok, status, latencyMs}`, updates `lastDeliveryAt`/`lastStatus`, and no real HTTP egress occurs in sandbox (simulated stub per ROADMAP).
- [ ] A machine key (any scope) receives `403 FORBIDDEN` on every `/webhooks*` call; `GET /openapi.json` with a `read`-scope key succeeds.
- [ ] No swagger UI bundle, no `#/api` view, and no generic batch endpoint exists in Phase 1 (grep-verifiable negatives); batch-style operations ride the LOCKED import/reorder/voucher/read-all endpoints.
- [ ] `bun run lint` passes; key + webhook management UI remains only in `#/system/api-keys` (M10) — no new views or routes.

---

## 8. Open Questions & Risks

- ~~**Rate-limit numbers are PROPOSED**~~ RESOLVED: §5.2 now mirrors API_STANDARDS §9 (key 60/min, session 300/min, login 5/min per username+IP); API_STANDARDS wins on future changes.
- **Scope matrix vs RBAC matrix drift:** §3.1 is the key-projection of ../07-SECURITY/AUTH_AND_RBAC.md; both docs must change in the same task whenever either changes — otherwise 403 behavior becomes unpredictable per route.
- **Webhook delivery is a stub by design** (RESOLVED REVIEW-4A, nuance kept): spec §1.15 lists webhooks as Phase-1 custom engineering; the console ships registration + simulated delivery (ROADMAP §5 "console ships stubs"), with the real HMAC sender appliance-side. If product later demands console-side real delivery, that is a contract change (new egress rules) — flag to the coordinator before building.
- **Machine-facing change notifications:** spec §1.15 "API change notifications (WebSocket push)" is satisfied for console clients by the locked socket events and for machine clients by webhooks + polling. If a machine-facing WebSocket channel is ever required, that would need a new event/surface decision (and an ADR) — currently deliberately not built; the 7-event realtime set is unchanged.
- **OpenAPI drift guard:** the generator must fail the build on §7.2 divergence; until the build exists, ENDPOINTS.md + this doc are the drift-controlled sources — update both in the same task as any route change.
- Attribution convention (`username` = key name, `bot-` prefix) is informal; consider a dedicated `actorType` column on `audit_log` in a Phase-2 schema pass instead of overloading strings.
- In-memory rate counters reset on process restart — acceptable in sandbox (ADR-010); appliance Redis counters must not silently change semantics (headers/limits) when AgentAdapter lands.
- Key secrets appear in shell history of whoever runs the quickstart; document `read -s` / env-file practice in the future developer guide (08-OPERATIONS) rather than complicating the API.
- Offset pagination + live-updating log tables can skip/repeat rows across pages; acceptable Phase 1 (log views pin `sort=-timestamp`), revisit with cursor pagination in Phase 2.
- ~~**Webhooks are spec-Phase-1 but contract-deferred**~~ RESOLVED (REVIEW-4A): `/webhooks*` + `/openapi.json` are in PROJECT_MEMORY §7.2 and ENDPOINTS §14; delivery is simulated (stub) in sandbox by ruling.

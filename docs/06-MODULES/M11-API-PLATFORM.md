# M11 — API Platform

> TL;DR: The console-as-platform rules: API-key lifecycle and scope matrix, rate limiting,
> machine-client conventions (envelope, pagination, error contract), and usage auditing.
> No dedicated UI view — keys are managed in `#/system/api-keys` (M10); webhooks and OpenAPI
> generation are documented strategy, explicitly NOT built in Phase 1.

Related: ../00-PROJECT-MEMORY/PROJECT_MEMORY.md (§7 API contract — LOCKED) · ../04-API/API_STANDARDS.md (authoritative standards) ·
../04-API/ENDPOINTS.md (full catalog) · ../07-SECURITY/AUTH_AND_RBAC.md (role matrix) · ../03-DATABASE/SCHEMA.md (ApiKey) ·
../05-FRONTEND/STATE_AND_DATA_FLOW.md (how the console itself consumes the API) · ../01-PRODUCT/ROADMAP.md ·
../02-ARCHITECTURE/ARCHITECTURE.md · siblings: M10-SYSTEM.md (key management UI), M03-FIREWALL.md (example resource)

---

## 1. Purpose & Scope (Phase 1)

Every console feature is API-first (ADR-002): the UI talks only to `/api/v1/…` route
handlers. This module defines the *platform* guarantees that make the same API usable by
machines: authentication modes (session cookie vs API key), scope enforcement, rate limits,
the response envelope and error contract, pagination, and audit of machine access. It also
records deliberate non-goals so nobody "helpfully" builds them early.

**In scope (Phase 1):**

| Area | Contents |
|---|---|
| Key lifecycle | Create (name, scopes, expiry), one-time secret reveal, list (prefix + `lastUsedAt`), revoke, expiry enforcement |
| Scope matrix | `read` / `write` / `admin` → allowed method classes per resource family (§3.1) |
| Rate limiting | Per-key and per-session defaults with `429 RATE_LIMITED` + `Retry-After` (§5.2) |
| Usage audit | `lastUsedAt` maintenance; machine actions attributed in `audit_log` (§5.3) |
| Client conventions | Envelope, error codes, pagination, filtering, auth headers (§5.4–5.5) with copy-paste curl quickstart |

**Out of scope (deferred — see ../01-PRODUCT/ROADMAP.md):**

| Feature | Why deferred |
|---|---|
| **Webhook support / event callbacks** (upstream 1.15, custom engineering) | Not in the Phase-1 contract; realtime today is the socket.io event set (PROJECT_MEMORY §7.3) and is console-facing only |
| **OpenAPI/Swagger generation** (upstream Ready via swaggo — that line targets the Go appliance API) | Documented as future work in §4.2; deliberately NOT built now |
| Batch/bulk operation endpoints | Upstream Ready, no Phase-1 contract beyond firewall import (`POST /api/v1/firewall-rules/import`) |
| API sandbox/test console, idempotency keys | Upstream Phase 2 |
| GraphQL | Dropped upstream |
| Cursor-based pagination | Deviation: Phase 1 is offset/page pagination (LOCKED §7.1); see §5.4 |

---

## 2. Data Model

Only one model is platform-owned (SCHEMA.md §3): `ApiKey`.

| Field | Meaning |
|---|---|
| `name` | Human label shown in lists and audit attribution |
| `prefix` | Unique `"ck_"` + 8 chars; stored in clear for lookup/display; the only surviving trace of the key |
| `hashedKey` | `sha256(full_key)`; lookup is by prefix then constant-time hash compare |
| `scopes` | JSON array — exactly one of `["read"]`, `["read","write"]`, `["read","write","admin"]` (SCHEMA §4) |
| `lastUsedAt` | Updated on successful key-authenticated requests (throttled ~1/min/key, M10 §5.4) |
| `expiresAt` | Optional; expired keys authenticate as `401 UNAUTHORIZED` |
| `revoked` | Soft-delete flag set by `DELETE /api/v1/api-keys/{id}`; revoked keys fail 401; the row remains for audit |

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
| Key management UI | `#/system/api-keys` — owned by M10 (create dialog with one-time secret reveal + copy, list with prefix/`lastUsedAt`/`expiresAt`/revoked, revoke ConfirmDialog) | This module defines the behavior; M10 renders it |
| Machine-client docs | This document (§5) + ../04-API/ENDPOINTS.md | The only "docs" until OpenAPI exists |
| Future: OpenAPI/Swagger docs page | Not built in Phase 1 | See §4.2 |

### 4.1 What NOT to build (negative requirements)

No `#/api` or `#/developers` view, no swagger UI bundle, no `/api/v1/openapi.json` route, no
webhook configuration screen — all absent by decision (§1). Grep-verifiable in acceptance
criteria §7.

### 4.2 OpenAPI / documentation strategy (future work — recorded, not built)

Stated explicitly so nobody builds it now: **no OpenAPI/Swagger artifact ships in Phase 1.**
The upstream spec's `swaggo` row applies to the Go appliance API, not this console. The
agreed future approach:

1. **Source of truth:** the zod validators in `src/lib/validators/` + the LOCKED route table
   in PROJECT_MEMORY §7.2 (single definition; no hand-written parallel spec to drift).
2. **Generation:** a build-time script compiles zod schemas → OpenAPI 3.1 (zod-to-json-schema
   pipeline), later served as `GET /api/v1/openapi.json` + a docs view; until then
   ../04-API/ENDPOINTS.md is the human-readable catalog.
3. **Contract tests first:** when the generator lands it must fail the build if a route
   handler diverges from §7.2 (paths are LOCKED — expand, never rename).
4. Until item 2 exists, machine-client documentation = this module + ENDPOINTS.md; both
   update in the same task per the doc rules.

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

---

## 6. Realtime

| Concern | Phase-1 position |
|---|---|
| Socket events for machine clients | **None.** The LOCKED event set (`metrics:tick`, `logs:tail`, `alerts:new`, `sessions:update`, `wan:status`, `vpn:status`, `config:updated`, §7.3) is console-facing only; machine clients poll the REST API |
| Webhooks / event callbacks | Out of scope Phase 1 (§1) — deferred to ROADMAP; do not add a sender or config UI |
| `config:updated` | Console-only cache invalidation trigger (../05-FRONTEND/STATE_AND_DATA_FLOW.md); when webhooks arrive later they will mirror this event semantics |
| Appliance-mode transport | Realtime stays socket.io → appliance mode swaps to Redis pub/sub → Go → WebSocket with the same event names (ADR-008/ADR-010) — transparent to this module |

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
- [ ] No OpenAPI route, swagger UI, webhook sender, `#/api` view, or batch endpoint exists in Phase 1 (grep-verifiable negative).
- [ ] `bun run lint` passes; key management UI remains only in `#/system/api-keys` (M10) — no new views or routes.

---

## 8. Open Questions & Risks

- ~~**Rate-limit numbers are PROPOSED**~~ RESOLVED: §5.2 now mirrors API_STANDARDS §9 (key 60/min, session 300/min, login 5/min per username+IP); API_STANDARDS wins on future changes.
- **Scope matrix vs RBAC matrix drift:** §3.1 is the key-projection of ../07-SECURITY/AUTH_AND_RBAC.md; both docs must change in the same task whenever either changes — otherwise 403 behavior becomes unpredictable per route.
- **Webhooks are spec-Phase-1 but contract-deferred:** the upstream spec lists webhook support under 1.15 (Phase 1); the locked build surface has no webhook endpoints, so Phase 1 console ships without them — revisit via PROJECT_MEMORY expansion before appliance mode (see §1).
- Attribution convention (`username` = key name, `bot-` prefix) is informal; consider a dedicated `actorType` column on `audit_log` in a Phase-2 schema pass instead of overloading strings.
- In-memory rate counters reset on process restart — acceptable in sandbox (ADR-010); appliance Redis counters must not silently change semantics (headers/limits) when AgentAdapter lands.
- Key secrets appear in shell history of whoever runs the quickstart; document `read -s` / env-file practice in the future developer guide (08-OPERATIONS) rather than complicating the API.
- Offset pagination + live-updating log tables can skip/repeat rows across pages; acceptable Phase 1 (log views pin `sort=-timestamp`), revisit with cursor pagination in Phase 2.

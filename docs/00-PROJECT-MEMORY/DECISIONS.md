# Architecture Decision Records — Cryptsk UTM/NGFW

> Append-only. Status: PROPOSED → ACCEPTED → (SUPERSEDED by ADR-xxx | DEPRECATED).
> Format: Context (problem + alternatives considered) → Decision → Consequences. New ADRs get the next number.

---

## ADR-001 — Appliance OS: Debian 13 (Trixie)

- **Status:** ACCEPTED (product-level, from spec)
- **Context:** The UTM needs nftables-first firewalling, eBPF/XDP acceleration, kernel 6.8+,
  glibc for ML libs, and maximal package support for security tooling.
  FreeBSD lacks nftables/eBPF/FRR; Rocky lags kernel features; Alpine is musl-limited;
  Ubuntu 24.04 is viable but heavier with larger attack surface.
- **Decision:** Debian 13 (Trixie) minimal install, custom 6.8+ LTS kernel; Debian 12 +
  backports kernel as fallback.
- **Consequences:** Smallest attack surface; all security tools have official Debian
  packages; predictable release cadence; team must maintain kernel config for
  XDP/AF_XDP/tc features.

## ADR-002 — Appliance backend in Go; console in Next.js

- **Status:** ACCEPTED (product-level, from spec)
- **Context:** Original spec proposed Java Spring Boot. An appliance needs a small,
  single-binary control plane with low memory. The management UI must be modern and
  API-first.
- **Decision:** Go (Gin/Fiber) for the appliance REST API + config generators;
  Next.js for the management console (UI + BFF). Every UI action goes through the
  same REST API (API-first rule).
- **Consequences:** One binary deploy per appliance; 10x less memory vs JVM;
  console repo can evolve independently; in sandbox mode the Go layer is simulated
  by Next API routes + adapters (see ADR-004).

## ADR-003 — Data plane: nftables + eBPF/XDP + Suricata + nDPI + tc

- **Status:** ACCEPTED (product-level, from spec)
- **Context:** Need 1–10 Gbps on commodity x86_64 with stateful firewalling, DPI, IPS,
  and QoS without proprietary ASICs.
- **Decision:** XDP for early-drop/rate-limit; nftables for stateful L3/L4 + NAT;
  conntrack for state; TPROXY → Squid/Coraza for proxy/WAF; nDPI for app
  classification; Suricata inline via **nftables NFQUEUE** (`queue num 1-4 fanout
  bypass`; AF_PACKET reserved for passive/SPAN capture, AF_XDP future); tc
  (HTB/FQ_CoDel) for shaping. Full pipeline: `docs/02-ARCHITECTURE/DATA_PLANE.md`.
- **Consequences:** Linux-only architecture (FreeBSD permanently excluded);
  kernel-version sensitivity; config generators must emit valid nftables/Suricata
  syntax (contract documented in SIMULATION_LAYER.md §6). NFQUEUE refines the spec's
  AF_PACKET bullet — it is the only inline mechanism that can sit between nftables/NAT
  and tc in the routed path (rationale in DATA_PLANE.md §1 and REVIEW-2A).

## ADR-004 — Sandbox build strategy: simulate the appliance behind SystemAdapter

- **Status:** ACCEPTED (build-level)
- **Context:** This dev environment cannot run nftables/Suricata/WireGuard or expose
  raw NICs, but the console must be built and demoed now. Rewriting UI later for a
  real backend would be waste.
- **Decision:** Define `SystemAdapter` (TS interface) with two implementations:
  `SimulatedAdapter` (MockEngine: deterministic traffic/log/event generation, config
  application simulation) and `AgentAdapter` (HTTP client to the future Go agent).
  All API services depend on the interface only. Details:
  `docs/02-ARCHITECTURE/SIMULATION_LAYER.md`.
- **Consequences:** Console code is appliance-ready; realistic demo data for free;
  risk: simulation drift from real behavior — mitigated by documenting generator
  output contracts (what a real nftables.conf/unbound.conf must look like).

## ADR-005 — Prisma + SQLite in the sandbox, PostgreSQL on appliance; no Prisma enums/Json/arrays

- **Status:** ACCEPTED (build-level)
- **Context:** Sandbox provides SQLite via Prisma; the appliance spec uses PostgreSQL
  with JSONB/arrays/enums. Prisma on SQLite does not give us portable enums/Json/array
  scalars we can rely on.
- **Decision:** SQLite + Prisma 6 with strict adaptation rules (PROJECT_MEMORY §10):
  JSONB/arrays → String-serialized JSON; enums → String + zod validation; INET/CIDR/
  MACADDR → String + zod; DATERANGE → two DateTime columns. Schema stays
  PostgreSQL-compatible in shape (snake_case via @@map).
- **Consequences:** Zero sqlite-specific surprises; app-layer validation is mandatory
  (zod schemas are the enforcement point); migration to PostgreSQL later is a
  datasource swap + typed JSON columns.

## ADR-006 — Single-route SPA shell with hash views

- **Status:** ACCEPTED (build-level; sandbox hard constraint)
- **Context:** The sandbox exposes exactly one user-visible route (`/`). A UTM console
  needs ~28 screens.
- **Decision:** One Next.js route (`src/app/page.tsx`) renders `AppShell`; the sidebar +
  hash router (`#/network/interfaces`, …) select views from a `viewRegistry`. Deep
  links, back/forward, and refresh all work via hash. No other Next.js routes ever.
  View map locked in PROJECT_MEMORY §8.
- **Consequences:** No route-level code splitting per view (mitigate with dynamic
  imports per view component); URL state is hash-based; auth gate renders login view
  in place of the shell.

## ADR-007 — Auth: custom JWT in httpOnly cookie (jose), not NextAuth

- **Status:** ACCEPTED (build-level)
- **Context:** Spec requires JWT auth + API-key machine access + RBAC with 8 roles.
  NextAuth's OAuth-oriented session model adds complexity we don't need for an
  appliance-style login.
- **Decision:** Custom JWT (lib: jose) with 8h expiry stored in httpOnly SameSite=Lax
  cookie `cryptsk_token`; bcrypt password hashing; RBAC middleware inside
  `lib/api/handler.ts`; API keys (`ck_…` bearer) for machine access. Design:
  `docs/07-SECURITY/AUTH_AND_RBAC.md`.
- **Consequences:** Full control of claims (`sub`, `role`, `tenantId`); we own
  rotation/revocation; MFA (TOTP) slots in later without vendor constraints.

## ADR-008 — Realtime: socket.io mini-service on port 3003

- **Status:** ACCEPTED (build-level; sandbox constraint)
- **Context:** Sandbox rules: realtime must use a socket.io mini-service on its own
  port behind the gateway (`?XTransformPort=`), not in-process SSE/polling.
- **Decision:** `mini-services/realtime-service/` — independent bun project
  (`bun --hot`, port 3003, own package.json). Emits locked event set
  (metrics:tick, logs:tail, alerts:new, sessions:update, wan:status, vpn:status,
  config:updated). Client connects with `io("/?XTransformPort=3003")`.
- **Consequences:** Realistic pub/sub boundary (appliance mode will use Redis pub/sub →
  Go → WebSocket with the same event names); mini-service must be started for any
  realtime view to work.

## ADR-009 — Multi-tenant schema, single default tenant in sandbox

- **Status:** ACCEPTED (build-level)
- **Context:** Spec is multi-tenant from day 1 (MSP story), but the sandbox demo has
  one appliance.
- **Decision:** Every tenant-scoped table carries `tenantId Int @default(1)`;
  API layer scopes all queries by the tenant claim in the JWT. Seed creates exactly
  one tenant (id 1, "Default").
- **Consequences:** MSP tenancy later = adding tenants + cross-tenant central manager;
  no schema migration needed; queries must always be tenant-scoped (handler injects it).

## ADR-010 — Eventing: Redis Streams on appliance; in-process queue in sandbox

- **Status:** ACCEPTED (build-level)
- **Context:** Spec replaced Kafka with Redis Streams for the appliance. Sandbox has
  no Redis.
- **Decision:** Appliance mode: Redis Streams between log shippers and API/AI layer.
  Sandbox mode: lightweight in-process ring buffers inside MockEngine feeding the
  realtime service via HTTP poll of the last N events.
- **Consequences:** Event names/payloads stay identical across modes (PROJECT_MEMORY
  §7.3); sandbox cannot test backpressure — acceptable for Phase 1 scope.

## ADR-011 — Config-versioning + audit on every mutation

- **Status:** ACCEPTED (build-level)
- **Context:** Firewall/UTM admins must answer "who changed what, when" and roll back.
- **Decision:** Every mutating API call writes an `audit_log` row (before/after JSON)
  via the shared handler; significant sections also snapshot into `config_versions`
  (incrementing version per tenant). Diff viewer uses the snapshots.
- **Consequences:** Slight write overhead; rollback = restore snapshot through the
  same validation pipeline; audit log is append-only.

## ADR-012 — MockEngine uses a seeded PRNG; realistic profiles

- **Status:** ACCEPTED (build-level)
- **Context:** Demo data must be reproducible (screenshots, bug reports) and
  plausible (office/hospitality/MSP traffic patterns).
- **Decision:** `MockEngine` uses a seeded PRNG (mulberry32, seed from env
  `MOCK_SEED`, default 1337) with named traffic profiles driving metrics, log lines,
  IPS events, WAN probe states, and session churn. Details + volumes:
  `docs/03-DATABASE/DATA_LIFECYCLE.md`.
- **Consequences:** Deterministic demos; changing the seed changes all volatile data;
  profiles are data, not code (JSON config), so new scenarios are cheap.

## ADR-013 — Charts use recharts via the shadcn chart wrapper; palette locked

- **Status:** ACCEPTED (build-level)
- **Context:** recharts 2.15 + `ui/chart.tsx` are already available; platform forbids
  indigo/blue.
- **Decision:** All charts go through `components/charts/` wrappers using the locked
  palette: emerald, teal, amber, rose, orange, violet, zinc (PROJECT_MEMORY §9).
  Area charts for throughput, bar for top-talkers, donut for app share, sparklines
  in cards.
- **Consequences:** Consistent visuals; no per-view color improvisation; dark-mode
  friendly by construction.

## ADR-014 — Module build order: M01 → M03 → M02 → M04 → M05 → M06 → M09 → M07 → M08 → M10 → M11

- **Status:** ACCEPTED (build-level)
- **Context:** Value-per-effort ordering for Phase 1 console; frontend-first rule.
- **Decision:** Dashboard first (shell + realtime visible), then Firewall (core
  CRUD + objects + NAT), Network (interfaces/WAN), IPS, VPN, DNS/DHCP, Logging,
  Identity, QoS, System/HA, API platform. Rationale in `docs/01-PRODUCT/ROADMAP.md`
  §Build Order.
- **Consequences:** Each module ships vertically (schema → API → view); the shell +
  contracts from PROJECT_MEMORY are prerequisites for all modules.

## ADR-015 — IPS event table named `ips_events` (spec said `ips_logs`)

- **Status:** ACCEPTED (review reconciliation, 2026-11-05)
- **Context:** Spec §7 schema sketch named the IPS log table `ips_logs`. The docs suite
  (SCHEMA.md, ENDPOINTS.md, M04, M09, PROJECT_MEMORY §7) consistently uses `ips_events`,
  because the table stores triage-grade *events* (with severity/action/suppression), not
  raw packet logs — which live in `firewall_logs`/ClickHouse.
- **Decision:** Canonical name is `ips_events` (model `IpsEvent`, endpoint `/ips/events`).
  The spec's `ips_logs` naming is treated as a spec typo. Do not introduce `ips_logs`
  anywhere.
- **Consequences:** Any doc/code reference to `ips_logs` is drift; appliance-side Suricata
  eve.json ingestion maps into `ips_events` with the same fields.

## ADR-016 — Error envelope carries an optional `requestId`

- **Status:** ACCEPTED (review reconciliation, 2026-11-05)
- **Context:** Review pass 2B flagged the error envelope as lacking a correlation id.
  For a security appliance, support/forensics workflows need "user reports error → we
  find the exact server log line" without timestamp guessing.
- **Decision:** Shared handler middleware generates a ULID `requestId` per request,
  echoes it in every error response (`error.requestId`), and writes it into the server
  log line. Success responses do NOT carry it (envelope stays lean). Documented in
  PROJECT_MEMORY §7.1 and API_STANDARDS §4.
- **Consequences:** One middleware line + one log field; no breaking envelope change
  (field is optional); Phase 2 request tracing can reuse the same id.

## ADR-017 — IPS bypass semantics: `sid: 0` = any SID; default policy = first enabled by seed order

- **Status:** ACCEPTED (review reconciliation, 2026-11-05)
- **Context:** Spec §1.6 lists "IPS bypass rules (skip IPS for source/dest)" as Phase 1,
  but the SID-keyed `exceptions` shape (`{sid, source?, dest?}`) cannot express a SID-less
  capture-level bypass. Separately, rules without an attached `ipsPolicyId` need a
  deterministic policy for simulation/testing.
- **Decision:** (1) In `IpsPolicy.exceptions`, `sid: 0` means "any SID" — the generator
  renders such entries as nftables `skip queue` rules placed ahead of the Suricata queue
  rule (true capture-level bypass); `sid > 0` keeps Suricata suppress semantics.
  (2) Traffic on rules without `ipsPolicyId` is evaluated by the first enabled policy by
  seed order (`id` ascending) — simulation-only convention, pinned in ENDPOINTS.md.
- **Consequences:** SCHEMA.md §4 + M04 §1/§5/§8 + ENDPOINTS.md are aligned; no schema
  migration (sid stays an Int); bypass entries with `sid: 0` must be surfaced in the M04
  UI as "bypass (any SID)" to avoid user confusion.

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
  needs ~29 screens (28 console views + the `#/setup` wizard added by REVIEW-4A).
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

## ADR-018 — Zero-feature-loss ruling: all spec features covered, console deferrals rescinded

- **Status:** ACCEPTED (product-owner ruling, 2026-11-05)
- **Context:** The master feature sheet (`docs/SPEC.md`) is the single source of truth for
  WHAT we build. Earlier build passes had deferred some spec-Phase-1 features from the
  console contract (PBR, DHCP relay, conditional forwarding, basic DHCPv6, per-user/
  per-app bandwidth hard limits, LLDP, IGMP snooping, MAC table, SPAN, L2/L3 toggle, BFD,
  IPS auto-update + presets, VPN user groups, session-limit/timeout UIs, firmware/NTP/
  SNMP/hardening surfaces, webhooks registration, OpenAPI JSON, setup wizard, …).
  The product owner then set a hard rule: **zero features may be missing from the doc
  suite.**
- **Decision:** (1) Every spec Phase-1 feature is restored to Phase 1 and fully covered by
  module docs + SCHEMA + ENDPOINTS + PAGE_MAP (audited: 188/188 — REVIEW-4A). (2) Every
  Phase 2/3/4 feature and §2–§9 product fact has a correctly phase-tagged home
  (REVIEW-4B). (3) `config:updated` may carry `section: "all"` as the sentinel for
  restore/template-apply events (full invalidate). (4) LLDP/MAC-table/HA derived views use
  polling fallback (10 s) instead of new socket events — the 7-event realtime set stays
  locked.
- **Consequences:** ROADMAP §5 restoration row + REVIEW-4A/4B reports are the evidence;
  build order (ADR-014) unchanged; the larger Phase-1 surface raises build effort —
  accepted by the owner. Any future deviation from SPEC.md requires a new ADR.

## ADR-020 — Phase 2 build order: M12→M23 in four parallel batches (owner directive 2026-11-07)

- **Status:** ACCEPTED (build-level; supersedes nothing — extends ADR-014 pattern to Phase 2)
- **Context:** owner directed "finish all Phase 2 and Phase 1 pending things, 100% production,
  Debian 13-ready" in one session. 13 spec-Phase-2 workstreams + 2 Phase-1 build divergences.
- **Decision:** 12 milestones, four parallel sub-agent batches with strict file ownership
  (each agent owns disjoint validators/routes/views/seed files; coordinator owns schema,
  shell wiring, RBAC, docs):
  - M12 enhanced logging & reports (2.13) + closes scheduled-reports/PDF divergence
  - M13 threat intelligence (2.11)
  - M14 PKI (2.12) — **real X.509 via node-forge** (not simulated PEM)
  - M15 SSL inspection (2.1) · M16 URL filtering (2.3) · M17 WAF (2.4)
  - M18 app control (2.2) · M19 dynamic routing (2.6) · M20 SD-WAN (2.5)
  - M21 IPv6 dual-stack (2.7) · M22 email security (2.8) · M23 identity/NAC (2.9+2.10)
  - M11-tail: real webhook delivery (HMAC-SHA256, retries, ledger) — closes webhook divergence
- **Consequences:** 17 new hash views (29→46); 47 new models; 12 new RBAC capability areas;
  simulated decision engines mirror the exact appliance services (Squid/Coraza/FRR/Kea/...) so
  AgentAdapter wiring is a 1:1 mapping (`deploy/AGENT_ADAPTER_CHECKLIST.md`). Production
  packaging shipped alongside (DEPLOYMENT.md, systemd, Caddyfile, .env.example).
  Every milestone committed+pushed on completion per HARD RULE §11.16.
- **Sandbox ops learnings (recorded in Gotchas §13):** OOM killer reaps next-server when
  tsc/lint run alongside the dev server (4 GB box) — use memory-capped restarts, close the
  browser when idle; Next.js dynamic segments at the same path level must share one slug name.

---

## ADR-019 — Enterprise white & blue theme (owner request; supersedes ADR-013 palette)

- **Status:** ACCEPTED (2026-11-06, owner-directed)
- **Context:** The owner found the emerald/teal look frustrating and directed an
  "enterprise white and blue" theme. ADR-013 had locked emerald as brand primary and
  forbidden blue entirely.
- **Decision:** (1) Brand primary = **blue-600** (light) / **blue-500** (dark); light is
  the default theme (`defaultTheme="light"`). (2) Chart palette LOCKED to
  blue → sky → amber → rose → orange → violet → slate (throughput rx = blue, tx = sky);
  `components/charts/palette.tsx PALETTE` is the implementation. (3) **Emerald/teal are
  forbidden as brand/UI-chrome colors** — reserved exclusively for health semantics
  (up/online/healthy badges + dots, UI_DESIGN_SYSTEM §2.4). (4) Tokens updated in
  `globals.css` (primary, ring, sidebar tint, chart vars); UI_DESIGN_SYSTEM.md §2 is the
  canonical color law going forward.
- **Consequences:** All existing and future views must follow UI_DESIGN_SYSTEM §2 (blue
  chrome, emerald health-only). M03+ module views authored after this ADR use blue for
  `allow` action badges. Dark mode remains fully supported.
- **REVISION (2026-11-09, owner-directed):** brand pivots to **white / red / dark red**
  (owner brand colors). Brand primary = **red-800** (light) / **red-500** (dark);
  chart palette LOCKED to red-700 → red-500 → amber → rose → orange → zinc → slate
  (throughput rx = red-700, tx = red-500); `info` severity moves violet → **zinc** so red
  never dilutes critical semantics; rose stays destructive/critical-only. Same emerald
  health-only rule carries over. `PALETTE`, `globals.css` tokens, `BrandLogo` mark
  (red-600 → red-900 gradient), favicon `src/app/icon.svg` and `public/logo.svg` all
  rebranded in the same pass; UI_DESIGN_SYSTEM §2 is the updated color law.

## ADR-021 — Real host data plane (ADAPTER_MODE=host); simulation demoted to opt-in demo

- **Status:** ACCEPTED (2026-11-09, owner-directed: "move everything to real data plane… no mock or simulated data")
- **Context:** The console was feature-complete against the SimulatedAdapter (ADR-004/ADR-020), but every operational value (traffic, logs, events, sessions, WAN states, service health, HA heartbeat) was MockEngine-generated. The owner is deploying to Debian 13 and requires zero fabricated data; the sandbox also supports real read-only telemetry (procfs/sysfs) that was unused.
- **Decision:** (1) `ADAPTER_MODE=host` is the DEFAULT data plane. A new `HostCollector` (`src/lib/engine/host-collector.ts`) replaces the MockEngine as the engine behind the same read surface (`metricsRing`, `logsRing`, `dnsRing`, `wanStates`, `systemVitals`, `forceProbe`, `uptimeSec`) — all consumers migrated to the `getEngine()` factory (`src/lib/engine/index.ts`). (2) Real sources: `/proc/net/dev|stat|meminfo|tcp|udp`, sysfs (operstate/carrier/MTU/MAC/thermal), nf_conntrack count, real gateway TCP probes, `systemctl is-active`, Suricata `eve.json` tail → `ips_events`, nftables kernel logs via `journalctl -k` → `firewall_logs`, `wg show all dump` → `vpn_sessions`, Kea lease CSV → `dhcp_leases`, unbound query log → dns ring. Real interfaces are auto-discovered/upserted into `interfaces`. (3) `HostAdapter` serves the dashboard summary from real rings + honest aggregates (no drift/temp fakery). HA status is real in host mode (keepalived unit + VIP presence + ICMP peer ping). Interface stats use real `/proc/net/dev` error/drop/packet deltas (hash fakes removed in host mode). WAN "probe now" runs a real gateway probe (Math.random() fallback removed). (4) Absent sources degrade to honest emptiness — the engine NEVER fabricates. (5) `ADAPTER_MODE=simulated` remains available as the explicit legacy demo plane. (6) Production packaging: `prisma/seed.ts --production` (identity/RBAC + defaults only, wizard gate `completed=false`), `scripts/purge-mock-data.ts` (removes all demo/mock rows), `ecosystem.prod.config.cjs` (pm2 production: `next start` + realtime), `deploy/install-debian13.sh` (fresh Debian 13 → apt deps → Node/bun/pm2 → clone → secrets → schema+production seed → build → pm2 → boot hook → smoke check) and `deploy/update.sh`. pm2 is the appliance process manager (owner mandate), replacing the systemd-units-first plan.
- **Consequences:** On Debian 13 the console shows only real host data; first-run UX is the setup wizard over an intentionally empty config (no demo rules/objects). Any value a source cannot provide is zero/empty with a visible reason — dashboards may look "quiet" until services (suricata/unbound/kea/wg) run. The MockEngine code path stays for `simulated` mode demos but is no longer booted by default (`instrumentation.ts` boots the collector). Real enforcement (applying nftables rulesets from the firewall config plane) remains future work for the appliance build (AGENT_ADAPTER_CHECKLIST stays the integration gate).

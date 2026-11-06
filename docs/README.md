# Cryptsk UTM/NGFW — Project Documentation

> **Purpose of this folder:** This documentation IS the project's long-term memory.
> It is written so that any developer or AI agent can understand, extend, and modify the
> project **without reading the full codebase** — saving tokens, time, and cost.
> Documentation-first: no code is written or changed without a matching doc update.

---

## 1. What This Project Is

**Cryptsk UTM / NGFW** is a Unified Threat Management + Next-Gen Firewall platform for
small enterprises (10–500 users), branch offices, MSPs, and hospitality.
The deliverable in this repository is the **Cryptsk Console** — the web management
dashboard (Next.js 16) — plus a **simulation layer** that stands in for the appliance
data plane (nftables / Suricata / WireGuard / etc.) during development.

- Full product spec (source of truth for WHAT we build):
  `docs/SPEC.md`
- These docs (source of truth for HOW we build it and WHAT STATE we are in): `docs/`

---

## 2. AI AGENT PROTOCOL — Read This Before Touching Any Code

**The Golden Rule:** docs first, code second. If you change behavior, you update docs
in the same task. If docs and code disagree, the docs win and the code is the bug.

Onboarding sequence (do this every session):

1. Read `docs/README.md` (this file) — you are here.
2. Read `docs/00-PROJECT-MEMORY/PROJECT_MEMORY.md` — project state, contracts, conventions.
   This one file gives you ~90% of what you need.
3. Read ONLY the topic docs relevant to your task (use the matrix below).
4. Use `PROJECT_MEMORY.md` §5 (Directory Map) to jump directly to the files you need.
   Do NOT speculatively read source files.
5. After finishing a task: append a dated entry to `PROJECT_MEMORY.md` §15 (Session Log),
   and update any doc your change invalidated.

Token-saving strategy: `PROJECT_MEMORY.md` + one topic doc should be enough for any task.
If you find yourself reading more than ~4 docs, the docs need improving — fix them.

### Reading-Order Matrix

| If your task is... | Read (in this order) |
|---|---|
| Onboard / understand the project | This file → PROJECT_MEMORY → GLOSSARY → ARCHITECTURE |
| Understand product scope / phases | PRODUCT_OVERVIEW → ROADMAP |
| Database work (schema, queries, seed) | PROJECT_MEMORY §10 → DATABASE/SCHEMA → DATABASE/ER_DIAGRAM → DATABASE/DATA_LIFECYCLE |
| API work (new/changed endpoints) | PROJECT_MEMORY §7 → API/API_STANDARDS → API/ENDPOINTS → relevant MODULE doc |
| UI work (views, components, styling) | PROJECT_MEMORY §8–9 → FRONTEND/UI_DESIGN_SYSTEM → FRONTEND/PAGE_MAP → FRONTEND/STATE_AND_DATA_FLOW → relevant MODULE doc |
| Build or extend module M01–M11 | PROJECT_MEMORY → MODULES/M0x → SCHEMA (its tables) → ENDPOINTS (its paths) |
| Realtime / WebSocket work | STATE_AND_DATA_FLOW → SIMULATION_LAYER |
| Auth / RBAC / sessions | SECURITY/AUTH_AND_RBAC → SCHEMA (User, ApiKey) |
| Data plane / packet pipeline (appliance) | ARCHITECTURE/DATA_PLANE → SIMULATION_LAYER |
| Environment setup / debugging | OPERATIONS/DEVELOPMENT_GUIDE → PROJECT_MEMORY §11 & §13 |
| Verify a claim / check known doc issues | 09-REVIEWS (latest report first) → the doc in question |

---

## 3. Documentation Map (File Tree)

```
docs/
├── README.md                          ← YOU ARE HERE. Index + agent protocol.
├── SPEC.md                            ★ MASTER FEATURE SHEET — the original product spec
│                                      (ground truth for WHAT: every feature, phase, table).
│                                      ZERO-FEATURE-LOSS rule (owner ruling 2026-11-05):
│                                      NOTHING in SPEC.md may be missing from the doc suite —
│                                      Phase-1 items are covered by SCHEMA/ENDPOINTS/module
│                                      docs; Phase 2–4 features + §2–§9 product facts by
│                                      ROADMAP/PRODUCT_OVERVIEW/memory docs (lanes 4A/4B).
│
├── 00-PROJECT-MEMORY/                 ★ READ FIRST — the project's brain
│   ├── PROJECT_MEMORY.md              State snapshot, tech stack, all contracts
│   │                                  (naming, API surface, view map, design tokens,
│   │                                  SQLite rules, sandbox constraints), recipes,
│   │                                  gotchas, append-only session log.
│   │                                  Authority note: the spec (`docs/SPEC.md`) is ground
│   │                                  truth for product facts; these docs govern the
│   │                                  build contracts; every deviation is recorded
│   │                                  (ADR or ROADMAP §5 divergence note).
│   ├── DECISIONS.md                   Architecture Decision Records (ADRs) —
│   │                                  every "why did we choose X" lives here.
│   └── GLOSSARY.md                    Domain terms (UTM/NGFW/networking vocabulary).
│
├── 01-PRODUCT/
│   ├── PRODUCT_OVERVIEW.md            Vision, market, positioning, honest gaps, pricing.
│   └── ROADMAP.md                     Phase 1–4 feature plan + build status tracker.
│
├── 02-ARCHITECTURE/
│   ├── ARCHITECTURE.md                System overview, dual-mode design (appliance vs
│   │                                  sandbox), container + sequence diagrams.
│   ├── DATA_PLANE.md                  Packet processing pipeline (real appliance):
│   │                                  XDP → nftables → conntrack → proxy → nDPI →
│   │                                  Suricata → tc/QoS.
│   ├── CONTROL_PLANE.md               UI ↔ API ↔ DB ↔ config generators ↔ services.
│   └── SIMULATION_LAYER.md            How the sandbox simulates the appliance:
│   │                                  SystemAdapter, SimulatedAdapter, MockEngine.
│
├── 03-DATABASE/
│   ├── SCHEMA.md                      Definitive Prisma schema (SQLite) + PostgreSQL
│   │                                  mapping rules + per-model notes + seed plan.
│   ├── ER_DIAGRAM.md                  Entity-relationship diagram + relation table
│   │                                  (hard FKs vs logical JSON-array references).
│   └── DATA_LIFECYCLE.md              Seeding, mock data generation, retention, reset.
│
├── 04-API/
│   ├── API_STANDARDS.md               Envelope, errors, pagination, auth, validation,
│   │                                  audit rules. MUST for any API work.
│   │
│   └── ENDPOINTS.md                   Complete Phase 1 endpoint catalog with
│                                      request/response examples per resource group.
│
├── 05-FRONTEND/
│   ├── UI_DESIGN_SYSTEM.md            Theme tokens (light/dark), color rules (NO
│   │                                  indigo/blue), component patterns, states.
│   ├── PAGE_MAP.md                    Single-route SPA shell + all hash views
│   │                                  (sidebar tree, layouts, navigation).
│   └── STATE_AND_DATA_FLOW.md         TanStack Query conventions, Zustand stores,
│                                      fetch wrapper, realtime (socket.io) wiring.
│
├── 06-MODULES/                        ★ One spec per functional module (Phase 1)
│   ├── M01-DASHBOARD.md               Overview dashboard (metrics, health, alerts).
│   ├── M02-NETWORK.md                 Interfaces, static routes, multi-WAN.
│   ├── M03-FIREWALL.md                Zones, objects, firewall rules, NAT.
│   ├── M04-IPS.md                     Suricata policies, events, tuning.
│   ├── M05-VPN.md                     WireGuard, IPSec, OpenVPN, sessions.
│   ├── M06-DNS-DHCP.md                Unbound policies/records, Kea subnets/leases.
│   ├── M07-IDENTITY.md                Users, groups, RADIUS, captive portal.
│   ├── M08-QOS.md                     Traffic shaping policies and rules.
│   ├── M09-LOGGING.md                 Firewall/IPS logs, live tail, audit, reports.
│   ├── M10-SYSTEM.md                  HA, backup/restore, settings, API keys, notifications.
│   └── M11-API-PLATFORM.md            API keys, webhooks, rate limits, OpenAPI.
│
├── 07-SECURITY/
│   └── AUTH_AND_RBAC.md               JWT design, roles matrix, permissions, MFA.
│
├── 08-OPERATIONS/
│   └── DEVELOPMENT_GUIDE.md           Setup, commands, ports, debugging, code style.
│
└── 09-REVIEWS/                        ★ Post-authoring review reports — read before
    │                                  trusting a doc's claims at face value.
    └── REVIEW-2C-SOLUTION-ARCHITECT.md  Solution-architecture/product review of the
                                           memory pack, product docs, M02/M04/M05 (product
                                           lens) and DEVELOPMENT_GUIDE (2026-11-05).
```

---

## 4. Documentation Rules (How This Folder Stays Alive)

1. **Same-task rule:** any code change that alters behavior, contracts, or structure
   must update the relevant doc(s) in the same task/PR/session.
2. **Session log:** every working session appends a dated entry to
   `PROJECT_MEMORY.md` §15. This is how continuity survives between AI sessions.
3. **ADRs are append-only:** decisions are never rewritten; superseded decisions get
   status `SUPERSEDED by ADR-xxx`. New decisions get the next number.
4. **Contracts are locked:** endpoint paths, view hash paths, socket event names, DB
   model names, and design tokens are defined in `PROJECT_MEMORY.md`. Changing them
   requires editing `PROJECT_MEMORY.md` first, then all dependent docs + code.
5. **No orphans:** when a feature moves phases or gets cut, update ROADMAP.md and the
   module doc the same day.
6. **Diagrams as code:** all diagrams are Mermaid blocks inside the docs so they stay
   diff-able and token-cheap. No binary images in docs.
7. **Spec authority:** the original spec (`docs/SPEC.md`)
   is ground truth for WHAT the product is (features, phases, pricing, gaps). These
   docs are ground truth for HOW we build and the current state. Where a doc
   intentionally deviates, it must say so and point at the ADR or ROADMAP §5
   divergence note that justifies it — silent deviation is doc drift.

## 4.1 Review Status (kept honest — update after each review pass)

| Doc group | Review | Status |
|---|---|---|
| 00-PROJECT-MEMORY (memory, ADRs, glossary) | Solution architecture / product (2C) | Reviewed & fixed ✓ 2026-11-05 — see `09-REVIEWS/REVIEW-2C-SOLUTION-ARCHITECT.md` |
| 01-PRODUCT (overview, roadmap) | Solution architecture / product (2C) | Reviewed & fixed ✓ 2026-11-05 |
| 06-MODULES M02 / M04 / M05 (product/scope lens) | Solution architecture / product (2C) | Reviewed & fixed ✓ 2026-11-05 |
| 08-OPERATIONS (development guide) | Solution architecture / product (2C) | Reviewed & fixed ✓ 2026-11-05 |
| 02-ARCHITECTURE, 06-MODULES M02/M04/M05/M06/M08 (technical), 07-SECURITY | Network core engineer / network architect (2A) | Reviewed & fixed ✓ 2026-11-05 — see `09-REVIEWS/REVIEW-2A-NETWORK-ARCHITECT.md` |
| 03-DATABASE, 04-API, 05-FRONTEND, 06-MODULES M01/M03/M07/M09/M10/M11 | Full-stack / database architect (2B) | Reviewed & fixed ✓ 2026-11-05 — see `09-REVIEWS/REVIEW-2B-FULLSTACK.md` |
| Spec coverage — Phase 1 zero-loss (module docs, SCHEMA, ENDPOINTS; console-deferred features restored) | Product assurance (4A) | Reviewed & fixed ✓ 2026-11-05 — **188/188 Phase-1 features covered, zero deferrals** — see `09-REVIEWS/REVIEW-4A-FEATURE-COVERAGE.md`; restoration formalized in ADR-018 |
| Spec coverage — Phase 2–4 features + §2–§9 product facts (product docs, memory, roadmap, glossary) | Product assurance (4B) | Reviewed & fixed ✓ 2026-11-05 — all Phase 2/3/4 features + §2–§9 facts phase-tagged — see `09-REVIEWS/REVIEW-4B-PRODUCT-COVERAGE.md` |
| Cross-agent reconciliation | Coordinator | Reconciled ✓ 2026-11-05 — NFQUEUE canon (ADR-003), `ips_events` canon (ADR-015), `requestId` envelope (ADR-016), IPS bypass `sid:0` + default policy (ADR-017), M06 lease release locked, SCHEMA wireguard_remote `peers` |

---

## 5. Current Project Status (One Paragraph)

As of **2026-11-05**: the product specification has been read and fully digested. The
complete documentation suite (this folder) has been authored before any implementation
and has passed a solution-architecture/product review (see §4.1 + `09-REVIEWS/`).
**No application code has been written yet** — the repo currently holds the docs suite
plus the Next.js scaffold (shadcn UI primitives, placeholder Prisma schema). The next
milestone is the Phase 1 build: Cryptsk Console (Next.js 16 single-route SPA) + SQLite
data layer + realtime mini-service + simulated appliance engine, following module order
M01 → M03 → M02 → M04 → M05 → M06 (see ROADMAP.md for the build order rationale). Live
status is tracked in `PROJECT_MEMORY.md` §2 and §15.

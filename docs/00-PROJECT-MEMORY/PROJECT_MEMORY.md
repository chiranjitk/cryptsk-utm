# PROJECT MEMORY — Cryptsk UTM/NGFW Console

> **THE single source of truth** for project state, contracts, and conventions.
> Every AI agent reads this file FIRST. Last updated: **2026-11-05**.
> If this file and any other doc disagree, this file wins — then fix the other doc.

---

## 1. Project Identity

| Field | Value |
|---|---|
| Product name | **Cryptsk UTM / NGFW** |
| Console app name | **Cryptsk Console** (the web dashboard built in this repo) |
| Category | Unified Threat Management + Next-Gen Firewall |
| Target market | Small enterprises (10–500 users), branch offices, MSPs, hospitality |
| Throughput target (product) | 1–10 Gbps per appliance |
| Full product spec | `docs/SPEC.md` — **ground truth for product facts** (features, phases, pricing, honest gaps). Where these docs deviate, the deviation is a documented build-level decision (see `DECISIONS.md` ADRs / `ROADMAP.md` §5); the spec wins on product facts unless an ADR explicitly justifies otherwise |
| Delivery model | Community / Professional / Enterprise / MSP editions; hardware appliance pre-installed |

---

## 2. Current Status Snapshot

| Item | Status (2026-11-05) |
|---|---|
| Product spec read & digested | DONE |
| Documentation suite (`docs/`) | DONE (this suite) |
| Spec coverage audit (zero-feature-loss) | IN PROGRESS — REVIEW-4A (Phase 1 features in module docs) + REVIEW-4B (Phase 2–4 features + §2–§9 product facts), 2026-11-05; ROADMAP §5 console-deferral row RESTORED to Phase 1 |
| Application code | **NOT STARTED** |
| Database schema (Prisma) | DEFINED in `docs/03-DATABASE/SCHEMA.md`, not yet pushed |
| Realtime mini-service | NOT STARTED (`mini-services/realtime-service/`, port 3003) |
| Build milestone | **M0: Project bootstrap** — see ROADMAP.md §Build Order |
| Current module in progress | none (docs phase just completed) |

---

## 3. Tech Stack (Build Mode = this repository)

| Layer | Choice | Version | Why / ADR |
|---|---|---|---|
| Framework | Next.js (App Router) + TypeScript 5 | 16.x | Non-negotiable platform; single repo for UI + API |
| UI | React + Tailwind CSS 4 + shadcn/ui (New York) | React 19 | Full component set already in `src/components/ui` |
| Icons | lucide-react | 0.5x | Bundled with shadcn |
| Charts | recharts | 2.15 | Already installed; use `src/components/ui/chart.tsx` wrapper |
| State (client) | zustand | 5 | `stores/` |
| State (server) | TanStack Query | 5 | `hooks/` with strict query-key convention |
| Validation | zod | 4 | All API input + DB JSON field shapes |
| DB | Prisma 6 + **SQLite** | 6.11 | Sandbox constraint; portable to PostgreSQL (ADR-005) |
| Auth | Custom JWT (jose) + httpOnly cookie | — | ADR-007 |
| Realtime | socket.io mini-service | 4.x | Port 3003, separate bun project (ADR-008) |
| Forms | react-hook-form + @hookform/resolvers | 7 | With zod resolvers |
| Toasts | sonner | 2 | Global `<Toaster>` in layout |
| Themes | next-themes | 0.4 | Light + dark, dark is default for ops console |
| Animation | framer-motion | 12 | Subtle only (view transitions, list stagger) |
| DnD (rule reorder) | @dnd-kit | 6 | Firewall/NAT/QoS rule ordering |
| Tables | @tanstack/react-table | 8 | Logs, rules, sessions tables |
| AI SDK (future admin assist) | z-ai-web-dev-sdk | 0.0.18 | **Backend only** — never in client code |

**NOT in this repo (appliance-side, documented for context only):** Go API, nftables,
eBPF/XDP, Suricata, nDPI, Unbound, Kea, Squid, StrongSwan, WireGuard, FRR, FreeRADIUS,
PostgreSQL, Redis, Prometheus/Grafana — plus the Phase 2–4 appliance stack: Coraza +
Caddy (WAF/reverse proxy), Step-CA (PKI), Postfix + Rspamd + ClamAV (email security),
ClickHouse / Meilisearch (log search, v2), ONNX Runtime (AI inference, Phase 3).
Versions + licenses: SPEC.md §3. See ARCHITECTURE.md for how the console will talk
to them in Appliance Mode.

---

## 4. Dual-Mode Architecture (the one concept that explains everything)

The console is built against a **`SystemAdapter` interface** with two implementations:

| Mode | Adapter | Where it runs | Data plane |
|---|---|---|---|
| **Sandbox Mode** (development, now) | `SimulatedAdapter` | Inside this repo (Next API + mini-service) | `MockEngine` generates traffic, logs, events, statuses |
| **Appliance Mode** (production, later) | `AgentAdapter` | Go agent on Debian appliance (port 8080) | Real nftables/Suricata/WireGuard/etc. |

All UI and API code is written once against the adapter interface. Details:
`docs/02-ARCHITECTURE/SIMULATION_LAYER.md`. This is ADR-004.

---

## 5. Directory Map (planned build structure)

```
/
├── AGENTS.md                       AI agent entry pointer (root)
├── docs/                           This documentation suite
├── prisma/
│   └── schema.prisma               Definitive schema = docs/03-DATABASE/SCHEMA.md
├── db/                             SQLite database file (cryptsk.db)
├── mini-services/
│   └── realtime-service/           socket.io service, port 3003, own package.json,
│       └── index.ts                started with `bun --hot`
├── src/
│   ├── app/
│   │   ├── layout.tsx              Root layout: ThemeProvider, QueryProvider, Toaster
│   │   ├── page.tsx                THE ONLY ROUTE — renders <AppShell/>
│   │   ├── globals.css             Tailwind 4 + theme tokens
│   │   └── api/
│   │       └── v1/                 ALL API route handlers (Next route handlers)
│   │           ├── auth/…          login, logout, me
│   │           ├── dashboard/…     summary
│   │           ├── interfaces/…    interfaces CRUD + stats
│   │           ├── routes/…        static routes
│   │           ├── wan-policies/…
│   │           ├── zones/…  address-objects/…  address-groups/…
│   │           ├── service-objects/…  service-groups/…  schedule-objects/…
│   │           ├── firewall-rules/…  nat-rules/…
│   │           ├── ips/…  vpn/…  dns/…  dhcp/…
│   │           ├── users/…  user-groups/…  radius-profiles/…
│   │           ├── captive-portal/…  identity/…
│   │           ├── qos/…  logs/…  ha/…
│   │           └── system/…  api-keys/…  notifications/…  config-versions/…
│   ├── components/
│   │   ├── ui/                     shadcn (EXISTS — do not rewrite, extend ok)
│   │   ├── shell/                  AppShell, Sidebar, Topbar, AuthGate, ViewRenderer
│   │   ├── views/                  One folder per module: dashboard/, network/,
│   │   │                           firewall/, ips/, vpn/, dns-dhcp/, identity/,
│   │   │                           qos/, logs/, ha/, system/, reports/
│   │   ├── charts/                 Chart wrappers (recharts + ui/chart)
│   │   └── shared/                 StatusBadge, ObjectPicker, RuleEditor, DataTable,
│   │                               EmptyState, ConfirmDialog, JsonFieldViewer …
│   ├── lib/
│   │   ├── db.ts                   EXISTS — Prisma client singleton
│   │   ├── utils.ts                EXISTS — cn() etc.
│   │   ├── auth/                   jwt.ts, session.ts, rbac.ts, password.ts
│   │   ├── api/                    envelope.ts, errors.ts, handler.ts, audit.ts
│   │   ├── adapters/               types.ts (SystemAdapter), simulated.ts, agent.ts
│   │   ├── engine/                 MockEngine, profiles, generators, seeds
│   │   └── validators/             zod schemas per resource + enums.ts
│   ├── stores/                     ui-store.ts (view/theme), app-store.ts (user)
│   ├── hooks/                      one file per resource: use-firewall-rules.ts …
│   └── types/                      api.ts, models.ts, realtime.ts
└── dev.log                         Dev server log (read recent tail when debugging)
```

---

## 6. Naming Conventions (LOCKED)

| Context | Convention | Example |
|---|---|---|
| Prisma model (TS name) | PascalCase singular | `FirewallRule` |
| SQLite table/column | snake_case via `@@map`/`@map` | `firewall_rules`.`source_addr_ids` |
| API JSON | camelCase | `sourceAddrIds` |
| TS variables/functions | camelCase | `getHitCount()` |
| TS types/components | PascalCase | `RuleEditor` |
| Files (TS) | kebab-case | `use-firewall-rules.ts` |
| Docs files | UPPERCASE-KEBAB or M0x-NAME | `PROJECT_MEMORY.md`, `M03-FIREWALL.md` |
| DB id columns | `id Int @id @default(autoincrement())` | — |
| Timestamps | `createdAt/updatedAt` → columns `created_at`/`updated_at` | — |
| Soft-delete | none (Phase 1: hard delete + audit log) | — |
| Booleans | `enabled`, `isRead` (no `is` prefix on DB columns except audit-ish fields) | — |

**Canonical enum values (stored as String, validated by zod — ADR-005):**

| Field | Allowed values |
|---|---|
| user.role | `super_admin` `tenant_admin` `security_admin` `network_admin` `soc_analyst` `helpdesk` `auditor` `api_service` |
| firewall_rules.action | `allow` `deny` `drop` `reject` |
| firewall_rules.logging | `none` `summary` `detail` |
| services.protocol | `tcp` `udp` `icmp` `any` |
| nat_rules.type | `snat` `dnat` `hairpin` `exempt` |
| interfaces.type | `physical` `vlan` `bridge` `bond` `loopback` `gre` `ipip` |
| interfaces.mode | `l2` `l3` (L2/L3 mode toggle — spec §1.2; `l3` default, IP config hidden when `l2`) |
| interfaces.role | `wan` `lan` `dmz` `vpn` `mgmt` `unused` |
| wan.config.type | `static` `dhcp` `pppoe` |
| wan_policies.mode | `priority` `failover` `load_balance` |
| wan_policies.probe_type | `icmp` `tcp` `dns` `http` |
| vpn_configs.type | `wireguard_s2s` `wireguard_remote` `ipsec_s2s` `ipsec_remote` `openvpn` |
| vpn_configs.status | `up` `down` `connecting` `error` |
| ips_policies.mode | `inline_drop` `inline_tap` `passive` |
| ips_events.action | `alert` `drop` `reject` `bypass` `suppressed` |
| severity (ips_events) | `info` `low` `medium` `high` `critical` |
| notifications.severity | `info` `warning` `critical` |
| dns_records.type | `A` `AAAA` `CNAME` `MX` `TXT` `SRV` `PTR` |
| dhcp_leases.state | `active` `expired` `released` |
| dhcp_subnets.family | `ipv4` `ipv6` (basic DHCPv6 — spec §1.9) |
| syslog_targets.protocol | `udp` `tcp` `tls` |
| netflow_targets.version | `v5` `v9` `ipfix` |
| report_schedules.range | `daily` `weekly` `monthly` |
| report_schedules.format | `pdf` `html` `csv` `json` |
| webhooks.events | `alerts.new` `config.updated` `wan.status` `vpn.status` `sessions.update` |
| snmp.version | `v2c` `v3` |
| directory_sources.type | `ldap` `ad` |
| ips_preset | `conservative` `balanced` `aggressive` (one-click policy presets — spec §1.6) |
| qos_policies.template | `voip` `video` `gaming` `bulk` `custom` |
| notifications.type | `threat` `system` `vpn` `ha` `config` |
| ha_configs.role | `disabled` `active` `standby` |
| bridge stpMode | `stp` `rstp` (JSON field on bridge config, spec §1.2) |
| identity method | `local` `radius` `captive_portal` `vpn` |
| audit_log.result | `success` `failure` `denied` |

---

## 7. API Contract (LOCKED)

### 7.1 General rules

- Base path: `/api/v1/…` (Next route handlers, NOT server actions).
- Auth: httpOnly cookie `cryptsk_token` (JWT, 8h). API keys via `Authorization: Bearer ck_<key>` for machine access.
- Response envelope: success `{ "data": …, "meta"?: … }`; error `{ "error": { "code", "message", "details"?, "requestId"? } }` (`requestId` = per-request correlation id from the shared handler middleware — ADR-016).
- Standard errors: `VALIDATION_ERROR` 400, `UNAUTHORIZED` 401, `FORBIDDEN` 403, `NOT_FOUND` 404, `CONFLICT` 409, `RATE_LIMITED` 429, `INTERNAL` 500.
- Pagination: `?page=1&limit=25&sort=-timestamp` → `meta: { page, limit, total, totalPages }`.
- Filtering: `?q=` free text + field filters (`?severity=critical&since=ISO&until=ISO`).
- All mutations write an `audit_log` row (actor, before/after) — enforced in `lib/api/handler.ts`.
- Full standards: `docs/04-API/API_STANDARDS.md`. Full catalog with examples: `docs/04-API/ENDPOINTS.md`.

### 7.2 API_SURFACE catalog (paths are LOCKED — expand, never rename)

```
AUTH
POST   /api/v1/auth/login                      {username, password, totpCode?} → sets cookie
                                               (totpCode required only when the user has
                                               enrolled TOTP — M07 §5.6)
POST   /api/v1/auth/logout
GET    /api/v1/auth/me                         current user + permissions

DASHBOARD
GET    /api/v1/dashboard/summary               health, throughput, sessions, alerts24h,
                                               topApps, topTalkers, wanStatus, vpnStatus

NETWORK
GET    /api/v1/interfaces                      list (with live stats)
POST   /api/v1/interfaces                      create (vlan/bridge/bond/gre)
GET    /api/v1/interfaces/{id}                 detail
PUT    /api/v1/interfaces/{id}                 update (ip config, mtu, role, zone…)
DELETE /api/v1/interfaces/{id}                 delete (non-physical only)
GET    /api/v1/interfaces/{id}/stats           per-iface counters
GET    /api/v1/routes                          static routes list
POST   /api/v1/routes
PUT    /api/v1/routes/{id}
DELETE /api/v1/routes/{id}
GET    /api/v1/wan-policies                    multi-WAN policies + probe states
POST   /api/v1/wan-policies
PUT    /api/v1/wan-policies/{id}
DELETE /api/v1/wan-policies/{id}
POST   /api/v1/wan-policies/{id}/probe         force probe now

OBJECTS
GET    /api/v1/zones                           + POST;  PUT/DELETE /api/v1/zones/{id}
GET    /api/v1/address-objects                 + POST;  PUT/DELETE /api/v1/address-objects/{id}
GET    /api/v1/address-groups                  + POST;  PUT/DELETE /api/v1/address-groups/{id}
GET    /api/v1/service-objects                 + POST;  PUT/DELETE /api/v1/service-objects/{id}
GET    /api/v1/service-groups                  + POST;  PUT/DELETE /api/v1/service-groups/{id}
GET    /api/v1/schedule-objects                + POST;  PUT/DELETE /api/v1/schedule-objects/{id}

FIREWALL
GET    /api/v1/firewall-rules                  ordered list (+ ?zone=&search=)
POST   /api/v1/firewall-rules
GET    /api/v1/firewall-rules/{id}
PUT    /api/v1/firewall-rules/{id}
DELETE /api/v1/firewall-rules/{id}
PATCH  /api/v1/firewall-rules/{id}/toggle      {enabled}
POST   /api/v1/firewall-rules/reorder          {orderedIds: number[]}
GET    /api/v1/firewall-rules/{id}/hits        hit counters
POST   /api/v1/firewall-rules/{id}/hits/reset  reset per-rule counters (audited)
POST   /api/v1/firewall-rules/validate         shadow/conflict check (no persist)
POST   /api/v1/firewall-rules/import           {format: json|csv, payload}
GET    /api/v1/firewall-rules/export?format=
GET    /api/v1/nat-rules                       + POST; PUT/DELETE /api/v1/nat-rules/{id}
PATCH  /api/v1/nat-rules/{id}/toggle           {enabled}
POST   /api/v1/nat-rules/reorder               {orderedIds: number[]}

IPS
GET    /api/v1/ips/policies                    + POST; PUT/DELETE /api/v1/ips/policies/{id}
GET    /api/v1/ips/rule-categories             ET category list + enabled state
GET    /api/v1/ips/events                      ?severity=&sid=&q=&since=&until=&category=&page=
POST   /api/v1/ips/events/{id}/suppress        {duration: "24h"|"7d"|"forever"}

VPN
GET    /api/v1/vpn/configs                     + POST; PUT/DELETE /api/v1/vpn/configs/{id}
GET    /api/v1/vpn/configs/{id}/status         tunnel state, DPD, handshakes
POST   /api/v1/vpn/configs/{id}/client-bundle  → wg .conf / .ovpn download payload
GET    /api/v1/vpn/sessions                    active sessions
POST   /api/v1/vpn/sessions/{id}/disconnect

DNS & DHCP
GET    /api/v1/dns/settings                    resolver config; PUT same path
GET    /api/v1/dns/policies                    + POST; PUT/DELETE /api/v1/dns/policies/{id}
GET    /api/v1/dns/records                     + POST; PUT/DELETE /api/v1/dns/records/{id}
GET    /api/v1/dns/query-logs                  ?q=&blocked=
GET    /api/v1/dhcp/subnets                    + POST; PUT/DELETE /api/v1/dhcp/subnets/{id}
GET    /api/v1/dhcp/reservations               + POST; PUT/DELETE /api/v1/dhcp/reservations/{id}
GET    /api/v1/dhcp/leases                     ?state=active|expired
POST   /api/v1/dhcp/leases/{id}/release        force-release a lease

IDENTITY
GET    /api/v1/users                           + POST; PUT/DELETE /api/v1/users/{id}
GET    /api/v1/user-groups                     + POST; PUT/DELETE /api/v1/user-groups/{id}
GET    /api/v1/auth-settings                   password policy, lockout, TOTP; PUT same
GET    /api/v1/radius-profiles                 + POST; PUT/DELETE /api/v1/radius-profiles/{id}
POST   /api/v1/radius-profiles/{id}/test       simulated connectivity test → {data:{ok, latencyMs}}
POST   /api/v1/radius-profiles/{id}/reveal     clear sharedSecret (super_admin/tenant_admin, audited)
GET    /api/v1/captive-portal                  profile; PUT same path
GET    /api/v1/captive-portal/vouchers         list vouchers (simulated, in-memory)
POST   /api/v1/captive-portal/vouchers         {count, ttlHours?, bandwidthKbps?} → batch
DELETE /api/v1/captive-portal/vouchers/{id}   revoke one voucher
GET    /api/v1/identity/sessions               live ip→user sessions map
POST   /api/v1/identity/sessions/{id}/expire   force-expire a session (audited)

QOS
GET    /api/v1/qos/policies                    + POST; PUT/DELETE /api/v1/qos/policies/{id}
GET    /api/v1/qos/rules                       + POST; PUT/DELETE /api/v1/qos/rules/{id}
       (qos rules are scoped by ?policyId=)

LOGS
GET    /api/v1/logs/firewall                   ?q=&action=&src=&dst=&since=&until=&page=
GET    /api/v1/logs/firewall/export            CSV of current filter (same params, no page)
GET    /api/v1/logs/ips                        ?severity=&category=&page=
GET    /api/v1/logs/audit                      ?user=&objectType=&page=
GET    /api/v1/logs/stats                      chart aggregates ?range=1h|24h|7d

HA
GET    /api/v1/ha/status                       local + peer state (simulated)
GET    /api/v1/ha/config                       PUT same path

SYSTEM
GET    /api/v1/system/status                   cpu/ram/disk/temp/uptime/services
GET    /api/v1/system/settings                 PUT same path
GET    /api/v1/system/backups                  + POST (create); POST /api/v1/system/backups/{id}/restore
GET    /api/v1/system/backups/{id}/download    JSON backup download
GET    /api/v1/notifications                   ?unread=; POST /api/v1/notifications/{id}/read
POST   /api/v1/notifications/read-all          mark all read (audited)
GET    /api/v1/config-versions                 ?page=; GET /api/v1/config-versions/{id}
GET    /api/v1/api-keys                        + POST; DELETE /api/v1/api-keys/{id}

PHASE-1 RESTORED SURFACE (REVIEW-4A — owner zero-loss ruling; additive, never renames)
SWITCHING / NETWORK EXTRAS (section interfaces)
GET    /api/v1/network/lldp-neighbors          derived LLDP neighbor table (MockEngine ring)
GET    /api/v1/network/mac-table               derived bridge FDB view (?iface=&vlan=&q=)
GET    /api/v1/network/port-mirrors            + POST; PUT/DELETE /api/v1/network/port-mirrors/{id}
GET    /api/v1/network/app-catalog             nDPI app-label catalog for rule/QoS pickers
POLICY ROUTES (section routing)
GET    /api/v1/pbr-rules                       + POST; PUT/DELETE /api/v1/pbr-rules/{id}
PATCH  /api/v1/pbr-rules/{id}/toggle           {enabled}
IPS (section ips)
POST   /api/v1/ips/policies/apply-preset       {preset: conservative|balanced|aggressive, name?}
GET    /api/v1/ips/update-settings             auto-update scheduler config; PUT same path
VPN (section vpn)
GET    /api/v1/vpn/user-groups                 + POST; PUT/DELETE /api/v1/vpn/user-groups/{id}
DHCP (section dhcp)
GET    /api/v1/dhcp/relay                      relay (ip-helper) config; PUT same path
IDENTITY (section identity)
GET    /api/v1/directory-sources               + POST; PUT/DELETE /api/v1/directory-sources/{id}
POST   /api/v1/directory-sources/{id}/test     simulated LDAP/AD connectivity test
LOGGING (section system)
GET    /api/v1/logs/syslog-targets             + POST; PUT/DELETE /api/v1/logs/syslog-targets/{id}
GET    /api/v1/logs/netflow-targets            + POST; PUT/DELETE /api/v1/logs/netflow-targets/{id}
GET    /api/v1/logs/report-schedules           + POST; PUT/DELETE /api/v1/logs/report-schedules/{id}
POST   /api/v1/logs/report-schedules/{id}/run  generate the report now (simulated)
GET    /api/v1/logs/reports/export             ?range=1h|24h|7d&format=csv|json
API PLATFORM (section system)
GET    /api/v1/webhooks                        + POST; PUT/DELETE /api/v1/webhooks/{id}
POST   /api/v1/webhooks/{id}/test              simulated delivery → {ok, status, latencyMs}
GET    /api/v1/openapi.json                    OpenAPI 3.1 artifact (generated from zod)
SYSTEM (section system)
POST   /api/v1/system/services/{name}/restart  restart a running service (audited, simulated)
GET    /api/v1/system/firmware                 current/channel/history; POST …/firmware/check
POST   /api/v1/system/firmware/upgrade         staged upgrade (safety backup first, simulated)
POST   /api/v1/system/firmware/rollback        roll back to previous version (simulated)
GET    /api/v1/system/policy-templates         per-vertical starter templates
POST   /api/v1/system/policy-templates/{id}/apply
GET    /api/v1/system/ssh-keys                 + POST; DELETE /api/v1/system/ssh-keys/{id}
POST   /api/v1/system/setup/complete           mark first-time-setup wizard done
```

### 7.3 Realtime events (socket.io, LOCKED)

Transport: connect with `io("/?XTransformPort=3003")` — NEVER a port in the hostname.
Service: `mini-services/realtime-service/` (bun --hot, port 3003).

| Event (server → client) | Payload shape | Emitted |
|---|---|---|
| `metrics:tick` | `{ ts, ifaces: [{name, rxKbps, txKbps}], cpuPct, memPct, conntrackCount }` | every 2s |
| `logs:tail` | `{ kind: "firewall"\|"ips", entry: FirewallLog \| IpsEvent }` | ~1–3/s, while tailed |
| `alerts:new` | `{ notification: Notification }` | on generated threat/system alerts |
| `sessions:update` | `{ kind: "vpn"\|"identity", diff: [...] }` | on session change |
| `wan:status` | `{ iface, state: up\|down\|degraded }` | on probe state change |
| `vpn:status` | `{ vpnId, status: up\|down\|connecting\|error, statusMessage? }` | on tunnel state change |
| `config:updated` | `{ section: string }` | after any config mutation (clients refetch) |

Client → server (subscribe control): `subscribe { channels: ["metrics","logs","alerts"] }`, `unsubscribe { channels }`.

---

## 8. View Map — Single-Route SPA (LOCKED)

**HARD SANDBOX RULE: the only Next.js route is `/` (`src/app/page.tsx`). Never create
other routes.** All navigation is client-side: `AppShell` parses `window.location.hash`
and renders the matching view from a `viewRegistry`. Deep links = hash links.

```
#/login                    auth gate (rendered instead of shell when no session)
#/dashboard
#/network/interfaces        tabs: Interfaces | LLDP Neighbors | MAC Table | Mirroring (SPAN)
#/network/routing           tabs: Static Routes | Policy-Based Routes
#/network/wan
#/firewall/rules
#/firewall/nat
#/firewall/objects         tabs: Address | Address Groups | Services | Service Groups | Schedules
#/firewall/zones
#/ips/policies
#/ips/events
#/vpn/configs              tabs: WireGuard | IPSec | OpenVPN | User Groups
#/vpn/sessions
#/dns-dhcp/dns             tabs: Resolver Settings | Policies | Records | Query Log
#/dns-dhcp/dhcp            tabs: Subnets | Reservations | Leases | Relay
#/identity/users
#/identity/sessions
#/identity/portal          captive portal settings + guest vouchers
#/qos/policies
#/logs/firewall
#/logs/ips
#/logs/audit
#/logs/live                realtime tail (socket.io logs:tail)
#/logs/reports             tabs: Reports | Scheduled | Forwarding
#/ha
#/system/settings
#/system/backups
#/system/api-keys          tabs: API Keys | Webhooks
#/setup                    first-time-setup wizard (view 29; renders instead of the
                           shell while `system_settings` `setup.completed = false` —
                           same gate pattern as AuthGate; not in the sidebar)
```

Sidebar groups (order): Dashboard, Network, Firewall, IPS, VPN, DNS & DHCP, Identity,
QoS, Logs & Reports, HA, System. Full layouts per view: `docs/05-FRONTEND/PAGE_MAP.md`.

---

## 9. Design Tokens Contract (LOCKED)

| Token | Value | Notes |
|---|---|---|
| Color hard rule | **NO indigo, NO blue** (any `indigo-*`, `blue-*`) | platform rule; applies to charts too |
| Brand primary | emerald (`--primary` = emerald-500 dark / emerald-600 light) | buttons, active nav |
| Accent | teal | charts secondary, focus rings may use standard ring token |
| Semantic allow/healthy | emerald-500 | allow rules, UP states |
| Semantic warn/degraded | amber-500 | degraded WAN, warnings |
| Semantic block/critical | rose-600 | deny/drop rules, critical alerts |
| Neutrals | zinc | backgrounds, borders, text (dark: zinc-950 base) |
| Charts palette | emerald, teal, amber, rose, orange, violet, zinc | ordered series colors |
| Theme | dark default, light available (next-themes, class strategy) | |
| Radius | shadcn default (`--radius`) | do not change |
| Density | cards `p-4`/`p-6`, grids `gap-4`/`gap-6` | consistency rule |
| Long lists | `max-h-96 overflow-y-auto` + custom scrollbar styles | logs, tables |
| Touch targets | min 44px on mobile controls | |
| Footer | sticky bottom via `min-h-screen flex flex-col` + `mt-auto` | only console login/marketing surfaces need it |
| Motion | framer-motion, subtle (150–250ms), respect reduced motion | |
| Icons | lucide only | no other icon sets |
| Logo | text wordmark "CRYPTSK" + ShieldCheck lucide glyph | no image assets needed |

---

## 10. Database Rules (SQLite Adaptation — LOCKED)

1. File DB at `db/cryptsk.db`; schema source = `prisma/schema.prisma`; apply with `bun run db:push`. Client: `import { db } from '@/lib/db'`.
2. **PostgreSQL → SQLite mapping rules:**

| Spec (PostgreSQL) | Build (Prisma/SQLite) |
|---|---|
| `SERIAL`/`BIGSERIAL` PK | `Int @id @default(autoincrement())` |
| `TIMESTAMPTZ` | `DateTime` (stored ISO-8601 UTC) |
| `JSONB` | `String` holding JSON (`@default("{}")` / `@default("[]")`), validated by zod, helpers in `lib/json.ts` |
| `TEXT[]`, `INET[]`, `INTEGER[]` | `String` holding JSON array |
| id-list references (`source_addr_ids INTEGER[]`) | `String` JSON array of ids = **logical reference**, integrity enforced in service layer |
| `INET`, `CIDR`, `MACADDR` | `String` + zod validation (`ipv4()`, `cidr`, mac regex) |
| `DATERANGE` | `startsAt DateTime?` + `endsAt DateTime?` |
| PG enums | `String` + zod enum (§6 table) — **do NOT use Prisma enums on SQLite** |

3. **No Prisma enums. No Prisma `Json` type. No array scalar types.** (Portability + SQLite guarantees.)
4. Every tenant-scoped model has `tenantId Int @default(1)` FK → `tenants`. Sandbox seeds exactly one tenant (id 1, name "Default").
5. Multi-row list endpoints paginate; big tables (`firewall_logs`, `ips_events`, `audit_log`) get `@@index` on `(tenantId, createdAt)` + hot filters.
6. Definitive schema + per-model notes: `docs/03-DATABASE/SCHEMA.md`. Relations: `ER_DIAGRAM.md`. Seed/reset: `DATA_LIFECYCLE.md`.

---

## 11. Sandbox Execution Rules (HARD CONSTRAINTS — memorize)

1. **Single route:** only `/` via `src/app/page.tsx`. Creating other pages/routes is a bug.
2. **Dev server:** `bun run dev` (port 3000) runs in background; never run a second instance; never `bun run build`.
3. **Logs:** check `/home/z/my-project/dev.log` (tail only) when debugging.
4. **Lint:** `bun run lint` must pass before declaring work done.
5. **Relative fetch only:** no absolute URLs, no ports in hostnames. Cross-service = `?XTransformPort=<port>`.
6. **Realtime** = socket.io mini-service on 3003; client connects `io("/?XTransformPort=3003")`. No SSE/polling substitutes for realtime features.
7. **z-ai-web-dev-sdk is backend-only** (API routes / mini-services). Never bundle into client.
8. **No test code.** Verification = lint + dev.log + browser check.
9. **Use existing shadcn/ui** in `src/components/ui`; don't rebuild primitives.
10. **API routes, not server actions.**
11. **Build frontend first** so the user sees results early, then backend wiring.
12. **Footer sticky** (`min-h-screen flex flex-col` + `mt-auto`) wherever a footer exists; never overlay content.
13. **No indigo/blue colors** anywhere (components, charts, docs examples).
14. **Schema changes:** edit `prisma/schema.prisma` → `bun run db:push` → update `docs/03-DATABASE/*` in the same task.
15. New dependencies allowed only when a doc'd reason exists (e.g. `socket.io`, `socket.io-client`, `jose`, `bcryptjs`).

---

## 12. Recipes (How To Do Common Things)

### Add a new view (client "page")
1. Create `src/components/views/<module>/<View>.tsx`.
2. Register in `src/components/shell/view-registry.ts` (hash path + component + nav meta).
3. Add sidebar entry (auto from registry, grouped per §8).
4. Add data hooks in `src/hooks/use-<resource>.ts` (TanStack Query, key `[resource, params]`).
5. Respect: p-4/p-6, gap-4/6, max-h scroll lists, EmptyState, skeleton loading, 44px targets.

### Add a new API resource
1. Zod schemas in `src/lib/validators/<resource>.ts` (reuse §6 enums).
2. Route handlers under `src/app/api/v1/<resource>/…` using `lib/api/handler.ts`
   (envelope + auth + RBAC + audit are injected there — do not hand-roll).
3. Adapter calls if runtime state is involved (`lib/adapters/`).
4. Hooks + wire into views. Add/verify endpoint in `docs/04-API/ENDPOINTS.md`.

### Add a DB table/column
1. Edit `prisma/schema.prisma` (follow §10 rules; snake_case maps).
2. `bun run db:push`.
3. Update `docs/03-DATABASE/SCHEMA.md` + `ER_DIAGRAM.md` (+ seed if needed).
4. Append session log entry.

### Apply a config change (the core loop of a UTM)
`UI → POST/PUT API → zod validate → DB write (tx) → audit_log → adapter.applyConfig(section)
→ (sandbox: SimulatedAdapter marks version + broadcasts config:updated)
→ (appliance: generator renders nftables.conf/unbound.conf/… → agent applies → status)`
Sections: firewall | nat | interfaces | routing | dns | dhcp | vpn | ips | qos | ha | identity | system.
Never let the UI talk to system services directly.

### Debug something
`bun run lint` → tail `dev.log` → browser check the exact hash view → check network tab
for envelope shape. Do not add console.log spam; remove temp logs after.

---

## 13. Gotchas (learned-the-hard-way section — keep appending)

- Next 16 + React 19: keep `"use client"` on every interactive component; server components
  cannot use zustand/socket hooks.
- recharts + React 19: use the `ui/chart.tsx` shadcn wrapper patterns; avoid dynamic
  imports inside render loops.
- Prisma on SQLite: no enums/Json/arrays (see §10). Forgetting `@map` breaks snake_case contract.
- TanStack Query: never inline `queryKey` objects without params; keys must include all
  filters so cache invalidation works (`config:updated` handler invalidates by prefix).
- socket.io through the gateway: query string must be exactly `?XTransformPort=3003`;
  the mini-service must bind 0.0.0.0 and print its port at boot.
- Mock data must be **seedable** (fixed seed) or screenshots/demos become unreproducible.
- Time handling: store UTC, display with `date-fns` in user locale; the spec's schedules
  use IANA timezone strings (`Asia/Calcutta` etc.).
- Never render raw JSON blobs in UI without a `JsonFieldViewer` (monospace, collapsible).
- Rate: logs tables must paginate server-side; loading 5k rows into a client table will jank.

---

## 14. Doc Map (see `docs/README.md` §3 for full tree + reading matrix)

Topic docs: 01-PRODUCT (2) · 02-ARCHITECTURE (4) · 03-DATABASE (3) · 04-API (2) ·
05-FRONTEND (3) · 06-MODULES (11) · 07-SECURITY (1) · 08-OPERATIONS (1) = 27 docs + this file + README + ADRs + glossary + review reports in `09-REVIEWS/`.

---

## 15. SESSION LOG (append-only — newest on top)

### 2026-11-05 — SPEC moved into docs + zero-feature-loss audit (4A/4B) — CLEARED FOR BUILD
- **Master feature sheet moved:** `upload/Cryptsk_UTM_Optimized_Spec (1).md` → **`docs/SPEC.md`**
  (git rename; all cross-references updated; `upload/` now git-ignored). SPEC.md is ground
  truth for WHAT; docs remain ground truth for HOW/state.
- **Owner hard rule:** ZERO features from SPEC.md may be missing from the doc suite.
  All prior "console-deferred Phase-1" deferrals are RESCINDED (formalized in **ADR-018**).
- **4A lane (Phase-1 completeness):** 188/188 spec Phase-1 features covered — zero gaps,
  zero deferrals. Restored (formerly deferred): PBR, BFD, LLDP, IGMP snooping, MAC table,
  SPAN/mirroring, L2/L3 toggle, DHCP relay, conditional forwarding, basic DHCPv6,
  per-user/per-app bandwidth hard limits, IPS auto-update + presets, VPN user groups,
  session-limit/timeout UIs, firmware/NTP/SNMP/hardening/SSH-keys/policy-templates,
  webhooks registration, OpenAPI JSON, `#/setup` wizard. New models: PbrRule, PortMirror,
  VpnUserGroup, SyslogTarget, NetflowTarget, ReportSchedule, Webhook, SshKey,
  DirectorySource (+HaConfig.sessionSync/trackedInterfaces etc.). ~33 endpoints restored;
  view registry now 29 views. Report: `09-REVIEWS/REVIEW-4A-FEATURE-COVERAGE.md`.
- **4B lane (Phase 2–4 + §2–§9):** every Phase 2/3/4 feature + OS/stack/architecture/
  roadmap/gaps/competitive/pricing/hardware fact phase-tagged in ROADMAP/PRODUCT_OVERVIEW/
  GLOSSARY (+24 terms). ROADMAP §5 deferral row → RESTORED note. Report:
  `09-REVIEWS/REVIEW-4B-PRODUCT-COVERAGE.md`.
- **Contract notes:** realtime stays 7 events (derived views poll 10 s); `config:updated
  {section:"all"}` = restore/template-apply sentinel (ADR-018); webhooks = console
  registration CRUD + simulated-delivery stub, appliance delivers for real.
- **STATUS: documentation complete & spec-audited — development authorized (M0 → M01…M11
  per ADR-014 order).**

### 2026-11-05 — Three-lane expert review (2A/2B/2C) + cross-agent reconciliation
### 2026-11-05 — Three-lane expert review (2A/2B/2C) + cross-agent reconciliation
- Three parallel expert agents reviewed every doc line-by-line against the spec:
  **2A** network architect (architecture/data-plane/modules M02/M04/M05/M06/M08 +
  AUTH_AND_RBAC — 23 issues), **2B** full-stack/db architect (database/API/frontend/
  modules M01/M03/M07/M09/M10/M11 — 32 issues), **2C** solution architect (memory/
  product/roadmap — 15 issues). Reports in `09-REVIEWS/REVIEW-2A-NETWORK-ARCHITECT.md`,
  `REVIEW-2B-FULLSTACK.md`, `REVIEW-2C-SOLUTION-ARCHITECT.md`.
- Coordinator reconciliation locked the canonical facts that now hold **project-wide**:
  1. Suricata Phase-1 inline = **nftables NFQUEUE** (`queue num 1-4 fanout bypass`);
     AF_PACKET = passive/SPAN only (ADR-003 refined; propagated to DECISIONS, ROADMAP,
     PRODUCT_OVERVIEW, GLOSSARY).
  2. `ips_events` is the canonical table name (spec's `ips_logs` = typo) — ADR-015.
  3. Error envelope now carries optional `requestId` (ULID from handler middleware) —
     ADR-016; PROJECT_MEMORY §7.1 + API_STANDARDS §4 updated.
  4. IPS bypass: `exceptions` `sid: 0` = any SID (nftables skip-queue); default policy
     for rules without `ipsPolicyId` = first enabled by seed order — ADR-017;
     SCHEMA §4 + ENDPOINTS §5 + M04 aligned.
  5. SCHEMA §4 `wireguard_remote` config now includes `peers[]` (bundle generation
     appends them; M05 §2/§4 aligned).
  6. `POST /dhcp/leases/{id}/release` is locked (M06 §3/§4/§7/§8 updated from "proposed
     PATCH").
  7. `vpn:status` confirmed in the locked 7-event realtime set everywhere (incl. ADR-008,
     M11 machine-client note).
  8. Notification severity = `info|warning|critical` (3-level); `ips_events` severity stays
     5-level; `notifications.type` = `threat|system|vpn|ha|config` — SCHEMA/ENDPOINTS/M09
     aligned.
  9. Hardware tier naming = Starter/Standard/Performance; default user role = `helpdesk`.
- Remaining open items before M0 code: none blocking. Console-deferred spec-Phase-1
  features (PBR, DHCP relay/conditional forwarding/DHCPv6, per-user/per-app hard limits,
  IPS auto-update presets, VPN user groups) stay tracked in ROADMAP §5 with product
  sign-off required — see REVIEW reports for the full lists.
  **[SUPERSEDED 2026-11-05, later same day]** The product owner's zero-feature-loss
  ruling rescinded ALL console deferrals — every listed feature is RESTORED to Phase 1
  and covered (see the newest session-log entry above + ADR-018).

### 2026-11-05 — Solution-architecture / product review (2C) + fixes
- Reviewed memory pack, product docs, M02/M04/M05 (product lens), DEVELOPMENT_GUIDE
  against the original spec. Fixed: spec-authority wording (§1), stale M05 `vpn:status`
  open question, stale M04 `?category=` note + `forever`-sentinel semantics (aligned to
  ENDPOINTS.md: `suppressedUntil = null` + `action = "suppressed"`), M02 PPPoE shape
  missing `password` (now matches SCHEMA.md), ADR-008 event list missing `vpn:status`,
  webhooks phase attribution in ROADMAP (spec Phase 1 custom engineering; console ships
  stubs), ROADMAP §5 build-deferral attribution for IGMP-snooping/LLDP/PBR/BFD/IPS-auto-
  update/VPN-user-groups rows, glossary RBAC role list + SASE/CASB split + IDS/IPS +
  shadow rule + TPROXY wording, PRODUCT_OVERVIEW "webhooks (stubs)" wording, README
  09-REVIEWS folder + review-status table + reading-matrix row, ROADMAP §1.4 Phase 1
  exit criteria (Architect note). Details: `docs/09-REVIEWS/REVIEW-2C-SOLUTION-ARCHITECT.md`.

### 2026-11-05 — Contract reconciliation pass (post-doc-suite review)
- Added additive endpoints to §7.2: hits/reset, nat toggle + reorder, ips events `?category=`,
  captive-portal vouchers (GET/POST/DELETE), identity sessions expire, radius test + reveal,
  dhcp lease release, logs/firewall/export, backups download, notifications read-all.
  Mirrored into 04-API/ENDPOINTS.md tables (same role floors + audit flags).
- Added `vpn:status` socket event (§7.3); M05 realtime table updated to consume it.
- Split severity enums (§6): ips_events = info|low|medium|high|critical;
  notifications = info|warning|critical.
- ConfigSection now includes `identity` (ARCHITECTURE §4 + SIMULATION_LAYER §3).
- SCHEMA.md fixes: User.role default `helpdesk` (no `viewer` role), PPPoE password field,
  HA priority = higher wins (Keepalived semantics corrected), §6 Pseudo-Resources table
  (dns settings → SystemSetting row, backups → filesystem JSON, vouchers in-memory).
- RBAC authority confirmed = 07-SECURITY/AUTH_AND_RBAC.md §4; M07 role table reconciled
  (security_admin owns firewall/IPS/VPN-session-ops; network_admin owns network/DNS/DHCP/QoS/HA/VPN-config;
  helpdesk read-only).
- Stale gap notes across 04-API + 07-SECURITY marked resolved.

### 2026-11-05 — Documentation phase (docs-first milestone)
- Read full product spec (`docs/SPEC.md`, 1562 lines).
- Authored complete `docs/` suite: memory pack (this file, ADRs, glossary), architecture
  (4 docs), database (3), API (2), frontend (3), modules M01–M11 (11), security (1),
  operations (1), plus root `AGENTS.md` pointer and `docs/README.md` index.
- Locked contracts: API_SURFACE (§7), view map (§8), design tokens (§9), SQLite rules (§10),
  naming + enums (§6), realtime events (§7.3).
- **No application code written yet.** Next milestone: M0 project bootstrap (see ROADMAP.md).

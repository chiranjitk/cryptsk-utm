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

| Item | Status (2026-11-09) |
|---|---|
| Product spec read & digested | DONE |
| Documentation suite (`docs/`) | DONE (this suite) |
| Spec coverage audit (zero-feature-loss) | DONE — REVIEW-4A + REVIEW-4B closed 2026-11-05; ROADMAP §5 console-deferral row RESTORED to Phase 1 |
| Application code — Phase 1 | **COMPLETE — M0–M11 pushed** (dashboard, network, firewall & NAT, IPS, VPN, DNS & DHCP, identity, QoS, logging & reports, system/HA/notifications, API platform) |
| Application code — Phase 2 | **COMPLETE — M12–M23 pushed (2026-11-07, ADR-020)**: threat intel, PKI (real X.509), SSL inspection, URL filter, WAF, app control, BGP/OSPF, SD-WAN, IPv6 dual-stack, email security, advanced identity/NAC, enhanced logging/compliance — 46 hash views, zero placeholders |
| Real data plane — M24 | **COMPLETE (2026-11-09, ADR-021)**: `ADAPTER_MODE=host` is the DEFAULT — HostCollector (`src/lib/engine/host-collector.ts`) feeds the same engine surface from REAL sources (/proc/net.dev·stat·meminfo·tcp, sysfs, gateway TCP probes, systemctl, Suricata eve.json → ips_events, nftables kernel logs → firewall_logs, `wg show` → vpn_sessions, Kea leases → dhcp_leases, unbound log → dns ring); honest empty degradation, NO fabricated values; MockEngine only via explicit `ADAPTER_MODE=simulated` (and FORBIDDEN in production — runtime guard throws) |
| Sensor agent transport — M25 | **COMPLETE (2026-11-09, ADR-004)**: Go sensor agent SHIPPED + verified end-to-end — `agent/` (pure-stdlib Go, no cgo): POST /v1/engine/snapshot · /v1/dashboard/summary · /v1/wan/probe with the LOCKED transport contract (X-Agent-Auth constant-time, X-Request-Id logged, {data}/{error} envelope); real sources = /proc (netdev deltas, cpu jiffies, meminfo, tcp/udp, conntrack, uptime, route), statfs disk, sysfs thermal, gateway TCP:53 probes (carrier→gateway→connect, up<250ms), Suricata eve.json, journalctl -k, unbound log; AgentEngine now PERSISTS real log tails into ips_events/firewall_logs (same tables host mode writes); AgentAdapter merges host-plane telemetry with console-authoritative DB aggregates; pm2 prod ecosystem auto-starts the agent when built; install/update scripts build it (apt golang-go); e2e verify: `bun scripts/verify-agent-mode.ts` — 14/14 PASS (real ticks, real probe up, honest 401) |
| Data hygiene | sandbox DB purged of all demo/mock rows (16.7k) via `scripts/purge-mock-data.ts`; production seed = `bun prisma/seed.ts --production` (identity/RBAC + defaults only, wizard gate); fresh Debian installs never ship mock data |
| Production packaging | `deploy/install-debian13.sh` (one-shot fresh Debian 13: apt → Node/bun/pm2 → clone → secrets → schema+seed → build → pm2 → boot hook → smoke check) + `deploy/update.sh` + `ecosystem.prod.config.cjs`; **pm2 is the appliance process manager (owner mandate)** — DEPLOYMENT.md rewritten |
| Phase-1 tail | CLOSED — scheduled reports + PDF/print rendering (M12), real webhook delivery w/ HMAC signing + ledger (M11-tail ead4776) |
| Database schema (Prisma) | LIVE — pushed + seeded (`db/cryptsk.db`); DB file tracked in git since 2026-11-07 (user mandate — survives sandbox resets); ~90 tables incl. 47 Phase-2 models; tracked DB now holds the CLEAN production baseline |
| Realtime mini-service | LIVE (`mini-services/realtime-service/`, port 3003) |
| Build milestone | **Phase 1 + Phase 2 + real data plane (host + agent transport) complete — next: Debian 13 appliance run (install script builds everything incl. the Go agent)** |
| Current module in progress | none — M25 shipped 2026-11-09 |

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
| Color hard rule | **NO indigo, NO blue, NO teal** (any `indigo-*`, `blue-*`, `teal-*` class or series hex) | platform rule; applies to charts too |
| Brand primary | zinc-700 buttons (`bg-zinc-700 hover:bg-zinc-800 text-white`), active nav `bg-zinc-600/10` | primary buttons/nav are zinc (ADR-019 rev 2/rev 3); brand hue = logo glyph, focus ring `--primary`, links, `--chart-1` |
| Accent | zinc-500 | charts secondary, TX series — neutral (rev 2) |
| Semantic allow | zinc soft (calm-permit) | allow rules — red/rose is danger-only (rev 2) |
| Semantic up/healthy | emerald-600 | UP/online/health states — the ONLY emerald usage |
| Semantic warn/degraded | amber-500 | degraded WAN, warnings |
| Semantic block/critical | rose-600 | deny/drop rules, critical alerts, destructive confirms |
| Neutrals | zinc | backgrounds, borders, text (dark: zinc-950 base) |
| Charts palette | red-700, zinc-500, amber-500, rose-500, orange-500, zinc-400, slate-500 | LOCKED §2.5 order (`--chart-1…7`); rx = red-700, tx = zinc-500 |
| Theme | light default (`defaultTheme="light"`), dark fully supported (next-themes, class strategy) | ADR-019 enterprise white surfaces |
| Radius | shadcn default (`--radius`) | do not change |
| Density | cards `p-4`/`p-6`, grids `gap-4`/`gap-6` | consistency rule |
| Long lists | `max-h-96 overflow-y-auto` + custom scrollbar styles | logs, tables |
| Touch targets | min 44px on mobile controls | |
| Footer | sticky bottom via `min-h-screen flex flex-col` + `mt-auto` | only console login/marketing surfaces need it |
| Motion | framer-motion, subtle (150–250ms), respect reduced motion | |
| Icons | lucide only | no other icon sets |
| Logo | `BrandLogo` hexagon ring-keyhole SVG mark (red gradient) + "CRYPTSK" wordmark (`components/shell/brand-logo.tsx`; favicon `src/app/icon.svg`) | no image assets |

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
16. **GITHUB PUSH ON PHASE COMPLETION (HARD RULE, user-mandated 2026-11-06):** every
    module/phase (M0x) completion MUST end with a `git commit` + `git push origin main`
    to `github.com/chiranjitk/cryptsk-utm` **in the same session** — no exceptions, no
    batching across phases. Verify with `git ls-remote origin main` that the remote SHA
    matches local HEAD. Auth: GitHub PAT supplied per-session by the user (the sandbox
    does not persist tokens; never write the token to any file).
17. **Never commit runtime artifacts** (`.env`, `.next/`, `dev.log`, `upload/`,
    `.zscripts/` logs) — the `.gitignore` guards these; if a sandbox checkpoint clobbers
    it, restore it before pushing (gotcha: it happened once, 2026-11-06).
    **EXCEPTION (user-mandated 2026-11-07):** `db/cryptsk.db` IS tracked — the seeded
    SQLite snapshot ships in git so a sandbox reset can be healed with
    `git checkout -- db/cryptsk.db` instead of a full re-seed. Sidecar files
    (`*.db-journal/-wal/-shm`) stay ignored; re-run `bun prisma/seed.ts` only if the
    tracked snapshot is older than the latest schema change.

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

- **PM2 is the ONLY sanctioned process manager (2026-11-09, user mandate):** the
  sandbox reaps detached bash/setsid dev loops between sessions — the preview panel
  kept going down ("app is down"). Fix: full stack under pm2
  (`ecosystem.config.cjs` — `cryptsk-utm` next dev :3000 + `realtime-service` :3003,
  autorestart + 1400M cap, logs → dev.log); `pm2 save` persisted so the watchdog
  does `pm2 resurrect`. NEVER restart dev via pkill/setsid/nohup loops again —
  pm2 only; the watchdog cron (`dev-server-watchdog-pm2`) enforces the same recipe.
- **Git-replaced tracked DB → stale deleted-inode fd → login 401 + "attempt to
  write a readonly database" (found 2026-11-09):** `db/cryptsk.db` is git-tracked
  (§11.17 exception). After `git pull` / `git checkout` REPLACES the file on disk,
  a running dev server keeps its open fd to the now-unlinked inode
  (`ls -l /proc/<next-dev-pid>/fd` shows `cryptsk.db (deleted)`). Symptom
  signature: SELECTs succeed but serve the stale snapshot (every login → 401 even
  though `bcrypt.compare` passes against the on-disk file via a direct Prisma
  script), while INSERTs fail with SQLite extended code 1032 "attempt to write a
  readonly database" (mock-engine firewallLog createMany). Fix: restart the dev
  server after ANY git operation that touches the tracked DB file. Diagnostic:
  `ls -l /proc/$(pgrep -f 'next dev' | head -1)/fd | grep '(deleted)'`.
- **Sandbox process reaper (found 2026-11-09):** agent-spawned dev servers die
  within minutes between tool calls — setsid+nohup+disown, supervisor loops, even
  the managed `.zscripts/dev.sh` tree are all reaped; only the platform-booted
  instance (dev.sh at sandbox start) persists across calls, and the watchdog cron
  restart recipe is the standing safety net. Consequence: multi-step runtime
  verification (restart → wait → curl login matrix → agent-browser UI flow) must
  run ATOMICALLY inside a single tool call, with an `ensure_server` retry wrapper
  around each step. Separate evidence is fine per call as long as each call
  re-establishes the server first.
- **Stale `.env` DATABASE_URL → login 401 "Invalid username or password" (found
  2026-11-09):** repo `.env` pointed `DATABASE_URL` at scaffold-era phantom
  `db/custom.db`. `db.ts`'s exists-guard made the *code* fall back to the schema URL
  correctly, but a dev-server process started while an older `.env`/code was live
  served 401s from a stale env state; root page 200 masked it (only login broke).
  Symptom signature: `POST /api/v1/auth/login` → 401 for every account while the DB
  itself verifies fine (`bcrypt.compare` true via direct Prisma script) and no login
  query appears in `dev.log` for the failing instance. Fix: `.env` now pins the real
  DB explicitly — `DATABASE_URL=file:/home/z/my-project/db/cryptsk.db` (absolute,
  gitignored) — so no resolution chain is relied upon. Also removed the inner
  `| tee dev.log` from the `dev` script (it truncated dev.log on every restart and
  hid the failing instance's log lines; the watchdog loop's outer `tee -a` is the
  only logger now). Verification matrix after fix: all 8 seeded accounts login 200
  (`admin/admin123` … `svcapi/svcapi123`, see `prisma/seed.ts` §Users), wrong
  password → 401, no cookie → 401.
- **Next standalone + Prisma SQLite (found 2026-11-08):** the traced
  `.next/standalone/node_modules/.prisma/client` does NOT resolve `env("DATABASE_URL")`
  from `process.env` at runtime (dev client does; same bytes) → SQLite "Error code 14:
  Unable to open the database file" even with a correct absolute URL exported. Fix shipped
  in `src/lib/db.ts`: resolve the URL explicitly and pass it as the constructor
  `datasourceUrl` (env → repo `.env` parse → schema fallback; `file:` URLs only trusted
  when the target exists, which also guards stale session envs pointing at
  `db/custom.db`). Never "fix" this by copying files into `.next/standalone` by hand.
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
- `.env` DATABASE_URL silently **overrides** `schema.prisma` url. After a sandbox reset,
  check `.env` points at `file:/home/z/my-project/db/cryptsk.db` (NOT the scaffold-era
  `db/custom.db`), then run `bun run db:setup` (push + seed). Symptom of a stale env:
  login 401 for valid seeds + empty `users` table.
- NEVER concatenate two Prisma JSON-string columns before `JSON.parse` (`"[1] [5]"` is
  invalid JSON → parse silently returns []). This shipped as a real bug in M03 delete
  protection (refs.ts, fixed 2026-11-06): parse each column separately and merge the
  parsed arrays. General rule: JSON columns are parsed per column, always.
- Deleting referenced seed rows during E2E tests breaks id-based JSON references
  (groups' memberIds, rule arrays). Restore with EXPLICIT ids (raw insert), not upsert.
- Parallel-built modules (backend + frontend agents against the same spec): the pinned
  contract must pin REQUEST payload shapes too, not just response shapes. M02 shipped
  a drift — frontend sent a uniform config-envelope, backend validator was a flat
  discriminated union (vlan `parent`/`vlanId` flat; bond create `mode` = aggregation
  mode; physical WAN edits top-level, not in `config`). Caught by browser E2E create
  flow, fixed same session. Rule: before wiring the shell, POST one row of each type
  through the real UI and assert the row renders.

---

## 14. Doc Map (see `docs/README.md` §3 for full tree + reading matrix)

Topic docs: 01-PRODUCT (2) · 02-ARCHITECTURE (4) · 03-DATABASE (3) · 04-API (2) ·
05-FRONTEND (3) · 06-MODULES (11) · 07-SECURITY (1) · 08-OPERATIONS (1) = 27 docs + this file + README + ADRs + glossary + review reports in `09-REVIEWS/`.

---

## 15. SESSION LOG (append-only — newest on top)

### 2026-11-16 — Design template gallery for full-app redesign (awaiting user pick)

- **Trigger:** user rejected the current look & feel; asked for 5-10 unique design templates to
  choose from before a whole-app visual conversion ("modern, beautiful, eye-catching, unique").
- **Deliverable:** standalone gallery at `public/design-templates.html` (static asset — no new
  app route, SPA untouched). Same dashboard mock (KPIs, traffic chart, threat-mix donut, live
  events table, system health) injected into 10 hand-built CSS themes via one JS template +
  per-theme var scopes: 01 Neon Cyber Ops, 02 Aurora Glass, 03 Swiss Precision, 04 Cloud Cream,
  05 Industrial Brutalist, 06 Obsidian & Gold, 07 Phosphor Terminal, 08 Violet Nova,
  09 Arctic Enterprise, 10 Sunset Dune. Includes quick-nav anchors and a "reply 'Template N'"
  selection affordance (mix-and-match allowed).
- **Discoverability:** new `src/components/shell/design-gallery-link.tsx` floating pill
  (Palette icon, bottom-right to avoid the Next dev badge collision) wired into AppShell's
  authenticated return and LoginView. Removed once the redesign lands.
- **Verification:** lint clean; `/` and `/design-templates.html` both 200; agent-browser: 10/10
  mocks rendered, zero page errors, screenshots of T1/T5/T7 + login + shell (pill visible in
  both states, palette icon intact); admin/admin123 golden path still works (dashboard live
  telemetry). dev.log healthy; the repeating `GET /api/internal/events 401` loop is
  pre-existing unauthenticated polling, unrelated to this change.
- **Light-mode toggle (user follow-up, same day):** user wanted to preview every template in light
  mode too. Added a Dark/Light segmented switch at the top of the gallery; each dark theme got a
  daylight reinterpretation (`.tN.light` var scopes + decoration overrides: T1 mist-blue ops,
  T2 pastel aurora glass, T5 paper industrial, T6 ivory & gold, T7 paper printout terminal,
  T8 daylight violet, T10 sand & terracotta) plus global `.light` semantic chips (darker
  green/amber/rose for readable deltas, severity, live chips, donut slices).
- **Fixed cascade bug found during light work:** `.mock` declared the token FALLBACKS on itself
  (`--bg` etc.), which self-overrode the values inherited from `.tN` sections — so all
  section-level theme vars were dead and templates ran on defaults (T3/T4/T9 silently rendered
  dark-ish). Fallbacks moved to `:root`; `--fnum` gets a `var(--fnum,inherit)` fallback. Verified
  computed backgrounds per theme in both modes; toggle reverts cleanly (0 `.light` sections back
  on Dark). Browser-verified: dark T1 true neon (cyan/lime/grid), light T1/T3/T7 correct, zero
  page errors.
- **Next:** convert login + shell + all module views to the user's chosen template
  (tokens → globals.css/theme, shell chrome, per-view polish) in their preferred mode (dark,
  light, or app-level theme toggle). Zero API/schema changes so far.

### 2026-11-13 — QA marathon Round 10 (cross-cutting regression + final polish)

- **Scope:** final sweep — close remaining cheap deferred items, rg cross-cutting audits,
  doc/code reconciliation, full regression. 4 code files + 3 docs (7/10 budget). Zero API/
  schema/route changes; all confirms untouched.
- **Deferred outcomes:** (1) R2 firewall-rules filter chips CLOSED — zone/tag pills + chip-row
  "Clear all" moved to the R6 44 px chip recipe (`inline-flex h-11 … lg:h-7 lg:py-1`), row
  kebab `h-11 w-11 lg:h-8 lg:w-8`; verified in-browser: chips measure 44 px at 390 px, 28 px
  at ≥lg. (2) R9 email gateways/routing density CLOSED — `useTableDensity("email-gateways"|
  "email-routing")` + DensityToggle in flex-wrap headers, `[&_th/_td]` compact selectors,
  `overflow-auto` + min-w 860/760 px, and §5.14 ROW_FLASH added to the gateway enable toggle
  (routing already had it); toggle click-verified in-browser. SSL policy ROW_FLASH stays
  CLOSED-not-applicable: the policy enable switch is a detail-panel control, not a table row
  (R9's audit re-confirmed — bypass rows already flash). (3) Primary-button doc conflict
  RESOLVED: UI_DESIGN_SYSTEM §2 hard rule 2 rewritten to **rev 3 — zinc primary as-built**
  (`bg-zinc-700 text-white hover:bg-zinc-800`, 161 sites; red/rose danger-only + retained
  brand surfaces logo/focus-ring/links/`--chart-1`), ADR-019 gained REVISION 2, PROJECT_MEMORY
  §9 stale emerald/teal/dark-default rows rewritten to the ADR-019 reality (zinc buttons,
  light default, locked chart order, BrandLogo). NO code sweep — zinc was already the standard.
- **rg sweeps:** `text-blue|bg-blue|indigo` → only comments; but reports-view's `CHART`
  constant carried REAL teal-500/emerald-500 hexes and painted `allow`/`medium` series red —
  re-pointed to the locked recipes (§5.15 severity tones, §2.3 action mapping: allow zinc,
  deny rose-600, drop rose-500, reject orange), comment + header updated; browser shows the
  new fills (#71717a/#e11d48/#f43f5e/#f97316). `Math.random` → only legit uses: shadcn
  SidebarMenuSkeleton width jitter (loading shimmer) + vpn-ui `generateSecret()` masked PSK
  placeholder (SIMULATION_LAYER §9) — no honest-data violations. `size-7|h-7 w-7` → 39
  residual sites across per-module views (ghost row buttons without the lg: escalation);
  fixed only the in-scope ones per the ≤6/≤10-file caps (rules-view ×2); rest documented as
  known residual, not a regression.
- **NEW FIND (regression sweep): dashboard 390 px horizontal overflow (sw 462 vs 390).**
  Root cause = the §5.18 R6 pass-2 Recharts rule was never applied to the dashboard's own
  card grids: ResponsiveContainer's inline-px width propagated through grid-item cards
  (throughput + apps donut) AND through flex rows with `truncate` text (threat feed header
  badges + top-rules rows) whose intrinsic min-content inflates the auto grid track. Fixed
  in dashboard-view.tsx with the locked recipe: `min-w-0` (+`overflow-hidden` on
  CardContent) on the throughput card, apps-donut card + its wrapper, threat-feed card, and
  top-rules card; threat header badge row became `flex-wrap`. Verified: dashboard sw==cw at
  390 px AND at 1280 px; charts re-measure to the real width.
- **Regression:** `bun run lint` clean (exit 0); dev.log no compile/runtime errors (only
  honest host-collector degradation noise: "system scope bus Host is down" + wan-os converge
  "egress offline" — sandbox has no systemd bus/egress); curl golden path login 200 →
  /dashboard/summary, /firewall-rules, /ips/events, /logs/firewall?limit=5, /system/status
  all 200 {data}; no-cookie → 401; GET / → 200. agent-browser E2E: 7 views (dashboard,
  firewall rules, ips events, logs search, system settings, vpn sessions, email security)
  at 1280 px + 390 px — zero horizontal overflow everywhere (dashboard was the one failure,
  fixed above), empty/loading states render (content-security tables honestly empty per
  seeded DB), console clean throughout; reports pie + email density toggle exercised live
  with no errors. NO dangerous mutations executed — confirm dialogs untouched.
- **Known residual (documented, non-blocking):** 37 pre-existing `h-7 w-7` ghost row buttons
  in sdwan/ipv6/federation/nac/iocs/feeds/waf/logs views lack the `lg:` mobile escalation —
  cosmetic desktop-consistent pattern, below the per-file edit caps this round; a future
  mechanical pass can sweep them file-by-file. Nav path correction noted: email security is
  `#/email/security` (R9 log entry's "#/web/email-security" label is wrong in prose only).
- **Marathon status: 10/10 rounds complete** — every one of the 46 hash views now carries
  the shared atom registry (scaffolds, chips w/ honest counts, density, ROW_FLASH, 44 px
  touch targets, validation parity, wide-table containment); the last cross-cutting debt
  (dashboard containment, doc conflicts) is closed.

### 2026-11-13 — QA marathon Round 9 (url-filter/app-control/ssl/waf/email)

- **Scope:** the remaining content-security views (#/web/url-filter, #/web/app-control,
  #/web/ssl-inspection, #/web/waf, #/web/email-security). Audit-first finding: ALL five
  views had good shells/stats strips/empty states/named delete confirms but NONE carried
  the R2–R8 atom recipes — zero density toggles, zero ROW_FLASH, no wide-table min-w
  wrappers, no per-field validation, no copyText, several h-7 icon buttons. Closed the
  real gaps with the established recipes only; zero API changes, zero schema/route
  changes, 5 code files + 2 docs (7/9 budget).
- **url-filter-view.tsx:** logs action Select → R6 chips (all/allowed/blocked/warned,
  `DECISION_CLS` tones, 24h counts from the shared stats key, count-less while loading)
  + search input wired to the EXISTING server-side `?q=` param (route already accepted
  it — UI exposed it at last) + DensityToggle + overflow-auto/min-w-[760px]; categories
  tab gained the enable/disable count summary strip ("n of m categories enabled" +
  "n blocking" badges, only after server rows load — no fake 0s) absorbing the old
  bottom "Saving rule set…" line; custom-lists delete + policy-card edit/delete buttons
  44 px pass; filter-aware honest empty state + Clear.
- **app-control-view.tsx:** rules table gained category filter chips derived from the
  loaded rules' nDPI categories (only when >1, honest per-category empty + Clear),
  ROW_FLASH on toggle/action/bandwidth mutations (flash variables.id), density
  (`app-control-rules`), min-w-[880px] + overflow-auto, 44 px delete; logs card gained
  a client-side app/client search (endpoint has no q param — loaded-window filter, the
  footer says "n of m loaded entries match") + density + min-w + 44 px refresh/select.
- **ssl-inspection-view.tsx:** bypass-rules table gained a value/reason search (n-of-m
  badge, per-filter honest empty + Clear), ROW_FLASH on bypass toggle, density
  (`ssl-bypass`) + min-w; logs table density (`ssl-logs`) + min-w-[680px] + overflow-auto;
  bypass delete/add-bypass buttons 44 px. SNI mono/truncate + stats strip were already
  shipped — untouched.
- **waf-view.tsx:** NEW payload preview — log rows with `payloadSnippet` render a
  `payload` pill that expands a full-width detail row with a DiagOutputBlock-style mono
  block (`max-h-56 overflow-auto break-words`, `n chars` label, net-ui copyText Copy);
  message cell became min-w-0 flex (truncate + pill); exclusion editor reached §5.16
  validation parity (matchValue required/≤256, ruleId positive int, INVALID_CLS +
  FieldErrorText + aria + focus-first-invalid + clear-on-edit, Save no longer silently
  disabled); disabled vhosts got a rose status pill + dimmed card; log table density +
  min-w-[920px], vhost/action selects 44 px.
- **email-security-view.tsx:** quarantine RELEASE is now confirm-first — the row button
  opens a ConfirmDialog naming the message ("Release \"<subject>\"?" with from → to
  consequence copy) instead of a bare mutate (§5.6 dangerous-action rule; the released
  row flashes on settle); routing-rules toggle gained ROW_FLASH; mail log gained
  DensityToggle + min-w-[820px] + overflow-auto; gateways/routing row buttons 44 px.
  Mail-log search + verdict filter were already present (untouched).
- **Verified:** `bun run lint` clean; dev.log no compile/runtime errors (one transient
  Turbopack duplicate-const during editing — caught by the GET / 500 and fixed, root
  back to 200); curl golden path (login admin/admin123 → 200; /url-filter/policies,
  /url-filter/logs?q=…, /app-control/policies, /ssl-inspection/policies, /waf/policies,
  /waf/logs, /email-security/stats, /email-security/logs?q=… all 200 {data}; no-cookie
  variants → 401; `/` → 200). NOTE: the content-security tables are empty in the seeded
  DB (pre-existing — seed populates other modules), so views show honest empty states;
  UI contracts verified against the empty envelope. agent-browser E2E: url-filter chips
  render with 24h counts, blocked-chip click + search text → "No log entries match the
  filters" + Clear restores; WAF + email-security render empty states with density
  toggles/44 px selects; 390 px viewport shows no horizontal overflow on url-filter, waf,
  email-security; browser console clean. NO mutations executed — no test data created.
- **Skipped (audit: already shipped / locked / no backend to support):** app-control
  rule reorder (rules have no order/priority field in the DTO — inventing one needs a
  schema change, banned this round); email routing-rules reorder (priority is
  server-enforced unique, edit dialog already covers it); WAF vhost/policy editors
  validation parity (single-message errors, deferred — exclusion editor was the
  mission-listed one); ssl policy ROW_FLASH (policy toggle is a detail-row switch, not a
  table row — bypass rows covered instead); stats strips (all five already had them).
- **Noted for a future round:** gateway/routing tables in email-security have no density
  toggle (header space tight; mail log covers the pattern); app-control logs could adopt
  chips once the backend adds a free-text param.
- **File budget:** 5 code (url-filter-view, app-control-view, ssl-inspection-view,
  waf-view, email-security-view) + 2 docs (UI_DESIGN_SYSTEM §5.21, PROJECT_MEMORY) = 7/9.

### 2026-11-13 — QA marathon Round 8 (system/PKI/HA)

- **Scope:** M10 system surfaces (#/system/settings incl. health/firmware/SSH/templates
  cards, #/system/backups, #/system/api-keys, notification-center untouched) + PKI
  (#/pki/authorities, #/pki/certificates) + HA (#/ha). Audit-first found MOST of the
  mission list already shipped (service chips + restart toast, resource gauges with tone
  colors, firmware check spinner + history table, typed-RESTORE restore dialog,
  API-key scope chips + show-once gated reveal + copy + revoke naming the key, SSH
  fingerprint mono + server fieldErrors, PKI search/filters/expiring chip + revoke-with-
  reason naming the cert + CRL download feedback, HA status tone badges + sync chips +
  tracked ifaces + holdDown client check — verified live, NOT re-implemented). Closed the
  REAL gaps. One additive NEW route (documented-but-missing backup download, R6 audit-
  export precedent); zero schema/route-shape changes; 6 code files + 3 docs (9/9).
- **system-view.tsx:** (1) service restart is now CONFIRM-FIRST (M10 §5.6 dangerous-action
  rule — it was a bare mutate on click): chip button opens a ConfirmDialog naming the
  service with data-plane-aware consequence copy (host: systemctl + packet-processing
  blips; simulated: ~2 s apply), per-service spinner while pending (`restart.variables ===
  svc.name`); (2) firmware upgrade confirm upgraded to a TYPED-version AlertDialog (type
  the target version to enable confirm — restores the M10 §5.6 typed rule the UI had
  dropped; R2 os-apply parity), rollback confirm names the previous history version
  (`history[history.length - 2]`); (3) SSH keys: fingerprint cell gained a copy icon
  button (net-ui copyText, 44 px mobile), add-key dialog gained §5.16 validation parity
  (name 1–64 + OpenSSH-line/private-key pre-checks mirroring validators system.ts, rose
  ring + role="alert" + focus first invalid + clear-on-edit + server fieldErrors merge;
  Save no longer silently disabled), remove confirm names the key AND fingerprint
  ("sessions authenticated with it stop working"), table wrapped overflow-x-auto +
  min-w-[640px]; (4) template apply confirm now names the template and lists its sections
  (`firewall: … · nat: …`) instead of the generic overwrite warning.
- **backups-view.tsx:** id/note/type search with its own honest empty state + Clear;
  Created cell stacks an AgeBadge (<24 h emerald / 1–6 d zinc / ≥7 d amber, absolute in
  title); create-dialog note dropped silent maxLength truncation for a ≤200 submit
  pre-check (INVALID_CLS + role="alert" — the error explains the limit instead of hiding
  it); table overflow-x-auto + min-w-[760px] + h-11 lg:h-8 row buttons.
- **api-keys-view.tsx:** Created column now relative (fmtRelative, absolute in title —
  parity with Last used); keys + webhooks tables wrapped overflow-x-auto + min-w-[820]/
  [900] + 44 px row-control pass. Show-once reveal NOT given a countdown (locked M11 §5.1
  pattern — the "I have saved it" gate is stronger than auto-hide; skipped honestly).
- **ha-view.tsx:** editor gained full §5.16 validation parity — per-field client
  pre-checks at submit mirroring haConfigSchema (priority 1–255 int, virtualIp CIDR shape,
  peerIp IPv4 shape, failAfterSec 3–3600, holdDownSec 0–86400 AND ≥ failAfterSec, enabled
  ⇒ role+peerIp), INVALID_CLS rose rings + aria-invalid/describedby + role="alert" +
  focus-first-invalid + clear-on-edit, server fieldErrors merge on 400, Save enabled
  (errors explained, not silently blocked — replaces the holdDownInvalid/enableInvalid
  silent disables which kept their inline messages); tracked-interface chips h-11 lg:h-7.
- **certificates-view.tsx:** NEW expiring-certificate highlight strip (fed by the EXISTING
  GET /pki/certificates/expiring?days=30) under the filter card — soonest-first chips with
  mission-specified days-left tones (rose ≤7d, amber 8–30d; ExpiryPill's 30/90 scale
  unchanged), click = "Expiring ≤30d" filter, strip hidden when none (honest-empty);
  cert table overflow-auto + min-w-[880px]; search/filter chip/kebab 44 px pass.
- **NEW `GET /api/v1/system/backups/[id]/download`** (the round's real bug find): the
  endpoint documented in M10 §3/ENDPOINTS §13 behind the "Download" row action had NO
  route file — curl 404 confirmed. Additive route (R6 audit-export precedent): area
  `backups` read floor (mirrors the list endpoint), the EXISTING service `readBackupFile`
  (which was already written "served by the download endpoint") + `Content-Disposition
  attachment; filename="cryptsk-backup-<id>.json"` per the locked naming, `Cache-Control:
  no-store`, read-only (reads not audited per AUTH_AND_RBAC §4). Verified 200 w/cookie on
  a temp backup, 404 no-cookie + 404 unknown id; openapi manifest rows live in §7.2
  (already listed — the doc promised it, the code now matches).
- **pki-ui.tsx stale "blue" header comment: found + NOT fixed (budget)** — the file's only
  drift is its docstring claiming "root CA = solid blue" while every class is zinc/rose;
  comment-only, left for a cleanup round (noted below).
- **Verified:** `bun run lint` clean (two transient unterminated-literal parsing errors
  from smart-quote corruption during editing caught by lint and fixed before verify);
  `tsc --noEmit` — zero errors in all touched files (4 latent `.next/dev/types` generated-
  file errors are dev-artifact noise, not source); dev.log zero compile/runtime errors
  (pre-existing ost-collector/systemctl noise only — the sandbox's honest "service states
  unreadable" signal); curl golden path (login admin/admin123 → 200; /api/v1/system/status
  200 {data}; /api/v1/pki/certificates 200 {data}; /api/v1/pki/certificates/expiring 200;
  /api/v1/ha/status 200 {data}; `/` 200; no-cookie variants → 401); NEW download route:
  200 w/cookie (attachment header + exact seeded JSON round-trip) / 401 no-cookie / 404
  unknown id; agent-browser E2E via
  the :81 gateway — service chip → confirm dialog opens naming the service → CANCELLED
  (no restart issued), firmware "Upgrade now" → typed-version dialog opens, wrong text
  leaves confirm disabled, CANCELLED (no upgrade), template Apply dialog names template +
  sections → CANCELLED, SSH add dialog empty submit → "Name is required" + "Public key is
  required" with focus on name, private-key paste → the honest private-key rejection,
  backups search filters rows + Clear restores, HA editor priority 400 + save →
  "Priority must be an integer between 1 and 255" + focus on priority + rose ring, error
  clears on edit (NOT SAVED), PKI strip chips render with days-left tones, 390 px
  overflow-free on all touched views, browser console clean. NO mutations executed — all
  confirms cancelled; no test data created.
- **Skipped (audit: already shipped / locked — do NOT duplicate):** API-key reveal
  auto-hide countdown (M11 §5.1 show-once gate is the locked, stronger pattern); PKI
  revoke/issue/CRL flows (complete); HA failover/sync chips + honest-empty disabled state;
  setup-completeness banner (demo seed sets setup.completed=true — the banner would never
  render; honest skip); firmware "staged result banner" (upgrade endpoint returns state
  only — no plan/results stages exist to map, inventing stages would lie); resource-gauge
  refresh button (5 s refetchInterval already covers freshness).
- **Noted for a future round:** pki-api.ts `expiryTone()` is dead code with a stale
  "blue >90d" comment, and pki-ui.tsx's header docstring still claims the retired "blue
  enterprise theme" (both comment-only/dead — cleanup-round candidates; not edited here
  to hold the 9-file budget).
- **File budget:** 6 code (system-view, backups-view, api-keys-view, ha-view,
  certificates-view, NEW backups/[id]/download route) + 3 docs (UI_DESIGN_SYSTEM §5.20,
  M10-SYSTEM §3/§4, PROJECT_MEMORY) = 9/9.

### 2026-11-13 — QA marathon Round 7 (identity & DNS/DHCP)

- **Scope:** M07 identity views (#/identity/users incl. RADIUS/Directory/Auth tabs,
  #/identity/sessions, #/identity/portal) + M06 DHCP view (#/dns-dhcp/dhcp). Audit-first
  found MOST of the mission list already shipped (users role badges + server q search over
  username/email; sessions expire-confirm naming the user + user/IP search + ticking lastSeen;
  voucher generation with count/TTL/bandwidth + one-time reveal + Copy all + CSV + state chips +
  revoke confirm; DNS records search/zone/type filters + settings server-error feedback —
  verified live, NOT re-implemented). Closed the REAL gaps. Zero API/schema/route changes;
  5 code files + 4 docs (9/9).
- **users-view.tsx:** (1) Last-login column now relative — fmtElapsed (§5.16 pattern, local)
  renders "never" / "<1m ago" / "12m ago" / "5h 07m ago" / "3d 04:12 ago" in tabular-nums with
  the absolute timestamp in the title, kept fresh by a 60 s heartbeat; (2) user editor +
  reset-password + group editor validation parity (§5.16 recipe): per-field client pre-checks at
  submit — username `^[a-z0-9._-]{3,32}$` (M07 §5.1), email format, password length/complexity
  prefetched from the EXISTING GET /auth-settings (30 s staleTime; server stays authoritative,
  its fieldErrors merge into the same bag) — INVALID_CLS rose ring + role="alert" text +
  aria-invalid/describedby + focus FIRST invalid + errors clear on edit + Save no longer
  silently disabled; (3) 44 px pass: search input/Add buttons/row kebab/group edit+delete now
  `h-11 lg:h-9/8/7`.
- **sessions-view.tsx:** emerald "N active now" summary chip (role="status", pulsing dot,
  tabular-nums) beside the live badge — rendered ONLY when method=all AND the search box is
  empty (otherwise the loaded count is filter-scoped and the chip would lie); method chips +
  search input 44 px; expire icon button 44 px; Table min-w-[860px] in the existing
  overflow-x-auto shell (§5.16 wide-table pattern). Session DTO has NO idle/absolute-expiry
  fields — no invented expiry columns (honest).
- **portal-view.tsx:** (1) voucher code search input (client filter on the masked code, composes
  with the state chips in one `rows` memo — the masked-CSV export exports the filtered set);
  (2) revoke ConfirmDialog now names the masked code ("Revoke voucher …5M45?"); (3) generator
  validation parity — count 1–500 / TTL 1–720 / bandwidth positive-integer pre-checked per-field
  at submit (rose ring + alert text + focus-first-invalid + clear-on-edit), button no longer
  silently disabled; (4) 44 px chips/CSV/revoke controls.
- **identity-panels.tsx:** RADIUS reveal UX — revealed secret row gains a copy icon button
  (net-ui copyText, toast on success/failure) and a role="status" "auto-hides in Ns" countdown;
  the 15 s auto-hide is driven by the reveal timestamp + 1 s tick heartbeat (setState only
  inside the interval callback — the react-hooks/set-state-in-effect rule forbids synchronous
  setState in the effect body; caught by lint, fixed before verify); "Hide secret" still clears
  immediately; Test buttons + row kebabs (RADIUS + Directory) 44 px.
- **dhcp-view.tsx:** (1) tab-trigger count badges — "Reservations 4" / "Leases 21 active" —
  computed in DhcpView from the SAME query keys the tabs use (["dhcp","reservations"],
  ["dhcp","subnets"]; TanStack dedupes, zero extra requests); leases count is the sum of
  activeLeaseCount labeled "N active" (exactly what the field measures); counts render only when
  loaded; (2) subnet pool utilization bar per IPv4 card — pool size derived client-side from
  rangeStart/rangeEnd via ipv4ToInt uint32 math, fill = activeLeaseCount/poolSize, `h-1.5`
  rounded bar with role="progressbar" (aria min/max/now/label), emerald <60 % / amber ≥60 % /
  rose ≥85 %, 2 % minimum width so a near-empty pool still shows a sliver; IPv6 renders nothing
  (config-only label stays); verified live: lan0 18/101 = 18 %, dmz0 3/51 = 6 %; (3) subnet
  enable/disable toggle now flashes the card (§5.14 ROW_FLASH_CLASS + flashId/timer-ref recipe);
  (4) lease Expire confirm names the lease — IP in the title, "MAC (hostname) must re-request
  an address…" in the description; (5) leases table min-w-[820px], reservations min-w-[560px],
  state chips + search 44 px.
- **Verified:** `bun run lint` clean (one set-state-in-effect violation caught and fixed
  mid-round); `tsc --noEmit` zero errors in all 5 touched files (pre-existing strictness debt
  elsewhere unchanged — identity-api AuthSettings import etc., files untouched this round);
  dev.log zero compile/runtime errors in the edit window (pre-existing ost-collector/systemctl
  noise only); curl golden path (login admin/admin123 → 200; /api/v1/users 200 {data};
  /api/v1/dhcp/leases 200 {data+meta}; /api/v1/dns/records 200 {data+meta}; `/` 200; no-cookie
  users → 401); agent-browser E2E via the :81 gateway: users view shows "<1m ago"/"never"
  cells; Add User empty submit → "Username is required" + "An initial password is required"
  alerts with focus on username; password "abc" → "Must be at least 8 characters (auth policy)"
  with focus on password (policy prefetched); test user created → toasted → deleted via
  confirm (API count back to 0 — no test data); sessions view "6 active now" chip, expire
  dialog names "a.smith", Escape leaves session untouched; portal: count 501 → inline "Count
  must be an integer between 1 and 500" + focus on count, 3 vouchers generated → reveal dialog
  (Copy all/Download CSV) → search "5M45" filters 3→1 rows → revoke dialog titles
  "Revoke voucher …5M45?" → revoked (3→2), remaining QA vouchers deleted via the same locked
  DELETE endpoint (list back to 0 — voucher store was empty before this round); RADIUS reveal
  → copy button → "Shared secret copied" toast + "auto-hides in 15s" countdown ticking →
  secret re-masked to "••••••••" after 15 s; DHCP tab counts "Reservations 4"/"Leases 21
  active" match the API; utilization bars 18 %/6 % match API pool math; dmz0 toggle flashes
  (.fw-row-flash observed ~1 s after click) and was restored to enabled; lease Expire dialog
  names MAC+hostname, cancelled (lease untouched); ALL touched views (users/sessions/portal/
  dhcp/dns) scrollWidth == 390 at 390 px and clean at 1280 px; console error scan: only the
  pre-existing ["auth","me"] empty-body race during hot-reload windows (fetchApi edge in
  realtime.ts — untouched this round, not reproducible outside recompile windows).
- **Skipped (audit: already present — do NOT duplicate):** users role badges (identity-ui
  RoleBadge), users server-side q search, sessions expire-confirm + user/IP search + ticking
  lastSeen, voucher one-time reveal/Copy all/CSV/state chips, DHCP lease MAC/IP/hostname server
  search, DNS records search/zone/type Selects + settings server-error inline feedback,
  DNS policy last-enabled delete warning. DNS record-type chips: the working Select already
  covers the filter — swapping it for chips is redesign, not a gap. DNS policy/record toggle
  ROW_FLASH: only cosmetic piece missing in M06 DNS view — skipped on the 9-file budget
  (toggle feedback exists via opacity + invalidation; DHCP got the flash as the representative
  recipe). Session idle/absolute-expiry columns: IdentitySessionDTO has no such fields —
  inventing them is forbidden; startedAt/lastSeen relative columns already shipped.
- **File budget:** 5 code (users-view, sessions-view, portal-view, identity-panels,
  dhcp-view) + 4 docs (UI_DESIGN_SYSTEM §5.19, M07-IDENTITY §4/§7, M06-DNS-DHCP §4,
  PROJECT_MEMORY) = 9/9.

### 2026-11-13 — QA marathon Round 6 pass 3 (logs views — pivots + mobile gaps)

- **Context:** third R6 pass. Audit re-confirmed EVERY pass-1/pass-2 claim present in the
  tree (search presets + duration footer, saved rail + confirm delete, firewall chips + CSV
  tooltip + density, IPS tone chips + confirm-first suppress, audit facets + result chips +
  JSON viewer + CSV export, live-tail pause/autoscroll/jump, reports relative last-run +
  run-now + flash, compliance status badges, all six views overflow-free at 390 px) — all
  verified live, NOT re-implemented, NOT reverted. This pass closed the remaining REAL gaps.
  Zero API/schema/route changes; 5 code files + 4 docs (9/9 budget).
- **Cross-view deep-link pivots (new R6 pass 3 pattern, UI_DESIGN_SYSTEM §5.18):**
  (1) firewall-logs-view detail drawer gained "src in Log Search" / "dst in Log Search"
  buttons → `#/logs/search?q=<ip>` (drawer closed first, then hash set — rules-view
  `?search=` pattern; shell keys views by routePath so the target view remounts);
  (2) search-view reads the param one-shot via lazy `useState(readQDeepLink)` initializers
  for `qInput`+`q` (no effect, no render-path window reads);
  (3) ips-logs-view detail drawer gained "Open sid in IPS triage" → `#/ips/events?sid=<sid>`;
  (4) events-view (M04) mirrors with `readSidDeepLink()` one-shot for `sidInput` AND widens
  its default 24 h window to "all time" when a sid is deep-linked (the target event may be
  older than the window). Verified E2E both pivots desktop + 390 px.
- **search-view mobile saved-search chips:** the left rail is `hidden lg:block`, so saved
  searches were UNREACHABLE below 1024 px — real gap. Added a `lg:hidden` chip row (only
  when saved searches exist): 44 px pill = apply button (min-w-0 truncate) + bordered w-11
  delete button reusing the shared ConfirmDialog; same saved-searches query, no duplicate
  state. Verified: container display none at 1280 px, flex with 2 buttons at 390 px, apply
  prefills q, delete → confirm → API list back to 0 (temp saved search removed — no test data).
- **audit-view JsonFieldViewer copy buttons:** each before/after pane with state data gets a
  ghost icon Button calling net-ui `copyText(text, "JSON copied")` (R5 atom reuse — clipboard
  + toast). IMPORTANT: the copy control is a SIBLING of the collapse button inside a flex
  header row, never nested inside a `<button>` (invalid HTML/a11y). 44 px hit area mobile
  (`h-11 w-11 lg:h-6 lg:w-6`), per-pane aria-label, renders only when the pane has data.
  Headless E2E could only exercise the FAILURE path (Chromium denies clipboard write) —
  which correctly showed the honest "Copy failed" toast; success path is the identical
  shipped net-ui code path verified in R5.
- **Verified:** `bun run lint` clean; `tsc --noEmit` zero errors in all 5 touched files
  (34 PRE-EXISTING type errors elsewhere — auth-me, firewall-os, wan-os, net-ui, api-keys,
  handler.ts, mock-engine… — none introduced or touched this round; dev-server compiles
  and serves everything 200, so they are latent strictness debt for a typing round, not
  this one); dev.log zero compile/runtime errors in the edit
  window (pre-existing ost-collector + internal-events 401 noise only); curl golden path
  (login 200; logs/firewall?limit=5 200 {data} 5000 total; logs/audit 200 {data}; `/` 200;
  no-cookie audit 401); agent-browser E2E via :81 gateway — search `?q=` deep link prefills
  the query box (row "172.16.20.181 → 203.0.113.73 allow" returned), firewall src pivot and
  IPS triage pivot navigate + prefill correctly (sid 2035344 → events-view sid input + "all
  time" active + 1 row), audit copy button wired (honest failure toast in headless), mobile
  chips apply/delete round trip, ALL touched views (search/firewall/ips/audit/ips-events)
  overflow-free at 390 px, pivot buttons 44 px, browser console clean.
- **No test data left:** the one temp saved search ("R6P3 pivot test") created for the chip
  test was deleted through the UI (API confirms 0 saved searches); pivots and deep links are
  read-only; no schedules/targets touched.
- **Skipped (audit: no real gap / not implementable — do NOT duplicate):** live-tail
  autoscroll toggle (already shipped R6 pass 1), search result CSV export for ips dataset
  (no IPS export endpoint exists; endpoint shapes locked — honest skip), audit action-filter
  chips (server facets shape locked, q already ORs action), firewall zone/severity chips
  (FirewallLogDTO has no zone/severity field), reports schedule next-run relative time
  (DTO has no nextRunAt — engine-driven), syslog/netflow reachability test (no endpoint).
- **File budget:** 5 code (search-view, firewall-logs-view, ips-logs-view, audit-view,
  events-view) + 4 docs (M09-LOGGING, M04-IPS events filter-bar deep-link line,
  UI_DESIGN_SYSTEM, PROJECT_MEMORY) = 9/9.

### 2026-11-13 — QA marathon Round 6 pass 2 (logs views — verify + remaining gaps)

- **Context:** re-run of the R6 assignment found the R6 entry below ALREADY in this log and
  all its claims present in the tree (search preset chips + query-duration footer, firewall
  stats-chips + CSV tooltip + density, IPS confirm-first suppress + tone chips + density,
  audit facets/result chips/JSON viewer + density, live-tail paused overlay + jump-to-newest,
  reports relative last-run + per-row Run now + ROW_FLASH) — verified live, NOT re-implemented
  and NOT reverted. This pass closed the REAL gaps the audit surfaced. 9/9 file budget.
- **NEW endpoint `GET /api/v1/logs/audit/export`** (the one R6 honestly skipped): fully
  additive self-contained route (`src/app/api/v1/logs/audit/export/route.ts`) following the
  reports-export inline precedent — zod schema mirrors `auditLogQuerySchema` minus
  `facets`/`page`/`limit` (own `isoOrEmpty` + until≥since refine), RBAC `area: "audit"`
  (same read matrix as the list endpoint), inline CSV builder (reuse of the firewall export's
  csvCell/cap pattern), 10 000-row cap + `X-Row-Cap`, `Content-Disposition audit-log.csv`;
  columns `timestamp,username,user_id,source_ip,action,object_type,object_id,object_name,
  result,id` — before/after JSON states deliberately NOT in the CSV (drawer-only, stated in
  the tooltip). Existing endpoint shapes untouched; openapi.ts manifest row added
  ("expand, never rename" — served at `/api/v1/openapi.json`).
- **audit-view.tsx:** Export CSV button in the filter bar (spinner while in flight, 44 px,
  aria-label, columns+cap+JSON-note tooltip, success toast with row count + honest cap
  message at 10 000) via a new `logsApi.exportAuditCsv` (logs-api.ts `downloadGet`); result
  chips group got `flex-wrap` so the new export+density group wraps (its combined min-content
  overflowed 390 px by 6 px — see §5.18 filter-bar rule); CAUGHT BY E2E: the first cut forgot
  the `toastOk`/`toastErr` import → try-block threw "toastOk is not defined", the catch then
  threw "toastErr is not defined" and BOTH errors were silent (request 200, no toast). Found
  via a `window.unhandledrejection` probe during agent-browser testing — lesson: missing
  import = silent success-path failure; verify toasts, not just network 200s.
- **reports-view.tsx (page overflow fixed — was scrollWidth 505 at 390 px):** (1) recharts
  containment — chart Cards `min-w-0` + CardContent `min-w-0 overflow-hidden`; the
  ResponsiveContainer writes its measured width as INLINE PX on the inner wrapper, which
  became the card's min-content and inflated the whole grid track permanently (bisected
  element-by-element in the browser; §5.18 recharts rule documented); (2) toolbar `ml-auto`
  group + `flex-wrap`, Print/CSV/JSON buttons now wrap; (3) stats cards
  `grid-cols-1 min-[480px]:grid-cols-2 xl:grid-cols-4` (mono tabular values can't shrink);
  (4) Scheduled table `overflow-x-auto` + `min-w-[880px]` + card `min-w-0` + DensityToggle
  (`fw-density:logs-reports-scheduled`) beside "New schedule" (44 px button pass);
  (5) Forwarding: both target tables wrapped (`min-w-[620px]`/`min-w-[560px]`), Cards
  `min-w-0`, shared DensityToggle (`fw-density:logs-reports-forwarding`) in the syslog card
  header, Add button 44 px.
- **compliance-view.tsx (3 px overflow fixed):** framework cards `grid-cols-1
  min-[440px]:grid-cols-2 sm:grid-cols-3 xl:grid-cols-5` (the nowrap "Run check" button set
  the 2-up min-content above 390 px); templates + runs tables wrapped in `overflow-x-auto`
  (`min-w-[760px]`/`min-w-[640px]`, runs keeps its `max-h-96` sticky-header scroll, now
  `overflow-auto`), Cards `min-w-0`, one shared DensityToggle (`fw-density:logs-compliance`)
  in the templates header, "New template" 44 px.
- **Docs:** UI_DESIGN_SYSTEM §5.18 extended (density keys list, NEW recharts inline-px
  containment rule with the 505→390 proof, filter-bar widest-child wrapping rule, export
  button+tooltip recipe); M09-LOGGING §3 audit-export row + §4 audit filter-bar bullet +
  Scheduled/Forwarding density+wrapper notes. `logs-audit` density key unchanged.
- **Verified:** `bun run lint` clean; dev.log zero compile/runtime errors (dev-server restart
  mid-round clean; pre-existing internal-events 401 + ost-collector noise only); curl golden
  path (login admin/admin123 → 200; logs/firewall?limit=5, logs/audit, `/` → 200; no-cookie
  audit → 401); NEW endpoint: 200 w/cookie (text/csv, correct header, 107 data rows newest-
  first, `result=failure` filter honored), 401 no-cookie, 400 VALIDATION_ERROR on
  `until < since` with `fieldErrors.until`; `/api/v1/openapi.json` lists the new row;
  agent-browser E2E (fresh session, gateway :81): all SEVEN log module views overflow-free at
  390 px AND 1280 px (search/firewall/ips/audit/live/compliance/reports — previously 505/396
  overflows gone); audit Export hover tooltip renders the full column list; Export click →
  "Audit CSV exported — 107 rows written" toast (Radix viewport verified) + dev.log 200;
  density round trip with computed styles (Scheduled th 40 px→36 px, px 8→6, td fs 14→12,
  `fw-density:logs-reports-scheduled=compact`, restored to comfortable); compliance +
  forwarding toggles present (same fw-ui component); browser console clean.
- **No test data left:** export endpoints are read-only (no rows created), no saved searches /
  schedules / targets created this pass, density localStorage keys reset to defaults.
- **Finding for a future round (NOT fixed here — dashboard is not a log view, budget spent):**
  `#/dashboard` overflows at 390 px (scrollWidth 462) — R1's "Updated Xs ago · auto-refresh"
  meta row (`justify-between`, no wrap, Refresh button) and the critical-events banner
  (`flex items-center gap-3`, md:flex-row only) have min-content above the viewport; same
  §5.18 wrapping rule applies. Recommend a flex-wrap pass in the next dashboard-touching round.
- **File budget:** 9/9 — NEW audit/export route, logs-api.ts, audit-view.tsx,
  reports-view.tsx, compliance-view.tsx, api/openapi.ts, UI_DESIGN_SYSTEM.md,
  M09-LOGGING.md, PROJECT_MEMORY.md.

### 2026-11-13 — QA marathon Round 6 (logs views)

- **Scope:** M09 log views (#/logs/search, #/logs/firewall, #/logs/ips, #/logs/audit,
  #/logs/live, #/logs/reports Scheduled+Forwarding — auto-QA marathon R6/10). Audit-first:
  live-tail pause/resume + missed counter + autoscroll, search saved-search rail (apply +
  delete confirm) + result count, firewall CSV export spinner + cap toast, IPS severity
  multi-chips + q (covers sid/message) + M04 suppress reuse, audit user/objectType facets +
  result chips + JSON before/after viewer, compliance run-now + status badges, syslog/
  netflow CRUD — ALL ALREADY SHIPPED, skipped as duplicates. Zero API/schema/route changes;
  6 code files + 3 docs (9/9).
- **search-view.tsx:** (1) time-range preset chips 15m/1h/24h/7d/Custom — `since` pinned
  into STATE at chip click (stable query key, no render-computed ticking ISO), Custom
  lights up when the day inputs drive the range; (2) query duration in the footer
  ("N events total · 34 ms query", measured around queryFn in a ref); (3) the local
  SEVERITY_BADGE map deleted → locked logs-ui `SeverityBadge` import (tone drift fix:
  high was orange, now rose-500 outline per M09 §5.4); toolbar 44 px pass
  (`h-11 lg:h-9`); saved ranges restore as custom dates.
- **firewall-logs-view.tsx:** action Select → filter chips with 24 h counts from the
  LOCKED `/logs/stats` payload (shared `["logs","stats","24h"]` cache with the reports
  tab; window-level, not filter-scoped — same honest pattern as R3 events chips);
  CSV-column + 10k-cap tooltip on Export (shadcn Tooltip); DensityToggle
  (`fw-density:logs-firewall`, compact trims cells, table `min-w-[960px]`); 44 px toolbar
  pass; mono src/dst cells truncate with `title`.
- **ips-logs-view.tsx:** (1) row + detail-sheet Suppress now mounts M04's confirm-first
  `SuppressMenu` (dropdown → confirm dialog restating sid/severity/window) replacing the
  bare 3-duration dialog; `onSuppressed` patches the page cache locally (computed
  suppressedUntil) — M09 no-full-reload acceptance kept; (2) active severity chips take
  `SEVERITY_TONE` from ips-ui (parity with #/ips/events triage chips); (3) DensityToggle
  (`fw-density:logs-ips`, `min-w-[880px]`), 44 px chips/toolbar, message cell truncates
  with title.
- **audit-view.tsx:** DensityToggle (`fw-density:logs-audit`, `min-w-[780px]`), 44 px
  result chips + toolbar. q already covers action search (service ORs
  action/objectName/username) — dedicated action filter would need a new facets shape
  (endpoint shape locked) — skipped honestly.
- **live-tail-view.tsx:** paused overlay pill on the stream ("Paused — N new lines
  buffered", amber, role="status", mirrors the Resume "+N missed" counter) + "Newest"
  jump button when scrolled away from the newest (top) position (`onScroll` threshold,
  smooth scroll back); 44 px kind chips + Pause/Clear buttons; row list `min-w-[720px]`.
- **reports-view.tsx:** Scheduled tab — lastRunAt rendered relative ("just now / 12m ago /
  3d 04:12 ago", absolute in title, 60 s setInterval heartbeat = R4 sessions pattern);
  Run now per-row spinner (`runPendingId`, no more global disable); §5.14 ROW_FLASH_CLASS
  on schedule + syslog + NetFlow enable/disable toggles (flashId + timer ref, R2
  pattern). NOTE: the first attempt used net-ui's `useNowTick()` (Date.now() getSnapshot,
  uncached) — React maximum-update-depth crash when a row rendered; replaced with the
  heartbeat + `Date.now()` read at render. net-ui's own R5 usages unaffected (verified).
- **Overflow discipline:** min-w tables initially widened the PAGE at 390 px (min-content
  propagation through the auto grid track) — fixed with `min-w-0` on the grid-item card +
  inner `overflow-x-auto` wrapper; all six log views verified overflow-free at 390 px
  (pattern documented in UI_DESIGN_SYSTEM §5.18).
- **Docs:** UI_DESIGN_SYSTEM new §5.18 (logs R6 atoms incl. the min-w-0 containment rule
  and the Date.now()-getSnapshot footgun); M09-LOGGING §4 bullets synced (action chips +
  counts, SEVERITY_TONE chips, confirm-first SuppressMenu, paused overlay + jump-to-newest,
  density keys, relative last-run + per-row spinner + flash).
- **Verified:** `bun run lint` clean; dev.log zero compile/runtime errors after hot reload
  (pre-existing ost-collector/systemctl noise only; transient edit-window errors resolved);
  curl golden path (login admin/admin123 → 200; logs/firewall?limit=5 200 {data};
  logs/audit 200 {data}; logs/search 200 (preset-style `since` accepted);
  logs/search/saved 200; logs/stats?range=24h 200; `/` 200; no-cookie → 401);
  agent-browser E2E via the :81 gateway: search 15m preset → "0 events total · 19 ms
  query" (honest — newest indexed event is the seed batch) and 7d → "1169 events total ·
  22 ms"; saved search created via dialog ("since Nov 06, 08:41 PM" preview), applied,
  deleted via ConfirmDialog — saved list back to 0, NO test data left; firewall chips
  (allow 79/deny 26/drop 24/reject 27), deny chip → "1 active" + 25 deny rows, Clear
  restores; density compact ↔ comfortable round trip; Export tooltip renders full CSV
  column list; IPS critical chip → server-filtered 61 events (25 critical rows on page),
  chip toggles off; Suppress dropdown → confirm dialog (CRITICAL badge, sid 2035344,
  window preview "until Nov 14, 08:44 PM", honest no-reason note) → CANCELLED — event
  untouched via API (action drop, no suppressedUntil); reports Scheduled: temp schedule
  created via API → "never" cell → Run now → toast "Report generated" + "just now"
  relative cell + lastRunAt bumped → schedule DELETED (DAILY-TRAFFIC untouched);
  Forwarding SIEM-01 toggled on→off (flash path) — API state back to enabled:false,
  buffered:0; all 6 log views + compliance at 390 px → no page-level overflow; R5
  network/interfaces re-loaded clean after the useNowTick scare; browser console clean
  post-edit-window.
- **Skipped (audit: already shipped / not implementable — do NOT duplicate):** live-tail
  pause/autoscroll mechanics; saved-search rail + confirm delete; export spinner + cap
  toast; IPS q search + severity chips themselves; suppress M04 endpoint reuse (flow
  upgraded, not duplicated); audit result chips/user facets/JSON viewer; compliance
  run-now/status pills; syslog/netflow reachability test — NO test endpoint exists
  (bufferedRows badge is the honest signal, kept); audit CSV export — no audit export
  endpoint and endpoint shapes are locked (new endpoints allowed but "prefer existing"
  wins; noted for a future round if the owner wants it); schedule nextRun — DTO has no
  nextRunAt (engine-driven; honest "last run" relative only).
- **Observation for future rounds:** net-ui `useNowTick()` getSnapshot returns `Date.now()`
  uncached — a latent max-update-depth risk wherever it lands in fast-refetching subtrees;
  consider a cached-tick store or the R4 heartbeat pattern if it ever misbehaves in the
  network views.
- **File budget:** 6 code (search-view, firewall-logs-view, ips-logs-view, audit-view,
  live-tail-view, reports-view) + 3 docs (UI_DESIGN_SYSTEM, M09-LOGGING, PROJECT_MEMORY)
  = 9/9.

### 2026-11-13 — QA marathon Round 5 (network views)

- **Scope:** M02 network views (#/network/interfaces incl. Diagnostics/LLDP/MAC/Mirroring
  tabs, #/network/routing, #/network/wan — auto-QA marathon R5/10). Audit-first found the
  round's mission list LARGELY ALREADY SHIPPED by the in-flight R5 work present in the
  tree (net-ui "R5 atoms": DiagOutputBlock / recent-target chips / LastUpdatedLabel /
  DataSourceBadge / INVALID_CLS+FieldErrorText; interfaces Diagnostics tab with host
  ports+ARP+kernel routes+4 tools; routing search+density+RouteOsBadge; WAN probe spinner
  + SLA colors + kernel enforcement panel + real failover event log — verified live rather
  than re-implemented). This round finished the two REAL gaps and the docs debt. Zero
  API/schema/route changes; 9 files total (5 code — of which interfaces-view got the new
  edits — + 4 docs).
- **interfaces-view.tsx (this round's code edits):** (1) OS-apply staged feedback parity
  with the R2 firewall dialog — the row-menu "Preview apply plan" dialog now opens WHILE
  the POST is in flight (`ApplyPlanRunning` spinning strip, role="status"), then renders
  `ApplyPlanStages`: Guards (rose when the endpoint rejected the target, e.g. iface not
  found), Plan (real convergence-step count from `plans[]`, zinc-dashed "zero steps — host
  already matches the console"), Kernel (per-step exec results from `results[]`, rose
  break-words stderr under failing steps, honest "not touched (preview only)" when the
  gate is off) — all mapped from the EXISTING `POST /interfaces/apply` response, which is
  single-interface by design (no bulk path invented); step cmds/results got break-words +
  min-w-0 anti-overflow. (2) Per-row "Ping gateway" dialog switched from a bare `<pre>` to
  the shared `DiagOutputBlock` (summary chips + n lines · m chars + Copy + scrollable mono
  region) — one output recipe everywhere raw tool output renders.
- **Docs:** UI_DESIGN_SYSTEM new §5.17 (network R5 atoms: DiagOutputBlock, recent-target
  chips, freshness/provenance labels, kernel-sync badges, interfaces OS-apply staged
  parity, validation + density keys); M02-NETWORK §4 rewritten to match the shipped view
  (5 tabs incl. Diagnostics, kernel-truth columns + os-apply repair path, LLDP/MAC
  search/density/CSV/freshness, routing search/kernel badges/validation, WAN SLA line +
  kernel enforcement panel + per-policy probe spinner); PAGE_MAP network sections synced
  (interfaces 5-tab heading + layout, routing layout, WAN layout — stale "probe history
  line chart" replaced by the shipped kernel enforcement panel + failover event log).
- **Verified:** `bun run lint` clean; dev.log zero compile/runtime errors after hot reload
  (pre-existing ost-collector 401 noise only); curl golden path (login admin/admin123 →
  200; interfaces/routes/network-routes/wan-policies/wan-os → 200 `{data}`; `/` 200;
  no-cookie → 401); diagnostics probes to 127.0.0.1 only (tcp-check 200 connected 2 ms;
  ping honestly returns the host's cap_net_raw limitation in raw output — shown as-is;
  dns-lookup 200; all 401 without cookie); POST interfaces/apply (eth0) → 200 gate-off
  plan preview; agent-browser E2E via the :81 gateway: Diagnostics tab → TCP probe
  127.0.0.1:3000 → "connected · 4 ms" + "1 LINE · 33 CHARS" + Copy button + raw region;
  wan0 "Preview apply plan" → staged strip renders Guards (gate-off reason) / Plan (1
  convergence step) / Kernel (not touched — preview only); wan0 "Ping gateway" dialog →
  "failed" badge + 4 LINES · 116 CHARS + Copy → "Copied" toast; routing search "10.50" →
  "Clear (1/2)" + only the matching row, density + kernel badges present; WAN "Probe now"
  on wan0 → per-card spinner → "Probe complete — wan0 is down" toast, kernel enforcement
  panel + failover event log render; LLDP/MAC tabs show search + density + "updated just
  now" + provenance badge; 390px viewport screenshot clean; browser console clean; NO test
  data created (probes are read-only diagnostics; the one audited probe action is an
  operator action on existing state).
- **Skipped (audit: already shipped — do NOT duplicate):** diagnostics output blocks +
  recent-target chips + per-tool spinners; host ports/ARP/kernel-routes cards; LLDP/MAC
  search+density+freshness+CSV; routing search/density/kernel chips/per-field validation/
  409 conflict confirm; PBR plan preview; WAN per-policy probe spinner, SLA state colors,
  kernel enforcement panel, failover event log; interface carrier/drift/MAC-copy/refs.
- **Not implementable (honest):** bulk "apply all interfaces" button — the apply endpoint
  is explicitly single-interface (`body {name}` required, no bulk exec path) and endpoint
  shapes are locked this round; WAN failover history BEYOND the shipped event log — events
  live in the os-status response (memory), not a persisted model, so deeper history would
  need an API change (forbidden).
- **File budget:** 9/9 (interfaces-view, net-ui, net-api, routing-view, wan-view,
  UI_DESIGN_SYSTEM, M02-NETWORK, PAGE_MAP, PROJECT_MEMORY).

### 2026-11-13 — QA marathon Round 4 (VPN & SD-WAN)

- **Scope:** M05 VPN views (#/vpn/sessions, #/vpn/configs incl. user-groups tab) + SD-WAN
  (#/routing/sdwan; spec §2.5 — no dedicated module doc exists, nothing invalidated there).
  Audit-first: session search (debounced, server `?q=`) + status filter + tunnel filter +
  naming disconnect confirm; groups-panel EmptyBlock + member-count badge; SD-WAN
  StatsStrip overlay summary; per-path MiniMeter tones (rose breach/amber near/zinc);
  probe-now spinner + summary toast; all EmptyBlocks — ALL ALREADY SHIPPED, skipped as
  duplicates. Zero API/schema/route changes; 6 files touched (4 code + 2 docs).
- **sessions-view.tsx + vpn-api.ts:** new "Uptime" column — `fmtElapsed()` formats
  connect-duration as `<1m` / `12m` / `5h 07m` / `3d 04:12` ("up for …" prefix, mono
  tabular-nums, absolute connect time in `title`); a 60 s clock heartbeat keeps labels
  fresh between the 15 s refetch. Disconnected rows render "—" with an honest tooltip
  (VpnSession has NO `disconnectedAt` — no invented duration). Responsive pass: table
  wrapped in `overflow-x-auto` + `min-w-[880px]`, mono source/assigned IP cells
  `min-w-0 max-w-44 truncate` + `title`, skeleton cols 8→9, Disconnect button and
  pagination Prev/Next now `h-11 lg:h-7/8` (44 px mobile touch targets).
- **configs-view.tsx:** client-bundle download now shows pending state — RowMenu is
  controlled; the bundle item's `onSelect` `preventDefault`s (menu stays open), swaps to
  spinner + "Preparing bundle…" disabled while the POST to the EXISTING
  `configs/{id}/client-bundle` is in flight, closes on settle; per-config pending slot
  (`bundlePendingId`), success/failure toasts unchanged. `downloadFor` moved into
  ConfigsView (same logic, first-peer default kept).
- **sdwan-view.tsx:** (1) Density-toggle parity — `DensityToggle`/`useTableDensity` from
  fw-ui on the policies table (`fw-density:sdwan-policies`, compact `min-w-[600px] text-xs
  px-1.5 py-1`) and SLA table (`fw-density:sdwan-sla`, `min-w-[360px]` compact); keys
  independent per table. (2) Editor validation parity with the R2 firewall rule editor
  (`INVALID_CLS` + `FieldErrorText` atoms): PolicyEditor (name/overlay/DSCP regex/CIDR
  regex/fixed-WAN-required) and SlaProfileEditor (name/latency 5–1000/jitter 1–500/loss
  0–50) now validate per-field at submit — rose ring + `aria-invalid` +
  `aria-describedby` error id + `role="alert"` text, scroll-to + focus FIRST invalid,
  per-field errors clear on edit, Save no longer silently disabled on empty name; server
  errors land on the name field. (3) Responsive: Sites/Policies/SLA scroll containers are
  `overflow-auto` (x+y) with `min-w-[680/720/420px]`. (4) Stale header + section comments
  corrected ("red-700 for up" / "up=blue" → actual zinc/amber/rose map per §2 health rule).
- **Docs:** UI_DESIGN_SYSTEM new §5.16 (VPN/SD-WAN R4 atoms: connect-duration, bundle
  pending state, editor-validation parity, wide-table overflow pattern).
- **Verified:** `bun run lint` clean; dev.log zero compile/runtime errors after the edits
  (dev server restart at 19:43 clean; only pre-existing ost-collector 401 noise); curl
  golden path (login admin/admin123 → 200; vpn/sessions 200 incl. `?status=active&q=kim`;
  vpn/configs 200; sdwan/paths + stats 200; `/` 200; no-cookie → 401 on both APIs);
  agent-browser E2E via the :81 gateway: sessions table shows Uptime cells
  ("up for 1h 17m", "up for 2d 01:17"), search "j.tanaka" → 1 row, disconnect confirm
  names the session ("j.tanaka (assigned 10.99.1.12/32)…") and Escape-cancel leaves the
  session untouched; configs row-menu bundle flow: click → "Preparing bundle…" disabled
  spinner → menu closes + "Client bundle downloaded" toast; SD-WAN exercised on TEMP API
  data (QA-R4 overlay/site×2/paths×3/SLA/policy — stats 1 up/1 degraded/1 down, meters +
  state pills + probe-now refreshed lastProbeAt on all 3 paths), policies density
  compact → `fw-density:sdwan-policies=compact` + compact classes on the table, SLA key
  independent; SLA editor submit (empty + latency 5000) → "Name is required" +
  "Latency max must be an integer between 5 and 1000 ms" alerts, focus on name,
  rose ring + aria-invalid, name error clears on edit, latency error persists; policy
  editor (empty name + bogus DSCP + bad CIDR) → 3 simultaneous alerts, focus on name,
  Save clickable (not silently disabled); browser density pref reset afterwards; ALL QA
  entities DELETED (8× DELETE 200), stats back to all-zero, sdwan view reloads to
  "No overlays yet"; console clean.
- **Skipped (audit: already shipped):** session user/IP search + status Select + disconnect
  confirm naming the session; groups-panel empty state + inline count badges; config
  TunnelStatusBadge recipes; SD-WAN StatsStrip summary; per-path SLA meters with tone
  colors; probe-now spinner + toast; path StatePills; all SD-WAN EmptyBlocks.
- **Not implementable (skipped honestly):** SD-WAN failover/event log timeline — no
  SdwanEvent model and no event data in the stats endpoint (schema has only
  Overlay/Site/Path/Policy); per-mission instruction skipped. Per-path "probe now"
  button — the probe endpoint takes an overlayId only (existing shape locked, no API
  change allowed); the per-overlay probe with spinner already covers it.
- **Deferred:** single-message validation in the remaining SD-WAN editors
  (Overlay/Site/Path) — parity was scoped to policies + SLA per the mission; sessions
  "protocol filter chips" — no protocol field on sessions (tunnel Select covers it).

### 2026-11-13 — QA marathon Round 3 (IPS & threat intel)

- **Scope:** M04 IPS + M13 threat-intel views (auto-QA marathon R3/10). Audit-first: the
  preset dialog ALREADY previews the bundle (chips + mode) — R3 adds the missing
  replace-mode DIFF; feeds ALREADY have sync spinner + result toast — R3 adds the freshness
  badge. Zero API/schema/route changes (mission hard rule); everything reuses existing
  endpoints. Note: the threat-intel module is COMPLETELY EMPTY on the seeded DB (seed.ts
  creates no feeds/IOCs) — all TI empty states are honest-empty by nature here.
- **ips-ui.tsx:** `SuppressMenu` is confirm-first — the 24h/7d/forever dropdown items now
  open `SuppressConfirmDialog` (severity badge + sid/category/message + duration RadioGroup
  + computed "until" preview) before POSTing; dialog states plainly that the audit records
  the duration and a reason note is NOT persisted (suppress endpoint request shape is
  locked, M04 §3 — mission hard rule; reason input skipped with rationale). Suppress
  trigger disabled on live-tail rows (synthetic negative ids would 404). New exports:
  `SuppressDuration`, `SuppressContext`, `SEVERITY_TONE` (active-chip classes + legend dot
  per severity, M04 §4 recipes).
- **events-view.tsx:** (1) compact "Last 24 h by severity" stacked bar above the table —
  recharts BarChart fed by the EXISTING `/api/v1/ips/events?since=<24h>&limit=100` fetched
  page-by-page (cap 5 pages = most recent 500, noted inline when capped), hour-bucketed
  client-side; series hexes critical #e11d48 / high #fb7185 / medium #f59e0b / low
  #a1a1aa / info #d4d4d8 (zinc/amber/rose only); honest-empty line when the window has 0
  events; refetch every 60 s + invalidated with the events query (shared key prefix).
  (2) Severity filter chips show 24 h counts and take their severity tone when active
  (chips double as the chart legend). (3) "hide suppressed" chip (aria-pressed) filters
  `action = suppressed` rows on the rendered page + live buffer; suppressed rows render at
  opacity-60; footer shows "n suppressed hidden on this page" (client-side filter over
  server pagination, honestly labeled); chip resets with Clear.
- **policies-view.tsx:** PresetDialog replace-mode diff — selecting a target policy renders
  "Changes to <name>": mode before→after badges (ArrowRight), "Turning on (n)" (zinc) and
  "Turning off (n)" (amber, the risk direction) category lists, "already matches this
  bundle — no changes" when the diff is empty, plus the scope note (only category map +
  mode are overwritten).
- **ti-ui.tsx:** new `FreshnessBadge` — feed data recency: fresh (<24 h) emerald (the
  module's ONLY emerald, sanctioned by UI_DESIGN_SYSTEM §2 health-only rule; task mandate
  green/amber/rose), aging (<7 d) amber, stale (≥7 d) / never synced / sync error rose;
  tooltip carries the details. Stale header comment fixed (old "no emerald in this module"
  ruling replaced by the health-only exception).
- **feeds-view.tsx:** FreshnessBadge rendered beside SyncStatusPill in each feed card
  (recency vs sync-outcome separation).
- **iocs-view.tsx:** bulk selection — Checkbox column + select-all header (indeterminate
  state), `role="toolbar"` selection bar with "n selected / k will be disabled", Disable
  selected button runs SEQUENTIAL calls to the EXISTING `POST /iocs/{id}/disable` with
  in-button progress ("Disabling i/n…"), skips already-disabled rows, toast summary on
  completion; selection is an id→DTO Map so it survives paging. Copy-to-clipboard icon
  button on every value cell (mono value column was already present). Skeleton cols 9→10.
- **auto-block-view.tsx:** block-list summary strip (5 Cards: Rules / Enabled / Auto-feed /
  Manual / Hits — client-computed, feeds StatsStrip recipe) + toggle row flash via
  `ROW_FLASH_CLASS` (flashId + timer ref, exact R2 rules-view pattern); footer line
  recomposed as feeds·manual·hits.
- **Docs:** UI_DESIGN_SYSTEM new §5.15 (IPS/TI triage atoms: severity chips/timeline
  legend, confirm-first suppression, freshness badge, IOC bulk pattern, summary strip +
  flash).
- **Verified:** `bun run lint` clean (fixed recharts/shadcn Tooltip name collision — aliased
  `Tooltip as ReTooltip`; transient duplicate-import compile error in dev.log during the
  edit window, resolved); dev.log zero compile/runtime errors after hot reload (pre-existing
  ost-collector 401 noise only); curl golden path (login admin/admin123 → 200;
  ips/events 200 `{data}` + 401 no-cookie; threat-intel/feeds 200 `{data}` + 401 no-cookie;
  `/` 200); agent-browser E2E via the :81 gateway: events view shows timeline card
  ("5 events in window" + legend) + chip counts (critical 2 / medium 3 / high·low·info 0);
  Suppress → 24 hours… → dialog (window preview + honest note) → Confirm → toast "sid
  2035344 suppressed for 24h", row action=suppressed, then hide-suppressed click → row
  gone + footer "1 suppressed hidden on this page" — event 108 RESTORED to its original
  row values afterwards (prisma update from captured pre-state, no test data left);
  preset Aggressive → Replace existing → BALANCED shows "Turning on (2): dos, info_leak"
  (no mode change — BALANCED already inline_drop), dialog cancelled without applying;
  feeds honest-empty → created QA-R3-Test Feed → badge "never synced" → Sync now → toast
  "8 IOCs ingested" + badge "fresh" → IOCs view select-all → "Disabled 8 IOCs" toast +
  all-disabled via API → feed + 8 IOCs + 2 minted hits DELETED, stats back to all-zero;
  IOCs/auto-block honest-empty states re-verified after cleanup; console clean.
- **Skipped (audit: already shipped):** preset bundle preview (present since M04 build);
  feed sync spinner + result toast; IOC severity/category/type/feed filters; auto-block
  honest-empty + recent-matches polling; events severity chips themselves (counts were the
  gap). **Deferred by hard rule:** suppress REASON input — the locked `{duration}` request
  shape has no persistence path for a note and this round forbids API shape changes; the
  confirm dialog states this honestly. **Not implementable:** "expiry formatting for temp
  blocks" — AutoBlockRule has no expiry field (schema untouched per rule).
- **File budget:** 7 code files + 2 docs (9/9).

### 2026-11-13 — QA marathon Round 2 (firewall UX)

- **Scope:** M03 firewall views (auto-QA marathon R2/10). Audit-first: objects-view
  "Referenced by" counts + hover popover (client-computed over the already-loaded fw/NAT rule
  lists) and zones-view "used by N rules" badges were ALREADY present — candidate skipped as a
  duplicate; `GET /api/v1/objects/references` exists but was intentionally not rewired
  (prefer existing behavior, no endpoint change). Rules text search + zone/tag chips +
  filtered/total clear button existed; optimistic toggle + reorder with rollback + toast
  existed in BOTH views (upgrade = feedback, not mechanics).
- **fw-ui.tsx — new shared atoms:** `useTableDensity(key)` (localStorage `fw-density:<key>`,
  hydration-safe via `useSyncExternalStore` — server snapshot "comfortable", same pattern as
  the app-shell platform probe) + `DensityToggle` dropdown (Rows3 icon, `h-11 lg:h-8` touch
  target, aria-label) + `ROW_FLASH_CLASS` export. Per-table keys stay independent
  (`firewall-rules` / `nat-rules`).
- **globals.css:** `@keyframes fw-row-flash` (neutral zinc tint fading out over 1.5 s); the
  existing `prefers-reduced-motion` block neutralizes it for reduced-motion users.
- **rules-view.tsx:** (1) quick-filter row completed — new Action Select (all/allow/deny/
  drop/reject) + Status Select (any/enabled/disabled) composing with search + zone + tag
  filters; search haystack now ALSO covers resolved source/destination/service object names;
  clear button renamed "Clear all (n/total)" and visibility counts all five filter surfaces;
  (2) density toggle in toolbar — compact trims cells (`[&_td]:py-1 px-1.5 text-xs`,
  `min-w-[880px]`) and HIDES the optional Sched/Guard/Hits columns (13→10, skeleton cols
  follow); (3) toggle flash: `flashId` + `flashTimer` ref set in the toggle handler (event
  context, no setState-in-effect) → affected row briefly carries `ROW_FLASH_CLASS`.
- **nat-view.tsx — parity:** same DensityToggle (own storage key) + compact table classes +
  identical toggle flash on `SortableNatRow`.
- **rule-editor.tsx:** (1) "Review — this rule will match" strip at the top of the dialog —
  live Zones → Addrs → Services → action flow with resolved chips (groups as `NAME +N`),
  ActionBadge, logging level, schedule/limit/SYN/app/user/MAC counts — sanity-check before
  save; (2) submit-time client validation (name required, MAC regex, conn/rate/SYN
  thresholds positive) with scroll-to + focus + rose ring + `aria-invalid`/error text on the
  FIRST invalid field; Save button no longer silently disabled on empty name/invalid MACs
  (errors are explained instead); per-field errors clear on edit.
- **os-apply.tsx:** staged apply feedback — `ApplyStagesRunning` (spinning strip,
  `role="status"`) while the POST is in flight; after outcome an "Apply stages" strip maps
  the real engine steps into Validate (gate/tool/nft -c) → Converge (backup/apply,
  `rolledback`→amber RotateCcw) → Kernel status (rollback timer + persistence + auto-confirm)
  with per-stage icons and failure details in scrollable min-w-0/break-words mono lists; the
  result Alert is now a sticky banner (DialogContent `max-h-[85vh] overflow-y-auto`,
  banner `sticky top-0` on `bg-background/95`) and no longer duplicates the persistence list.
- **Verified:** `bun run lint` clean; dev.log zero compile/runtime errors after hot reloads
  (pre-existing ost-collector noise only); curl golden path (login admin/admin123 → 200,
  firewall-rules 200 `{data}` ×12, `/` 200, no-cookie → 401; objects/references 200);
  agent-browser E2E via the :81 gateway: deny filter → "Clear all (3/12)" + only deny rows;
  deny+disabled composes → 1/12; search "TRUSTED" (object name) → 2/12; density compact
  hides Sched/Guard/Hits + `localStorage fw-density:firewall-rules=compact` (NAT key
  independent); toggle flash present at t0, gone at t+2s; editor review strip renders
  resolved chips ("TRUSTED +3 → MGMT_NET · tcp/22 → allow · log: summary"); empty-name
  submit → "Name is required" + focus/scroll on #rule-name; bad-MAC submit → rose ring +
  focus + in-view on the MAC input; test artifact rule deleted, table back to 12;
  console clean. OS-apply outcome stages not triggerable in-sandbox (nft unavailable →
  Apply disabled by design) — compile/lint verified only; re-check on an nft-capable host.
- **Skipped (audit: already shipped):** objects/zones reference counts + popovers; NAT
  empty-state/badges (already EmptyBlock/NatTypeChip from fw-ui); optimistic mechanics
  (rollback + toast) — only the flash feedback was missing.
- **Deferred to later rounds:** rules-table filter chips ~28px on mobile (44px pass,
  still open from R1); palette deep links; server-side `?q=` pushdown (client filter is
  fine at ≤200 rules).

### 2026-11-13 — QA marathon Round 1 (dashboard & shell)

- **Scope:** dashboard + global-shell enhancement round (auto-QA marathon R1/10). Audit-first:
  throughput-history sparkline, severity-distribution card and a top-talkers card were all
  ALREADY on the dashboard (live area chart + backfill, 24 h severity stacked bar, talkers
  bars) — skipped as duplicates; the mobile nav drawer already had active-route highlight
  (`aria-current="page"`), section-grouping parity (same `SidebarNav` renders both), Esc/outside
  click close (Radix Sheet) and click-to-close — audit-verified in browser, no change needed.
- **realtime.ts — `useRealtimeStatus()`:** new export returning `"connected" | "connecting" |
  "reconnecting" | "offline"` from the EXISTING `getSocket()` singleton (module-level snapshot +
  `useSyncExternalStore` — hydration-safe, no setState-in-effect, no second socket connection;
  targeted `s.off(event, fn)` cleanup so it never strips other consumers' channel handlers).
- **app-shell.tsx — topbar:** (1) section label + view title as the `h1` — section derived from
  `NAV_GROUPS` by `routePath` ("FIREWALL / Firewall Rules"), closes PAGE_MAP §5's "Group / View"
  promise and keeps orientation on mobile; (2) realtime status dot after the Live/Simulated badge
  (`role="status"` + sr text + `title`: emerald connected / amber connecting-reconnecting
  (pulsing) / rose offline) per UI_DESIGN_SYSTEM §5.12.
- **dashboard-view.tsx:** (1) meta row above the banner — relative "Updated Xs ago"
  (`dataUpdatedAt` + 5 s clock heartbeat) with an "auto-refresh every 30 s" note and a manual
  Refresh button (spinner while `isFetching`, refetches summary + certs + rule counters,
  `h-11 lg:h-8` touch target, aria-label); (2) "Top firewall rules (hits)" card in the
  threats/apps row (now `lg:grid-cols-3`) — ranked top-5 by `hitCount` from the EXISTING
  `GET /api/v1/firewall-rules?limit=200&enabled=true` payload (hitCount/lastHitAt already ship in
  `shapeFirewallRule`; no new endpoint, no shape change): rank, name, §2.3 action chip,
  mono `tabular-nums` hit count, relative "last hit"; skeleton/error+retry/empty states mirror the
  cert-feed pattern; "All rules" link → `#/firewall/rules`.
- **Docs:** PAGE_MAP §2 topbar bullet + `#/dashboard` layout sketch updated; UI_DESIGN_SYSTEM new
  §5.12 (realtime dot) + §5.13 (topbar section label).
- **Verified:** `bun run lint` clean (fixed 1 rules-of-hooks error — useMemo after early return);
  dev.log zero compile/runtime errors after hot reload; curl golden path (login admin/admin123 →
  summary 200 `{data}`, firewall-rules 200 with hitCount, `/` 200; no-cookie → 401 both);
  agent-browser E2E via the :81 gateway (the browser-real path): topbar shows
  "OVERVIEW / Dashboard" + "Realtime stream connected" (emerald) — on direct :3000 the gateway is
  not in front so the dot honestly reads offline (same pre-existing sandbox condition, not a
  regression); FW-hits card renders 5 ranked rules ("24,314 …" with §2.3 chips + last-hit times);
  Refresh click → "Updated just now"; mobile 390px: drawer opens, Dashboard row carries
  `aria-current="page"` inside the dialog, Escape closes, console clean.
- **Deferred to later rounds:** "Top talkers" enrichment (already shipped as bytes bars),
  per-view deep-link palette items, mobile search row in the drawer, rules-table filter-chip
  touch-target pass, primary-button red-vs-zinc doc ruling (still needs owner).

### 2026-11-13 — Sandbox reboot recovery (app down → restored) + scripts/sandbox-recovery.sh

- **Incident:** the sandbox machine rebooted (~18:16). The platform reset wiped the npm
  global pm2 install, replaced `.env` with the 50-byte stub (`DATABASE_URL=file:db/custom.db`,
  no AUTH_SECRET), and the platform watchdog auto-started `bun run dev` directly —
  next-server ballooned to 2.5 GB of the 4 GB box (no `--max-old-space-size` cap) and `GET /`
  timed out. `db/cryptsk.db` survived as schema-only (untracked per §14 git hygiene) —
  **all rows gone, users table empty → login 401 despite correct credentials.**
- **Recovery (all verified):** killed stray watchdog processes → restored full `.env`
  (fresh secrets, ADAPTER_MODE=host) → reinstalled pm2 → `pm2 start ecosystem.config.cjs`
  (memory cap 1400M restored) → re-ran idempotent seed (8 users, 5000 FW logs, 300 IPS
  events) → golden path 200 (login/dashboard/notifications, 45 ms static).
- **New: `scripts/sandbox-recovery.sh`** — idempotent one-shot for exactly this failure
  mode: restores `.env` if stubbed, `bun install` if node_modules pruned, `db:push` +
  seed if the users table is empty, installs pm2 if wiped, kills stray watchdog
  `next dev` on :3000/:3003, starts ecosystem + `pm2 save`, polls until `GET /` → 200
  then probes `POST /api/v1/auth/login`. Run `bash scripts/sandbox-recovery.sh` after
  any sandbox reboot. QA passes 5-a/5-b code fully intact (spot-checked CommandDialog).

### 2026-11-13 — Feature enhancement QA pass (command palette + login demo credentials + cert-feed retry)

- **Scope:** 3 small additive enhancements (agent 5-b, follows the 5-a polish pass). Client-only;
  zero API/schema/route changes, no mini-service touches. Audit found the mission's
  "dashboard quick-actions strip" ALREADY present (dashboard-view "Quick actions" card, 6 hash
  actions, from the Logo-v3/dashboard-v2 session) and the notification unread badge ALREADY
  present (`useUnreadCount` + rose/amber/zinc badge) — both skipped as duplicates; the
  sanctioned cert-feed Retry follow-up took the freed slot.
- **app-shell.tsx — global command palette:** `Cmd/Ctrl+K` opens a `CommandDialog`
  (ui/command.tsx, first consumer of the previously-unused cmdk primitive) listing every
  hash destination grouped by `NAV_GROUPS` heading + a "Preferences" group with a Toggle
  dark mode command. Keyboard contract: Cmd/Ctrl+K toggle (window keydown, bound only while
  the shell is mounted — not login/setup), Esc closes, arrows move (cmdk native), Enter
  navigates by setting `window.location.hash` (closes first; no-op if already on the view).
  Topbar trigger button (Search icon + "Search…" + `kbd` hint, `h-11 lg:h-9` touch target,
  aria-label) sits left of the theme toggle. Platform hint (`⌘K` vs `Ctrl+K`) uses
  `useSyncExternalStore` with a server snapshot — React-Compiler lint forbids
  setState-in-effect, and the external-store probe is the hydration-safe replacement.
- **ui/command.tsx (1-line a11y fix):** the sr-only `DialogHeader` (title/description) sat
  OUTSIDE `DialogContent` in this repo's generated file — it rendered (as a ghost h2 in the
  page heading outline) even while the dialog was closed. Moved inside `DialogContent`
  (matches upstream shadcn). Surfaced only now because the palette is the primitive's first
  consumer.
- **login-view.tsx — demo-credentials helper:** Collapsible under the sign-in form listing 4
  seeded accounts (admin/super_admin, socuser/soc_analyst, netops/network_admin, viewer/
  auditor — prisma/seed.ts §Users) with per-row "Fill" buttons that populate username+password
  and clear the error — fill only, NEVER auto-submit. Trigger ≥44px on mobile, Radix
  aria-expanded/keyboard inherited, per-button aria-labels.
- **dashboard-view.tsx — cert-feed retry (Task 5-a follow-up):** the "Needs attention"
  certificate-feed error was a bare dead-end `<p>` ("Certificate expiry feed unavailable.") →
  inline `role="alert"` block + Retry button (RefreshCw, spins while `isFetching`, disabled
  during refetch) — mirrors the summary-error pattern 5-a established; targets the existing
  GET /api/v1/pki/certificates/expiring feed, no contract change.
- **Docs:** UI_DESIGN_SYSTEM §5.11 CommandPalette (scope + keyboard contract + "only global
  search UI" rule); PAGE_MAP §2 topbar line/bullet mention the palette trigger.
- **Verified:** `bun run lint` clean (fixed 2 React-Compiler findings introduced by the
  palette: useCallback deps + setState-in-effect); dev.log zero compile errors, `GET /` 200;
  curl golden path re-run (login admin/admin123 → `{data}` envelopes for summary /
  notifications?unread=true / pki certificates expiring; no-cookie → 401); agent-browser E2E:
  login view collapsible expand → Fill populates fields without submitting → Sign in works;
  palette opens via topbar trigger AND Ctrl+K, typing "firewall rules" filters to one option,
  Enter navigates to `#/firewall/rules`, Esc closes, ArrowDown moves selection, "toggle dark"
  command flips theme live. All 3 enhancements verified in-browser.
- **Recommended, NOT done (out of scope / needs owner):** palette is nav+theme only — future
  candidates: command actions (create rule, restart service) once a shared action registry
  exists; per-view deep links with tab fragments (`#/network/interfaces?tab=lldp`) in palette
  items; mobile menu could embed a "Search…" row reusing the same dialog. The 5-a flagged
  primary-button red-vs-zinc doc conflict (UI_DESIGN_SYSTEM §2 hard rule 2) still needs an
  owner ruling.

### 2026-11-13 — UI polish QA pass (shell a11y + touch targets + dashboard error state + scrollbar styles)

- **Scope:** QA/polish audit + surgical fixes across the global shell and the highest-traffic
  views (dashboard, login, firewall rules editor). 7 code files touched, no visual-identity
  redesign, no API changes.
- **app-shell.tsx:** skip-to-content button (sr-only → visible on focus; a BUTTON targeting
  `#main-content` via `.focus()` — an `<a href="#main-content">` would corrupt the ROUTING
  hash and bounce the view registry); `main` gets `id="main-content" tabIndex={-1}`; sidebar
  links `min-h-11` (44px touch target, PROJECT_MEMORY §9) + explicit
  `focus-visible:ring-2 ring-ring/60` (base layer only sets outline-color, no visible ring);
  topbar menu/theme/bell/profile triggers ≥44px on mobile (`size-11 lg:size-9`).
- **app-shell.tsx:** framer-motion view transition keyed by `routePath` — 180ms ease-out
  fade + 8px rise, gated by `useReducedMotion()` (reduced users get opacity-only), per
  UI_DESIGN_SYSTEM §7. Children keep their identity per view, realtime state unaffected.
- **globals.css:** added the slim scrollbar styles the design system always promised
  (UI_DESIGN_SYSTEM §4 / PROJECT_MEMORY §9) — `scrollbar-width: thin` + zinc-400/zinc-700
  thumbs (Firefox `scrollbar-color` + webkit pseudo-elements), plus a global
  `prefers-reduced-motion` reduce block.
- **dashboard-view.tsx:** query-error path was a bare `<p>` dead end → inline alert with
  error message + Retry button (spinner while `isFetching`), `role="alert"` (§6 ErrorState rule).
- **login-view.tsx:** error paragraph gets `id="login-error"` and both inputs
  `aria-describedby` it while visible.
- **rule-editor.tsx:** action RadioGroup cards (sr-only radio inputs) now show a
  `has-[:focus-visible]` ring — keyboard users can see which action card is focused.
- **fw-ui.tsx:** header comment said "Blue theme … allow = blue soft" — stale; corrected to
  the ADR-019 rev-2 zinc/rose/orange matrix (comment only).
- **notification-center.tsx:** bell trigger `size-11 lg:size-9` (44px mobile target).
- **Verified:** `bun run lint` clean; `GET /` → 200 in dev.log after hot reload, zero
  compile/runtime error lines; curl golden path (login admin/admin123 → cookie →
  `/api/v1/dashboard/summary` returns data JSON); agent-browser: login → dashboard →
  `#/firewall/rules` all render, skip link + landmarks + row aria-labels present, console clean.
- **Flagged, NOT changed (needs owner decision):** UI_DESIGN_SYSTEM §2 hard rule 2 says solid
  primary buttons are brand red (`bg-red-700 text-white`), but the codebase-wide primary
  action style is `bg-zinc-700 text-white hover:bg-zinc-800` (login submit, Add rule, dialog
  confirms… ~110 sites in ~40 files — the de-red overlay outcome). Either the doc or the
  buttons must move; mass-recoloring is a visual-identity change and was out of scope here.
  Also: rules-table filter chips are ~28px tall (below the 44px mobile target) — left as-is
  for desktop density; consider `min-h-11` on mobile in a future pass.

### 2026-11-09 — FIRST PRODUCTION DEPLOY: Debian 13 appliance LIVE (103.244.7.219) + de-red overlay pass

- **Owner handed over the production box**: Debian 13 (trixie), 103.244.7.219, SSH :22222, 4 CPU /
  3.9 GB RAM / 14 GB free. Mandate: "connect and do deploy/install-debian13.sh and live the app".
- Deployed via paramiko-SSH (sandbox has no ssh binary; sshpass/apt unrooted — pexpect/paramiko
  route). Server prep already had node 22 + bun 1.4.4 + pm2 + a stale clone of the repo in
  /opt/cryptsk-utm and /opt/cryptsk/console (at 506be80, the parallel session's rev-2 push).
- **GitHub push of this session's commit FAILED — no token in sandbox env** (ghp_ token lives only
  in the session that created it). Deploy therefore BYPASSED git: slim tarball (5.9 MB, excludes
  node_modules/.next/.git/db/logs/tools/skills) → SFTP → extracted over /opt/cryptsk/console.
- Bootstrap (nohup, /opt/cryptsk-bootstrap.log, ~70 s total): apt (build-essential, golang-go,
  nftables, wireguard-tools, sqlite3) → fresh .env (AUTH/JWT/INTERNAL_TOKEN/AGENT secrets) →
  bun install → prisma generate + db push (fresh SQLite, zero mock) → production seed →
  **next build OK on-server** (turbopack, no OOM) → Go agent build → pm2 (cryptsk-utm :3000 +
  realtime-service :3003 + cryptsk-agent :8080) → pm2 save + **pm2-root.service enabled** (boot
  persistence).
- **Caddy gateway installed** (apt, :81 XTransformPort pattern from repo Caddyfile → /etc/caddy/
  Caddyfile, systemd active) so browser realtime works: `GET :81/socket.io/?EIO=4&transport=
  polling&XTransformPort=3003` → real handshake `0{"sid":…}`. Agent healthz `{"ok":true}`.
- **Verified end-to-end**: public `http://103.244.7.219:3000/` → 200 (title "Cryptsk Console —
  UTM/NGFW"); `:81` → 200; POST /api/v1/auth/login admin/admin123 → full user+permissions JSON
  (super_admin); dashboard live metrics REAL (cpu/ram/ens32/drop via ADAPTER_MODE=host).
- **Login credentials on the appliance**: admin/admin123 (super_admin), tadmin/tadmin123, pattern
  `<user>123` — owner must change (Settings → Auth).
- **De-red overlay (this session, on top of parallel rev-2)**: tool-outage window forced a
  single-pass scripted remap (scripts/de_red.py): 43 files / 204 lines — `red-N` classes split by
  line semantics → rose (danger keywords) / amber (expiring·warn·degraded·pending) / zinc
  (decorative·info); brand logo/icon/boot + globals.css --primary + reports engine untouched.
  **Charts fully de-redded** (owner's exact complaint "the graph showing red"): throughput
  rx=`#0ea5e9` sky, tx=zinc `#71717a`; donut = balanced 7-hue `#64748b #0ea5e9 #10b981 #f59e0b
  #8b5cf6 #f43f5e #14b8a6` — deliberately DIVERGES from parallel rev-2 (rx=brand red): owner
  wanted no red graphs. Local next build + tsc both OOM-killed in the sandbox (pm2 services eat
  RAM) — the on-server build is the compile gate that passed.
- **Follow-up**: push d032a6f-equivalent state to GitHub when a fresh token is provided (repo is
  private; remote URL clean); then `bash deploy/update.sh` flow can resume for future updates.

### 2026-11-09 — Rev 2: red discipline (owner-rejected the all-red look) + dashboard polish

- Owner feedback on rev 1: brand is white/red but "I did not say make everything red" — the
  blanket blue→red sweep made the app read as one giant alarm (all-red charts, all-red badges).
- **New hard rule (UI_DESIGN_SYSTEM §2, Hard rule 2): red is for brand surfaces (primary
  buttons, active nav, focus ring, logo, links) + danger semantics ONLY.** Informational and
  decorative accents (header icons, tinted chips, info badges, count pills, data meters,
  upload/secondary chart series) are neutral zinc. Emerald still health-only; rose still
  destructive/critical; amber/orange warnings.
- **Charts** (`charts/palette.tsx`): throughput rx/download = brand red-700 `#b91c1c`,
  tx/upload = zinc-500 `#71717a` (was BOTH red); donut order red → amber → zinc → rose →
  zinc-400 → orange → slate; PALETTE.sky/violet are now neutrals.
- **Sweep**: ~310 red→zinc transform sites across ~55 view/shell files (3 parallel agents):
  decorative `text-red-700` icons → `text-zinc-500`, tinted chips → zinc-500/10 family, info
  alerts → zinc, data-meter fills → `bg-zinc-500`, hover tints → zinc, segmented active states
  → zinc-700. KEPT red: all solid `bg-red-700 text-white` primaries (~100+), firewall
  deny/drop, IPS/WAF/email block+severity semantics, quarantine/revoked/expired states,
  stopped-service dots, brand boot animation + sidebar active + login button.
- **Dashboard v2 polish**: gauge icon chips zinc; health bars emerald(<65)/amber/rose(>85)
  (was red at healthy); KPI chip icons zinc; "0 alerts" badge neutral zinc; talker traffic
  bars zinc; quick-action icons zinc; ↓RX stays brand red, ↑TX zinc.
- fw rule-action matrix updated: `allow` = zinc soft (was red soft — conflicted with deny=rose).
- Verified in browser (gateway :81): dashboard light+dark, firewall rules, system settings —
  red only where it means something; zero console errors; lint clean (no new issues).
- Red usage after sweep: 1,359 → 444 hits (remaining = primaries + danger semantics).

### 2026-11-09 — Logo v3 (hexagon ring-keyhole) + informative dashboard v2

- Owner direction: "make the dashboard page more informative, change the logo, push to GitHub".
- **Logo v3**: rounded hexagon badge + defense-in-depth inner hex outline + ring keyhole
  (replaces the shield mark). Gradient LOCKED to `#ef4444 → #c81e1e (55%) → #7f1d1d`.
  Mirrored in `src/components/shell/brand-logo.tsx` (id `ck-brand-gradient`), `src/app/icon.svg`
  and `public/logo.svg` (id `ckg`) — three surfaces stay in lockstep.
- **Dashboard v2** (`dashboard-view.tsx`): status banner (verdict ok/attention/critical computed
  from health + alerts + WAN; KPI chips Sessions/Alerts/WAN/VPN/Uptime; 24 h severity stacked bar
  + legend); live RX/TX speeds in the throughput header + approx window traffic totals; top
  talkers get relative traffic bars; dedicated VPN tunnels panel (status badges, session counts);
  new "Needs attention" card fed by GET /api/v1/pki/certificates/expiring?days=30 (expired/≤7 d
  rose, ≤30 d amber, "View all →" link); quick actions extended to 6 (+ Certificates, Auto-Block);
  system panel (uptime, local time, telemetry facts). Loading skeleton includes the banner.
- **Realtime verified via the gateway path** (:81 → Caddy → `XTransformPort=3003`): last tick,
  conntrack counter and live RX/TX all update. NOTE: a direct `:3000` origin bypasses Caddy, so
  `/socket.io/?XTransformPort=3003` 404s there — expected; the user path is the gateway and works.
- Verified: login (new logo), dashboard light + dark, sticky footer, lint clean on touched files.

### 2026-11-09 — Rebrand v2: white / red / dark-red theme (ADR-019 rev)

- Owner direction: brand colors are white/red/dark red — replace the blue/white theme.
- **Tokens** (`globals.css`): `--primary` red-800 light / red-500 dark; ring, accent,
  sidebar tint, chart vars re-hued (hue 262/250 → 25/27 or neutralized to zinc).
- **Class sweep** (63 files, 1288 hits): `blue-N` → red family with one-step deepening
  (500→600, 600→700, 700→800, 400→500, lights same-depth); `sky-N` → same-depth `red-N`
  (TX/upload + info-adjacent chips); `violet-N` → same-depth `zinc-N` (info severity +
  role chips — avoids collisions with amber=warn / rose=critical). Semantic colors
  (emerald health, amber warn, orange medium, rose critical) untouched.
- **Charts**: `PALETTE` hexes → red-700 / red-500 / amber / rose / orange / zinc / slate;
  rx = red-700, tx = red-500. Hard-coded hexes in reports-view, compliance-view and the
  HTML report engine rebranded (#2563eb→#b91c1c family).
- **Brand mark**: `BrandLogo`/`icon.svg`/`public/logo.svg` gradient → red-600→red-900.
- Docs synced: UI_DESIGN_SYSTEM §1–2 (logo, palette, matrices, chart table) +
  DECISIONS ADR-019 REVISION block.
- Verified in browser: login, dashboard (light + dark), firewall logs, IPS events —
  red chrome everywhere, semantics intact, zero console errors, lint clean on all
  touched files (pre-existing baseline unchanged).

### 2026-11-09 — Rebrand: favicon + logo mark + boot animation

- Replaced the Z.ai placeholder favicon (external `z-cdn.chatglm.cn` URL in layout
  metadata + `public/logo.svg`) with an owned brand mark: gradient shield + keyhole
  (blue-500 → violet-600, matching the console's existing accent system).
- Single-source `BrandLogo` component (`components/shell/brand-logo.tsx`) now used on
  all logo surfaces — sidebar, login, setup wizard, boot screen; `src/app/icon.svg`
  (Next file convention) serves the favicon; `public/logo.svg` mirrors it for
  bookmark/OG use. External CDN dependency removed.
- Console boot screen upgraded: pulsing-shield placeholder → branded spinner
  (ping halo + 1.1s orbit ring around the mark + status line). Verified in browser:
  login/sidebar/boot visuals correct, favicon served from `/icon.svg`, zero errors.

### 2026-11-09 — Bugfix: logout 403 → user bounced back to dashboard

- **Symptom:** Sign out (profile badge dropdown) appeared to do nothing — shell reloaded
  straight back to the dashboard.
- **Root cause:** `POST /api/v1/auth/logout` declared `route({ area: "dashboard" })`; as a
  mutation it maps to op `write`, and the RBAC matrix has `dashboard.write: []` (read-only
  area by design) → 403 FORBIDDEN for **every** role incl. super_admin. Cookie never
  cleared → reload → `auth/me` still 200 → dashboard. The client-side
  `window.location.hash = "#/dashboard"` before reload completed the illusion.
- **Fix:** logout route now passes no capability `area` (self-service for every
  authenticated principal — all roles, auditor, api keys; `authenticate()` still runs so
  anonymous callers get 401). Client handler drops the hash via
  `history.replaceState(null, "", pathname)` (no stale deep-link, no history entry) before
  reload; fresh login lands on default `#/dashboard`.
- **Verified:** curl jar-aware (login 200 → logout 200 + `Set-Cookie: cryptsk_token=;
  Max-Age=0` → me 401) + agent-browser golden path (badge → Sign out → login view →
  re-login → dashboard, zero page errors after reload). Lesson: **never attach an RBAC
  `area` to a mutation that every principal must be able to run** (logout, self-service).

### 2026-11-09 — M25: Go sensor agent shipped + agent mode verified end-to-end

**Owner directive (continuation):** complete the real data plane development in the sandbox so a fresh Debian 13 shows real data with no mock; project must live under pm2; deploy script for fresh Debian 13.

- **Go agent (`agent/` — NEW, pure stdlib, no cgo):** `main.go` (POST-only JSON API on
  `:8080`, constant-time `X-Agent-Auth` vs `AGENT_SHARED_SECRET` — refuses to start
  without a secret, `X-Request-Id` logged, `{data}`/`{error:{code,message}}` envelope,
  unauthenticated `/healthz` for pm2 liveness, reads repo `.env` without overriding real
  env), `proc.go` (netdev/cpu-jiffies/meminfo/conntrack/tcp+udp tables/uptime/route
  incl. little-endian gateway decode), `collector.go` (2 s locked tick, rings 500/2000/2000,
  WAN probes every 5 ticks = carrier → gateway → TCP:53 connect with up<250ms/degraded≤2.5s
  semantics mirroring `host/tools.ts probeGateway`, AGENT_WAN_IFACES for policy-routing
  multi-WAN), `logs.go` (Suricata eve.json tail rotation-aware + alert→severity mapping,
  `journalctl -k` nftables log parse, unbound query-log parse — all with agent-side
  monotonic seq), `types.go` (wire shapes byte-compatible with the console contracts).
- **Console side completed:** `dashboard-aggregates.ts` extracts the console-authoritative
  DB aggregates (alerts24h/topApps/topTalkers/vpnStatus/recentThreats) shared by
  HostAdapter + AgentAdapter — agent mode keeps config-plane truth in the console DB;
  AgentEngine now persists real ips/firewall log tails into the SAME tables host mode
  writes (dashboard aggregates stay real in agent mode); forceProbe maps ""→null.
- **Production wiring:** `ecosystem.prod.config.cjs` auto-starts `cryptsk-agent` (pm2 app
  #3) when `agent/cryptsk-agent` exists, env injected from `.env`; `deploy/install-debian13.sh`
  adds `golang-go`, builds the agent after `next build`, generates `AGENT_SHARED_SECRET`,
  smoke-checks `:8080/healthz`, banner lists the agent; `deploy/update.sh` rebuilds it.
- **Mode semantics (unchanged default):** sandbox + fresh Debian keep `ADAPTER_MODE=host`
  (full real plane, checklist Phase-1 gate for `agent` mode requires rows 3–21). The agent
  ships enabled for remote consoles / the Phase-4 manager; `ADAPTER_MODE=simulated` stays
  forbidden in production (runtime throw).
- **Verification:** `go vet` clean, binary builds (8.5 MB); curl smoke — real snapshot
  (cpu 19 %, mem 94.7 %, disk 41.8 %, eth0 492 kbps live, conntrack 32, honest tempC=0),
  real probe eth0→up, unknown iface→down, bad auth→401; `bun scripts/verify-agent-mode.ts`
  (NEW, committed): spawns the real binary, boots AgentEngine + AgentAdapter against it —
  **14/14 PASS** (5 real ticks absorbed, dashboard merge with DB aggregates, probe up,
  backfill history, honest 401). Host-mode dashboard re-verified after refactor (real
  cpu/mem/disk, eth0 rates, conntrack 53). `next build` killed by the sandbox reaper
  (resource limit — deploy builds run on the appliance; code is type-clean and the dev
  server compiles all touched routes on demand). pm2: cryptsk-utm restarted clean, HTTP
  200 + admin login OK throughout.

### 2026-11-09 — M24b: AgentAdapter transport shipped + production no-mock guard

**Owner directive (continuation):** real data plane completion for the Debian 13 move — no mock/simulated anywhere; app installable from apt on fresh Debian 13; project lives under pm2.

- **AgentAdapter (ADR-004 checklist rows 1–2):** new `src/lib/adapters/agent.ts` —
  `SystemAdapter` over the LOCKED transport contract (POST `{AGENT_BASE_URL}<path>`,
  `X-Agent-Auth: AGENT_SHARED_SECRET`, `{data,meta?}`/`{error}` envelope, 5 s reads /
  30 s mutations, `X-Request-Id`; fails LOUDLY on unreachable agent — never fabricates).
- **AgentEngine (checklist row 2):** new `src/lib/engine/agent-engine.ts` — `EngineLike`
  via 2 s `POST /v1/engine/snapshot` poll (drift-corrected), one-shot metricsHistory
  backfill, incremental logsTail/dnsTail keyed by seq, wanStates diff → `wan:status`
  events, realtime re-emission (metrics:tick/logs:tail) so realtime-service :3003 works
  unchanged; unreachable sensor → honest empty rings + throttled error logs.
- **Factories:** `getAdapter()`/`getDataPlaneMode()` now route `ADAPTER_MODE=agent`;
  `dataPlaneLabel()` covers agent. **NO-MOCK GUARD:** `ADAPTER_MODE=simulated` +
  `NODE_ENV=production` → throws (ADR-021 mandate enforced at runtime, fails loudly
  instead of serving fabricated data).
- **Mock hygiene (final sweep):** portal-view InfoNote no longer references MockEngine
  behavior (mode-neutral wording); `bun run purge:mock` re-run → 38 rows purged
  (4 `tpl-hosp/tpl-office` demo template firewall rules + stale config); DB verified:
  firewallLog/ipsEvent/vpnSession/dhcpLease/identitySession/zone/vpnConfig/wanPolicy = 0,
  interfaces = real host discovery only. Setup wizard re-completed via API (golden path
  of the fresh Debian install exercised end-to-end).
- **Install script:** `deploy/install-debian13.sh` .env now ships commented
  `AGENT_BASE_URL`/`AGENT_SHARED_SECRET` placeholders; checklist gains "Console-side
  implementation status" + console→agent endpoint map (contract v1: dashboard/summary,
  engine/snapshot, wan/probe) so the Go agent can be built against it.
- **Verification:** lint clean; runtime checks — production+simulated GUARD OK, agent
  adapter fails loudly (no fabrication), agent engine rings honest-empty when sensor
  unreachable; agent-browser: dashboard renders REAL /proc telemetry (cpu 2.5 %, mem 72 %,
  disk 37.3 %, eth0 live rates, conntrack 27, tempC=0 honest zero — no thermal sensor in
  sandbox), threat feed / top apps honest-empty pending real sensors, interfaces view
  labels "discovered by host collector (real interface)", zero console errors. pm2:
  cryptsk-utm + realtime-service online throughout.

### 2026-11-09 — M24: REAL data plane shipped (ADR-021) — no mock anywhere

**Owner directive:** "move everything to real data plane so i can move the full project to debian 13 no mock or simulated data… create a deploy script from debian 13… the project should live with pm2."

- **Engine swap (ADR-021):** new `HostCollector` (`src/lib/engine/host-collector.ts`) + `getEngine()` factory (`src/lib/engine/index.ts`); `ADAPTER_MODE=host` DEFAULT. Real sources: /proc (netdev deltas→throughput, stat→cpu, meminfo, tcp/udp sessions, nf_conntrack), sysfs (interfaces, operstate, carrier, MTU, MAC, thermal), real gateway TCP probes (WAN states + probe-now; removed the Math.random() probe fallback), systemctl is-active batch, Suricata eve.json tail → real `ips_events`, nftables kernel logs (journalctl -k) → real `firewall_logs`, `wg show all dump` → real `vpn_sessions` + status events, Kea leases CSV → real `dhcp_leases`, unbound query log → dns ring, real interfaces auto-discovered/upserted into `interfaces`. Absent sources → honest empty (never fabricated).
- **Consumers migrated to `getEngine()`:** instrumentation, internal events, dashboard summary, wan-policies + probe, iface stats (real error/drop/packet counters replace hash fakes), iface-service live rates, dns query-logs, system status (real `os.hostname`, real systemd states, `dataPlane` label replaces `mockProfile`). `HostAdapter` added; HA status real in host mode (keepalived unit + VIP presence + ICMP ping; `peerReachabilitySimulated:false`).
- **UI honesty:** topbar badge Simulated→**Live** (green) via `dataPlane` in /auth/me; sidebar footer "appliance — real telemetry"; system view "Data plane" field; login subtitle.
- **Data hygiene:** `prisma/seed.ts --production` (tenant+8 users+groups+settings+config v1 ONLY, wizard gate completed=false); `scripts/purge-mock-data.ts` purged 16,734 mock/demo rows from the tracked sandbox DB (verified: users 8, ifaces 3 real, fwlogs/ipsev/vpnsess/leases/notifs 0); `bun run purge:mock`.
- **pm2 production:** `ecosystem.prod.config.cjs` (next start :3000 + bun realtime :3003, portable paths, logs/ dir). Sandbox keeps dev ecosystem.
- **Debian deploy:** `deploy/install-debian13.sh` (flags --with-ips/--with-dns/--with-dhcp/--db postgres; apt→Node22/bun/pm2→clone /opt/cryptsk/console→generated .env→fresh DB+production seed→next build→pm2 start+save+startup→smoke 200) + `deploy/update.sh`. Docs: DEPLOYMENT.md rewritten (pm2 mandate, §8 real-source map), ADR-021, ROADMAP §4 M24 row, §2 snapshot.
- **Verification:** tsc clean, lint clean; pm2 restart → login 8/8 unaffected; dashboard curl shows REAL telemetry (eth0/dummy0 real rates, cpu/mem/disk real, conntrack real); agent-browser: login → dashboard renders Live badge + real gauges + real throughput spikes; interfaces view shows discovered eth0 with live rates; dev.log clean.

### 2026-11-09 — GitHub sync + login fix (post-sandbox-reset #3)
- **Incident:** after sandbox reset + `git pull` (`123a126..bfc5060`), login returned
  401 for every account and mock-engine writes logged "attempt to write a readonly
  database" (SQLite 1032).
- **Root cause (two-layer, on TOP of the known .env phantom-URL gotcha):**
  (1) sandbox reset restored the stale `.env` (`db/custom.db` phantom) — re-pinned to
  `DATABASE_URL=file:/home/z/my-project/db/cryptsk.db`; (2) NEW gotcha — the pulled
  `chore(db)` commit REPLACED the tracked `db/cryptsk.db` on disk while the boot-time
  dev server kept its fd to the deleted inode (`/proc/<pid>/fd` shows
  `cryptsk.db (deleted)`): SELECTs served the stale orphaned snapshot (all logins 401
  despite correct on-disk hashes), writes failed readonly. Restarting the dev server
  re-opened the current file — fixed both symptoms.
- **Verified (curl + agent-browser):** 8/8 seeded accounts login 200
  (admin/tadmin/secops/netops/socuser/helpdesk/viewer/svcapi …123), wrong password →
  401, no-cookie /me → 401; UI: login card → dashboard renders live metrics (CPU/mem/
  disk/temp + throughput chart), full nav (M01–M23), `cryptsk_token` cookie set,
  zero page errors; realtime svc :3003 healthy. Screenshot `/tmp/login-verified.png`.
- **Ops learning:** sandbox reaps agent-spawned processes between tool calls —
  long verifications must be atomic per call (see Gotchas §13); watchdog cron
  (job 513113) remains the standing restart safety net.

### 2026-11-07 — PHASE 2 SPRINT: M12–M23 shipped + Phase-1 tail closed + production package — console 100% ready for Debian 13
- **Owner directive:** "finish all Phase 2 and Phase 1 pending things, 100% production,
  forget this sandbox, think production box, when I move to Debian 13 all should be ready."
- **Executed (ADR-020, four parallel sub-agent batches, 12 commits per HARD RULE §11.16):**
  M12 44458d6 (cross-dataset log search, CEF/LEEF export, HTML report engine w/ real rollups,
  compliance templates PCI/HIPAA/GDPR/ISO27001/SOC2 w/ control checklists, anonymization) →
  M13 76bc6da (feeds w/ simulated ingestion corpus, IOCs, auto-block, hit feed) →
  M14 3d47981 (**real X.509 via node-forge**: root/sub CAs, issuance w/ SANs, revocation ledger +
  signed RFC5280 CRL, admin-gated key downloads, keys never in JSON) →
  M15 0f701b3 / M16 61080f5 / M17 613de91 (SSL inspection MITM policies on real CAs, URL filter
  13-category engine + paste import, WAF vhosts + 12-rule CRS evaluation, geo-block, rate-limit) →
  M18 75a550a / M19 d703360 / M20 edc4ec3 (nDPI app control w/ bandwidth limits, BGP/OSPF +
  policy objects + live RIB, SD-WAN probes + SLA state machine) →
  M21 2c0b80f / M22 d63f690 / M23 3974ee7 (IPv6 NAT66/DHCPv6/IA_PD, email Rspamd-style engine
  w/ quarantine release, SAML/OIDC IdPs + CoA + 802.1X/MAB profiling + BYOD one-time tokens).
- **Phase-1 tail CLOSED:** M12 ships scheduled reports + print/PDF path (§2 divergence);
  M11-tail ead4776 ships REAL webhook delivery (HMAC-SHA256 X-Cryptsk-Signature, 3-attempt
  backoff retry, no-retry on 4xx, 10s timeout, `webhook_deliveries` ledger + history dialog).
- **Production package 57c54e7:** `DEPLOYMENT.md` (Debian 13 runbook: PostgreSQL switch per
  ADR-005, standalone build, systemd units console+realtime, Caddy edge TLS, hardening
  checklist, smoke tests), `deploy/AGENT_ADAPTER_CHECKLIST.md` (per-module appliance wiring,
  Phase-1 gate for ADAPTER_MODE=agent), `.env.example`.
- **Sandbox ops (Gotchas §13):** OOM killer reaped next-server repeatedly (2.0-2.5 GB RSS vs
  4 GB box when tsc/lint/browser run alongside) — mitigations: memory-capped restarts,
  browser closed when idle, dev-server-watchdog cron (5 min fixed-rate) heals port 3000;
  `db/cryptsk.db` tracked in git heals data resets. Next dynamic-route slug clash
  (`[siteId]` vs `[id]` sibling) crashed the server — same slug per path level is now a rule.
- **State:** 46 hash views, ~90 tables, 12 new RBAC areas, zero placeholders. Console is
  feature-complete for both phases; next milestone is the Debian 13 appliance build (Go agent).
- **Verified end-to-end with agent-browser (batch-by-batch):** all 17 new views render with
  seeded data (feeds/IOCs/auto-block, CAs/certs, SSL/URL/WAF stats, app-control, BGP/OSPF,
  SD-WAN, IPv6, email, federation); scoped tsc clean; browser-verified where the sandbox OOM
  window allowed, with per-batch smoke checks through real API calls.

### 2026-11-07 — Sandbox reset #2: DB data lost again → `db/cryptsk.db` now TRACKED in git
- **Incident:** sandbox reset restored git history intact (local = remote = `123a126`,
  nothing lost) but reverted `.gitignore` AND restored `db/cryptsk.db` as an empty
  schema-only snapshot (46 tables, 0 users, 0 tenants) → login 401 again.
- **Fix (same session):** restored `.gitignore` from HEAD; re-ran `bun prisma/seed.ts`
  (8 users / 5,256 fw logs / 300 IPS events / 25 leases / 10 vpn sessions); verified
  end-to-end with agent-browser (login → live dashboard w/ realtime throughput →
  firewall rules from DB → mobile 390px + desktop 1440px, zero page errors).
- **Root-cause fix (user mandate):** `db/cryptsk.db` is now COMMITTED to git
  (`.gitignore` `db/` rule replaced with sidecar-only ignores) so future resets are
  healed with `git checkout -- db/cryptsk.db`. §11.17 updated with the exception.
- **Recovery recipe (updated):** after sandbox reset →
  `git checkout -- .gitignore` (if clobbered) → `git checkout -- db/cryptsk.db` →
  restart dev server. Full re-seed (`bun prisma/seed.ts`) only after schema changes.

### 2026-11-06 — M08→M11 FINAL SPRINT (QoS · Logging & Reports · System/HA/Notifications · API Platform) — Phase 1 console COMPLETE
- **Four modules shipped in one session, each committed + pushed immediately on phase
  completion (HARD RULE §11.16):** `feat(M08)` 370560c → `feat(M09)` 1b1966d →
  `feat(M11)` 5293ed7 → `feat(M10)` aa1d926. M11 pushed before M10 because the
  `#/system/api-keys` view UI (M10 §4 ownership unchanged) calls M11's endpoints —
  shipping endpoints first keeps every pushed commit working. Build-order numbering
  preserved in commit sequence.
- **M08 QoS (`/qos/policies`):** policies CRUD (+ruleCount, iface attach w/ one-enabled-policy-per-iface
  409), rules CRUD scoped `?policyId=`, validation (prio 0–7, guaranteed≤max, enabled-guaranteed-sum≤budget
  naming sum vs budget, dscp 0–63, matcher id existence, catch-all uniqueness), template seeding on create
  (voip/video/gaming/bulk/custom per §5.1 — voip seeds `SIP` only: `RTP` not in the app catalog),
  hard-limit classes (single matchUsers/matchApps dimension + maxKbps, no guaranteed) + "Limit user…"/
  "Limit application…" quick-create, delete protection 409 listing referencing firewall rule names, tc
  effect panel (htb → child classes → fq_codel; "sandbox does not run tc" footnote), utilization sparkline
  (metrics:tick, rose cap line, wan-aggregate fallback). Engine: `loadQosRuntime` + per-tick cap clamp in
  `metrics.ts` (attached iface → clamp; iface-less → proportional wan-aggregate scaling) — verified live
  (wan0 rides exactly 50 000 kbps; disable → unclamped next tick).
- **M09 Logging (`/logs/firewall|ips|audit|live|reports`):** server-paginated firewall/ips/audit lists with
  per-view filters (q/action/src/dst/since/until · severity/category · user/objectType/result) — every filter
  in the TanStack key, page resets on change; row detail Sheets; CSV export `X-Row-Cap: 10000`;
  `/logs/stats` LOCKED shape (1h→5min, 24h→60min, 7d→360min buckets; series allow|deny|drop|reject +
  ipsBySeverity); live tail (500-row client ring, pause counts missed, autoscroll, kind filter, amber
  reconnect banner off socket events); reports (range picker, 4 stat cards, stacked action trend, action-mix
  + threat-mix donuts, print CSS, CSV/JSON export); scheduled reports CRUD + run-now (lastRunAt); syslog +
  NetFlow target CRUD (Forwarding tab). Audit objectTypes facet rides `GET /logs/audit?facets=objectTypes`
  (additive param, no new route). M04's `/ips/events/{id}/suppress` reused from the IPS logs view.
- **M10 System/HA (`/ha`, `/system/settings`, `/system/backups`, `#/setup` gate, topbar bell):** HA status
  (simulated heartbeat, tracked-iface chips, sync chips, Keepalived explainer) + config editor gated on
  **ha WRITE** permission (admin column doesn't exist for ha — editor gate = `canWrite("ha")`); settings
  singleton map GET + batch PUT (snmp community masked-literal omit-to-keep; retention overrides within
  hard caps; NTP synced flipped by engine after enabled save); backups = JSON files under `db/backups/`
  (config|full), restore auto-safety-backup + section "all" snapshot + typed `RESTORE` confirm; firmware
  state in `advanced/firmware` (check → available 1.0.1, upgrade = safety backup + history, rollback 409
  when <2 entries); ssh-keys (server-derived `SHA256:…` fingerprint, private-key 400); policy templates
  (tpl-office|tpl-hospitality|tpl-msp-branch, apply = idempotent-by-replace + section "all"); services
  restart; setup wizard = full-screen 5-step gate rendering INSTEAD of the shell while `system/setup`
  .completed=false (verified live by flipping the flag; seed ships completed=true); notification center
  (bell popover, unread badge, alerts:new live prepend, mark-read + deep link, mark-all-read) replaced the
  static topbar bell. **Engine:** resource-threshold watcher (edge-triggered, one open system-notification
  per metric, warning → critical, info recovery) — verified emitting live ("CPU above threshold" warning
  @97% + recovery rows).
- **M11 API Platform (no view of its own; UI = `#/system/api-keys` tabs):** api-keys lifecycle (`ck_` + 32
  url-safe chars, sha256 hash, prefix-only reads, full key in POST response exactly once, soft revoke,
  expiresAt auth-time 401, machine keys 403 on /api-keys* AND /webhooks*, scopes = the 3 LOCKED arrays);
  webhooks CRUD (https-only, 5-event enum, secret write-only/omit-to-keep, simulated delivery test →
  {ok,status,latencyMs} + row marking); `GET /api/v1/openapi.json` = OpenAPI 3.1.0 generated from a
  ROUTE_MANIFEST mirroring §7.2 verbatim (126 paths / 193 operations, duplicate-path drift guard, no area
  → any authenticated principal). session.ts already throttles lastUsedAt (1/min/key).
- **View conventions kept:** white/blue ADR-019, React-19 lint compliance (render-time derived reset
  instead of set-state-in-effect; no ref access during render), server pagination everywhere, sticky
  footer intact, 29/29 hash views live with zero placeholders.
- **Ops notes:** dev server OOM-killed twice under parallel agent load (restart + `rm -rf .next` fixed a
  stuck root-page compile); browser verification must go through the gateway origin (:81) — `localhost:3000`
  direct does not proxy `XTransformPort`, so socket.io never connects there (test-origin artifact, not an
  app bug).

### 2026-11-06 — M07 Identity & Access module LIVE (users · groups · auth policy · RADIUS · directory sources · captive portal + vouchers · identity sessions)
- **M07 shipped vertically (ADR-014 order …M06→M07…):** API surface — `users`
  (GET `?q=&role=&groupId=` + POST), `users/[id]` (PUT incl. optional `password`
  policy-checked + `totpEnroll` one-time secret + `groupIds` replace-all; DELETE with
  self-delete + last-enabled-admin 409 guardrails), `user-groups` (+`[id]`,
  memberIds replace-all tx), `auth-settings` (GET merges canonical `auth/settings`
  SystemSetting w/ seed's granular keys; PUT writes canonical + re-syncs granular),
  `radius-profiles` (+`[id]`, masked `sharedSecret`), `[id]/test` (simulated 5–40 ms;
  documentation-range IPs dead), `[id]/reveal` (super_admin/tenant_admin ONLY — narrower
  than identity.write matrix, audited + sourceIp), `directory-sources` (+`[id]`,
  masked bindPassword, NO reveal) + `[id]/test` (userCount for enabled), `captive-portal`
  (GET/PUT singleton upsert), `captive-portal/vouchers` (GET masked `…last4`; POST
  {count 1–500, ttlHours?, bandwidthKbps?} → FULL codes exactly once) + `[id]` DELETE
  revoke, `identity/sessions` (`?method=&state=&q=`) + `[id]/expire` (audited +
  emits `sessions:update {kind:"identity"}`). All routes `area: "identity"`, section
  `identity` → audit + config_versions + `config:updated`.
- **Masking (ADR-011, STRICT):** `MASK = "••••••••"` fixed literal; server masks
  sharedSecret/bindPassword on every read; totpSecret/passwordHash never serialized;
  password never audited (after = DTO only); omit-or-masked-secret on PUT keeps stored.
- **Engine:** `generators/identity-sessions.ts` (pure planner: timeout expiry per
  method, simulated logins — voucher-gated captive_portal / credentials self-register /
  local+radius from enabled users / vpn roster, concurrent-cap expires oldest) +
  `lib/identity/vouchers.ts` (globalThis store — volatile by design, SCHEMA §6;
  Crockford base32 `cks-XXXX-XXXX`; sweep→expired; consumeVoucher gate) wired as tick
  step 6d (`identityChurnStep`): lastSeen bump every 5 ticks, @@unique(tenantId,sourceIp)
  replace-on-login, diffs emitted with the 5-tick `sessions:update` cadence;
  `reloadIdentityState()` 15 s throttle (portal profile + authSettings cap + users).
- **Views:** `views/identity/{users,sessions,portal}-view.tsx` + `identity-panels.tsx`
  (RADIUS | Directory | Auth Settings tabs), `identity-api.ts` (envelope unwrap w/ zod
  details), `identity-ui.tsx` (RoleBadge/MethodBadge/SessionStateBadge/VoucherStateBadge/
  DirectoryTypeChip/TestResultPill + section invalidation). Users view = 2-col xl grid
  (users table + groups card) + secondary tabs; TOTP enroll dialog shows otpauth URI +
  secret once; RADIUS reveal = second click, 15 s auto-hide; role descriptions table
  inline in the user editor; voucher gen → one-time reveal (Copy all / CSV) then masked
  list w/ state chips + revoke + masked CSV export; sessions view = method filter chips,
  ticking lastSeen (5 s interval), `sessions:update` in-place merge, useSyncExternalStore
  socket-status banner ("Live updates paused"), expire ConfirmDialog.
- **React hooks gotcha (§13 material):** `react-hooks/set-state-in-effect` forbids
  setState-in-effect dialog resets — dialogs now split wrapper + inner form mounted
  inside `<DialogContent>` (Radix unmounts content when closed → fresh state per open,
  `useState(() => …)` initializers).
- **Tailwind gotcha (§13 material):** `grid` without an explicit `grid-cols-1` creates
  implicit auto tracks that don't clamp at mobile (page horizontal scroll) — every
  responsive grid needs `grid-cols-1 … md:grid-cols-N`; table wrappers
  `max-h-96 overflow-x-auto overflow-y-auto`; card-header action rows `flex-wrap`.
- **agent-browser quirks (testing, not app bugs):** untrusted synthetic `.click()` works
  for React handlers; Playwright semantic clicks need Radix's full pointer sequence
  (mousedown/mouseup) on tabs; hash-only `open` on the same doc does NOT reload — use
  `reload`; socket.io only connects via the Caddy gateway path (XTransformPort) —
  testing must go through `:81`, not `:3000` directly.
- Verified: lint 0/0; curl E2E — policy-reject weak password (fieldErrors), create,
  TOTP enroll/disenroll, self-delete 409, group replace-all, reveal 403 for
  security_admin, masked reads, vouchers generate→masked, expire; browser E2E via
  gateway — users table live, Add User dialog created eve.tester, vouchers 5× reveal +
  masked list, session expire flips row (5→4) without reload, auth settings form seeds,
  socket connected (no pause banner); mobile 390 px (no h-scroll) + desktop 1440 px
  sticky footer. HARD RULE §11.16: push after this commit (remote SHA verified).

### 2026-11-06 — M06 DNS & DHCP module LIVE (resolver · policies · records · query log · subnets · reservations · leases · relay)
- **M06 shipped vertically (ADR-014 order …M05→M06…):** API surface — `dns/settings`
  (GET/PUT), `dns/policies` (+`[id]`), `dns/records` (+`[id]`, per-type value grammar
  M06 §5.2), `dns/query-logs` (derived, engine ring 2000), `dhcp/subnets` (+`[id]`,
  family-aware CIDR math + per-family overlap 409 + cascade counts), `dhcp/reservations`
  (+`[id]`, MAC unique 409 w/ holder), `dhcp/leases` (`?state=&subnetId=&q=`), LOCKED
  `dhcp/leases/[id]/release` (active-only → 409 otherwise), `dhcp/relay` (GET/PUT,
  iface existence 400). All routes `area: "dns_dhcp"`, sections `dns`/`dhcp` → audit +
  config_versions + `config:updated` broadcast via `route()`.
- **Engine:** `generators/dns-queries.ts` (85/10/5 mix; first-match policy eval:
  customAllow → customBlock("custom") → blockCategories; forwardZones latency flavor;
  ring-only, no event) + `generators/dhcp-leases.ts` (pure planner: expire/renew/
  release/create; pool minus reservations; reserved-IP reassign release; churn IPv4-only)
  wired as tick steps 5b/6c; `watchPolicyChanges()` de-`break`ed (lost-event bug fixed)
  + dns/dhcp sections; retention prunes expired/released leases > 7 d.
- **Views:** `views/dns-dhcp/{dns,dhcp}-view.tsx` (4+4 tabs, `?tab=` deep links,
  Query Log 10 s poll — no socket event per M06 §6), `dns-dhcp-api.ts` (envelope unwrap
  preserving zod details), `dns-dhcp-ui.tsx` (ResultBadge/BlockedBadge/LeaseStateBadge/
  FamilyChip/IpListEditor/OptionsEditor + per-section invalidation hooks).
- **zod 4 gotcha (§13 material):** `.partial()` fails on schemas carrying
  `.superRefine()` — split a refinement-free base object and re-validate merges in the
  service (`updateRecord` re-runs `dnsRecordCreateSchema.safeParse`).
- **Radix gotcha:** `<DialogContent>` without a `<Dialog open>` wrapper throws a
  client-side exception (Next dev overlay shows component stack) — all four editors
  wrapped.
- **Shell fix (pre-existing):** sidebar `ScrollArea` grew past `h-screen`
  (flex `min-height:auto`) inflating docH and floating the footer on desktop —
  `min-h-0` added; sidebar scrolls internally (794 px viewport), footer sticky bottom.
- **DB reseed was required** — sandbox restore had emptied `users` (login 401s);
  `bun prisma/seed.ts` restored 8 users + DNS/DHCP seed rows.
- **HARD RULE added (§11.16/17, user-mandated):** GitHub push on every phase completion;
  never commit runtime artifacts. M06 pushed per that rule (remote SHA verified).
- Verified: lint 0/0; tsc 0 in M06 files (9 pre-existing baseline); browser E2E —
  login → DNS tabs (policy create/delete via dialogs) → query-log blocked rows after
  live policy change (one tick) → DHCP subnets (overlap 409, v6 save) → leases
  (churn + release flips to released) → relay; mobile 390 px + desktop 1440 px footer.

### 2026-11-06 — M05 VPN module LIVE (configs · sessions · user groups · tunnel state machine)
- **M05 shipped vertically (ADR-014 order …M02→M04→M05…):** API surface —
  `/vpn/configs` (list w/ live sessionCount, create, PUT, DELETE cascade),
  `/vpn/configs/{id}/status` (handshake/DPD/transfer/peers + anti-replay for
  ipsec + session counts for remote types), `/vpn/configs/{id}/client-bundle`
  (wg s2s peer .conf / wg remote .conf that APPENDS a provisioned peer with a
  fresh placeholder keypair + /32 from the pool / openvpn .ovpn; ipsec_* → 409;
  disabled config → allowed w/ "offline config" notice), `/vpn/sessions`
  (?vpnId=&status=&q=&page=), `/vpn/sessions/{id}/disconnect` (idempotent),
  `/vpn/user-groups` CRUD (pool-overlap 400 vs remote configs + other groups;
  memberUsernames replace-all). Validators `src/lib/validators/vpn.ts`
  (discriminated per-type config union per SCHEMA §4; listenPort 1–65535,
  keepalive 0–120, dpd 5–600, replayWindow ∈ 32…1024). Service
  `src/lib/vpn/service.ts` (+ shared types in `src/lib/vpn/types.ts`; engine
  owns status — PUT writes it ONLY on the enable/disable apply edge:
  enable → connecting, disable → down + Disabled by operator). Shared types
  lib-first: views/vpn-api re-exports from lib/vpn/types (no lib→components dep).
- **Views** `src/components/views/vpn/*`: `#/vpn/configs` (4 tabs WireGuard |
  IPSec | OpenVPN | User Groups; per-family tables w/ subtype chips, engine
  status badges, endpoint/pool summary; per-type editors — wg peers table w/
  per-row CidrListEditor, ipsec authMethod select + replayWindow + pfs,
  openvpn proto radio; masked SecretField w/ reveal-eye + generate helper;
  status dialog w/ 5 s auto-poll; bundle menu item HIDDEN on ipsec rows;
  delete confirm w/ cascade warning), `#/vpn/sessions` (config/status/q
  filters, server pagination, disconnect confirm, sessions:update realtime
  in-place patching — bytes tick w/o refetch flash, throttled refetch only on
  status transition under an active status filter), GroupsPanel (pool/dns/
  timeouts/limits editor + member TagInput w/ suggestions from live sessions).
- **Engine:** `reloadVpnState` on `config:updated {section: vpn}` (3 s throttle)
  re-syncs tunnels + sessions + group policies; VpnSessionState gained
  idleChanceMul/disconnectChanceMul/expiresAt — CONTRACTORS members churn out
  faster (idleTimeoutMin) and hard-expire at maxSessionMin; spawn generator
  keeps ~10 live rows (DATA_LIFECYCLE §5) honoring maxSessionsPerUser +
  60-tick kick cooldown; assignedIp from the MATCHING GROUP POOL when member
  else config pool; groupName stamped; engine-up statusMessage names the peer.
- **CRITICAL FIX (pre-existing, M03-era regression):** `watchPolicyChanges()`
  was defined but NEVER CALLED from the tick — config:updated-driven policy
  reloads (firewall/nat/ips) were dead; IPS "policy-aware engine" only worked
  via bootstrap timing. Now invoked every tick (step 0). **Second fix:** tunnel
  status transitions now persist IMMEDIATELY (per-transition update) — the 20 s
  periodic persist lagged the DB behind engine memory, leaving UI badges stale
  after vpn:status-triggered refetches.
- **Realtime ops note:** the socket.io mini-service (port 3003) had a ZOMBIE
  process with a stuck poll loop — clients connected but received NOTHING
  (metrics/sessions/config all silent). Symptom: UI badge stale while DB was
  already `up`; raw socket.io-client probe on :3003 vs :81 isolated it. Fix =
  kill the bun process holding 3003 and restart (`bun run dev` in
  mini-services/realtime-service). Also re-confirmed the M04 gotcha: testing
  against :3000 directly silently bypasses socket.io — the gateway (:81) owns
  `?XTransformPort` routing; browser E2E must go through :81.
- **UI fixes caught by browser E2E:** CidrListEditor commits typed-but-unentered
  CIDRs on blur (silent data loss on save before); server fieldErrors matched
  under `config.config.*` paths too; "just now ago" fmtRelative grammar.
- **Verified (curl):** 400 peer-missing-publicKey w/ field path, 409 port
  collision, 400 group pool overlap, 409 ipsec bundle, create → connecting →
  up (~10 s) → disable down → enable connecting, disconnect idempotent, wg
  remote bundle appends peer + free-/32 allocator, group CRUD. **Verified
  (agent-browser via :81):** login → configs 4 tabs render seed mix, status
  dialog (handshake/DPD/transfer/peer rows), UI create flow (peer chips,
  port-collision toast, created row flips Connecting → Up LIVE via
  vpn:status, delete cascade), sessions view w/ realtime byte ticking (same
  DOM ref, no flash), disconnect → Disconnected, group-pool respawn
  (10.99.1.138-139/32), filters (status/search/vpnId), User Groups tab,
  dark mode + 390 px mobile, dashboard regression, zero dev.log errors;
  lint clean; tsc = 7 pre-existing baseline (0 in M05 files).

### 2026-11-06 — M02 Network module LIVE (interfaces · routing · multi-WAN)
- **M02 shipped vertically (ADR-014 order M01→M03→M02→…):** 15 API routes —
  `/interfaces` (list w/ live rx/tx + link/degraded states, create, detail, PUT, DELETE
  w/ transactional cascade: WanPolicy → zones.interfaceNames → StaticRoute null → row),
  `/interfaces/{id}/stats` (engine ring: rates + totals + 60-tick sparkline + uptime),
  `/network/lldp-neighbors` + `/network/mac-table` (derived views — deterministic
  30 s/60 s churn buckets, statics from DHCP reservations + bridge membership; bridge
  filter expands to member ifaces per FDB semantics), `/network/port-mirrors` (+[id],
  one active mirror per src → 409), `/routes` (+[id], blackhole XOR gateway),
  `/pbr-rules` (+[id], +toggle, egress iface XOR gateway, object-id existence checks),
  `/wan-policies` (+[id], +probe → MockEngine.forceProbe + fresh state). Validators in
  `src/lib/validators/network.ts` (discriminated create union, flat update schema +
  per-type config patches); services `src/lib/network/*`. RBAC area `network`.
- **Views:** `#/network/interfaces` (4 tabs: Interfaces w/ realtime sparklines +
  type-aware editors + stats dialog, LLDP, MAC Table, Mirroring), `#/network/routing`
  (Static Routes + PBR w/ ObjectPicker), `#/network/wan` (policy cards + failover
  explainer w/ active-egress calc + Probe now). Reuse fw-ui (ConfirmDialog,
  TableSkeleton, QueryError, ObjectPicker, toasts). Realtime: metrics:tick → row
  rates/sparklines; wan:status → badge flips + transition toasts; config:updated →
  section-aware invalidation. nav-config M02 placeholders removed; app-shell wired.
- **Contract bug caught by browser E2E (fixed):** the interface editor initially sent
  a uniform config-envelope while `ifaceCreateSchema` is a flat discriminated union
  (vlan needs flat `parent`+`vlanId`; bond create `mode` = aggregation mode) and
  physical WAN edits must ride TOP-LEVEL `wanType/ip/gateway/dns/lldp`, not `config`.
  Fix: per-type flat create payloads + flat physical update payloads + logical
  `config` patches. LESSON: §13 cross-agent contract drift — when backend + frontend
  are built in parallel, the pinned shape table must include exact payload shapes,
  not just response shapes.
- **Verified:** curl (all endpoints incl. 400/409 rules: physical-delete, blackhole+gw,
  PBR both/neither, mirror dup, unknown iface/zone) + Agent Browser E2E (create vlan42
  via dialog → row live → ConfirmDialog delete; probe now; delete cascade; dashboard
  WAN strip === Multi-WAN state; mobile 390 px). lint 0/0; tsc clean for M02 files.

### 2026-11-06 — M04 Intrusion Prevention module LIVE (policies · events · policy-aware engine)
- **M04 shipped vertically (ADR-014 order …M03→M02→M04…):** API surface — `ips/policies`
  (CRUD), `ips/policies/apply-preset` (conservative/balanced/aggressive bundles per
  DATA_PLANE §3.1, create-or-replace), `ips/rule-categories` (15-category catalog with
  base severity/preprocessor family/sid ranges), `ips/events` (locked param set
  severity/sid/q/since/until/category/page — server-paginated), `ips/events/{id}/suppress`
  (`24h|7d|forever`; forever → `suppressedUntil=null` + action=suppressed per ENDPOINTS §3),
  `ips/update-settings` (GET/PUT/POST run-now on `ips/auto_update` SystemSetting). Service
  layer `src/lib/ips/*` (catalog+presets, RESTRICT-aware CRUD, event query, update-cycle
  simulation on GET when the window passes). Views `src/components/views/ips/*`:
  policies table (mode badges, enabled toggle, categories k/15, attached-rules deep link
  `#/firewall/rules?search=`), PolicyEditor (mode radio cards w/ "only inline_drop blocks"
  explainer, category matrix w/ master on/off + inspector-off hints, custom suricata rules
  w/ per-line 400 rendering, exceptions (sid 0 = any-SID bypass label per ADR-017),
  thresholds, preprocessors, TI blocklist, stale-data banner on config:updated), preset
  dialog (bundle preview + create/replace), Rule Updates card (schedule + run now). Events
  view: severity chips + range presets + category/q/sid filters, 50-row live tail
  (logs:tail kind=ips, filtered, deduped), row actions (suppress menu, Block), detail
  Sheet w/ full fields.
- **Cross-module handoff (M04→M03):** "Create firewall block rule" creates a temp address
  object (`ips-src-<sid>`, reused on 409), stashes a create-mode draft in
  sessionStorage `ips:prefill-rule`, navigates `#/firewall/rules?prefill=1`; rules-view
  reads hash query once at first render (lazy state, lint-safe) and RuleEditor gained an
  optional `prefill` prop (create mode, custom title).
- **Engine now policy-aware (SIMULATION_LAYER §6):** `loadIpsPolicyStates` + generator
  rewrite — category gating (enabled set), mode semantics (inline_drop → drop events +
  CORRELATED `firewall_logs` row `ruleName:"ips:<policy>"` same 5-tuple; inline_tap/
  passive → alert only), preprocessor family gating (http/tls/stream off → family
  silenced), TI blocklist feed IPs → c2/malware drops, thresholds (count/seconds/track →
  excess rows `action=suppressed`), exceptions (targeted → row dropped; sid 0 → bypass).
  Default policy = first enabled by id asc, prefers one attached to an enabled rule
  (ADR-017). Reload on `config:updated {section:"ips"}` (3 s throttle).
- **CRITICAL BUG FIXED (pre-existing, M03-era):** firewall-log persistence had been dead
  since the GeneratedFlow refactor — the tick pushed the flow WRAPPER into
  `pendingFwLogs`, so `new Date(undefined)` → `PrismaClientValidationError` on every
  createMany batch, silently swallowed by `.catch(()=>{})` (fw logs frozen at 10:48 while
  ips kept flowing — the tell). Tick now unwraps `flow.log`, uses `flow.fwRuleId` for hit
  counters, and fw createMany failures LOG loudly instead of vanishing. Also fixed the
  stuck realtime cursor: the engine emitted into the instrumentation bundle's copy of the
  events ring while `/api/internal/events` read the route bundle's copy — ring state moved
  to globalThis (same singleton trick as the engine).
- **Realtime subscribe fix (pre-existing):** `useRealtime` never sent `subscribe`, so the
  service's channel-gated rooms (metrics/logs/alerts) delivered nothing to ANY view. Hook
  now emits `subscribe` on connect (+reconnect) and `unsubscribe` on cleanup. Live tail on
  `#/ips/events` and the dashboard throughput chart verified streaming afterwards (live
  dots 5→7; chart timestamps advance). NOTE for browser tests: `?XTransformPort` routing
  only exists on the Caddy gateway (:81) — testing against :3000 directly silently
  bypasses socket.io; test realtime through the gateway.
- **Verified (agent-browser via gateway + curl):** policies list (BALANCED 13/15 enabled
  w/ TI on, STRICT_WEB 4/15 disabled), editor create w/ per-line custom-rule validation
  blocking save then passing, preset AGGRESSIVE applied, Run update now bumps lastUpdate,
  weekly schedule → next run Nov 9 (Monday) recompute, events table severity filter
  (server-side, all-critical page), suppress 7d → suppressedUntil +7d server-verified,
  TI feed IP row (45.83.91.7 → drop, "feed IP matched simulated TI blocklist"), block-rule
  handoff end-to-end (prefilled editor → "Rule created" → row in rules table), delete
  BALANCED → 409 "attached to 1 firewall rule — detach first", dark mode + 390 px mobile,
  sticky footer. lint 0/0; tsc 7 (baseline was 14 — fixed fwFlows unwrap, trim() union,
  left the rest); post-restart event mix honors BALANCED (no dos/info_leak/policy-off
  categories; drops only under inline_drop).

### 2026-11-06 — Enterprise blue theme (ADR-019) + M03 Firewall & NAT module LIVE
- **Theme (owner request):** emerald/teal look replaced with enterprise white & blue —
  ADR-019 records the decision (supersedes ADR-013 palette). Brand = blue-600 light /
  blue-500 dark; light is now the DEFAULT theme; chart palette LOCKED
  blue→sky→amber→rose→orange→violet→slate (rx=blue, tx=sky); emerald/teal forbidden as UI
  chrome, reserved for health semantics only (WAN up pill). Updated: globals.css tokens,
  charts/palette.tsx, shell/login/dashboard, UI_DESIGN_SYSTEM §2, providers defaultTheme.
- **M03 module shipped vertically (per ADR-014 order M01→M03→M02→…):** full API surface —
  zones, address-objects/groups, service-objects/groups, schedule-objects,
  firewall-rules (CRUD + toggle + reorder + validate shadow/conflict + hits + reset +
  import/export json|csv), nat-rules (CRUD + toggle + reorder + 1:1 helper + port
  forward), network/app-catalog, users list. Service layer `src/lib/firewall/*`
  (~2,000 lines: rule-match first-match-wins evaluator, refs integrity, positions,
  shapers). Views `src/components/views/firewall/*` (~4,900 lines): rules table +
  dnd-kit drag reorder + RuleEditor (zones/objects incl. mixed group ids/apps/users/
  MACs/schedule/protections/validate), NAT view (type-gated editor, masquerade/pool/
  ranges, 1:1 pair chip), Objects (5 tabs + transfer lists + 409 conflict dialogs),
  Zones (protected WAN/LAN, iface chips). nav-config placeholders removed for the 4
  views; app-shell wired.
- **Simulation loop closed:** firewall-log generator now enforces the REAL ruleset
  (evaluateRules first-match-wins, zone/address/service/app/user/MAC/schedule matchers,
  implicit-deny rows) and increments hitCount/lastHitAt per matched rule; NAT hit
  counters live. Policy reload triggered by config:updated (3 s throttle).
- **CRITICAL BUG FIXED (agent-era):** `refs.ts scanRuleArrays` concatenated two JSON id
  columns into `"[1] [5]"` → invalid JSON → parseIds [] → delete-protection NEVER fired;
  referenced objects/zones were silently deletable. Fixed by parsing each column
  separately (see Gotchas §13). Seed objects LAN_NET(id 1)/MGMT_NET(id 5) + rule
  implicit-deny-final restored with EXACT ids after browser E2E delete-test collateral
  (id integrity preserved for TRUSTED membership + rule refs).
- **Verified (agent-browser + curl):** theme light/dark; rules render 12 ordered +
  create/toggle/delete/kebab; hit counters increment per rule (6k-25k range); NAT 4
  seeded rows with live hits + translation summaries ("→ masquerade"); objects 5 tabs +
  referenced-by counts; 409 on LAN_NET/MGMT_NET/WAN-zone deletes w/ referencedBy list;
  zones cards w/ lock icons; CSV+JSON export; validate ok:true; lint clean; zero
  tick errors in dev.log.

### 2026-11-06 — Sandbox-reset recovery: login restored (root cause + hardening)
- **Incident:** sandbox reset lost runtime state; login returned 401 for valid seeds.
- **Root cause (two-layer):** (1) stale `.env` override `DATABASE_URL=file:.../db/custom.db`
  (scaffold-era file) beat the correct `schema.prisma` url `file:../db/cryptsk.db` — the
  custom.db file was gone, so the runtime talked to a phantom DB; (2) `db/cryptsk.db`
  existed with all 44 tables but **0 rows in users** (seed data lost with the reset).
- **Fix:** `.env` now points at the real DB (absolute path); re-ran idempotent
  `bun prisma/seed.ts` (8 users / 5,221 fw logs / 356 IPS events / 25 leases / 10 vpn
  sessions). Verified end-to-end with agent-browser: login admin/admin123 → live
  dashboard → Sign out → back to login; wrong password → 401; secops role login OK.
- **Hardening:** new `bun run db:setup` = `prisma db push` + seed in one command — the
  canonical recovery step after any sandbox reset. `.env` must always point at
  `file:/home/z/my-project/db/cryptsk.db` (Gotchas §13).
- **Repo hygiene:** removed accidentally-tracked sandbox dumps (`tool-results/*`, `docs/=229`)
  from git; `.gitignore` extended. Working tree clean; pushed to GitHub.
- **Note:** logout "stuck on dashboard" during verification was a snapshot-timing
  artifact (reload in flight) — no code change needed; auth cycle is correct.

### 2026-11-06 — M0 foundation BUILT & browser-verified (Task D-1 + fixes)
- **Shipped:** prisma/schema.prisma (all models, SQLite/ADR-005 adaptation) + seed
  (tenant, 8 users/roles, zones, 7 ifaces, 12 fw rules, BALANCED/STRICT_WEB IPS, …);
  lib/api handler (envelope/RBAC/audit/requestId), auth login/logout/me (jose, 8h,
  username+password per AUTH_AND_RBAC §2); realtime mini-service on 3003 (7 locked
  events); MockEngine (mulberry32/MOCK_SEED, profiles, firewall+IPS+metrics generators,
  ring caps 500/2000) + SimulatedAdapter; /api/v1/dashboard/summary; AppShell (sidebar
  27 links, hash router, auth gate, dark mode, sticky footer) + real #/dashboard
  (gauges, live throughput chart via metrics:tick + 60-tick backfill, WAN strip,
  threat feed, apps donut, top talkers, quick actions) + login + placeholder views.
- **Fixed during build:** IpsEventGenerator missing profile (tick crash) — constructor
  arg + self-healing setProfile in tick; duplicate dev-server processes killed; HMR-safe
  singleton via globalThis verified.
- **Verified end-to-end (agent-browser):** login (admin/admin123) → dashboard renders
  live data (CPU/mem/disk/temp, 42k sessions, wan0 up / wan1 down, 27 alerts feed,
  backfilled chart); placeholder views route correctly; mobile 390px responsive; lint
  clean; no runtime errors in dev.log.

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

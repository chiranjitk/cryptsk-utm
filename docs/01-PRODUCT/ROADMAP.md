# Roadmap — Cryptsk UTM/NGFW (Phases + Console Build Order)

> TL;DR: Product delivery is 4 phases over 24 months (spec). The console in this repo is
> built in 12 milestones (M0 + M01–M11) implementing Phase 1 against the simulated
> appliance first. This file is the living tracker: the status table in §4 is updated in
> the same task that changes the status (same-task rule, `docs/README.md` §4).

Related: [PRODUCT_OVERVIEW.md](PRODUCT_OVERVIEW.md) ·
[../00-PROJECT-MEMORY/DECISIONS.md](../00-PROJECT-MEMORY/DECISIONS.md) (ADR-014 build
order) · [../00-PROJECT-MEMORY/PROJECT_MEMORY.md](../00-PROJECT-MEMORY/PROJECT_MEMORY.md)
§2 (status snapshot)

---

## 1. Phase Overview (Product, from Spec)

| Phase | Months | Theme | Headline deliverables |
|---|---|---|---|
| Phase 1 — MVP | 1–6 | "Deployable UTM with core firewall, VPN, IPS, DNS security" | Dashboard, interfaces/VLAN/bond, static routing + multi-WAN, zone firewall + objects + NAT, Suricata IPS, WireGuard/IPSec/OpenVPN, Unbound DNS security, Kea DHCP, identity + RADIUS + captive portal, QoS, logging, HA (active/passive), system + backup, REST API + API keys |
| Phase 2 — Growth | 7–12 | "Enterprise features" | SSL/TLS inspection (Squid + Step-CA), enhanced app control, URL filtering (aggregated lists), WAF (Coraza + OWASP CRS), SD-WAN basics (SLA probes, path selection), BGP/OSPF (FRR), IPv6 dual-stack, email security (Postfix + Rspamd), advanced identity (SAML/OIDC, RADIUS CoA/VLAN), NAC basics (802.1X/MAB), threat intelligence feeds + IOC auto-block, PKI (Step-CA), enhanced logging (full-text search, CEF/LEEF, compliance templates) |
| Phase 3 — Intelligence | 13–18 | "AI/ML capabilities, ATP sandbox, advanced threat detection" | 3 AI models — DGA detection, network anomaly (UEBA-lite), encrypted traffic classification (ONNX Runtime); ATP sandbox (Cuckoo + YARA + Suricata file extraction); DLP (regex/keyword, file type control); DNS tunneling detection; basic incident response (workflow, timeline, manual block/quarantine); IoT device management (fingerprinting, quarantine) |
| Phase 4 — Platform | 18–24+ | "Scale, multi-site, SASE basics, advanced automation" | Multi-site central manager (policy push, log aggregation, templates), SASE basics (cloud nodes, WireGuard mesh), CASB basics (SaaS visibility, shadow IT), ZTNA basics (identity-based access, posture checks), advanced AI models (C2 beaconing, lateral movement, phishing NLP), SOAR integration (webhooks, playbooks) |

Phase 4 explicit framing from the spec: full SASE is a multi-year, multi-million-dollar
effort; this is a deliberate starting point, not a Zscaler replacement.

### 1.1 Phase 2 Workstreams (detail)

| Spec area | Scope | Key packages |
|---|---|---|
| 2.1 SSL/TLS inspection | MITM proxy, TLS 1.2/1.3, selective bypass, cert-pinning/HSTS handling, root CA export | Squid, Step-CA |
| 2.2 Enhanced app control | Block/allow by nDPI app, per-app bandwidth, unknown-app policy, SaaS detection (partial) | nDPI + nftables/tc |
| 2.3 Web security (URL filtering) | Explicit + transparent proxy, category blocking via aggregated free lists, safe-search enforcement, file-type control | Squid + blocklists |
| 2.4 WAF | Reverse proxy, OWASP CRS, anomaly scoring, FP exclusions, learning mode, per-vhost policies | Coraza + Caddy |
| 2.5 SD-WAN basics | SLA monitoring (latency/jitter/loss), app-aware path selection, hub-spoke overlay, brownout handling | Custom Go + WireGuard/FRR |
| 2.6 Dynamic routing | BGP (v4/v6), OSPFv2/v3, route maps, prefix lists, BFD, graceful restart | FRR |
| 2.7 IPv6 dual-stack | Firewall/NAT66 (NPTv6), routing, DHCPv6, SLAAC, VPN/QoS over v6 | nftables, Kea, radvd |
| 2.8 Email security | SMTP proxy, anti-spam/phishing, DKIM/SPF/DMARC, attachment scanning | Postfix + Rspamd + ClamAV |
| 2.9 Advanced identity | SAML 2.0, OIDC, RADIUS CoA + dynamic VLAN, Kerberos/NTLM proxy auth, user activity timeline | FreeRADIUS + custom |
| 2.10 NAC basics | 802.1X, MAB, dynamic VLAN, device profiling, rogue detection, BYOD onboarding | FreeRADIUS + custom |
| 2.11 Threat intelligence | Feed ingestion (Abuse.ch/OTX/Spamhaus), IOC management, reputation scoring, auto-block, STIX/TAXII | Custom Go |
| 2.12 PKI | Internal CA (root + subordinate), lifecycle, OCSP/CRL, auto-renew, export | Step-CA |
| 2.13 Enhanced logging | Full-text search, CEF/LEEF, compliance templates (PCI/HIPAA/GDPR), anonymization, scheduled reports | ClickHouse/Meilisearch + Go |

### 1.2 Phase 3 Workstreams (detail)

| Spec area | Scope | Feasibility note (spec) |
|---|---|---|
| 3.1 AI engine (3 models) | DGA domain detection (public datasets); network anomaly UEBA-lite (own baseline, 4–8 weeks data); encrypted traffic classification (JA3/JA4 + flow features) | High / Medium / Medium |
| 3.2 ATP sandbox | Cuckoo detonation + YARA scanning + Suricata file extraction + quarantine + reports | ~50–60% of commercial quality; weight behavioral detection instead |
| 3.3 DLP | Regex patterns (cards/SSN/IBAN), keyword matching, file-type control, protocol-aware scanning, incident workflow | No EDM/IDM — pattern-based only |
| 3.4 DNS tunneling detection | Entropy analysis, volume/frequency analysis, DGA model correlation | Custom Go + Redis |
| 3.5 Incident response | Incident creation from alerts, workflow (new → investigating → resolved), timeline, manual block/quarantine, assignment | Custom Go + PostgreSQL |
| 3.6 IoT management | Device fingerprinting (OUI/DHCP/nDPI), inventory, rogue detection, quarantine, risk scoring | Custom |

AI infrastructure: Python/scikit-learn feature extraction, PyTorch offline training,
ONNX Runtime inference served by Go, model registry in PostgreSQL, confidence thresholds,
human-in-the-loop FP/FN feedback, drift monitoring. Eight further models (C2 beaconing,
lateral movement, phishing NLP, IPS FP reduction, DLP NLP, config anomaly, …) wait for
Phase 4 / deployed-base data.

### 1.3 Phase 4 Workstreams (detail)

| Spec area | Scope |
|---|---|
| 4.1 Multi-site manager | Central dashboard, central policy push, log aggregation (ClickHouse), firmware management, site templates, per-site limits |
| 4.2 SASE basics | Cloud firewall nodes (same codebase in cloud VM), central controller, WireGuard mesh, identity-aware routing |
| 4.3 CASB basics | SaaS visibility via nDPI, shadow-IT detection, API controls for top 5–10 SaaS (Google, Microsoft, Salesforce, Dropbox, Slack) |
| 4.4 ZTNA basics | Identity-based access (user-to-resource), basic device posture checks, continuous re-validation |
| 4.5 Advanced AI | C2 beaconing, lateral movement (graph), phishing NLP, IPS FP reduction, DLP NLP, config anomaly |
| 4.6 SOAR integration | Webhook triggers, REST integration with Cortex XSOAR / Splunk SOAR, basic response playbooks |

### 1.4 Phase 1 Exit Criteria (product) — (Architect note: measurable gate, derived from spec §1.1–1.15; the spec defines no explicit gate, so this is the 2C review's proposal)

Phase 1 is DONE when **all** of the following hold:

1. Every spec §1.1–1.15 feature row marked ✅ Ready or 🟡 Custom engineering ships (the 🟡 subset is the appliance's own engineering work list — not silently dropped; console-level deferrals are tracked in §5).
2. A default-denial zone-based firewall + NAT is enforced at boot with no manual CLI.
3. Suricata inline blocking demonstrably stops a test attack (ET rule hit → drop → alert in the dashboard).
4. WireGuard + IKEv2 + OpenVPN tunnels pass traffic per their status views; client bundles import into real clients.
5. Multi-WAN failover completes on primary-link drop without manual intervention (probe-driven; independent of VRRP).
6. HA active/passive failover via Keepalived succeeds within the documented hold-down; conntrackd preserves stateful sessions.
7. RBAC (8 roles) + audit trail verified: each role's allow/deny matrix matches AUTH_AND_RBAC §4.
8. First-time-setup wizard produces a working LAN/WAN configuration from factory defaults.
9. Console build: M0 + all 11 module milestones DONE per §4 tracker, with contracts locked.

## 2. Phase 1 Feature Areas Mapped to Console Modules

The spec defines 15 Phase 1 feature areas (spec §1.1–1.15). The console groups them
into 11 module docs (A: `../06-MODULES/M0x-*.md`):

| Spec area | One-line scope | Module doc |
|---|---|---|
| 1.1 Dashboard | Live traffic, sessions, top apps/talkers, health, alert summary, tunnel/WAN status, quick actions | M01-DASHBOARD |
| 1.2 Network — Interfaces | Physical/VLAN/bridge/bond/GRE, WAN modes (static/DHCP/PPPoE), MTU/MSS, LLDP, diagnostics | M02-NETWORK |
| 1.3 Network — Routing | Static/policy/floating/blackhole routes, multi-WAN failover + load balance, health probes | M02-NETWORK |
| 1.4 Firewall (NGFW) | Zones, address/service/schedule objects, L3/L4 + app/user/FQDN/GeoIP rules, hit counters, validation | M03-FIREWALL |
| 1.5 NAT | SNAT/masquerade, DNAT/port-forward, 1:1, hairpin, exemption (no-NAT) | M03-FIREWALL |
| 1.6 IPS / IDS | Suricata inline (nftables NFQUEUE; spec's AF_PACKET refined — see ADR-003), ET free rules, policy profiles, exceptions, thresholds, suppression | M04-IPS |
| 1.7 VPN | WireGuard site-to-site + remote access, IPSec IKEv2, OpenVPN, split tunnel, DPD, client bundles | M05-VPN |
| 1.8 DNS Security | Unbound resolver, RPZ block/allow lists, custom records, conditional forwarding, sinkhole, RRL, DoT | M06-DNS-DHCP |
| 1.9 DHCP | Kea DHCPv4(/v6 basic), pools, MAC reservations, leases, relay, option sets | M06-DNS-DHCP |
| 1.10 Identity & Access | Local users/groups, AD/LDAP via RADIUS, captive portal (clickthrough/credentials/voucher), password/lockout policy, TOTP field | M07-IDENTITY |
| 1.11 QoS | HTB + FQ_CoDel, per-interface/user/app limits, DSCP marking + queue mapping, templates (voip/video/gaming/bulk) | M08-QOS |
| 1.12 Logging & Reporting | Central log store, search/filter, live tail (WebSocket), syslog/NetFlow export, retention, basic reports | M09-LOGGING |
| 1.13 High Availability | Keepalived VRRP active/passive, VIP, config sync, conntrackd session sync, health dashboard | M10-SYSTEM |
| 1.14 System | Backup/restore, firmware upgrade/rollback, config versioning + diff, RBAC, audit, NTP, SNMP, wizard | M10-SYSTEM |
| 1.15 API | Versioned REST `/api/v1`, OpenAPI docs, API keys, rate limiting, pagination, batch, audit, webhooks (spec Phase 1, custom engineering — console ships stubs, see divergence note below), WS push | M11-API-PLATFORM |

Mapping note: spec areas 1.2/1.3 both live in M02; 1.4/1.5 in M03; 1.8/1.9 in M06;
1.13/1.14 in M10. Console-only groupings (M09 live tail, M11 keys/webhooks) are splits
of spec areas, not extra scope.

> **Spec divergence (report scheduling):** spec §1.12 lists scheduled reports
> (daily/weekly/monthly, PDF/HTML via wkhtmltopdf) as Phase 1. The build contract
> (M09) defers report *scheduling* and PDF rendering to Phase 2; Phase 1 console ships
> basic traffic and threat reports on-screen with a print-friendly stylesheet (browser
> print as the Phase-1 substitute). Tracked in §5 below.
>
> **Spec divergence (webhook delivery):** spec §1.15 includes webhook support as a
> Phase 1 feature (🟡 custom engineering). The console build (M11) ships the webhook
> surface as stubs (registration/CRUD + payload shape) in Phase 1 and defers real
> delivery/dispatch to the appliance-side implementation — a build-level decision,
> tracked in §5. The spec's phase assignment is unchanged: webhooks are NOT a Phase 2
> product feature.

## 3. Console Build Order (This Repository)

The console implements Phase 1 in 12 milestones. Ordering (ADR-014) is value-per-effort,
frontend-first (sandbox rule 11): prove the shell + adapter + realtime contracts early,
then ship the modules an admin touches most.

```mermaid
flowchart LR
    M0["M0 Bootstrap"] --> M01["M01 Dashboard"] --> M03["M03 Firewall"] --> M02["M02 Network"]
    M02 --> M04["M04 IPS"] --> M05["M05 VPN"] --> M06["M06 DNS+DHCP"]
    M06 --> M09["M09 Logging"] --> M07["M07 Identity"] --> M08["M08 QoS"]
    M08 --> M10["M10 System+HA"] --> M11["M11 API Platform"]
```

Why this order:

| Rationale | Detail |
|---|---|
| Contracts prove early | M0 establishes the four contracts everything else depends on: schema (SCHEMA.md), shell + hash views (ADR-006), SystemAdapter (ADR-004), socket.io realtime (ADR-008). Every later module is then "just" another vertical slice |
| Value-first | Dashboard after M0 means a demoable product exists after two milestones; firewall is the #1 daily-use surface, so it precedes network plumbing |
| Dependencies flow downhill | Firewall needs objects/zones (its own scope) but not VPN; IPS events feed logging; identity is mostly CRUD; QoS is isolated; System/HA and API keys are administrative polish |
| Riskiest simulations early | Realtime (socket.io through the gateway) and MockEngine determinism are proven in M0/M01, not discovered late |
| Why not interface-first | Network plumbing (M02) is high-effort, low-demo-value compared to firewall; interfaces also depend on zones/objects existing for roles and zone assignment |

Per-milestone scope and Definition of Done:

| Step | Scope | Definition of Done (every step) |
|---|---|---|
| M0 Bootstrap | Replace `prisma/schema.prisma` with the definitive schema (SCHEMA.md §3) → `bun run db:push`; seed (`bunx prisma db seed`); app shell (layout, sidebar, topbar, hash router, view registry, AuthGate); auth (login/logout/me, jose JWT, bcrypt, cookie); realtime-service skeleton (port 3003, `bun --hot`, listening line); `SimulatedAdapter` + `MockEngine` tick loop + seed profiles; add `socket.io`, `socket.io-client`, `jose`, `bcryptjs` | Lint clean; dev.log free of new errors; login works, dashboard renders with simulated `metrics:tick` via `io("/?XTransformPort=3003")`; seed idempotent (run twice, no duplicates); session log appended |
| M01 Dashboard | Summary endpoint; health cards; throughput area chart; top apps/talkers; alert summary; WAN/VPN status widgets; quick actions | Views functional against SimulatedAdapter; live tiles update per 2 s tick; DoD below |
| M03 Firewall | Zones, address/service/schedule objects + groups, firewall rules CRUD + reorder + toggle + validate, NAT rules; rule editor + object pickers | Shadow-rule validation returns findings; NAT rule types all four; generator simulation bumps `config_versions` |
| M02 Network | Interfaces CRUD (non-physical), interface stats, static routes, WAN policies + probe states | Multi-WAN failover state machine visible in UI (up/degraded/down) |
| M04 IPS | Policies + category toggles, ET category list, events list with filters, suppress action, exceptions/thresholds editors | Inline-drop policy changes correlate with firewall_logs drops (simulation contract, SIMULATION_LAYER §6) |
| M05 VPN | WireGuard/IPSec/OpenVPN configs, tunnel status, sessions, disconnect, client bundle download | Client bundle renders valid wg `.conf` / `.ovpn` text; tunnel state machine per SIMULATION_LAYER §5 |
| M06 DNS+DHCP | Resolver settings, DNS policies (categories, custom lists, sinkhole), DNS records, query log; DHCP subnets, reservations, leases | Enabling a DNS block category immediately changes generated query-log behavior |
| M09 Logging | Firewall/IPS/audit log tables (server-side pagination), live tail (`logs:tail`), log stats charts, basic reports | Pagination over 5k+ seeded rows stays smooth; live tail pauses/resumes |
| M07 Identity | Users, user groups, auth settings (password policy, lockout), RADIUS profiles, captive portal profile + vouchers, identity sessions | Lockout policy change affects simulated login behavior; portal modes all three selectable |
| M08 QoS | Policies (templates, bandwidth), rules (priority, guarantees, caps, DSCP), per-WAN shaper | Metrics series flatten at a QoS cap (simulation contract, SIMULATION_LAYER §3) |
| M10 System+HA | System status, settings, backups (create/restore), config versions + diff, notifications, HA status/config | Backup/restore round-trips a JSON snapshot; config diff renders between two versions |
| M11 API Platform | API keys CRUD + scoping + revocation, request logging polish, rate limiting, OpenAPI doc generation, webhooks stub | API key auth works end-to-end (`Bearer ck_...`); revocation is immediate |

Universal Definition of Done for every milestone (in addition to the step-specifics):

1. `bun run lint` passes (zero errors, zero new warnings).
2. `dev.log` contains no new errors after exercising the flows.
3. All new views are functional in the browser against the SimulatedAdapter, per
   `AGENTS.md` verification rules (single route `/`, hash deep links work, refresh-safe).
4. Docs updated in the same task (README §4 same-task rule): module doc status, API docs
   if endpoints changed, SCHEMA.md if tables changed, and this file's §4 tracker.
5. Session log appended to PROJECT_MEMORY §15 (newest on top, dated).

### 3.1 Milestone Dependencies

| Milestone | Hard prerequisites | Soft prerequisites (nice to have) |
|---|---|---|
| M0 | none (contracts in PROJECT_MEMORY are the spec) | — |
| M01 | M0 (shell, auth, realtime, MockEngine tick) | — |
| M03 | M0 (adapter, schema objects/zones/rules tables) | M01 (layout patterns) |
| M02 | M0 | M03 (zones for interface-role assignment UX) |
| M04 | M0, M03 (rules to correlate drops with) | M01 (alert widgets) |
| M05 | M0 | M02 (interfaces for wg0), M07 later for per-user sessions |
| M06 | M0 | M02 (lan subnets for DHCP defaults) |
| M09 | M0 (seeded log volumes), M04 (events) | M03 (rule names in logs) |
| M07 | M0 | M05 (vpn session identity), M03 (user-based rules) |
| M08 | M0 | M02 (interfaces), M01 (chart wrappers) |
| M10 | M0 | all modules (backups cover their tables; versions need their sections) |
| M11 | M0 (auth) | M03–M10 (endpoints to document/key-scope) |

## 4. Status Tracker (Living)

Update rule: when a task changes a milestone's status, edit this table **in the same
task** (same-task rule, `docs/README.md` §4) and mirror the one-line state in
PROJECT_MEMORY §2. Docs column points at the module spec. Never mark DONE without the
DoD checklist in §3. Allowed status values: `NOT STARTED`, `IN PROGRESS` (add a note
naming the current sub-step), `DONE`, `BLOCKED` (note the blocker + ADR/link). Status
column changes without a matching session-log entry are considered doc drift.

| Milestone | Status | Docs | Notes |
|---|---|---|---|
| Docs suite (memory, architecture, database, API, frontend, modules, security, operations) | DONE | `docs/README.md` + tree | Authored before any code; contracts locked in PROJECT_MEMORY |
| M0 Bootstrap | NOT STARTED | `../00-PROJECT-MEMORY/PROJECT_MEMORY.md` §5/§10, `../03-DATABASE/SCHEMA.md`, `../08-OPERATIONS/DEVELOPMENT_GUIDE.md` | Current `prisma/schema.prisma` is scaffold placeholder; deps `socket.io`/`jose`/`bcryptjs` not yet installed |
| M01 Dashboard | NOT STARTED | `../06-MODULES/M01-DASHBOARD.md` | Needs M0 |
| M02 Network | NOT STARTED | `../06-MODULES/M02-NETWORK.md` | Built after M03 (ADR-014) |
| M03 Firewall | NOT STARTED | `../06-MODULES/M03-FIREWALL.md` | Largest module; objects + rules + NAT |
| M04 IPS | NOT STARTED | `../06-MODULES/M04-IPS.md` | Depends on M03 objects for correlated drops |
| M05 VPN | NOT STARTED | `../06-MODULES/M05-VPN.md` | WireGuard first, then IPSec, then OpenVPN |
| M06 DNS+DHCP | NOT STARTED | `../06-MODULES/M06-DNS-DHCP.md` | One module, two services |
| M07 Identity | NOT STARTED | `../06-MODULES/M07-IDENTITY.md` | Captive portal + vouchers simulated |
| M08 QoS | NOT STARTED | `../06-MODULES/M08-QOS.md` | Simulation honors caps in metrics |
| M09 Logging | NOT STARTED | `../06-MODULES/M09-LOGGING.md` | Built before identity so audit views exist early |
| M10 System+HA | NOT STARTED | `../06-MODULES/M10-SYSTEM.md` | Backups, versions, notifications, HA |
| M11 API Platform | NOT STARTED | `../06-MODULES/M11-API-PLATFORM.md` | Keys, rate limits, OpenAPI, webhooks stub |

Product phases (appliance-side work beyond this repo) are tracked outside this tracker;
this table tracks the console only.

## 5. Deferred / Cut List (from Spec)

One-liners so nobody re-adds these without a new decision:

| Item | Status | One-liner |
|---|---|---|
| RIP / RIPng | Cut (spec) | Dead protocol; OSPF/BFD (Phase 2) covers the need |
| IS-IS | Cut (spec) | ISP/carrier protocol, no small-enterprise use case |
| CGNAT / deterministic NAT | Cut (spec) | ISP feature, not firewall feature |
| Browser isolation (RBI) | Cut (spec) | Not feasible with open source; documented in PRODUCT_OVERVIEW §4 |
| Endpoint agent | Cut (spec) | Separate product; partner with existing endpoint solutions |
| Snap packages | Cut (spec) | Debian 13 chosen over Ubuntu partly to avoid Snap on the appliance |
| GraphQL | Cut (spec) | Overkill next to the versioned REST API + WebSocket |
| IKEv1 | Cut (spec) | Insecure legacy; IKEv2 only |
| SSTP VPN | Cut (spec) | Niche Microsoft-only protocol |
| Java Spring Boot API | Superseded (spec) | Go single binary (ADR-002) |
| Apache Kafka | Superseded (spec) | Redis Streams (ADR-010) |
| TensorFlow + PyTorch at inference | Superseded (spec) | ONNX Runtime inference, PyTorch offline training only |
| Netdata | Superseded (spec) | Prometheus + node_exporter + Grafana |
| 10–100 Gbps throughput target | Rescoped (spec) | 1–10 Gbps realistic for small enterprise |
| Secure Boot / LUKS | Cut / Phase 2 (spec) | Secure Boot is hardware/firmware level; LUKS deferred to Phase 2 |
| VRF, VXLAN, MACVLAN, MACsec, QinQ | Phase 2 / dropped (spec) | VRF+VXLAN Phase 2; MACsec/QinQ/ERPS dropped (ISP/hardware) |
| PPPoE server, cellular/5G, satellite | Phase 2 / dropped (spec) | PPPoE client ships Phase 1; server/wan-media later |
| BGP/OSPF, DNSSEC, DHCP failover, SSO/SAML/OIDC (identity), RADIUS CoA/VLAN | Phase 2 (spec) | All planned Phase 2 — listed here because the original spec marked some Phase 1 |
| Twice-NAT, NAT44/66/NPTv6, per-rule NAT timeouts | Phase 2 (spec) | With IPv6 work in Phase 2 |
| CAKE qdisc, ingress shaping, hierarchical QoS | Phase 2 (spec) | HTB + FQ_CoDel Phase 1 |
| Full-text log search, compliance reports, log anonymization, CEF/LEEF | Phase 2 (spec) | Needs ClickHouse/Meilisearch decision in Phase 2 |
| Scheduled reports + PDF/HTML rendering | Phase 2 (build decision) | Spec divergence — see note in §2 |
| Active/Active HA, IPS state sync | Phase 3 (spec) | Active/passive Phase 1 is sufficient |
| API sandbox console, idempotency keys | Phase 2 (spec) | Overkill for the Phase 1 console |
| Webhook real delivery/dispatch | Console Phase 2 (build decision) | Spec Phase 1 keeps webhooks (custom engineering); M11 ships the stub surface (CRUD + payload shape) — see divergence note in §2 |
| SOAR playbooks, threat hunting UI | Phase 4 (spec) | Webhook/API integration path defined in Phase 4 |
| SASE (full), CASB (full) | Phase 4 basics only (spec) | Multi-year effort explicitly out of early scope |
| JA3/JA4 TLS fingerprint filtering | Phase 2 (spec) | Needs SSL visibility groundwork; encrypted-traffic AI (Phase 3) builds on it |
| PCAP-on-match logging, rule dry-run/simulation | Phase 2 (spec) | Hit counters + log correlation cover Phase 1 needs |
| Blackhole/mirror rule actions | Phase 2 (spec) | Allow/deny/drop/reject covers Phase 1 semantics |
| L2TP over IPSec, VPN load balancing | Phase 2 (spec) | IKEv2 remote access + OpenVPN cover remote-user needs |
| VPN post-connect scripts/hooks | Phase 2 (spec) | Client bundles + session limits cover Phase 1 provisioning |
| Bond rate/fallback tuning | Phase 2 (spec) | Bond/bridge create + status ships Phase 1; fine-tuning knobs later |
| Console Phase 1 UI deferrals (spec-Phase-1 items the console does not manage yet): LLDP neighbor view, IGMP snooping, MAC table, SPAN/port-mirroring, L2/L3 mode toggle, policy-based routing, BFD route monitoring, IPS auto-update scheduler UI, IPS one-click preset profiles (seeded presets serve instead), VPN user groups, per-user/per-group session-limit & timeout UIs | Console Phase 2 (build decision, not a spec phase change) | Console Phase 1 covers the core admin surface first (M02/M04/M05 §1); the appliance-side spec scope is unchanged and these remain spec Phase 1 features the appliance must expose (UI, CLI, or config file) |

Nothing in this list is "someday maybe": each row was considered against the spec and
either cut with a reason or assigned a phase. Re-introducing a cut item requires a new
ADR and updates to this file and the affected module doc the same day.

Additions relative to spec (build-level refinements, not scope creep):

| Addition | Where | Why |
|---|---|---|
| `interfaces.role` enum (wan/lan/dmz/vpn/mgmt/unused) | SCHEMA.md, PROJECT_MEMORY §6 | Simulation profiles and UX need interface roles; spec's `interfaces.config` JSON alone is too loose |
| `wan_policies` as a dedicated table | SCHEMA.md | Multi-WAN policies + probe state machine need first-class rows (spec folded this into routing) |
| `identity_sessions`, `radius_profiles`, `user_groups` as concrete tables | SCHEMA.md | Spec listed identity features without concrete tables; console needs them for M07 |
| `api_keys` with prefix/sha256-hash split | SCHEMA.md | Spec listed api_keys table only; auth design (AUTH_AND_RBAC §3) defines the concrete shape |
| JSON-string adaptation of all PG arrays/JSONB | ADR-005 | SQLite portability; PostgreSQL-compatible in shape |

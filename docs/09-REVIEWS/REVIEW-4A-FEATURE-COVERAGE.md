# REVIEW-4A — Phase-1 Feature Coverage Audit (Zero-Feature-Lane)

> **Attestation up front:** the master spec's Phase-1 inventory (SPEC.md §1.1–§1.15) contains
> **188 features**. After the REVIEW-4A lane (agent `4-a`) plus this continuation pass
> (agent `4-a-CONT`), **all 188 are covered by the docs — zero uncovered, zero deferrals.**
> The formerly console-deferred features are restored per the owner zero-feature-loss ruling
> (2026-11-05, REVIEW-4A; ROADMAP §5 "RESTORED" row by REVIEW-4B).

Related: [REVIEW-4B-PRODUCT-COVERAGE.md](./REVIEW-4B-PRODUCT-COVERAGE.md) (Phase 2–4 + product facts lane) ·
[../01-PRODUCT/ROADMAP.md](../01-PRODUCT/ROADMAP.md) §5 (RESTORED row) · [../docs/SPEC.md](../SPEC.md) (ground truth)

---

## (a) Method

1. **Ground truth:** read SPEC.md §1 (Phased Feature Roadmap, tables 1.1–1.15) and §7
   (SIMPLIFIED DATABASE SCHEMA — Core Tables "Phase 1" + the Phase-2+ block's "Phase 1"
   comment rows: captive-portal tables, ha_config, api_keys/webhooks, syslog/netflow
   targets, vpn_pools/groups) in full; enumerated every Phase-1 feature row (N = 188).
2. **Continuation context:** this lane was **completed by a continuation agent**
   (`4-a-CONT`) after agent `4-a` timed out. `4-a` had already edited (verified, not redone):
   M01–M09 (each carries `REVIEW-4A` restoration markers), SCHEMA.md (§3 "Phase-1 restored
   models" block + §4 JSON shapes), ER_DIAGRAM.md, DATA_LIFECYCLE.md, ENDPOINTS.md (§3/§6/§7/
   §8/§11/§13/§14 rows), API_STANDARDS.md (§2 capability note), AUTH_AND_RBAC.md (§4/§5 rows),
   and PROJECT_MEMORY §6/§7/§8 (enums, `PHASE-1 RESTORED SURFACE` API block, view map).
3. **Completed by `4-a-CONT`** (this pass), against the same inventory and the conventions
   `4-a` established (`IN — … (restored REVIEW-4A)` scope rows, additive endpoints, locked
   enums, 7-event realtime set preserved):
   - `06-MODULES/M10-SYSTEM.md` — rewritten scope; HA `sessionSync`/`trackedInterfaces`
     surfaces; firmware, NTP, SNMP, hardening, SSH keys, setup wizard, policy templates,
     resource alerts, health checks, CLI-via-SSH+API, licensing/community note; Webhooks tab.
   - `06-MODULES/M11-API-PLATFORM.md` — webhooks (registration + simulated delivery, ROADMAP
     stub nuance kept), `GET /api/v1/openapi.json`, batch-operations mapping, machine-facing
     change-notification position (no new socket event).
   - `05-FRONTEND/PAGE_MAP.md` — 29-view registry (+#/setup), all new tabs, per-view
     blueprints synced to the module §4 lists.
   - `05-FRONTEND/STATE_AND_DATA_FLOW.md` — `config:updated` invalidation rows for every new
     resource; derived-view (LLDP/MAC) polling note.
   - `02-ARCHITECTURE/SIMULATION_LAYER.md` — `switching` generator contract; §3 behavior rows
     (PBR/BFD, relay/DHCPv6, VPN groups, presets/auto-update/TI, HA chips, directory tests,
     firmware/service-restart/thresholds); §5 BFD state; §6 generator table rows; §8 seeds.
   - `02-ARCHITECTURE/DATA_PLANE.md` — egress-selection bullet (PBR fwmark → policy tables,
     BFD via FRR `bfdd`, dhcrelay note); per-user/per-app hard limits restored in §5.
   - `02-ARCHITECTURE/CONTROL_PLANE.md` — generator contract additions (routing/dhcp/system
     rendering), FRR row (bfdd), report-scheduling row, firmware sandbox analogs.
   - `02-ARCHITECTURE/ARCHITECTURE.md` — SystemServices box (dhcrelay, bfdd, lldpd,
     conntrackd). Diagram-level only.
   - Drift fixes in previously-edited files: M01 §1 (restart no longer "stub"), M02 §6
     (invalidation prefixes), M10 SystemSetting category list aligned to SCHEMA.
4. **Consistency sweep:** module §3 API tables ↔ ENDPOINTS.md ↔ PROJECT_MEMORY §7.2 (paths,
   role floors, audit flags); view names ↔ PROJECT_MEMORY §8; enums ↔ §6; envelope/pagination/
   RBAC floors unchanged; new tables all carry `tenantId @default(1)` + audit + version
   snapshots via the shared handler; no new realtime event introduced anywhere (7-event set
   intact); `UI_DESIGN_SYSTEM.md` needed **no edits** — no new shared primitives were required
   (wizard/diff/masked-secret compose existing primitives).

---

## (b) Phase-1 Coverage Matrix (188 features)

Legend — Status: **COVERED** (was already covered pre-4A) · **RESTORED-4A** (restored by
agent `4-a`) · **RESTORED-CONT** (restored/completed by `4-a-CONT`). "Fix applied" names the
agent when the row needed one; `—` otherwise. File refs: M01…M11 = `docs/06-MODULES/`,
SCHEMA = `03-DATABASE/SCHEMA.md`, EP = `04-API/ENDPOINTS.md`, PM = PROJECT_MEMORY §,
SL = SIMULATION_LAYER, DP = DATA_PLANE, CP = CONTROL_PLANE, PMAP = PAGE_MAP.

### §1.1 Dashboard (9)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 1 | 1.1 | Live traffic graph (throughput per interface) | COVERED | M01 §2/§4; `metrics:tick` + `/dashboard/summary` | — |
| 2 | 1.1 | Active sessions count | COVERED | M01 §2 (summary + `conntrackCount`) | — |
| 3 | 1.1 | Top 10 applications (nDPI) | COVERED | M01 §2/§4 (`topApps`) | — |
| 4 | 1.1 | Top 10 talkers (users/IPs) | COVERED | M01 §2/§4 (`topTalkers`) | — |
| 5 | 1.1 | System health (CPU/RAM/disk/temp) | COVERED | M01 gauges; M10 §4 health strip | — |
| 6 | 1.1 | Threat alert summary (last 24 h) | COVERED | M01 §4 threat feed | — |
| 7 | 1.1 | VPN tunnel status | COVERED | M01 §4 + `vpn:status` | — |
| 8 | 1.1 | WAN link status | COVERED | M01 WAN strip + `wan:status` | — |
| 9 | 1.1 | Quick actions (restart service, backup) | RESTORED-4A | M01 §4; `POST /system/services/{name}/restart`, `POST /system/backups` | 4-a: restart endpoint restored; CONT: "stub" wording removed (M01 §1, PMAP dashboard row) |

### §1.2 Network — Interfaces (16)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 10 | 1.2 | Physical interface management | COVERED | M02 §2/§4 | — |
| 11 | 1.2 | WAN (static / DHCP / PPPoE) | COVERED | M02 §2 (`wanType`, PPPoE shape) | — (PPPoE password fixed pre-4A, REVIEW-2C) |
| 12 | 1.2 | LAN interface | COVERED | M02 §4 | — |
| 13 | 1.2 | VLAN (802.1Q) | COVERED | M02 §4 | — |
| 14 | 1.2 | Bridge (L2) | COVERED | M02 §4 | — |
| 15 | 1.2 | Bond / LACP | COVERED | M02 §4 (bond modes) | — |
| 16 | 1.2 | MTU / MSS clamp per interface | COVERED | M02 §2/§5 | — |
| 17 | 1.2 | Interface L2/L3 mode toggle | RESTORED-4A | M02 §1/§2/§4 (`mode l2\|l3`); PM §6 | 4-a |
| 18 | 1.2 | Loopback interface | COVERED | M02 §1 (type selector; seeded) | — |
| 19 | 1.2 | GRE / IPIP tunnels | RESTORED-4A (IPIP) | M02 §1/§2 (`type ipip`); SCHEMA §4 | 4-a (GRE was covered) |
| 20 | 1.2 | LLDP neighbor discovery | RESTORED-4A | M02 §1/§4 (LLDP tab); `GET /network/lldp-neighbors`; SL §6 switching | 4-a |
| 21 | 1.2 | STP/RSTP on bridges | COVERED | M02 §2 (`stp`, `stpMode`) | — |
| 22 | 1.2 | IGMP snooping | RESTORED-4A | M02 §1/§5 (bridge `igmpSnooping`) | 4-a |
| 23 | 1.2 | MAC table management | RESTORED-4A | M02 §1/§4 (MAC tab); `GET /network/mac-table`; SCHEMA §6 derived view | 4-a |
| 24 | 1.2 | Port mirroring / SPAN | RESTORED-4A | M02 §1/§4 (Mirroring tab); `PortMirror` model; EP §3 | 4-a |
| 25 | 1.2 | Interface diagnostics (speed/errors/drops) | COVERED | M02 §4 stats dialog | — |

### §1.3 Network — Routing (9)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 26 | 1.3 | Static routes | COVERED | M02 §4 | — |
| 27 | 1.3 | Policy-based routing (source/dest) | RESTORED-4A | M02 §1/§4 (PbrRule + tab); `pbr-rules*` EP §3; DP §1 (fwmark), CP §2, SL §3/§6 | 4-a (schema+module); CONT (DP/CP/SL contracts, PMAP) |
| 28 | 1.3 | Default route management | COVERED | M02 §1 (`0.0.0.0/0` static route) | — |
| 29 | 1.3 | Route monitoring / reachability (FRR + BFD) | RESTORED-4A | M02 §1/§2/§4 (`StaticRoute.bfd`); SL §5 BFD state, §6 | 4-a (schema+module); CONT (SL/DP/CP) |
| 30 | 1.3 | Multi-WAN failover (priority + probe) | COVERED | M02 §4/§5 | — |
| 31 | 1.3 | Multi-WAN load balance (weighted) | COVERED | M02 §4/§5 | — |
| 32 | 1.3 | WAN health probes (ICMP/TCP/DNS/HTTP) | COVERED | M02 wan-probes; SL §5/§6 | — |
| 33 | 1.3 | Floating static routes | COVERED | M02 §1 (`distance`) | — |
| 34 | 1.3 | Blackhole routes | COVERED | M02 §2/§4 | — |

### §1.4 Firewall (25)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 35 | 1.4 | Zone-based firewall | COVERED | M03 zones + rules | — |
| 36 | 1.4 | L3/L4 rules | COVERED | M03 §4 | — |
| 37 | 1.4 | Address Objects / Groups | COVERED | M03 §4; EP §4 | — |
| 38 | 1.4 | Service Objects / Groups | COVERED | M03 §4; EP §4 | — |
| 39 | 1.4 | Schedule Objects (time-based) | COVERED | M03 §4; CP §5 | — |
| 40 | 1.4 | Rule groups / categories | RESTORED-4A | M03 §1/§4 (first-class `tags` chips) | 4-a |
| 41 | 1.4 | Rule enable/disable without delete | COVERED | M03; `PATCH …/toggle` | — |
| 42 | 1.4 | Rule comments / descriptions | COVERED | M03 §2/§4 | — |
| 43 | 1.4 | Rule hit counters (resettable) | COVERED | M03; `…/hits`, `…/hits/reset` | — (locked pre-4A) |
| 44 | 1.4 | Actions allow/deny/drop/reject | COVERED | M03; PM §6 enum | — |
| 45 | 1.4 | Connection limit per rule | COVERED | M03 §2 (`connLimit`) | — |
| 46 | 1.4 | Rate-limiting rules | COVERED | M03 §2 (`rateLimit`) | — |
| 47 | 1.4 | SYN flood protection | COVERED | M03 §2 (`synProtection`) | — |
| 48 | 1.4 | Port forwarding (DNAT) | COVERED | M03 §4 (NAT editor) | — |
| 49 | 1.4 | Logging none/summary/detail | COVERED | M03; PM §6 enum | — |
| 50 | 1.4 | Implicit deny logging | COVERED | M03 §5 (generator) | — |
| 51 | 1.4 | Rule validation engine | COVERED | M03; `POST …/validate` | — |
| 52 | 1.4 | GeoIP filtering | COVERED | M03 (geo objects); DP §2.2 (`geo_blocked` set) | — |
| 53 | 1.4 | FQDN-based rules | COVERED | M03 (fqdn address objects → nftables sets) | — |
| 54 | 1.4 | App-aware rules (nDPI) | RESTORED-4A | M03 §1/§4 (Applications picker + `/network/app-catalog`) | 4-a |
| 55 | 1.4 | User-based rules (RADIUS map) | RESTORED-4A | M03 §1/§4 (Users picker) | 4-a |
| 56 | 1.4 | DNS security rules (block/allow DNS) | COVERED | M06 §1 (DNS filter policies block/allow; sinkhole) | — |
| 57 | 1.4 | ICMP type/code filtering | COVERED | M03 service objects (`icmpType`) | — |
| 58 | 1.4 | Rule import / export (CSV, JSON) | COVERED | M03; `…/import`, `…/export` | — |
| 59 | 1.4 | MAC filtering rules | RESTORED-4A | M03 §1/§4 (`srcMacs`); SCHEMA §4; DP §3 | 4-a |

### §1.5 NAT (9)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 60 | 1.5 | SNAT / masquerade | COVERED | M03 §4/§5 | — |
| 61 | 1.5 | DNAT | COVERED | M03 §4/§5 | — |
| 62 | 1.5 | 1:1 NAT (static) | RESTORED-4A | M03 §1/§5 (paired dnat+snat helper) | 4-a |
| 63 | 1.5 | Hairpin NAT | COVERED | M03 §5; DP §4 sequence | — |
| 64 | 1.5 | NAT exemption (no-NAT) | COVERED | M03; DP §4 ordering | — |
| 65 | 1.5 | NAT pool management (range, overload) | RESTORED-4A | M03 §1/§5 (`translatedSrcPool`, `overload`) | 4-a |
| 66 | 1.5 | NAT logging | RESTORED-4A | M03 §1/§5 (`logging` on NAT rows → firewall_logs) | 4-a |
| 67 | 1.5 | Port forwarding with port translation | COVERED | M03 §4 | — |
| 68 | 1.5 | Destination NAT port ranges | RESTORED-4A | M03 §1/§5 (`translatedPortRange`) | 4-a |

### §1.6 IPS / IDS (14)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 69 | 1.6 | Suricata inline mode | COVERED | M04; DP §1 (NFQUEUE, ADR-003) | — |
| 70 | 1.6 | Emerging Threats (free) rule set | COVERED | M04 §1/§4 | — |
| 71 | 1.6 | Signature-based detection | COVERED | M04 §1/§4 | — |
| 72 | 1.6 | Anomaly detection (preprocessors) | RESTORED-4A | M04 §1/§2/§4 (`preprocessors` toggles) | 4-a |
| 73 | 1.6 | Auto rule updates | RESTORED-4A | M04 §1/§4 (Rule Updates card); `ips/update-settings`; SCHEMA §4 `ips/auto_update` | 4-a |
| 74 | 1.6 | IPS Policy Profiles (presets) | RESTORED-4A | M04 §1/§4; `POST /ips/policies/apply-preset`; PM §6 `ips_preset`; DP §3.1 | 4-a |
| 75 | 1.6 | IPS exception rules | COVERED | M04 §2 (`exceptions`, ADR-017) | — |
| 76 | 1.6 | IPS bypass rules | COVERED | M04 (`sid: 0` skip-queue; ADR-017) | — |
| 77 | 1.6 | Custom IPS rules | COVERED | M04 §2 (`customRules`) | — |
| 78 | 1.6 | Rule category enable/disable | COVERED | M04 §4 (category matrix) | — |
| 79 | 1.6 | IPS performance modes | COVERED | M04 §2 (`inline_drop\|inline_tap\|passive`) | — |
| 80 | 1.6 | IPS threshold tuning | COVERED | M04 §2 (`thresholds`) | — |
| 81 | 1.6 | IPS event suppression | COVERED | M04; `…/events/{id}/suppress` | — |
| 82 | 1.6 | Threat intelligence correlation | RESTORED-4A | M04 §1/§2/§5 (`tiBlocklist`); SCHEMA §3; SL §3/§6 | 4-a (feed ingestion stays §2.11 Phase 2 by the spec's own assignment) |

### §1.7 VPN (16)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 83 | 1.7 | WireGuard (s2s + remote access) | COVERED | M05 §2/§4 | — |
| 84 | 1.7 | IPSec IKEv2 — site-to-site | COVERED | M05 §2/§4 | — |
| 85 | 1.7 | IPSec IKEv2 — remote access (EAP) | COVERED | M05 §2 (`authMethod`) | — |
| 86 | 1.7 | SSL VPN (OpenVPN) — remote access | COVERED | M05 §2/§4 | — |
| 87 | 1.7 | Split tunneling | COVERED | M05 (subnets / `allowedIps`) | — |
| 88 | 1.7 | VPN DNS assignment | COVERED | M05 (`dns` pushes) | — |
| 89 | 1.7 | Dead peer detection (DPD) | COVERED | M05 (`dpdSec`) | — |
| 90 | 1.7 | VPN tunnel monitoring | COVERED | M05 `…/status`; `vpn:status` | — |
| 91 | 1.7 | PFS | COVERED | M05 (`pfs`) | — |
| 92 | 1.7 | VPN user groups | RESTORED-4A | M05 §1/§2/§4 (`VpnUserGroup` + tab); EP §7 | 4-a |
| 93 | 1.7 | VPN address pools (per-group) | RESTORED-4A | M05 §1/§5 (config pool + group override) | 4-a |
| 94 | 1.7 | VPN session limits (per-user, per-group) | RESTORED-4A | M05 §1/§5 (`maxSessionsPerUser`; per-user = single-member group) | 4-a |
| 95 | 1.7 | VPN session timeout (idle, max) | RESTORED-4A | M05 §1/§5 (`idleTimeoutMin`, `maxSessionMin`) | 4-a |
| 96 | 1.7 | IPsec anti-replay window | RESTORED-4A | M05 §1/§2 (`replayWindow` 32–1024); SCHEMA §4 | 4-a |
| 97 | 1.7 | Client provisioning (.conf bundles) | COVERED | M05; `POST …/client-bundle` | — |
| 98 | 1.7 | VPN keepalive settings | COVERED | M05 (`keepaliveSec`, `dpdSec`) | — |

### §1.8 DNS Security (10)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 99 | 1.8 | DNS resolver (recursive + caching) | COVERED | M06 §4 (resolver settings) | — |
| 100 | 1.8 | DNS filtering (block/allow lists) | COVERED | M06 §1/§4 | — |
| 101 | 1.8 | Custom DNS records | COVERED | M06 §4 | — |
| 102 | 1.8 | Conditional forwarding (per-domain) | RESTORED-4A | M06 §1/§4 (`forwardZones`); SCHEMA §4 | 4-a |
| 103 | 1.8 | DNS query logging | COVERED | M06 §4 (derived query log) | — |
| 104 | 1.8 | DNS sinkhole | COVERED | M06 §1 (`sinkholeIp`) | — |
| 105 | 1.8 | Malware domain blocking | COVERED | M06 §1 (aggregated blocklists) | — |
| 106 | 1.8 | DNS response rate limiting (RRL) | COVERED | M06 (`rrl` toggle) | — |
| 107 | 1.8 | DNS-over-TLS (DoT) server | COVERED | M06 (`dot` toggle; appliance `tls-port 853`) | — |
| 108 | 1.8 | DNS-over-HTTPS (DoH) server | RESTORED-4A | M06 §1/§4 (`doh` toggle + port; display-only in sandbox); SCHEMA §4 | 4-a |

### §1.9 DHCP (9)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 109 | 1.9 | DHCPv4 server | COVERED | M06 §4 | — |
| 110 | 1.9 | IP address pools | COVERED | M06 §4 (ranges) | — |
| 111 | 1.9 | Static MAC-IP binding | COVERED | M06 reservations | — |
| 112 | 1.9 | Lease tracking / viewing | COVERED | M06 §4 (leases + release) | — |
| 113 | 1.9 | DHCP relay (ip-helper) | RESTORED-4A | M06 §1/§4 (Relay tab); `GET/PUT /dhcp/relay`; SCHEMA §4/§6; DP §1, CP §2, SL §3 | 4-a |
| 114 | 1.9 | DHCP option sets (custom options) | COVERED | M06 §2 (`options` JSON) | — |
| 115 | 1.9 | Per-subnet options override | COVERED | M06 §2 (subnet-level options) | — |
| 116 | 1.9 | DHCP lease conflict detection | COVERED | M06 §5 (unique IP per subnet → 409) | — |
| 117 | 1.9 | DHCPv6 (basic) | RESTORED-4A | M06 §1/§2/§5 (`family ipv6`; kea-dhcp6.conf); SCHEMA §4 | 4-a |

### §1.10 Identity & Access (11)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 118 | 1.10 | Local user database | COVERED | M07 §4 | — |
| 119 | 1.10 | Local user groups | COVERED | M07 §4 | — |
| 120 | 1.10 | Active Directory / LDAP sync | RESTORED-4A | M07 §1/§4 (`DirectorySource` + test); EP §9 | 4-a |
| 121 | 1.10 | RADIUS authentication | COVERED | M07 §4 (profiles, test/reveal) | — |
| 122 | 1.10 | Captive portal | COVERED | M07 §4/§5 | — |
| 123 | 1.10 | Guest user management (vouchers) | COVERED | M07 §4 (vouchers, in-memory) | — |
| 124 | 1.10 | Password policy | COVERED | M07 §5.2 (`auth-settings`) | — |
| 125 | 1.10 | Account lockout policy | COVERED | M07 §5.2 | — |
| 126 | 1.10 | MFA (TOTP) | RESTORED-4A | M07 §4/§5.6 (enroll + enforce); EP §1 (`totpCode`) | 4-a |
| 127 | 1.10 | User identity mapping (IP→user) | COVERED | M07 §5.5; DP §3 | — |
| 128 | 1.10 | Concurrent session limits | RESTORED-4A | M07 §5.2 (`maxConcurrentPerUser`); SCHEMA §4 | 4-a |

### §1.11 QoS (10)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 129 | 1.11 | HTB shaping | COVERED | M08; DP §5 | — |
| 130 | 1.11 | FQ_CoDel queuing | COVERED | M08; DP §5 | — |
| 131 | 1.11 | Per-interface bandwidth limits | COVERED | M08 (`bandwidthKbps` policies) | — |
| 132 | 1.11 | Per-user bandwidth limits | RESTORED-4A | M08 §1/§4/§5 (hard-limit classes via `matchUsers` + `maxKbps`; quick-create); DP §5 | 4-a (module); CONT (DP) |
| 133 | 1.11 | Per-application bandwidth limits | RESTORED-4A | M08 §1/§4/§5 (`matchApps`); DP §5 | 4-a (module); CONT (DP) |
| 134 | 1.11 | Priority queues | COVERED | M08 (`priority` 0–7) | — |
| 135 | 1.11 | DSCP marking | COVERED | M08 (`dscpMark`); DP §5 table | — |
| 136 | 1.11 | DSCP-to-queue mapping | COVERED | M08; DP §5 | — |
| 137 | 1.11 | QoS templates (VoIP/Video/Gaming/Bulk) | COVERED | M08 (`template` enum) | — |
| 138 | 1.11 | QoS per-WAN shaper | COVERED | M08 (per-iface policies; tc+ifb appliance-side) | — |

### §1.12 Logging & Reporting (11)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 139 | 1.12 | Central log storage | COVERED | M09 §2 | — |
| 140 | 1.12 | Log severity levels | COVERED | M09 §4 | — |
| 141 | 1.12 | Log search / filter | COVERED | M09 §3/§4 | — |
| 142 | 1.12 | Raw log viewer (real-time tail) | COVERED | M09 `#/logs/live`; `logs:tail` | — |
| 143 | 1.12 | Syslog forwarding | RESTORED-4A | M09 §1/§2/§4 (Forwarding tab); `logs/syslog-targets*`; SCHEMA `SyslogTarget` | 4-a |
| 144 | 1.12 | NetFlow/IPFIX export | RESTORED-4A | M09 §1/§2/§4; `logs/netflow-targets*`; SCHEMA `NetflowTarget` | 4-a |
| 145 | 1.12 | Log forwarding reliability (buffer on disconnect) | RESTORED-4A | M09 §1/§4 (per-target `bufferedRows`) | 4-a |
| 146 | 1.12 | Log storage management (retention, rollover, quota) | COVERED | M09/DATA_LIFECYCLE §4; `logging/disk_quota` | — |
| 147 | 1.12 | Scheduled reports (daily/weekly/monthly) | RESTORED-4A | M09 §1/§4 (Scheduled tab); `logs/report-schedules*` (+run); SCHEMA `ReportSchedule`; CP §5 | 4-a |
| 148 | 1.12 | Report formats (PDF, HTML, CSV, JSON) | RESTORED-4A | M09 §1/§4 (formats + run-now; PDF via print / appliance wkhtmltopdf; email appliance-side) | 4-a |
| 149 | 1.12 | Basic traffic reports | COVERED | M09 §4 (Reports tab from `/logs/stats`) | — |

### §1.13 High Availability (9)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 150 | 1.13 | Active/Passive failover | COVERED | M10 §4/§5; SL §5 | — |
| 151 | 1.13 | Virtual IP (VIP) management | COVERED | M10 §4 | — |
| 152 | 1.13 | Configuration sync (bidirectional) | RESTORED-CONT | M10 §1/§5.1 (`syncConfig` IN — simulated copy-on-apply; appliance rsync+PG) | 4-a-CONT (scope clarified from "toggle only") |
| 153 | 1.13 | HA link monitoring | RESTORED-CONT | M10 §1/§4/§5 (`trackedInterfaces` chips + multiselect); SCHEMA; EP §12 | 4-a: SCHEMA/EP fields; 4-a-CONT: M10/PMAP surfaces |
| 154 | 1.13 | HA split-brain prevention | COVERED | M10 §4 (priority + track explanation) | — |
| 155 | 1.13 | HA graceful failback (hold-down) | COVERED | M10 §4/§5.1 | — |
| 156 | 1.13 | Firewall session sync (conntrackd) | RESTORED-CONT | M10 §1/§4/§5 (`sessionSync` switch + status chips); SCHEMA; EP §12 | 4-a: SCHEMA/EP fields; 4-a-CONT: M10/PMAP surfaces |
| 157 | 1.13 | VPN tunnel failover | RESTORED-CONT | M10 §1/§4 (StrongSwan + Keepalived explanation; VIP floats) | 4-a-CONT |
| 158 | 1.13 | HA cluster health dashboard | COVERED | M10 §4 (`#/ha` status panel) | — |

### §1.14 System (20)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 159 | 1.14 | Backup / restore (full config + DB) | COVERED | M10 §3/§4/§5.3 | — |
| 160 | 1.14 | Firmware upgrade | RESTORED-CONT | M10 §1/§3/§4/§5.6; `system/firmware*`; SCHEMA §4 `advanced/firmware`; CP §6.2; SL §3 | 4-a-CONT (was deferred in M10) |
| 161 | 1.14 | Firmware rollback | RESTORED-CONT | M10 §3/§5.6; `POST /system/firmware/rollback`; CP §6.2 | 4-a-CONT (was deferred in M10) |
| 162 | 1.14 | Configuration versioning | COVERED | M10 §2/§4 (`config_versions`, ADR-011) | — |
| 163 | 1.14 | Configuration diff viewer | COVERED | M10 §4 (side-by-side diff) | — |
| 164 | 1.14 | CLI (management) | RESTORED-CONT | M10 §1 (spec's own "SSH + API" option; SSH keys managed in M10; no bespoke CLI binary) | 4-a-CONT (was unaddressed) |
| 165 | 1.14 | REST API | COVERED | M11; API_STANDARDS | — |
| 166 | 1.14 | WebSocket (real-time updates) | COVERED | PM §7.3 (7 locked events) | — |
| 167 | 1.14 | JWT authentication | COVERED | AUTH_AND_RBAC §2 (ADR-007) | — |
| 168 | 1.14 | RBAC | COVERED | AUTH_AND_RBAC §4 (8 roles) | — |
| 169 | 1.14 | Audit trail | COVERED | M09; API_STANDARDS §7 (ADR-011) | — |
| 170 | 1.14 | Admin MFA (TOTP) | RESTORED-4A | M07 §5.6 (TOTP required flag + enrollment) | 4-a |
| 171 | 1.14 | NTP configuration | RESTORED-CONT | M10 §1/§4/§5.7 (System time card); SCHEMA §4 `general/ntp`; EP §13 | 4-a-CONT (was deferred in M10; SCHEMA shape by 4-a) |
| 172 | 1.14 | SNMP v2c/v3 | RESTORED-CONT | M10 §1/§4/§5.7 (SNMP card, masked community); SCHEMA §4 `advanced/snmp`; PM §6 `snmp.version` | 4-a-CONT (was deferred in M10) |
| 173 | 1.14 | SSH key management | RESTORED-CONT | M10 §1/§3/§4/§5.7; `system/ssh-keys*`; SCHEMA `SshKey` | 4-a: SCHEMA/EP/PM; 4-a-CONT: M10 view+rules |
| 174 | 1.14 | First-time setup wizard | RESTORED-CONT | M10 §4 (`#/setup`, view 29); `POST /system/setup/complete`; PM §8; PMAP blueprint | 4-a: PM §7.2/§8 + EP; 4-a-CONT: M10 wizard + PMAP |
| 175 | 1.14 | Default policy templates (per vertical) | RESTORED-CONT | M10 §1/§3/§4/§5.8; `system/policy-templates*` | 4-a: EP/PM; 4-a-CONT: M10 view+semantics |
| 176 | 1.14 | System hardening toggle | RESTORED-CONT | M10 §1/§4/§5.7 (Hardening card); SCHEMA §4 `advanced/hardening` | 4-a-CONT (was deferred in M10) |
| 177 | 1.14 | Health check endpoints | RESTORED-CONT | M10 §1/§3 (`GET /system/status` = Phase-1 health surface: uptime + per-service status + resource levels) | 4-a-CONT (was unaddressed) |
| 178 | 1.14 | Resource alerts (CPU/RAM/disk/temp) | RESTORED-CONT | M10 §1/§4/§5.5 (thresholds + edge-triggered notifications); SCHEMA §4 `notifications/thresholds`; DATA_LIFECYCLE §2.5 | 4-a: SCHEMA shape; 4-a-CONT: M10 view+engine semantics |

### §1.15 API (10)

| # | Spec § | Feature | Status | Where covered | Fix applied |
|---|---|---|---|---|---|
| 179 | 1.15 | REST API (all features) | COVERED | M11 §1; ADR-002 | — |
| 180 | 1.15 | API versioning (`/api/v1/`) | COVERED | M11/API_STANDARDS §1 | — |
| 181 | 1.15 | OpenAPI/Swagger docs | RESTORED-CONT | M11 §1/§4.2/§7; `GET /api/v1/openapi.json` (zod-generated, EP §14); no swagger UI bundle by decision | 4-a: EP/PM rows; 4-a-CONT: M11 scope + negative list fixed |
| 182 | 1.15 | API key management (create/revoke/scope) | COVERED | M11 §2/§3/§5.1; M10 §4 | — |
| 183 | 1.15 | API rate limiting | COVERED | M11 §5.2; API_STANDARDS §9 | — |
| 184 | 1.15 | API pagination | COVERED (documented deviation) | M11 §5.4 (offset/page LOCKED; cursors reserved — API_STANDARDS §6) | — (deviation documented pre-4A) |
| 185 | 1.15 | API batch operations | RESTORED-CONT | M11 §1 (locked batch-style endpoints: import, reorder ×2, voucher batch, read-all); generic batch endpoint explicitly out | 4-a-CONT (M11 formerly listed it "out of scope") |
| 186 | 1.15 | API request/response logging (audit) | COVERED | M11 §5.3; API_STANDARDS §7 | — |
| 187 | 1.15 | Webhook support (event callbacks) | RESTORED-CONT | M11 §1/§3/§5.6; `/webhooks*` (EP §14); Webhook model; Webhooks tab (M10 §4); **console ships stubs** (simulated delivery) per ROADMAP §2/§5 nuance — spec phase unchanged | 4-a: SCHEMA/EP/PM/AUTH rows; 4-a-CONT: M11 semantics + M10 view + PMAP tab |
| 188 | 1.15 | API change notifications (WebSocket push) | RESTORED-CONT | M11 §1/§6: console clients = locked socket events; machine clients = webhooks (`alerts.new`… dot-form) + REST polling. **No new realtime event** — the 7-event set is unchanged; a machine-facing WS channel would be a new ADR (flagged §f) | 4-a-CONT |

**Count check:** 9 + 16 + 9 + 25 + 9 + 14 + 16 + 10 + 9 + 11 + 10 + 11 + 9 + 20 + 10 = **188**.

---

## (c) New schema fields/tables (from the REVIEW-4A lane; SCHEMA.md is definitive)

**New models (9)** — SCHEMA.md §3 "Phase-1 restored models (REVIEW-4A)" block, all
tenant-scoped with `tenantId @default(1)` + audit + config-version snapshots via the shared
handler: `PbrRule`, `PortMirror`, `VpnUserGroup`, `SyslogTarget`, `NetflowTarget`,
`ReportSchedule`, `Webhook`, `SshKey`, `DirectorySource`.

**New/extended fields:** `HaConfig.sessionSync`, `HaConfig.trackedInterfaces`;
`StaticRoute.bfd`; `NetworkInterface.mode` (l2|l3), `config.lldp`, bridge `stpMode` +
`igmpSnooping`, `type: ipip`; `FirewallRule.srcMacs`; `IpsPolicy.preprocessors`,
`IpsPolicy.tiBlocklist`; `VpnConfig.config(*).replayWindow`, `.dns`, wireguard_remote
`peers[]`; `DhcpSubnet.family` (ipv4|ipv6).

**New `SystemSetting` JSON shapes (SCHEMA §4):** `general/ntp`, `advanced/snmp`,
`advanced/hardening`, `advanced/firmware`, `notifications/thresholds`, `dhcp/relay`,
`dns/resolver.forwardZones` + `.doh`, `ips/auto_update`, `auth/totp` + `auth/sessionLimits`,
`general/setup.completed`. **New enum rows (PM §6):** `ips_preset`, `dhcp_subnets.family`,
`snmp.version`, `webhooks.events`, `directory_sources.type`, `interfaces.mode`.

## (d) New endpoints (PROJECT_MEMORY §7.2 "PHASE-1 RESTORED SURFACE"; cataloged in ENDPOINTS §3/§6/§7/§8/§9/§11/§13/§14)

`/network/lldp-neighbors` · `/network/mac-table` · `/network/port-mirrors` (+PUT/DELETE) ·
`/network/app-catalog` · `/pbr-rules` (+PUT/DELETE, `/{id}/toggle`) ·
`/ips/policies/apply-preset` · `/ips/update-settings` (GET/PUT) · `/vpn/user-groups`
(+PUT/DELETE) · `/dhcp/relay` (GET/PUT) · `/directory-sources` (+PUT/DELETE, `/{id}/test`) ·
`/logs/syslog-targets*` · `/logs/netflow-targets*` · `/logs/report-schedules*` (+`/{id}/run`) ·
`/logs/reports/export` · `/webhooks` (+PUT/DELETE, `/{id}/test`) · `/openapi.json` ·
`/system/services/{name}/restart` · `/system/firmware` (+`/check`, `/upgrade`, `/rollback`) ·
`/system/policy-templates` (+`/{id}/apply`) · `/system/ssh-keys` (+POST/DELETE) ·
`/system/setup/complete`. All follow the envelope/pagination/RBAC floors; role floors and
audit flags are in ENDPOINTS.md and AUTH_AND_RBAC §4/§5 (log forwarding: network_admin full;
report schedules: security_admin/soc_analyst; webhooks: security_admin, machine keys none;
firmware/restart/templates/setup: tenant_admin).

## (e) New views/tabs (PMAP + PROJECT_MEMORY §8)

- **View 29:** `#/setup` — first-time setup wizard; renders **instead of the shell** while
  `setup.completed` is false (gate pattern like `#/login`; not in the sidebar). Registry is
  now 29 views (was 28).
- **New tabs:** `#/network/interfaces` → LLDP Neighbors | MAC Table | Mirroring (SPAN);
  `#/network/routing` → Policy-Based Routes; `#/vpn/configs` → User Groups;
  `#/dns-dhcp/dhcp` → Relay; `#/logs/reports` → Scheduled | Forwarding;
  `#/system/api-keys` → Webhooks.
- **New cards/panels:** `#/system/settings` (System time/NTP, SNMP, Hardening, Firmware,
  SSH keys, resource-alert thresholds, Policy templates); `#/ips/policies` (Rule Updates card
  + preset row); `#/identity/users` (Directory sources card).

## (f) Flagged items for the coordinator

1. **Realtime-event needs (none introduced — by design):**
   - Derived engine views (LLDP neighbors, MAC/FDB) have **no socket event**; they poll
     (10 s) per the documented fallback rule (STATE_AND_DATA_FLOW §2/§4). If live-push is
     ever demanded, that is a new event → ADR + PM §7.3 change first.
   - HA status has no event → refetch-on-focus + `config:updated`; HA incidents arrive as
     `alerts:new` notifications (`type: "ha"`). Same rule applies.
   - Machine-facing "API change notifications (WebSocket push)" is satisfied by webhooks
     (dot-form subset) + polling; a machine WS channel would need a **new ADR + PM §7.3
     change** — deliberately not built.
2. **ADR/decision needs:**
   - `config:updated { section: "all" }` sentinel (restore **and** template-apply) needs a
     one-line ADR or PM §7.3 note so realtime-service and cache invalidation agree.
   - Webhook sender: console ships the stub surface (simulated delivery) per ROADMAP §2/§5;
     real HMAC delivery is appliance-side. If product wants console-side delivery, that is a
     contract change (egress rules) — flag before building.
   - Setup-gate escape hatch for CI/demos (`SETUP_SKIP=1` or seed `setup.completed = true`) —
     decide at M0; do not weaken the gate silently.
   - `audit_log.actorType` column (machine key attribution) — Phase-2 schema pass candidate.
3. **Out-of-scope-by-spec items intentionally NOT restored** (not deferrals): license
   management (spec §1.14 cut list — Phase 2; Community tier runs unlicensed), full TI feed
   management (spec §2.11), cursor pagination (documented LOCKED deviation), swagger UI
   bundle, generic batch endpoint, bespoke CLI binary (SSH+API chosen — the spec's own
   alternative).
4. **Files outside this lane's ownership that still carry pre-4A wording** (cannot edit;
   historical/owned elsewhere): `DECISIONS.md` ("~28 screens" — now 29 with `#/setup`);
   `REVIEW-2B-FULLSTACK.md` §"no webhook endpoints" (superseded by REVIEW-4A — reviews are
   point-in-time records); ROADMAP §2 webhook divergence note is **correct as written**
   (stub nuance) — no action.

## (g) Final attestation

Audited inventory: **SPEC.md §1.1–§1.15 = 188 Phase-1 features** (matrix in §b, one row
each). Status after the combined REVIEW-4A lane: **188 / 188 covered — zero uncovered, zero
console deferrals.** 7-event realtime set unchanged; envelope/pagination/RBAC/audit floors
unchanged; all new tables tenant-scoped + audited + version-snapshotted.

*Report by agent `4-a-CONT` (continuation of timed-out `4-a`), 2026-11-05.*

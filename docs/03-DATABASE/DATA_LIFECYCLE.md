# Data Lifecycle — Seeding, Mock Generation, Retention, Reset

> TL;DR: One seed command populates a believable 30-day-old appliance. MockEngine keeps
> it alive. Retention caps log tables. `--reset` wipes volatile data and reseeds.

Related: SCHEMA.md · ER_DIAGRAM.md · ../02-ARCHITECTURE/SIMULATION_LAYER.md (profiles)

---

## 1. Commands

| Command | Effect |
|---|---|
| `bun run db:push` | apply `prisma/schema.prisma` to `db/cryptsk.db` (sandbox standard) |
| `bunx prisma db seed` | run `prisma/seed.ts` (configured in package.json `prisma.seed`) |
| `bunx prisma db seed -- --reset` | delete volatile rows (logs/events/sessions/leases) + reseed them; keeps config tables in place |
| `bunx prisma studio` | inspect data while developing (do not leave running) |

Seed MUST be idempotent: running twice must not duplicate config rows (upserts by
natural keys: tenant+name, mac, cidr, etc.).

## 2. Seed Dataset (deterministic — ADR-012, `MOCK_SEED=1337` default)

### 2.1 Identity & tenant
| Item | Value |
|---|---|
| Tenant | id 1, name `Default`, company `Cryptsk Demo Ltd.` |
| Users | `admin` / `admin123` (super_admin), `secops` / `secops123` (security_admin), `netops` / `netops123` (network_admin), `viewer` / `viewer123` (auditor) — bcrypt hashed; demo creds documented here and shown on the login view helper text |
| User groups | `IT Staff` (admin, netops), `Security` (secops) |
| ApiKeys | 1 read-only key `ck_demo_readonly_…` (hashed; prefix shown in UI) |

### 2.2 Network
| Item | Value |
|---|---|
| Interfaces | `wan0` (physical, wan, static 203.0.113.2/24 gw 203.0.113.1), `wan1` (physical, wan, dhcp, disabled), `lan0` (physical, lan, 192.168.10.1/24), `dmz0` (physical, dmz, 172.16.20.1/24), `vlan10` (vlan on lan0, role lan), `br-mgmt` (bridge, mgmt), `wg0` (vpn) |
| Zones | WAN [wan0,wan1], LAN [lan0,vlan10], DMZ [dmz0], VPN [wg0] |
| Static routes | 2 (one to 10.50.0.0/16 via 192.168.10.254, one blackhole example) |
| PBR rules | 1 (`VOIP-VIA-WAN1` — SIP service forced out wan1, priority 1) |
| WAN policies | wan0 (icmp → 1.1.1.1, priority 1), wan1 (http → connectivity check, priority 2, failover) |

### 2.3 Objects & firewall
- Address objects: `LAN_NET`, `DMZ_NET`, `VPN_NET`, `PRINTER_01`, `SERVER_WEB`, `GEO_BLOCKLIST` (geo), `OFFICE_HOURS_NET` … (10)
- Address groups: `TRUSTED`, `SERVERS` (3)
- Service objects: `HTTP`, `HTTPS`, `DNS_UDP`, `SSH`, `RDP`, `WIREGUARD`, `SIP` (7)
- Service groups: `WEB_SERVICES`, `ADMIN_SERVICES` (2)
- Schedule: `BUSINESS_HOURS` (recurring Mon–Fri 09:00–17:00, Asia/Calcutta)
- Firewall rules (12, mixed actions/zones): management allow, LAN→WAN allow, DMZ→LAN deny (logged detail), WAN→DMZ DNAT-protected web allow, guest VLAN restrictions, business-hours social block, geo-block WAN ingress, implicit-deny comment placeholder (disabled), etc.
- NAT rules: `MASQ_LAN_WAN` (snat), `WEB_PORT_FWD` (dnat 8080→172.16.20.5:80), `HAIRPIN_WEB` (hairpin), `VPN_NO_NAT` (exempt)

### 2.4 IPS / VPN / DNS / DHCP / QoS
| Item | Value |
|---|---|
| IPS policies | `BALANCED` (inline_drop, most categories on), `STRICT_WEB` (tap-only sample) |
| IPS events | 300 backfilled across 30 days, severity mix per profile |
| VPN | `HQ-MESH` (wireguard_s2s), `ROADWARRIORS` (wireguard_remote, pool 10.99.0.0/24), `BRANCH-IPSEC` (ipsec_s2s), `SSL-ACCESS` (openvpn) — statuses up/up/connecting/down for variety |
| VPN sessions | ~10 across configs |
| DNS | policy `DEFAULT` (block ads+malware+phishing), resolver settings (incl. one `forwardZones` example `corp.local → 192.168.10.254`), 12 records in `corp.local`, 1 week of query-log aggregates |
| DHCP | subnet 192.168.10.0/24 (range .100–.200) + 172.16.20.0/24 (family `ipv4`); 4 reservations; ~25 leases (mixed states); relay disabled sample (`servers: [192.168.10.254]`) |
| VPN groups | `CONTRACTORS` (idle 30 min, max 1 session/user, members `c.reyes`) |
| Log forwarding | syslog target `SIEM-01` (disabled, udp 10.20.0.9:514), netflow target `NFDUMP-01` (disabled, ipfix :2055) |
| Webhooks | 1 disabled sample `soc-callback` (events `["alerts.new"]`) |
| Report schedules | 1 sample `DAILY-TRAFFIC` (daily, html, traffic+threats) |
| QoS | `WAN-SHAPER` (50000 kbps, video template) + 3 rules (VoIP priority 0 guaranteed, Streaming priority 5 max cap, Bulk priority 7) |
| HA | disabled by default (`standby` sample config present) |

### 2.5 System
- Settings: general (hostname `cryptsk-demo`, timezone `Asia/Calcutta`, NTP `pool.debian.org` synced), auth (password policy, lockout 5/15m, TOTP off, concurrent sessions 4), logging (retention days, syslog off, disk quota 2048 MB), notifications (email off, thresholds cpu 90 / mem 90 / disk 85 / temp 80), advanced (hardening defaults, firmware `1.0.0` stable), dhcp relay sample, ips auto-update daily 03:00 (enabled)
- Notifications: 5 unread (2 critical threat, 1 vpn down `BRANCH-IPSEC`, 1 ha info, 1 system update)
- Config versions: v1 seed snapshot per section
- SSH keys: 1 sample `ops-laptop` (ed25519 placeholder line); Directory sources: none enabled |

## 3. Mock Traffic Profiles (MockEngine)

| Profile | Character | Enabled via env `MOCK_PROFILE` |
|---|---|---|
| `office` (default) | Daytime business traffic: web/SaaS heavy 09–17, backup spikes 02:00, occasional BitTorrent (blocked by rule → drops visible), lunch-hour YouTube bump | office |
| `hospitality` | Guest Wi-Fi: flat all-day HTTPS, streaming bursts, DNS-heavy, many blocked adult/gambling attempts | hospitality |
| `msp_branch` | Small office + IPS-noisy: more scans, more critical events, WAN flaps (demo failover) | msp_branch |

Profile controls: baseline kbps per iface role, app-mix weights, blocked-category hit
rates, event severity distribution, WAN probe jitter, session churn rates.
(Profiles are JSON in `src/lib/engine/profiles.ts` — extend without touching engine code.)

## 4. Retention & Housekeeping

| Table | Cap | Enforcement |
|---|---|---|
| firewall_logs | 50,000 rows | `lib/engine/retention.ts` — runs inside MockEngine every 500 ticks; batch delete oldest beyond cap |
| ips_events | 5,000 rows | same job |
| audit_log | 20,000 rows | same job (never auto-delete config_versions) |
| notifications | 500 rows | prune read+older-than-7d |
| dhcp_leases | replace expired | lease state machine expires → `expired` (kept 7d) |
| report_schedules | n/a (config) | engine bumps `lastRunAt` when a schedule window elapses; run-now endpoint updates it too |

Retention settings (`system_settings` category `logging`) override caps per tenant.

Note on `audit_log`: the 20,000-row cap is housekeeping only (batch delete of the oldest
rows by the retention job). The audit log stays **append-only at the API layer**
(ADR-011 — no updates, no user-facing deletes); `--reset` never purges it (§5).

> **Appliance mode (future):** on the real appliance these log tables live in
> PostgreSQL with **native monthly partitioning** (`firewall_logs`, `ips_events`)
> and retention expressed in days instead of row caps; long-term analytics archival
> goes to ClickHouse (optional, v2 per the product spec). The sandbox row caps above
> emulate that lifecycle at demo scale.

## 5. Reset Semantics (`--reset`)

Volatile (deleted + regenerated): `firewall_logs`, `ips_events`, `identity_sessions`,
`vpn_sessions`, `dhcp_leases`, `notifications` (regenerated), realtime ring buffers
(incl. the derived LLDP-neighbor and MAC-table views).
Preserved: all config tables (incl. pbr_rules, port_mirrors, vpn_user_groups, syslog/netflow
targets, webhooks, report_schedules, ssh_keys, directory_sources), users, api_keys,
config_versions, system_settings, audit_log (audit is append-only by ADR-011; reset does
not purge it — use manual SQL only when explicitly asked).

## 6. Demos & Debugging Recipes

- "Show me a critical incident": set `MOCK_PROFILE=msp_branch` + restart → scan burst within ~5 min; or POST a manual IPS event via seed helper `scripts/inject-incident.ts` (optional helper, documented when built).
- "Reproduce yesterday's screenshot": same `MOCK_SEED` + same profile → same series shape.
- "Clean slate": `bunx prisma db seed -- --reset`.
- "Inspect generated data": `bunx prisma studio` (stop it afterwards).

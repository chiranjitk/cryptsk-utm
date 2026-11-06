# Cryptsk UTM/NGFW — Optimized Specification (2026)
# Small Enterprise Focus | Open-Source First | Phased Delivery

---

## PRODUCT OVERVIEW

- **Product Name**: Cryptsk UTM / NGFW
- **Category**: Unified Threat Management + Next-Gen Firewall
- **Target Market**: Small enterprises (10–500 users), branch offices, MSPs, hospitality
- **Target Throughput**: 1–10 Gbps (single appliance)
- **Differentiation vs Fortinet/Sophos**: No per-user licensing, modern UI, API-first, WireGuard-native, open-source transparency
- **Honest Limitation**: URL filtering depth, AV engine quality, and sandbox sophistication will trail commercial vendors — compensated by AI over time

---

## OS SELECTION — DETAILED ANALYSIS & RECOMMENDATION

### Comparison Matrix

| Criterion | **Debian 13 (Trixie)** | Ubuntu 24.04 LTS | Rocky Linux 9 | FreeBSD 14 | Alpine Linux |
|---|---|---|---|---|---|
| **Kernel Version** | 6.8+ LTS | 6.8 LTS | 5.14 (RHEL) | N/A (FreeBSD kernel) | 6.6 LTS |
| **eBPF/XDP Support** | Excellent | Excellent | Good (limited XDP) | **Broken / Incomplete** | Good |
| **nftables** | Default firewall | Default firewall | iptables default (nftables available) | **Not available** (uses pf) | iptables/nftables |
| **Suricata Performance** | Excellent (AF_PACKET + eBPF) | Excellent | Excellent | **Limited** (no AF_XDP) | Good |
| **WireGuard** | Kernel native | Kernel native | Kernel native | Native (since 13.0) | Kernel native |
| **StrongSwan** | Excellent | Excellent | Excellent | Good | Limited packages |
| **nDPI** | Excellent | Excellent | Excellent | Good | Good |
| **FRR (BGP/OSPF)** | Excellent | Excellent | Excellent | **No FRR port** (use Quagga fork) | Good |
| **Docker/Containers** | Excellent | Excellent | Good (Podman) | **No native Docker** (jails only) | Excellent |
| **Package Freshness** | Good | Excellent | Conservative | Good | Very fresh |
| **Release Cycle** | ~2 years | 2 years (LTS: 5yr support) | ~3 years | ~1 year | 6 months |
| **Long Term Support** | ~5 years | 5 years (LTS) | 10 years (RHEL compat) | N/A (rolling) | 2 years per release |
| **Security Posture** | Excellent (minimal, audited) | Good (more attack surface) | Excellent (SELinux) | **Best** (jails, Capsicum) | Good (musl) |
| **Community / Docs** | Massive | Massive | Growing | Niche | Small |
| **Hardware Compatibility** | Very good | **Best** (newest drivers) | Good (enterprise HW) | Limited (NIC support) | Limited |
| **Disk Footprint** | ~2 GB base | ~4 GB base | ~3 GB base | ~1 GB base | ~150 MB |
| **Memory Overhead** | Low | Medium | Medium | Low | Very low |

### Why NOT These OSes

#### FreeBSD — DISQUALIFIED
- **No nftables** — relies on pf (Packet Filter), a completely different firewall paradigm
- **No eBPF/XDP** — the entire modern data-plane acceleration strategy fails
- **Suricata runs in AF_PACKET mode only** — no AF_XDP, significantly lower throughput
- **FRR (FRRouting) has no official FreeBSD port** — BGP/OSPF requires old Quagga forks
- **Docker does not run natively** — service isolation requires FreeBSD jails (different paradigm, less ecosystem)
- **WireGuard support is newer and less battle-tested** than on Linux
- **nDPI, StrongSwan, Kea, and many security tools** have second-class FreeBSD support
- **Verdict**: FreeBSD is excellent for OPNsense/pfSense (which use pf), but **fundamentally incompatible** with a Linux-native eBPF + nftables + Suricata + FRR architecture

#### Rocky Linux — NOT RECOMMENDED
- **Default firewall is iptables/firewalld**, not nftables-first
- **SELinux adds complexity** for UTM (Suricata, eBPF programs, and custom services require extensive SELinux policy tuning)
- **Kernel is older** (5.14 based, backported) vs Debian/Ubuntu 6.8+
- **eBPF/XDP features lag** behind mainline kernel by 1-2 years
- **RPM ecosystem** — most open-source security tools document Debian/Ubuntu first
- **Good for**: Traditional enterprise servers, not cutting-edge network appliances

#### Alpine Linux — NOT RECOMMENDED
- **musl libc** — some security tools (Suricata with certain features, Python ML libraries) assume glibc
- **Small community** — less troubleshooting resources for complex UTM issues
- **Limited package selection** — you'd be building many packages from source
- **Good for**: Containers, routers, minimal appliances — not a full UTM platform

#### Ubuntu 24.04 LTS — CLOSE SECOND
- **Advantages over Debian**: Newer kernel out-of-box, better hardware compatibility, larger community, Snap packages (controversial but useful for some services), cloud-init for deployment
- **Disadvantages**: Heavier base (~4 GB vs ~2 GB), more attack surface (more default services), Snap dependency (some consider it a negative for appliances), slightly faster release cadence can introduce instability
- **Verdict**: Perfectly viable. If your team is more familiar with Ubuntu, use it.

### RECOMMENDATION: Debian 13 (Trixie)

**Primary choice: Debian 13 (Trixie)** with Debian 12 (Bookworm) as fallback.

**Why Debian 13 wins for a UTM appliance:**
1. **nftables is the default** — no iptables legacy baggage
2. **Kernel 6.8+ LTS** — full eBPF/XDP, modern NIC driver support, WireGuard, all current
3. **Smallest attack surface** — minimal default installation, no Snap, no cloud bloat
4. **Predictable** — slow release cycle = fewer surprise breakages in production appliances
5. **Every major open-source security tool tests on Debian first** — Suricata, StrongSwan, FRR, nDPI, Kea, Unbound all have official Debian packages
6. **glibc** — full compatibility with all Python ML libraries (PyTorch, TensorFlow, ONNX Runtime)
7. **Docker/Podman** — first-class support for service isolation
8. **Proven in production** — pfSense CE was Debian-based, OPNsense is the only major FreeBSD holdout
9. **Pure FOSS** — no proprietary components, no telemetry, no licensing games
10. **Long-term stability** — Debian releases are the gold standard for "set it and forget it" servers

**Kernel Requirements (must backport if not in default kernel):**
```
- eBPF (BPF_PROG_TYPE_XDP, BPF_PROG_TYPE_CGROUP_SKB)
- XDP (native, redirect, pass, drop actions)
- nftables with all extensions (conntrack, tproxy, hash, limits)
- WireGuard (kernel module or built-in)
- AF_XDP (for future 10G+ optimization)
- Netfilter conntrack enhancements (max, timeout tuning)
- tc (traffic control) with FQ_CoDel, CAKE, HTB qdiscs
```

**If Debian 13 is not yet stable at your build time, use Debian 12 (Bookworm) + backports kernel (6.8+).**

---

## OPTIMIZED TECH STACK

### Core Platform
| Component | Package | Version | License | Notes |
|-----------|---------|---------|---------|-------|
| OS | Debian 13 (Trixie) | 13.x | FOSS | Minimal install, no desktop |
| Kernel | Linux LTS | 6.8+ | GPL | Custom tuned for UTM |
| Container Runtime | Docker | 27+ | Apache 2.0 | Per-service isolation |

### Data Plane
| Component | Package | License | Throughput | Notes |
|-----------|---------|---------|-----------|-------|
| Packet Engine | nftables + eBPF/XDP | GPL | 10 Gbps | Kernel-native, hardware-accelerated |
| DPI Engine | nDPI | LGPL 3.0 | 5+ Gbps | ~300 protocol signatures |
| IPS Engine | Suricata | GPL 2.0 | 5+ Gbps | Emerging Threats (free) rules |
| Connection Tracking | conntrack (kernel) | GPL | 10+ Gbps | Kernel-native, tuneable |

### Routing & VPN
| Component | Package | License | Notes |
|-----------|---------|---------|-------|
| Dynamic Routing | FRR (FRRouting) | GPL 2.0 | BGP, OSPFv2/v3 |
| IPSec VPN | StrongSwan | GPL 2.0 | IKEv2, site-to-site, remote access |
| WireGuard VPN | WireGuard | GPL 2.0 | Kernel-native, fastest VPN |
| SSL VPN | OpenVPN | GPL 2.0 | Proven, widely compatible |

### Network Services
| Component | Package | License | Notes |
|-----------|---------|---------|-------|
| DNS Resolver | Unbound | BSD | Recursive + caching, DoH/DoT server |
| DNS Filtering | Rpzmate / Unbound RPZ | BSD | RPZ-based blocking |
| DHCP Server | Kea (ISC) | MPL 2.0 | Modern DHCPv4/v6, HA-ready |
| Web Proxy | Squid | GPL 2.0 | Explicit + transparent proxy |
| RADIUS | FreeRADIUS | GPL 2.0 | 802.1X, MAB, CoA, VLAN assignment |

### Security
| Component | Package | License | Notes |
|-----------|---------|---------|-------|
| WAF Engine | Coraza | Apache 2.0 | OWASP CRS compatible, ModSecurity syntax |
| Reverse Proxy | Caddy / Nginx | Apache 2.0 | Auto-TLS, modern HTTP/2/3 |
| Spam / Email | Rspamd | Apache 2.0 | DKIM/SPF/DMARC + Bayesian |
| Certificate Authority | Step-CA | Apache 2.0 | Internal PKI for SSL inspection |
| Malware Scanning | ClamAV | GPL 2.0 | Basic AV (60-70% detection) |
| YARA Rules | YARA | BSD | Custom malware pattern matching |

### Data & Messaging
| Component | Package | License | Notes |
|-----------|---------|---------|-------|
| Database | PostgreSQL | PostgreSQL | Primary config + log DB |
| Cache / Queue | Redis | BSD | Caching, session store, pub/sub |
| Log Storage | ClickHouse | Apache 2.0 | High-performance log analytics (optional, v2) |
| Search (v2) | Meilisearch | MIT | Full-text log search (v2) |

### Monitoring
| Component | Package | License | Notes |
|-----------|---------|---------|-------|
| Metrics | Prometheus | Apache 2.0 | Time-series metrics collection |
| Visualization | Grafana | AGPL v3 / Apache 2.0 | Dashboards, alerting |
| Health | Netdata | GPL 3.0 | Real-time system health (optional, can use Prometheus node_exporter) |

### API & UI
| Component | Package | License | Notes |
|-----------|---------|---------|-------|
| Backend API | Go (Gin/Fiber) | BSD | Fast, single-binary, low memory |
| Frontend UI | Next.js | MIT | Modern dashboard, React |
| API Docs | Swagger/OpenAPI | — | Auto-generated from Go structs |

### AI/ML
| Component | Package | License | Notes |
|-----------|---------|---------|-------|
| Inference Runtime | ONNX Runtime | MIT | Fast, supports most model formats |
| Training (offline) | PyTorch | BSD | For offline model training only |
| Feature Extraction | Python + scikit-learn | BSD | Feature engineering pipeline |

### What Changed From Original Spec
| Original | Optimized | Why |
|----------|-----------|-----|
| Java Spring Boot API | **Go (Gin/Fiber)** | Single binary, 10x less memory, faster, simpler deployment for appliance |
| Apache Kafka | **Redis Streams** | Kafka is overkill for single appliance. Redis already needed for caching |
| TensorFlow + PyTorch (both) | **ONNX Runtime** (inference) + PyTorch (offline training) | One lightweight inference runtime. Train with PyTorch, export to ONNX |
| Netdata + Prometheus | **Prometheus + node_exporter** | One metrics system. Add Grafana. Netdata is redundant |
| Target 10-100 Gbps | **1-10 Gbps** | Small enterprise realistic throughput |

---

## ARCHITECTURE

### Data Plane (Packet Processing Pipeline)
```
NIC → XDP (early drop/rate-limit) → eBPF (flow export, metadata)
  → nftables (L3/L4 firewall + NAT)
  → conntrack (state tracking)
  → TPROXY/SQUID (if proxy or SSL inspection enabled for this flow)
  → nDPI (application classification)
  → Suricata IPS (inline mode, if policy attached)
  → tc/QoS (traffic shaping)
  → Output NIC
```

**Key Design Decisions:**
- XDP handles **syn-flood protection, basic L3/L4 ACLs, and rate-limiting** at line rate before kernel
- nftables handles **all stateful firewall + NAT** rules
- TPROXY redirects selected traffic to Squid/Coraza for proxy/WAF
- nDPI runs as **a helper** to Suricata or standalone for app classification
- Suricata runs in **inline mode** with AF_PACKET (or AF_XDP in future)
- tc handles **all QoS/shaping** at egress

### Control Plane
```
Next.js UI ←→ Go REST API ←→ PostgreSQL (config store)
                                 ←→ Redis (cache, sessions, pub/sub)
                                 ←→ System Services (via systemd / Docker)
```

**Key Design Decisions:**
- All configuration is **database-driven** (PostgreSQL)
- Changes are deployed to system services via **configuration generators** (Go templates → service config files)
- Real-time UI updates via **WebSocket** (Redis pub/sub → Go → WebSocket)
- API-first: **every UI action calls the same REST API**

### AI Layer (Simplified)
```
Log/Flow Data → Redis Queue → Python Feature Extractor
  → ONNX Runtime Inference → Risk Score → Action (alert/block/quarantine)
  → PostgreSQL (inference log) → Feedback Loop
```

---

## PHASED FEATURE ROADMAP

---

## PHASE 1 — MVP (Months 1–6)
### "Deployable UTM with core firewall, VPN, IPS, DNS security"

---

### 1.1 Dashboard

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Live traffic graph (throughput per interface) | Prometheus + Grafana | ✅ Ready |
| Active sessions count | conntrack + API | ✅ Ready |
| Top 10 applications (nDPI classified) | nDPI + Prometheus | ✅ Ready |
| Top 10 talkers (users/IPs) | NetFlow from eBPF | ✅ Ready |
| System health (CPU, RAM, disk, temp) | node_exporter | ✅ Ready |
| Threat alert summary (last 24h) | Suricata logs + API | ✅ Ready |
| VPN tunnel status | StrongSwan/WireGuard status | ✅ Ready |
| WAN link status | ICMP probes | ✅ Ready |
| Quick action buttons (restart service, backup) | System API | ✅ Ready |

**Phase 1 Dashboard does NOT include:** AI risk score (Phase 3), threat heatmap (Phase 2), security posture score (Phase 3)

---

### 1.2 Network — Interfaces

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Physical interface management | iproute2 / netplan | ✅ Ready |
| WAN (Static / DHCP / PPPoE Client) | ifupdown2 / NetworkManager | ✅ Ready |
| LAN interface | iproute2 | ✅ Ready |
| VLAN (802.1Q) | iproute2 / bridge | ✅ Ready |
| Bridge (L2) | bridge-utils | ✅ Ready |
| Bond / LACP | ifenslave / iproute2 | ✅ Ready |
| MTU / MSS clamp per interface | iproute2 | ✅ Ready |
| Interface L2/L3 mode toggle | iproute2 | ✅ Ready |
| Loopback interface | Kernel | ✅ Ready |
| GRE / IPIP tunnels | iproute2 | ✅ Ready |
| LLDP neighbor discovery | lldpd | ✅ Ready |
| STP/RSTP (on bridges) | bridge-utils / mstpd | ✅ Ready |
| IGMP snooping | bridge-utils + mcproxy | ✅ Ready |
| MAC table management | bridge + fdb | ✅ Ready |
| Port mirroring / SPAN | tc + mirred | ✅ Ready |
| Interface diagnostics (link speed, errors, drops) | ethtool / ip -s link | ✅ Ready |

**Cut from original:** VRF (Phase 2), VXLAN (Phase 2), MACVLAN/IPVLAN (Phase 2), MACsec (dropped — needs hardware), QinQ (dropped — ISP feature), PPPoE Server (Phase 2), Cellular/LTE/5G (Phase 2), Satellite (dropped), DPDK/AF_XDP (Phase 3+), ERPS (dropped — ISP), Ring redundancy (dropped — ISP), Bond rate/fallback tuning (Phase 2), IPv6 dual-stack (Phase 2 — do IPv4 first, add IPv6 thoroughly)

---

### 1.3 Network — Routing

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Static routes | iproute2 / FRR | ✅ Ready |
| Policy-based routing (source/dest based) | FRR + nftables | ✅ Ready |
| Default route management | iproute2 | ✅ Ready |
| Route monitoring / reachability | FRR + BFD | ✅ Ready |
| Multi-WAN failover (priority + probe) | Custom (health probes + iproute2) | 🟡 Custom engineering |
| Multi-WAN load balance (weighted, per-connection) | Custom (nftables + hash + probes) | 🟡 Custom engineering |
| WAN health probes (ICMP/TCP/DNS/HTTP) | Custom (Go service) | 🟡 Custom engineering |
| Floating static routes | FRR | ✅ Ready |
| Blackhole routes | iproute2 | ✅ Ready |

**Cut from original:** BGP/OSPF (Phase 2), RIP/RIPng (dropped — dead protocol), IS-IS (dropped), Route maps/prefix lists/community lists (Phase 2 with BGP), Route leaking (Phase 2 with VRF), Graceful restart (Phase 2)

---

### 1.4 Firewall (NGFW)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Zone-based firewall (define zones, inter-zone policies) | nftables | 🟡 Custom engineering |
| L3/L4 rules (source/dest/port/protocol) | nftables | ✅ Ready |
| Address Objects / Groups (IP, range, subnet, FQDN) | Custom (DB + nftables sets) | 🟡 Custom engineering |
| Service Objects / Groups (TCP/UDP port, ICMP type) | Custom (DB + nftables) | 🟡 Custom engineering |
| Schedule Objects (time-based, recurring) | Custom (cron + nftables) | 🟡 Custom engineering |
| Rule groups / categories | DB | ✅ Ready |
| Rule enable/disable without delete | DB + nftables | ✅ Ready |
| Rule comments / descriptions | DB | ✅ Ready |
| Rule hit counters (per-rule, resettable) | nftables counters | ✅ Ready |
| Actions: Allow / Deny / Drop / Reject | nftables | ✅ Ready |
| Connection limit per rule (max concurrent) | nftables ct count | ✅ Ready |
| Rate-limiting rules (connections/sec per source) | nftables limit | ✅ Ready |
| SYN flood protection (SYN cookies, per-rule threshold) | nftables + sysctl | ✅ Ready |
| Port forwarding (DNAT) | nftables dnat | ✅ Ready |
| Logging: None / Summary / Detail | nftables log | ✅ Ready |
| Implicit deny logging | nftables | ✅ Ready |
| Rule validation engine (shadow rules, conflicts, orphans) | Custom (Go) | 🟡 Custom engineering |
| GeoIP filtering | nftables + MaxMind GeoLite2 | ✅ Ready |
| FQDN-based rules (resolve and update) | Custom (DNS resolve + nftables sets) | 🟡 Custom engineering |
| App-aware rules (allow/block by nDPI app) | Custom (nDPI + nftables) | 🟡 Custom engineering |
| User-based rules (map IP to user via RADIUS) | Custom (FreeRADIUS + nftables) | 🟡 Custom engineering |
| DNS security rules (block/allow DNS queries) | Unbound + nftables | 🟡 Custom engineering |
| ICMP type/code filtering | nftables | ✅ Ready |
| Rule import / export (CSV, JSON) | API | ✅ Ready |
| MAC filtering rules | nftables ether | ✅ Ready |

**Cut from original:** TLS fingerprint (JA3/JA4) filtering (Phase 2), Blackhole/Mirror actions (Phase 2), PCAP-on-match logging (Phase 2), Rule versioning/change tracking (Phase 2), Rule simulation/dry-run (Phase 2), Asymmetric routing handling (Phase 2), Fragment handling policy (Phase 2), Rule count limits per tenant (Phase 2)

---

### 1.5 NAT

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| SNAT (source NAT / masquerade) | nftables snat/masquerade | ✅ Ready |
| DNAT (destination NAT) | nftables dnat | ✅ Ready |
| 1:1 NAT (static NAT) | nftables dnat + snat | ✅ Ready |
| Hairpin NAT | nftables | ✅ Ready |
| NAT exemption (no-NAT / identity NAT) | nftables (no NAT rule) | ✅ Ready |
| NAT pool management (range, overload) | nftables | ✅ Ready |
| NAT logging (who got what translation) | nftables log | ✅ Ready |
| Port forwarding (DNAT with port translation) | nftables dnat | ✅ Ready |
| Destination NAT port ranges | nftables | ✅ Ready |

**Cut from original:** Twice-NAT/Dual-NAT (Phase 2), Deterministic NAT/CGNAT (dropped — ISP feature), NAT with route-map (Phase 2), NAT44/NAT66/NPTv6 (Phase 2 with IPv6), NAT session timeouts per rule (Phase 2)

---

### 1.6 IPS / IDS

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Suricata inline mode | Suricata | ✅ Ready |
| Emerging Threats (free) rule set | Emerging Threats | ✅ Ready |
| Signature-based detection | Suricata | ✅ Ready |
| Anomaly detection (preprocessors) | Suricata | ✅ Ready |
| Auto rule updates | suricata-update | ✅ Ready |
| IPS Policy Profiles (conservative/balanced/aggressive) | Custom (rule category toggles) | 🟡 Custom engineering |
| IPS exception rules (disable specific SID for traffic) | Suricata threshold.config | ✅ Ready |
| IPS bypass rules (skip IPS for source/dest) | Suricata bypass | ✅ Ready |
| Custom IPS rules (user-defined Suricata rules) | Suricata | ✅ Ready |
| Rule category enable/disable | Suricata + suricata-update | ✅ Ready |
| IPS performance modes (inline-tap, inline-drop, passive) | Suricata | ✅ Ready |
| IPS threshold tuning (per-rule, per-source) | Suricata threshold.config | ✅ Ready |
| IPS event suppression (rate-limit alerts) | Suricata | ✅ Ready |
| Threat intelligence correlation (block known bad IPs from feeds) | Suricata + custom feed sync | 🟡 Custom engineering |

**Cut from original:** File extraction for sandbox (Phase 3 with ATP), Stream reassembly settings UI (Phase 2), Protocol decoding options UI (Phase 2)

---

### 1.7 VPN

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| **WireGuard** (site-to-site + remote access) | WireGuard | ✅ Ready |
| **IPSec (IKEv2)** — site-to-site | StrongSwan | ✅ Ready |
| **IPSec (IKEv2)** — remote access (EAP-MSCHAPv2, EAP-TLS) | StrongSwan + FreeRADIUS | ✅ Ready |
| **SSL VPN (OpenVPN)** — remote access | OpenVPN | ✅ Ready |
| VPN split tunneling (include/exclude networks) | StrongSwan / WireGuard / OpenVPN | ✅ Ready |
| VPN DNS assignment (push DNS to clients) | All VPN packages | ✅ Ready |
| VPN dead peer detection (DPD) | StrongSwan | ✅ Ready |
| VPN tunnel monitoring (probes, status) | Custom (health checks) | 🟡 Custom engineering |
| VPN PFS (Perfect Forward Secrecy) | StrongSwan | ✅ Ready |
| VPN user groups (different policies per group) | FreeRADIUS + StrongSwan | 🟡 Custom engineering |
| VPN address pools (per-group) | StrongSwan / iproute2 | ✅ Ready |
| VPN session limits (per-user, per-group) | Custom (session tracker) | 🟡 Custom engineering |
| VPN session timeout (idle, max) | All VPN packages | ✅ Ready |
| VPN IPsec anti-replay window | StrongSwan | ✅ Ready |
| VPN client provisioning (.conf bundles) | Custom (template generator) | 🟡 Custom engineering |
| VPN keepalive settings | WireGuard persistent-keepalive, StrongSwan dpd | ✅ Ready |

**Cut from original:** IKEv1 (dropped — insecure legacy), L2TP over IPSec (Phase 2), SSTP VPN (dropped — niche), VPN load balancing (Phase 2), Post-connect scripts/hooks (Phase 2)

---

### 1.8 DNS Security

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| DNS resolver (recursive + caching) | Unbound | ✅ Ready |
| DNS filtering (block/allow lists) | Unbound RPZ / Rpzmate | ✅ Ready |
| Custom DNS records (A, AAAA, CNAME, MX, TXT, SRV, PTR) | Unbound local-data | ✅ Ready |
| Conditional forwarding (per-domain to specific server) | Unbound forward-zone | ✅ Ready |
| DNS query logging | Unbound log | ✅ Ready |
| DNS sinkhole | Unbound (return NXDOMAIN/0.0.0.0) | ✅ Ready |
| Malware domain blocking | Unbound + aggregated free blocklists | 🟡 Custom engineering |
| DNS response rate limiting (RRL) | Unbound (ratelimit config) | ✅ Ready |
| DNS-over-TLS (DoT) server | Unbound | ✅ Ready |
| DNS-over-HTTPS (DoH) server | dnsproxy / DoH proxy | 🟡 Custom engineering |

**Cut from original:** DNSSEC validation (Phase 2), DNS tunneling detection (Phase 3 with AI), DGA detection (Phase 3 with AI), DNS failover/load balancing (Phase 2), DNS rewriting (Phase 2)

---

### 1.9 DHCP

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| DHCPv4 server | Kea | ✅ Ready |
| IP address pools (ranges) | Kea | ✅ Ready |
| Static MAC-IP binding | Kea reservations | ✅ Ready |
| Lease tracking / viewing | Kea + API | ✅ Ready |
| DHCP relay (ip-helper) | Kea / dhcrelay | ✅ Ready |
| DHCP option sets (custom options) | Kea (option-data) | ✅ Ready |
| Per-subnet DHCP options override | Kea (subnet-level options) | ✅ Ready |
| DHCP lease conflict detection | Kea | ✅ Ready |
| DHCPv6 (basic) | Kea | ✅ Ready |

**Cut from original:** DHCP failover (Phase 2), DHCP client classification (Phase 2)

---

### 1.10 Identity & Access

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Local user database (not just AD/LDAP) | PostgreSQL + bcrypt | ✅ Ready |
| Local user groups | PostgreSQL | ✅ Ready |
| Active Directory / LDAP sync | FreeRADIUS + LDAP | ✅ Ready |
| RADIUS authentication | FreeRADIUS | ✅ Ready |
| Captive portal (click-through, credentials, voucher) | Custom (Go + nftables + Unbound) | 🟡 Custom engineering |
| Guest user management (self-registration, time-limited) | Custom (Go + PostgreSQL) | 🟡 Custom engineering |
| Password policy (length, complexity, expiry) | Custom (Go) | ✅ Ready |
| Account lockout policy | Custom (Go) | ✅ Ready |
| MFA (TOTP) | Custom (Go + TOTP library) | 🟡 Custom engineering |
| User identity mapping (IP-to-user via RADIUS) | FreeRADIUS + custom | 🟡 Custom engineering |
| Concurrent session limits | Custom (session tracker) | 🟡 Custom engineering |

**Cut from original:** SSO/Kerberos/NTLM (Phase 2), SAML 2.0 (Phase 2), OIDC (Phase 2), Kerberos Constrained Delegation (Phase 2), RADIUS CoA (Phase 2), RADIUS Dynamic VLAN (Phase 2), User activity timeline (Phase 2)

---

### 1.11 QoS

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| HTB (Hierarchical Token Bucket) shaping | tc + HTB qdisc | ✅ Ready |
| FQ_CoDel queuing | tc + fq_codel | ✅ Ready |
| Per-interface bandwidth limits | tc + tbf/htb | ✅ Ready |
| Per-user bandwidth limits | Custom (nftables + tc) | 🟡 Custom engineering |
| Per-application bandwidth limits | Custom (nDPI + tc) | 🟡 Custom engineering |
| Priority queues | tc + prio qdisc | ✅ Ready |
| DSCP marking | nftables + tc | ✅ Ready |
| DSCP-to-queue mapping | tc | ✅ Ready |
| QoS templates (VoIP, Video, Gaming, Bulk) | Custom (predefined tc configs) | 🟡 Custom engineering |
| QoS per-WAN shaper | tc + ifb | ✅ Ready |

**Cut from original:** CAKE qdisc (Phase 2), Reverse path QoS / ingress shaping (Phase 2), Hierarchical QoS (parent-child classes) (Phase 2), Per-class monitoring dashboard (Phase 2), QoS burst allowance (Phase 2)

---

### 1.12 Logging & Reporting

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Central log storage | PostgreSQL | ✅ Ready |
| Log severity levels | Syslog + PostgreSQL | ✅ Ready |
| Log search / filter (field-based, time-range) | PostgreSQL queries via API | ✅ Ready |
| Raw log viewer (real-time tail, pause) | API (WebSocket) | ✅ Ready |
| Syslog forwarding | rsyslog | ✅ Ready |
| NetFlow/IPFIX export | nfdump / softflowd | ✅ Ready |
| Log forwarding reliability (buffer on disconnect) | rsyslog queue | ✅ Ready |
| Log storage management (retention, auto-rollover, disk quota) | Custom (cron + PostgreSQL) | 🟡 Custom engineering |
| Scheduled reports (daily/weekly/monthly) | Custom (Go + template engine) | 🟡 Custom engineering |
| Report formats (PDF, HTML, CSV, JSON) | Custom (Go template + wkhtmltopdf) | 🟡 Custom engineering |
| Basic traffic reports (top apps, users, threats) | SQL + Grafana | ✅ Ready |

**Cut from original:** Full-text search (Phase 2 — add ClickHouse or Meilisearch), Compliance report templates (Phase 2), Executive summary reports (Phase 2), Log integrity (hash chain) (Phase 2), Log anonymization (Phase 2), Custom report builder (Phase 3), CEF/LEEF format (Phase 2)

---

### 1.13 High Availability

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Active/Passive failover | Keepalived (VRRP) | ✅ Ready |
| Virtual IP (VIP) management | Keepalived | ✅ Ready |
| Configuration sync (bidirectional) | Custom (rsync + PostgreSQL replication) | 🟡 Custom engineering |
| HA link monitoring | Keepalived (track interfaces) | ✅ Ready |
| HA split-brain prevention | Keepalived (priority + track) | ✅ Ready |
| HA graceful failback (with hold-down) | Keepalived | ✅ Ready |
| Firewall session sync (conntrack replication) | conntrackd | ✅ Ready |
| VPN tunnel failover | StrongSwan + Keepalived | ✅ Ready |
| HA cluster health dashboard | Custom (API) | ✅ Ready |

**Cut from original:** Active/Active mode (Phase 3), IPS state sync (Phase 3)

---

### 1.14 System

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Backup / restore (full config + DB) | pg_dump + tar | ✅ Ready |
| Firmware upgrade | Custom (apt + systemd) | 🟡 Custom engineering |
| Firmware rollback (previous version) | Custom (versioned backups) | 🟡 Custom engineering |
| Configuration versioning (before/after) | PostgreSQL + audit log | ✅ Ready |
| Configuration diff viewer | Custom (Go) | ✅ Ready |
| CLI (management) | Custom (Go CLI or just SSH + API) | 🟡 Custom engineering |
| REST API | Go (Gin/Fiber) | ✅ Ready |
| WebSocket (real-time updates) | Go (gorilla/websocket) | ✅ Ready |
| JWT authentication | Go (jwt-go) | ✅ Ready |
| RBAC (role-based access) | Custom (Go + PostgreSQL) | 🟡 Custom engineering |
| Audit trail (who changed what, when) | PostgreSQL + middleware | ✅ Ready |
| Admin MFA (TOTP) | Custom (Go) | 🟡 Custom engineering |
| NTP configuration | chrony / systemd-timesyncd | ✅ Ready |
| SNMP v2c/v3 | net-snmp | ✅ Ready |
| SSH key management | Custom (authorized_keys) | ✅ Ready |
| First-time setup wizard | Next.js UI | 🟡 Custom engineering |
| Default policy templates (per vertical) | Custom (predefined configs) | 🟡 Custom engineering |
| System hardening toggle | Custom (systemd service manager) | 🟡 Custom engineering |
| Health check endpoints | Go HTTP | ✅ Ready |
| Resource alerts (CPU, RAM, disk, temp) | Prometheus alerting | ✅ Ready |

**Cut from original:** Secure Boot (dropped — hardware/firmware level), Disk encryption LUKS (Phase 2), Service isolation via containers (can use systemd first), Secrets management Vault (Phase 2), Change approval workflow (Phase 2), License management (Phase 2 — need business model first)

---

### 1.15 API

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| REST API (all features) | Go (Gin/Fiber) | ✅ Ready |
| API versioning (/api/v1/) | Go router | ✅ Ready |
| OpenAPI/Swagger docs | swaggo | ✅ Ready |
| API key management (create, revoke, scope) | Custom (Go + PostgreSQL) | 🟡 Custom engineering |
| API rate limiting | Go middleware | ✅ Ready |
| API pagination (cursor-based) | Go + PostgreSQL | ✅ Ready |
| API batch operations | Go + PostgreSQL | ✅ Ready |
| API request/response logging (audit) | Go middleware | ✅ Ready |
| Webhook support (event callbacks) | Custom (Go) | 🟡 Custom engineering |
| API change notifications (WebSocket push) | Go WebSocket | 🟡 Custom engineering |

**Cut from original:** GraphQL (dropped — overkill), API sandbox/test console (Phase 2), API idempotency keys (Phase 2)

---

---

## PHASE 2 — GROWTH (Months 7–12)
### "Enterprise features: SSL inspection, WAF, SD-WAN, IPv6, routing"

---

### 2.1 SSL/TLS Inspection

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| MITM proxy (intercept TLS traffic) | Squid + mitmproxy / sslsplit | 🟡 Custom engineering |
| TLS 1.2 + 1.3 decryption | OpenSSL / BoringSSL | ✅ Ready |
| Selective bypass (per-destination, per-user) | Custom (policy engine) | 🟡 Custom engineering |
| Certificate pinning bypass handling | Custom (detect + block or bypass) | 🟡 Custom engineering |
| HSTS bypass handling | Custom | 🟡 Custom engineering |
| SSL error handling policy (block/allow/intercept on error) | Custom | 🟡 Custom engineering |
| Certificate expiry monitoring & alerts | Custom (Go + certificates DB) | ✅ Ready |
| Root CA export for endpoint deployment | Step-CA | ✅ Ready |
| Certificate revocation checking (CRL + OCSP) | OpenSSL | ✅ Ready |
| Decryption failure logging | Custom | ✅ Ready |

**Open-Source Gap**: Internal PKI management. **Step-CA** (smallstep) is excellent and free — it provides root CA, subordinate CAs, ACME protocol, OCSP stapling. This is genuinely good.

**Cut from original:** Client certificate authentication / mutual TLS (Phase 3), Per-tenant CA trust store (Phase 3), Unsupported cipher/block handling UI (Phase 3)

---

### 2.2 Application Control (Enhanced)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| nDPI classification (~300 protocols) | nDPI | ✅ Ready |
| Block/allow applications | Custom (nDPI + nftables) | 🟡 Custom engineering |
| Per-application bandwidth limits | Custom (nDPI + tc) | 🟡 Custom engineering |
| Unknown application handling (allow/block/alert) | Custom | ✅ Ready |
| Application QoS mapping | Custom (nDPI + tc) | 🟡 Custom engineering |
| SaaS application detection | nDPI (partial) | 🟡 Limited — nDPI covers major SaaS but not granularly |
| Custom application signatures | nDPI custom rules | 🟡 Advanced custom engineering |

**Open-Source Gap**: nDPI covers ~300 protocols vs Fortinet's ~7000+ apps. For small enterprises, the top 50-100 apps (YouTube, Netflix, Facebook, BitTorrent, Zoom, Teams, etc.) are well-covered. Granular control ("block Facebook Chat but allow Facebook Video") is NOT possible with nDPI.

---

### 2.3 Web Security (URL Filtering)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Explicit proxy mode (with auth) | Squid | ✅ Ready |
| Transparent proxy mode (intercept) | Squid + nftables TPROXY | 🟡 Custom engineering |
| URL category blocking | Squid + aggregated free lists | 🟡 Custom engineering |
| Custom URL block/allow lists | Squid + DB | ✅ Ready |
| Safe search enforcement (Google, Bing, YouTube) | Squid rewrite rules | ✅ Ready |
| HTTP file type blocking | Squid | ✅ Ready |
| HTTP header manipulation | Squid | ✅ Ready |
| Web authentication (NTLMSSP for AD proxy) | Squid + FreeRADIUS | 🟡 Custom engineering |
| HTTP bandwidth limits | Squid + delay pools | ✅ Ready |
| HTTPS inspection | Squid + SSL bump | 🟡 Custom engineering |

**Open-Source Gap — URL Categorization Database**: This is the **biggest quality gap**. Your options:
1. **Aggregate free blocklists**: StevenBlack hosts, OISD, Blklist, hagezi, UT1 (dead but forks exist) — covers ~5-10M domains vs FortiGuard's 300M+
2. **Pi-hole + dnscrypt-proxy lists**: Good for ad/malware blocking, not full web categorization
3. **Shalla's Blacklists**: Was the go-to free option, now defunct
4. **Build your own**: Crawl + classify — months of engineering, still inferior
5. **Paid option**: Webshrinker ($$$) or similar for commercial-grade DB

**Realistic approach**: Aggregate 5-8 free blocklists, categorize them (ads, malware, phishing, adult, social media, gambling, etc.), let admins manage custom lists. Accept ~60-70% coverage vs commercial. This is **good enough for small enterprises** who mainly want to block adult content, malware, and ads.

---

### 2.4 WAF (Web Application Firewall)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Reverse proxy | Caddy / Nginx | ✅ Ready |
| OWASP Core Rule Set (CRS) | Coraza + OWASP CRS | ✅ Ready |
| WAF virtual hosts / policies (per-domain) | Coraza + Caddy | 🟡 Custom engineering |
| WAF anomaly scoring (threshold-based blocking) | Coraza (paranoia levels) | ✅ Ready |
| WAF false positive management | Coraza (rule exclusions) | ✅ Ready |
| WAF custom rules | Coraza | ✅ Ready |
| WAF rate limiting (per-URL, per-IP) | Caddy / Coraza | ✅ Ready |
| WAF logging levels | Coraza | ✅ Ready |
| WAF geo-blocking per vhost | Coraza + GeoIP | ✅ Ready |
| WAF API protection (basic) | Coraza | 🟡 Custom engineering |
| WAF learning mode (observe-only) | Custom (log-only mode) | ✅ Ready |

**Cut from original:** Bot management (Phase 3), API schema validation (Phase 3), Virtual patching (Phase 3)

---

### 2.5 SD-WAN (Basic)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Multi-WAN SLA monitoring (latency, jitter, loss) | Custom (Go + probes) | 🟡 Custom engineering |
| SLA threshold configuration | Custom (DB) | ✅ Ready |
| Application-aware path selection | Custom (nDPI + policy engine + routing) | 🟡 Heavy custom engineering |
| Path quality score algorithm | Custom (weighted composite) | 🟡 Custom engineering |
| Hub & Spoke topology | WireGuard/StrongSwan + FRR | 🟡 Custom engineering |
| Per-path traffic statistics | Custom (eBPF flow export) | 🟡 Custom engineering |
| SD-WAN QoS integration (per-path queues) | tc + ifb | 🟡 Custom engineering |
| Brownout / degraded link handling | Custom (policy engine) | 🟡 Custom engineering |
| Overlay encryption | WireGuard | ✅ Ready |

**Open-Source Gap**: SD-WAN is **entirely custom engineering**. No open-source SD-WAN controller exists that matches VeloCloud/Viptela. You build this from FRR + custom path monitoring + policy engine. It's doable but is the **hardest feature** in Phase 2.

---

### 2.6 Dynamic Routing

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| BGP (IPv4 + IPv6) | FRR | ✅ Ready |
| OSPFv2 / OSPFv3 | FRR | ✅ Ready |
| Route maps | FRR | ✅ Ready |
| Prefix lists | FRR | ✅ Ready |
| BFD (fast convergence) | FRR | ✅ Ready |
| Graceful restart | FRR | ✅ Ready |

---

### 2.7 IPv6 Dual-Stack

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| IPv6 firewall rules | nftables | ✅ Ready |
| IPv6 NAT (NPTv6) | nftables | ✅ Ready |
| IPv6 routing | FRR / iproute2 | ✅ Ready |
| DHCPv6 | Kea | ✅ Ready |
| IPv6 VPN (WireGuard, IPSec) | All VPN packages | ✅ Ready |
| IPv6 QoS | tc | ✅ Ready |
| IPv6 SLAAC | Kernel (radvd) | ✅ Ready |

---

### 2.8 Email Security (Basic)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| SMTP proxy (receive and relay) | Postfix + Rspamd | ✅ Ready |
| Anti-spam | Rspamd | ✅ Ready |
| Anti-phishing | Rspamd | ✅ Ready |
| DKIM verification + signing | Rspamd + OpenDKIM | ✅ Ready |
| SPF verification | Rspamd | ✅ Ready |
| DMARC verification + reporting | Rspamd + OpenDMARC | ✅ Ready |
| Email routing rules | Postfix + Rspamd | 🟡 Custom engineering |
| Blocked file extensions | Rspamd + ClamAV | ✅ Ready |
| Attachment scanning (ClamAV) | ClamAV | ✅ Ready |

**Open-Source Gap**: Rspamd is genuinely excellent — probably the best open-source email security solution. The gap vs commercial (Sophos Email, Mimecast) is in:
- Sandstorm-style attachment sandbox (ClamAV is signature-only)
- URL rewriting in emails (click-time protection)
- Email archiving/continuity

---

### 2.9 Advanced Identity

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| SAML 2.0 federation | Custom (Go + SAML library) | 🟡 Custom engineering |
| OIDC (OpenID Connect) | Custom (Go + OIDC library) | 🟡 Custom engineering |
| RADIUS CoA (Change of Authorization) | FreeRADIUS | ✅ Ready |
| RADIUS Dynamic VLAN Assignment | FreeRADIUS | ✅ Ready |
| Kerberos/NTLM authentication (for web proxy) | Custom (Heimdal + Squid) | 🟡 Advanced custom engineering |
| User activity timeline | Custom (log aggregation) | 🟡 Custom engineering |

---

### 2.10 NAC (Basic)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| 802.1X authentication | FreeRADIUS | ✅ Ready |
| MAC Authentication Bypass (MAB) | FreeRADIUS | ✅ Ready |
| Dynamic VLAN assignment | FreeRADIUS | ✅ Ready |
| Device profiling (fingerprint → type/OS/vendor) | Custom (DHCP + ARP + OUI lookup) | 🟡 Custom engineering |
| Rogue device detection | Custom (ARP monitoring + MAC table) | 🟡 Custom engineering |
| BYOD onboarding (captive portal + certificate) | Custom (captive portal + Step-CA) | 🟡 Heavy custom engineering |

---

### 2.11 Threat Intelligence

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Free feed ingestion (Abuse.ch, AlienVault OTX, Spamhaus) | Custom (Go + API clients) | 🟡 Custom engineering |
| IOC management (IP, domain, hash, URL) | Custom (PostgreSQL + API) | 🟡 Custom engineering |
| Reputation scoring (aggregate from multiple feeds) | Custom (scoring algorithm) | 🟡 Custom engineering |
| Auto-block malicious IPs (feed → firewall) | Custom (feed sync → nftables) | 🟡 Custom engineering |
| STIX/TAXII feed support | Custom (Go + STIX library) | 🟡 Custom engineering |

---

### 2.12 PKI / Certificate Management

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Internal CA (root + subordinate) | Step-CA | ✅ Ready |
| Certificate lifecycle (issue, renew, revoke) | Step-CA (ACME protocol) | ✅ Ready |
| OCSP / CRL | Step-CA | ✅ Ready |
| Auto-renewal | Step-CA + cert-manager | ✅ Ready |
| Certificate export (PEM, PKCS12) | Step-CA | ✅ Ready |

---

### 2.13 Enhanced Logging

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Full-text log search | ClickHouse / Meilisearch | 🟡 Custom engineering |
| CEF / LEEF format for SIEM integration | Custom (Go) | 🟡 Custom engineering |
| Compliance report templates (PCI-DSS, HIPAA, GDPR) | Custom (Go + templates) | 🟡 Custom engineering |
| Log anonymization (mask PII) | Custom (Go) | 🟡 Custom engineering |
| Report scheduling (email delivery) | Custom (Go) | 🟡 Custom engineering |
| Executive summary reports | Custom (Go + Grafana) | 🟡 Custom engineering |

---

---

## PHASE 3 — INTELLIGENCE (Months 13–18)
### "AI/ML capabilities, ATP sandbox, advanced threat detection"

---

### 3.1 AI/ML Engine (Simplified — 3 Models, Not 13)

**Start with these 3 models only. Add more after you have real traffic data.**

| Model | Purpose | Open Source Tools | Training Data | Feasibility |
|-------|---------|------------------|---------------|------------|
| **DGA Detection** | Detect algorithmically generated domains | PyTorch → ONNX | Public DGA datasets (Bambenek, Intel 471) | ✅ **High** — public datasets available, well-researched |
| **Network Anomaly (UEBA-lite)** | Detect unusual user/network behavior patterns | PyTorch → ONNX | Your own flow data (need 4-8 weeks of baseline) | 🟡 **Medium** — need deployed base first |
| **Encrypted Traffic Classification** | Classify apps inside TLS (using JA3/JA4 + flow features) | PyTorch → ONNX | Public ISCX/UNSW datasets + your traffic | 🟡 **Medium** — research papers exist, but needs fine-tuning |

**Deferred to Phase 4+ (add when you have training data):**
- C2 beaconing detection
- Lateral movement detection (graph-based)
- Phishing detection (NLP)
- Malware classification (sandbox results)
- IPS false positive reduction
- DLP NLP
- Config anomaly detection
- Capacity prediction

**AI Infrastructure:**
| Component | Package | Notes |
|-----------|---------|-------|
| Feature extraction | Python + scikit-learn | Flow features, timing, volume, protocol ratios |
| Model training | PyTorch (offline) | Train on separate dev machine, export ONNX |
| Model inference | ONNX Runtime | Lightweight, fast, no GPU needed for these models |
| Model serving | Custom Go + ONNX Runtime | HTTP/gRPC inference endpoint |
| Model registry | PostgreSQL + filesystem | Track version, metrics, deployment status |
| Confidence thresholds | Configurable per model | High confidence = auto-block, low = alert only |
| Human-in-the-loop | Admin feedback UI | FP/FN marking → retraining trigger |
| Model drift detection | Statistical monitoring | Alert when accuracy degrades |

---

### 3.2 ATP (Advanced Threat Protection) — Sandbox

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Malware detonation sandbox | Cuckoo Sandbox | 🟡 Custom engineering |
| YARA rule scanning | YARA | ✅ Ready |
| File extraction from network streams | Suricata file extraction | ✅ Ready |
| Auto-quarantine malicious files | Custom | ✅ Ready |
| Sandbox report generation | Cuckoo | ✅ Ready |

**Open-Source Gap — Sandbox Quality**:
- Cuckoo Sandbox is **functional but slow** (minutes per file) and **easily evaded** by modern malware
- FortiSandbox/Sophos Sandstorm use custom hypervisors with anti-evasion techniques
- **Your approach**: Cuckoo + YARA + AI classification (Phase 3 model) = ~50-60% of commercial sandbox quality
- **Mitigation**: Rely more on behavioral IPS (Suricata) + AI anomaly detection than file detonation

---

### 3.3 DLP (Data Loss Prevention)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Regex pattern matching (credit card, SSN, email, phone, IBAN) | Custom (Go regex) | ✅ Ready |
| Keyword matching | Custom (Go + Aho-Corasick) | ✅ Ready |
| File type control (block/allow by extension) | Custom | ✅ Ready |
| Protocol-aware scanning (HTTP, SMTP, FTP) | Custom (proxy integration) | 🟡 Custom engineering |
| DLP incident workflow (alert → review → resolve) | Custom (Go + PostgreSQL) | 🟡 Custom engineering |
| DLP user notification (block page, warning) | Custom (Go HTTP server) | 🟡 Custom engineering |
| DLP severity levels (low/medium/high/critical) | DB | ✅ Ready |
| DLP file type granularity (PDF, DOCX, XLSX, etc.) | Custom (file parsers) | 🟡 Heavy custom engineering |

**Open-Source Gap**:
- **Exact Data Matching (EDM)** and **Indexed Document Matching (IDM)**: No open-source solution. These require hashing entire databases/documents — commercial only (Symantec DLP, Forcepoint).
- **OCR-based DLP**: Tesseract (open source) exists but integrating it into real-time traffic inspection is impractical for a UTM.
- **NLP-based DLP**: Possible with open-source NLP (spaCy, HuggingFace) but needs training data and significant engineering.

---

### 3.4 DNS Tunneling Detection

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Entropy-based detection | Custom (Go) | 🟡 Custom engineering |
| Volume/frequency analysis | Custom (Go + Redis) | 🟡 Custom engineering |
| DGA detection (AI model) | ONNX Runtime | 🟡 Custom engineering |

---

### 3.5 Incident Response (Basic)

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Incident creation (from alerts) | Custom (Go + PostgreSQL) | 🟡 Custom engineering |
| Incident workflow (new → investigating → resolved) | Custom (Go) | 🟡 Custom engineering |
| Incident timeline (all actions on an incident) | PostgreSQL | ✅ Ready |
| Manual block/quarantine actions | API → nftables | ✅ Ready |
| Incident assignment | Custom (Go) | ✅ Ready |

**Cut from original:** Playbooks/SOAR (Phase 4), Threat hunting interface (Phase 4)

---

### 3.6 IoT Device Management

| Feature | Open Source Package | Status |
|---------|-------------------|--------|
| Device fingerprinting (MAC OUI + DHCP + nDPI) | Custom (OUI DB + nDPI) | 🟡 Custom engineering |
| IoT device inventory | PostgreSQL | ✅ Ready |
| Rogue device detection | Custom (ARP + MAC table monitoring) | 🟡 Custom engineering |
| Device quarantine | nftables | ✅ Ready |
| Device risk scoring | Custom (AI model, Phase 3+) | 🟡 Custom engineering |

---

---

## PHASE 4 — PLATFORM (Months 18–24+)
### "Scale, multi-site, SASE basics, advanced automation"

---

### 4.1 Multi-Site Management (Central Manager)

| Feature | Approach |
|---------|--------|
| Central dashboard for multiple UTM instances | Custom web UI |
| Central policy deployment (push to remote sites) | API + WebSocket |
| Central logging aggregation | ClickHouse cluster |
| Central firmware management | API |
| Site templates (deploy new site from template) | Custom |
| Per-site resource limits | DB |

---

### 4.2 SASE Basics

| Feature | Approach |
|---------|--------|
| Cloud firewall node (deploy in AWS/Azure/GCP) | Custom (Debian + same codebase in cloud VM) |
| Central controller (manage on-prem + cloud nodes) | Custom web UI + API |
| Edge-to-cloud tunnel (WireGuard mesh) | WireGuard |
| Identity-aware routing (user → nearest node) | Custom |

**Note**: Full SASE (like Zscaler, Netskope) is a multi-year, multi-million dollar effort. This is a **basic starting point**.

---

### 4.3 CASB (Basic)

| Feature | Approach |
|---------|--------|
| SaaS visibility (detect SaaS usage via nDPI) | nDPI + logs |
| Shadow IT detection | Custom (analyze traffic for unknown SaaS) |
| Basic API-based controls (Google Workspace, O365) | Custom (vendor APIs) |

**Note**: Full CASB requires 50+ SaaS API integrations. Start with top 5-10 (Google, Microsoft, Salesforce, Dropbox, Slack) based on customer demand.

---

### 4.4 ZTNA (Basic)

| Feature | Approach |
|---------|--------|
| Identity-based access (user-to-resource) | Custom (RADIUS + policy engine) |
| Device posture check (basic: OS, AV, disk encrypt) | Custom (endpoint agent or WMI/SSH probe) |
| Continuous validation | Custom (periodic re-check) |

---

### 4.5 Advanced AI (Add After Deployed Base Exists)

| Model | Purpose | Prerequisite |
|-------|---------|-------------|
| C2 beaconing detection | Detect command-and-control communication | 6+ months of network flow data |
| Lateral movement detection | Detect lateral movement patterns | Graph-based, needs NetFlow + auth logs |
| Phishing detection (NLP) | Detect phishing in email content | Labeled email dataset (can use public: PhishTank, Nazario) |
| IPS false positive reduction | Reduce Suricata alert noise | 3+ months of IPS alert + admin feedback data |
| DLP NLP | Detect sensitive data in text | Labeled DLP dataset (hard to get publicly) |
| Config anomaly | Detect firewall misconfigurations | Rule-based initially, ML later |

---

### 4.6 SOAR Integration (Basic)

| Feature | Approach |
|---------|--------|
| Webhook triggers to external SOAR | Webhook (Phase 1 API) |
| API integration with external SOAR (Cortex XSOAR, Splunk SOAR) | REST API |
| Basic automated response playbooks | Custom (Go + DB) |

---

---

## OPEN-SOURCE GAP SUMMARY — HONEST ASSESSMENT

### Gaps You Must Accept (No Open-Source Solution Exists)

| Feature | Commercial Equivalent | Gap Severity | Mitigation Strategy |
|---------|---------------------|---------------|-------------------|
| **URL Categorization Database** | FortiGuard Web, Sophos Web | 🔴 **Critical** | Aggregate 5-8 free blocklists. Accept 60-70% coverage. Add AI-based uncategorized URL classification (Phase 3). |
| **Anti-Virus Engine Quality** | Fortinet AV, Sophos LiveProtect | 🔴 **Critical** | Rely on Suricata IPS + behavioral detection + sandbox (Phase 3). Don't compete on file-scanning AV. ClamAV for basic coverage only. |
| **Sandbox Sophistication** | FortiSandbox, Sophos Sandstorm | 🟡 **Medium** | Cuckoo + YARA + AI classification. Accept 50-60% zero-day catch rate. |
| **Application Control Granularity** | Fortinet App Control (7000+ apps) | 🟡 **Medium** | nDPI covers top 300 protocols. Good enough for 90% of small enterprise use cases. |
| **IPS Signature Coverage** | ET Pro (paid), Fortinet IPS | 🟡 **Medium** | Emerging Threats (free) + AI false positive reduction (Phase 3) + custom rules. |
| **EDM/IDM for DLP** | Symantec DLP, Forcepoint | 🟡 **Medium** | Regex + keyword matching only. No fingerprint-based matching. |
| **Threat Intelligence Depth** | Recorded Future, Mandiant | 🟡 **Medium** | Free feeds (Abuse.ch, OTX, Spamhaus) are sufficient for small enterprises. |
| **Browser Isolation (RBI)** | Menlo Security, Globo | 🔴 **N/A** | Dropped. Not feasible with open source. |
| **Endpoint Agent / Integration** | FortiClient, Sophos Endpoint | 🔴 **N/A** | Dropped. Separate product. Use FDE/AV from existing endpoint solutions. |
| **Cold-Start AI Training Data** | Fortinet (billions of daily flows) | 🟡 **Medium** | Start rule-based. Add ML after 3-6 months of deployed traffic data. Use public datasets for DGA/phishing models. |

### Gaps That Don't Matter for Small Enterprise

| Feature | Why It Doesn't Matter |
|---------|---------------------|
| 40-100 Gbps throughput | Small enterprises run 1-5 Gbps. eBPF + nftables handles 10 Gbps easily on commodity hardware. |
| 7000+ application signatures | Small enterprises care about blocking YouTube, Facebook, Netflix, BitTorrent, gaming — all covered by nDPI. |
| Zero-day sandbox catch rate > 90% | Small enterprises are not APT targets. Suricata + good firewall rules + DNS security covers 95% of threats they face. |
| 24/7 SOC-backed threat research | Your product is self-managed. Admins get alerts and respond. AI assists with triage. |

---

## SIMPLIFIED DATABASE SCHEMA

### Core Tables (Phase 1)

```sql
-- Tenancy
CREATE TABLE tenants (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    company         VARCHAR(256),
    contact_email   VARCHAR(256),
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Users & Roles
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    username        VARCHAR(128) NOT NULL,
    password_hash   VARCHAR(256) NOT NULL,
    role            VARCHAR(32) NOT NULL DEFAULT 'viewer',
    -- super_admin, tenant_admin, security_admin, network_admin,
    -- soc_analyst, helpdesk, auditor, api_service
    email           VARCHAR(256),
    totp_secret     VARCHAR(256),
    is_active       BOOLEAN DEFAULT true,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, username)
);

-- Network Objects
CREATE TABLE zones (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(64) NOT NULL,
    type            VARCHAR(20) NOT NULL, -- L3, L2, VPN
    interface_names TEXT[] NOT NULL,
    description     TEXT,
    UNIQUE(tenant_id, name)
);

CREATE TABLE address_objects (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    type            VARCHAR(20) NOT NULL, -- ip, range, subnet, fqdn, geo, wildcard
    value           TEXT NOT NULL,
    description     TEXT,
    UNIQUE(tenant_id, name)
);

CREATE TABLE address_groups (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    member_ids      INTEGER[] NOT NULL,
    description     TEXT,
    UNIQUE(tenant_id, name)
);

CREATE TABLE service_objects (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    protocol        VARCHAR(10) NOT NULL, -- tcp, udp, icmp, any
    src_port        VARCHAR(64),
    dst_port        VARCHAR(64),
    icmp_type       SMALLINT,
    description     TEXT,
    UNIQUE(tenant_id, name)
);

CREATE TABLE service_groups (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    member_ids      INTEGER[] NOT NULL,
    description     TEXT,
    UNIQUE(tenant_id, name)
);

CREATE TABLE schedule_objects (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    type            VARCHAR(20) NOT NULL, -- always, recurring, onetime
    recurrence      JSONB, -- {days:[1,2,3,4,5], start:"09:00", end:"17:00"}
    date_range      DATERANGE,
    timezone        VARCHAR(64) DEFAULT 'UTC',
    UNIQUE(tenant_id, name)
);

-- Firewall Rules
CREATE TABLE firewall_rules (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    description     TEXT,
    enabled         BOOLEAN DEFAULT true,
    position        INTEGER NOT NULL,
    source_zone_ids INTEGER[],
    dest_zone_ids   INTEGER[],
    source_addr_ids INTEGER[],
    dest_addr_ids   INTEGER[],
    service_ids     INTEGER[],
    application_ids INTEGER[], -- nDPI app IDs
    user_ids        INTEGER[],
    schedule_id     INTEGER REFERENCES schedule_objects(id),
    action          VARCHAR(20) NOT NULL DEFAULT 'deny', -- allow,deny,drop,reject
    logging         VARCHAR(20) DEFAULT 'none', -- none,summary,detail
    conn_limit      INTEGER,
    rate_limit      INTEGER,
    syn_protection  BOOLEAN DEFAULT false,
    syn_threshold   INTEGER,
    ips_policy      VARCHAR(64), -- attach IPS profile name
    qos_policy_id   INTEGER,
    nat_type        VARCHAR(20), -- snat,dnat,hairpin,null
    nat_target      INET,
    nat_port        INTEGER,
    comment         TEXT,
    tags            VARCHAR(256)[],
    hit_count       BIGINT DEFAULT 0,
    last_hit_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- NAT Rules
CREATE TABLE nat_rules (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128),
    position        INTEGER NOT NULL,
    type            VARCHAR(20) NOT NULL, -- snat,dnat,hairpin,exempt
    enabled         BOOLEAN DEFAULT true,
    source_addr_ids INTEGER[],
    dest_addr_ids   INTEGER[],
    service_ids     INTEGER[],
    outgoing_iface  VARCHAR(64),
    translated_src  INET,
    translated_dst  INET,
    translated_port INTEGER,
    comment         TEXT,
    hit_count       BIGINT DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Interfaces
CREATE TABLE interfaces (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id),
    name            VARCHAR(64) NOT NULL,
    type            VARCHAR(20) NOT NULL, -- physical,vlan,bridge,bond,loopback,gre
    parent_name     VARCHAR(64),
    vlan_id         SMALLINT,
    mtu             INTEGER DEFAULT 1500,
    mss_clamp       INTEGER,
    zone_id         INTEGER REFERENCES zones(id),
    enabled         BOOLEAN DEFAULT true,
    config          JSONB NOT NULL DEFAULT '{}',
    -- physical: {mac, speed, duplex}
    -- vlan: {parent, vlan_id}
    -- bond: {mode, members}
    -- bridge: {stp, members}
    -- wan: {type:static|dhcp|pppoe, ip, gateway}
    description     TEXT,
    UNIQUE(tenant_id, name)
);

-- VPN
CREATE TABLE vpn_configs (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    type            VARCHAR(20) NOT NULL, -- ipsec_site, ipsec_remote, wireguard, openvpn
    enabled         BOOLEAN DEFAULT true,
    config          JSONB NOT NULL DEFAULT '{}',
    -- IPSec: {local_ip, remote_ip, local_subnet, remote_subnet, psk, ikev2, dpd, pfs}
    -- WireGuard: {private_key, port, peers:[{public_key, allowed_ips, endpoint}]}
    -- OpenVPN: {proto, port, cipher, auth}
    status          VARCHAR(20) DEFAULT 'down',
    status_message  TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE TABLE vpn_sessions (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    vpn_id          INTEGER NOT NULL REFERENCES vpn_configs(id),
    user_id         INTEGER REFERENCES users(id),
    username        VARCHAR(256),
    source_ip       INET NOT NULL,
    assigned_ip     INET,
    bytes_in        BIGINT DEFAULT 0,
    bytes_out       BIGINT DEFAULT 0,
    connected_at    TIMESTAMPTZ NOT NULL,
    last_activity   TIMESTAMPTZ DEFAULT NOW(),
    status          VARCHAR(20) DEFAULT 'active'
);

-- IPS
CREATE TABLE ips_policies (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    mode            VARCHAR(20) DEFAULT 'inline_drop', -- inline_drop, inline_tap, passive
    enabled         BOOLEAN DEFAULT true,
    rule_categories JSONB DEFAULT '{}', -- {"trojan":true, "web_attack":false, ...}
    custom_rules    TEXT[], -- Suricata rule text
    exceptions      JSONB DEFAULT '[]', -- [{sid, source, dest, comment}]
    thresholds      JSONB DEFAULT '[]', -- [{sid, track, count, seconds}]
    UNIQUE(tenant_id, name)
);

-- DNS
CREATE TABLE dns_policies (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    enabled         BOOLEAN DEFAULT true,
    block_categories TEXT[], -- ads, malware, phishing, adult, social, gambling
    custom_block    TEXT[],
    custom_allow    TEXT[],
    sinkhole_ip     INET DEFAULT '0.0.0.0',
    UNIQUE(tenant_id, name)
);

CREATE TABLE dns_records (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    zone            VARCHAR(256) NOT NULL,
    name            VARCHAR(256) NOT NULL,
    type            VARCHAR(10) NOT NULL, -- A, AAAA, CNAME, MX, TXT, SRV, PTR
    value           TEXT NOT NULL,
    ttl             INTEGER DEFAULT 3600,
    priority        INTEGER,
    enabled         BOOLEAN DEFAULT true
);

-- QoS
CREATE TABLE qos_policies (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    name            VARCHAR(128) NOT NULL,
    enabled         BOOLEAN DEFAULT true,
    template        VARCHAR(64), -- voip, video, gaming, bulk, custom
    bandwidth_kbps  INTEGER NOT NULL,
    UNIQUE(tenant_id, name)
);

CREATE TABLE qos_rules (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    policy_id       INTEGER NOT NULL REFERENCES qos_policies(id),
    name            VARCHAR(128) NOT NULL,
    priority        SMALLINT NOT NULL, -- 0=highest, 7=lowest
    guaranteed_kbps INTEGER,
    max_kbps        INTEGER,
    dscp_mark       SMALLINT,
    match_apps      INTEGER[], -- nDPI app IDs
    match_users     INTEGER[],
    match_addresses INTEGER[]
);

-- DHCP
CREATE TABLE dhcp_subnets (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    interface_name  VARCHAR(64) NOT NULL,
    subnet          CIDR NOT NULL,
    range_start     INET NOT NULL,
    range_end       INET NOT NULL,
    gateway         INET,
    dns_servers     INET[],
    lease_time      INTEGER DEFAULT 86400,
    options         JSONB DEFAULT '{}', -- custom DHCP options
    enabled         BOOLEAN DEFAULT true
);

CREATE TABLE dhcp_reservations (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    subnet_id       INTEGER NOT NULL REFERENCES dhcp_subnets(id),
    mac_address     MACADDR NOT NULL,
    ip_address      INET NOT NULL,
    hostname        VARCHAR(256),
    UNIQUE(mac_address)
);

-- Logs
CREATE TABLE firewall_logs (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(10),
    action          VARCHAR(20),
    rule_name       VARCHAR(128),
    app_name        VARCHAR(64), -- nDPI classified
    bytes           BIGINT DEFAULT 0,
    packets         BIGINT DEFAULT 0,
    user_name       VARCHAR(128)
);
CREATE INDEX idx_fw_logs_tenant_ts ON firewall_logs(tenant_id, timestamp);
CREATE INDEX idx_fw_logs_src ON firewall_logs(src_ip);
CREATE INDEX idx_fw_logs_dst ON firewall_logs(dst_ip);

CREATE TABLE ips_logs (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip          INET,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    action          VARCHAR(20),
    sid             VARCHAR(32), -- Suricata rule ID
    severity        VARCHAR(10),
    category        VARCHAR(64),
    rev             INTEGER
);
CREATE INDEX idx_ips_logs_tenant_ts ON ips_logs(tenant_id, timestamp);

-- System
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       INTEGER,
    user_id         INTEGER REFERENCES users(id),
    username        VARCHAR(256),
    source_ip       INET,
    action          VARCHAR(128) NOT NULL,
    object_type     VARCHAR(64) NOT NULL,
    object_id       INTEGER,
    object_name     VARCHAR(256),
    before_state    JSONB,
    after_state     JSONB,
    result          VARCHAR(20) DEFAULT 'success',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE config_versions (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    version         INTEGER NOT NULL,
    config_snapshot JSONB NOT NULL,
    change_summary  TEXT,
    created_by      INTEGER REFERENCES users(id),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE system_settings (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id),
    category        VARCHAR(64) NOT NULL,
    key             VARCHAR(128) NOT NULL,
    value           JSONB NOT NULL,
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, category, key)
);

-- Notifications
CREATE TABLE notifications (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    user_id         INTEGER REFERENCES users(id),
    type            VARCHAR(32) NOT NULL, -- threat, system, vpn, ha
    severity        VARCHAR(10) NOT NULL, -- info, warning, critical
    title           VARCHAR(512) NOT NULL,
    message         TEXT,
    source_module   VARCHAR(32),
    is_read         BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

### Phase 2+ Tables (add when needed)
```sql
-- SSL Inspection (Phase 2)
-- ssl_policies, ssl_bypass_rules, certificate_authorities, certificates

-- URL Filtering (Phase 2)
-- url_categories, url_filter_policies

-- App Control (Phase 2)
-- app_control_policies

-- WAF (Phase 2)
-- waf_virtual_hosts, waf_policies, waf_custom_rules, waf_events

-- Email Security (Phase 2)
-- email_policies

-- NAC / IoT (Phase 2)
-- nac_policies, iot_devices

-- Captive Portal (Phase 1, but add when UI ready)
-- captive_portal_profiles, captive_portal_sessions, captive_portal_vouchers

-- Threat Intelligence (Phase 2)
-- threat_feeds, iocs, ioc_reputations

-- DLP (Phase 3)
-- dlp_patterns, dlp_policies, dlp_incidents

-- SD-WAN (Phase 2)
-- sdwan_policies, sdwan_slas, sdwan_path_stats

-- HA (Phase 1, but add when HA ready)
-- ha_config, ha_status

-- AI (Phase 3)
-- ai_model_registry, ai_inference_log, ai_feedback, ai_drift_reports

-- Incident Response (Phase 3)
-- incidents, incident_timeline

-- Compliance Reports (Phase 2)
-- compliance_report_templates, generated_reports

-- API Keys & Webhooks (Phase 1)
-- api_keys, webhooks

-- Syslog / NetFlow Targets (Phase 1)
-- syslog_targets, netflow_targets

-- VPN Pools & Groups (Phase 1)
-- vpn_pools, vpn_user_groups

-- Tenant Limits (Phase 2)
-- tenant_limits

-- Licenses (Phase 2)
-- licenses
```

---

## COMPETITIVE POSITIONING

### Where You WIN vs Fortinet/Sophos for Small Enterprise

| Advantage | Details |
|-----------|--------|
| **Price** | No per-user, per-feature, per-GBPS licensing. Free + support contract. |
| **WireGuard** | Native WireGuard is faster and simpler than any commercial VPN. |
| **Modern UI** | Next.js dashboard looks and feels better than FortiOS/Sophos UI. |
| **API-First** | Full REST API + webhooks. Automate everything. Commercial vendors charge extra for this. |
| **Transparency** | Customers can audit the code. No backdoors, no telemetry, no data harvesting. |
| **No Vendor Lock-in** | Standard protocols (nftables, StrongSwan, WireGuard, FRR). Export configs anytime. |
| **Flexibility** | Run on any x86_64 hardware. No proprietary ASIC required. |
| **Rapid Feature Delivery** | Open-source velocity vs 6-12 month commercial release cycles. |
| **Multi-tenant from Day 1** | MSPs can manage multiple customers from one appliance. |

### Where You LOSE (Be Honest With Customers)

| Weakness | Mitigation |
|----------|-----------|
| URL filtering covers ~60-70% of commercial DB | Aggregate multiple free lists + custom lists + AI categorization (Phase 3) |
| No proprietary AV engine (ClamAV is 60-70% effective) | Rely on Suricata IPS + behavioral detection + sandbox. Recommend endpoint AV separately. |
| Sandbox zero-day catch ~50-60% | Good enough for small enterprise threat profile. APTs target large enterprises. |
| No 24/7 SOC team behind threat intel | AI-assisted detection + free feeds (Abuse.ch, OTX, Spamhaus) covers common threats. |
| Smaller application signature database (300 vs 7000) | Top 50-100 apps well-covered. Most small enterprises need <20 app control rules. |
| No dedicated endpoint agent | Partner with existing endpoint solutions (CrowdStrike, SentinelOne, even Windows Defender). |

### Pricing Strategy Suggestion

| Model | Description |
|-------|-------------|
| **Community Edition** | Free, all Phase 1 features, no SLA, community support |
| **Professional Edition** | $99-199/appliance/month — Phase 1 + Phase 2 features, email support, updates |
| **Enterprise Edition** | $299-499/appliance/month — All features, priority support, SLA, training |
| **MSP Edition** | Per-tenant pricing, central management, white-label |
| **Hardware Appliance** | Sell pre-built appliances (Supermicro, Intel NUC) with Cryptsk pre-installed |

---

## REQUIRED PACKAGES (apt install list)

```
# Core
nftables conntrack iproute2 ethtool tcpdump iputils-ping traceroute

# Data Plane
suricata ndpi libndpi

# Routing
frr

# VPN
strongswan wireguard-tools openvpn

# Network Services
unbound kea-kea-dhcp4-server kea-kea-dhcp6-server squid

# Authentication
freeradius

# DNS Filtering
dnscrypt-proxy  # or dnsproxy for DoH

# WAF (Phase 2)
caddy coraza

# Email (Phase 2)
postfix rspamd clamav clamav-daemon

# Certificate Management (Phase 2)
step-ca

# Database
postgresql-17 redis-server

# Monitoring
prometheus node-exporter grafana-server

# AI/ML (Phase 3)
onnxruntime python3-scikit-learn python3-pytorch

# System
cron logrotate rsyslog chrony snmpd
```

---

## HARDWARE RECOMMENDATIONS (Small Enterprise)

| Tier | Users | Throughput | CPU | RAM | Storage | NIC | Approx Cost |
|------|-------|-----------|-----|-----|---------|-----|-------------|
| **Starter** | 10-50 | 500 Mbps | Intel i3 / AMD Ryzen 3 (4C/8T) | 8 GB | 128 GB SSD + 500 GB HDD (logs) | 2x 1GbE | $300-500 |
| **Standard** | 50-200 | 2 Gbps | Intel i5 / AMD Ryzen 5 (6C/12T) | 16 GB | 256 GB SSD + 1 TB HDD (logs) | 4x 1GbE | $600-1000 |
| **Performance** | 200-500 | 5-10 Gbps | Intel Xeon E / AMD Ryzen 7 (8C/16T) | 32 GB | 512 GB NVMe + 2 TB HDD (logs) | 2x 10GbE + 4x 1GbE | $1500-3000 |

**NIC Considerations:**
- Intel i225 (1GbE) and Intel X710 (10GbE) have best Linux support
- Avoid Realtek NICs for production (driver issues under load)
- For 10 Gbps: Intel X710 or Mellanox ConnectX-4/5 (excellent eBPF/XDP support)

---

## FINAL NOTES

1. **This is a 24-month roadmap, not a 6-month one.** The original MD tried to build a Fortinet-killer in one shot. That's not realistic for a startup. Phase 1 alone (6 months) gives you a deployable product.

2. **Open source is your advantage, not your weakness.** Fortinet and Sophos spend millions on proprietary engines that you get for free. Your job is to integrate them well, build a great UI, and sell on price + transparency.

3. **AI is a marathon, not a sprint.** Don't build 13 AI models on day one. Build rule-based + statistical detection first. Add ML when you have real traffic data from deployed units.

4. **The URL filtering gap is your biggest vulnerability.** Invest early in aggregating free lists and building a simple categorization system. Consider a hybrid model: free lists + optional paid Webshrinker API for customers who need better coverage.

5. **Go, not Java.** For an appliance, a single-binary Go backend is dramatically simpler to deploy, update, and debug than a Java Spring Boot application.

6. **Compete on UX, not on security depth.** A Next.js dashboard that's 10x easier to use than FortiOS is a genuine competitive advantage. Small enterprise admins are not security experts — they want something that works out of the box with sensible defaults.

# Glossary — Cryptsk UTM/NGFW Domain Vocabulary

> One line per term. Grouped by area. If a term appears in docs/code, it means exactly this.

## Product & Market

| Term | Meaning |
|---|---|
| UTM | Unified Threat Management — firewall + IPS + VPN + gateway AV + web/DNS filtering in one box |
| NGFW | Next-Generation Firewall — stateful firewall with application awareness (DPI) |
| MSP | Managed Service Provider — operates many customer networks; drives our multi-tenancy |
| Appliance | The x86_64 hardware box running Debian + Cryptsk stack |
| Console | The web management UI built in this repo ("Cryptsk Console") |
| Zone | Group of interfaces with a trust role (WAN, LAN, DMZ, VPN); the zone-based firewall enforces inter-zone policy between them |

## Data Plane (appliance-side)

| Term | Meaning |
|---|---|
| XDP | eXpress Data Path — eBPF program hooked at the NIC driver for line-rate early drop/rate-limit |
| eBPF | In-kernel sandboxed program VM used for XDP, flow export, and telemetry |
| AF_PACKET / AF_XDP | Linux socket modes for Suricata packet capture; in this project used **only for passive/SPAN (IDS) capture** — inline IPS runs via nftables NFQUEUE (ADR-003); AF_XDP is the future zero-copy fast path |
| nftables | Linux firewall subsystem (successor of iptables) — all L3/L4 rules + NAT |
| Shadow rule | Firewall rule that can never match because an earlier rule already handles the same traffic; flagged by the rule-validation engine (M03 `/firewall-rules/validate`) |
| conntrack | Kernel connection-tracking table (stateful firewalling); capacity measured in rows |
| NAT | Network Address Translation; SNAT (source/masquerade), DNAT (destination/port-forward), hairpin (loopback NAT) |
| TPROXY | Linux transparent-proxy interception — policy-routes packets to a local TPROXY socket so Squid receives original client traffic unchanged; no client proxy config needed |
| nDPI | Deep-packet-inspection library (~300 protocol signatures) → application classification |
| Suricata | IPS/IDS engine; runs inline (drop) or passive (alert) with Emerging Threats rules |
| IDS vs IPS | IDS = detect + alert only (passive/off-path, e.g. Suricata on a SPAN port); IPS = inline, can drop/reject the offending flow in real time. Our modes: `passive` = IDS; `inline_drop`/`inline_tap` = IPS (only `inline_drop` blocks) |
| SID | Suricata rule identifier (integer) referenced by exceptions/thresholds |
| ET | Emerging Threats — the free/open IPS rule set used in Phase 1 |
| tc / qdisc | Linux traffic control; HTB (hierarchical token bucket) shapes bandwidth, FQ_CoDel fights bufferbloat |
| DSCP | 6-bit IP-header marking for QoS classes |
| SPAN / mirred | Port mirroring — copy traffic to an analysis interface |
| MSS clamp | Rewrite TCP MSS in SYN to avoid PMTU black holes on tunnels |
| NetFlow/IPFIX | Flow export format for top-talkers/statistics |
| GeoIP | Country-level IP filtering using MaxMind GeoLite2 |

## VPN

| Term | Meaning |
|---|---|
| WireGuard | Kernel-native fast VPN; peer model with public keys + AllowedIPs |
| IPSec / IKEv2 | Site-to-site and remote-access VPN via StrongSwan |
| OpenVPN | TLS-based SSL VPN (UDP/TCP), maximum client compatibility |
| Split tunnel | Route only chosen networks through the VPN |
| DPD | Dead Peer Detection — IKE keepalive to notice dead tunnels |
| PFS | Perfect Forward Secrecy — rekeyed sessions never reuse keys |
| EAP-MSCHAPv2 / EAP-TLS | Extensible Authentication methods for IPSec remote access |
| S2S | Site-to-site VPN (gateway-to-gateway) |
| Client bundle | Generated .conf/.ovpn file the admin downloads for a remote user |

## DNS & DHCP

| Term | Meaning |
|---|---|
| Unbound | Recursive/caching DNS resolver; our DNS engine |
| RPZ | Response Policy Zones — feed-driven DNS blocking lists |
| Sinkhole | Answer blocked domains with NXDOMAIN or a fixed IP (0.0.0.0) |
| DoT / DoH | DNS-over-TLS (853) / DNS-over-HTTPS — encrypted DNS |
| RRL | Response Rate Limiting — anti-amplification for DNS |
| Kea | ISC DHCP server (DHCPv4/v6) with API + reservations |
| Reservation | Static MAC→IP binding in DHCP |
| Lease | Dynamic address assignment with expiry |
| DGA | Domain Generation Algorithm — malware-generated random domains (AI model target) |
| DNS tunneling | Exfiltration/covert channel encoded in DNS queries (entropy/volume detection) |

## Identity & Access

| Term | Meaning |
|---|---|
| RADIUS | AAA protocol (FreeRADIUS) — auth for VPN/802.1X/captive portal |
| 802.1X | Port-based network access control (switch/Wi-Fi asks RADIUS) |
| MAB | MAC Authentication Bypass — non-802.1X devices authenticated by MAC |
| CoA | RADIUS Change of Authorization — live policy push (e.g. VLAN change) |
| Captive portal | Web page intercepting guest traffic for click-through/credentials/voucher login |
| Voucher | Time-limited guest access code |
| TOTP | Time-based one-time password (MFA) |
| RBAC | Role-Based Access Control — exactly 8 roles: `super_admin`, `tenant_admin`, `security_admin`, `network_admin`, `soc_analyst`, `helpdesk`, `auditor`, `api_service` |
| Identity mapping | IP→user correlation (from RADIUS/portal/VPN sessions) for user-based rules |
| Dynamic VLAN | RADIUS assigns the VLAN for a session |

## Security Features

| Term | Meaning |
|---|---|
| WAF | Web Application Firewall — Coraza with OWASP CRS rules (Phase 2) |
| CRS | OWASP Core Rule Set — WAF signature base |
| SSL/TLS inspection | MITM decryption of HTTPS using internal CA (Step-CA) (Phase 2) |
| HSTS | HTTP Strict Transport Security — browser forces HTTPS (bypass handling in Phase 2) |
| JA3/JA4 | TLS client fingerprints — app classification inside TLS (Phase 2) |
| ATP | Advanced Threat Protection — sandbox detonation of files (Phase 3, Cuckoo) |
| YARA | Pattern-matching rules for malware identification |
| DLP | Data Loss Prevention — regex/keyword scanning of egress content (Phase 3) |
| IOC | Indicator of Compromise — IP/domain/hash from threat feeds |
| STIX/TAXII | Threat-intel exchange formats/protocols |
| UEBA | User & Entity Behavior Analytics — anomaly detection on behavior (our AI model) |
| C2 beaconing | Periodic malware callbacks to command-and-control servers (AI model target) |
| SD-WAN | Multi-WAN path selection by SLA (latency/jitter/loss) + app policy (Phase 2) |
| SLA probe | Synthetic health check (ICMP/TCP/DNS/HTTP) measuring link quality |
| ZTNA | Zero-Trust Network Access — identity-based app access (Phase 4) |
| SASE | Secure Access Service Edge — cloud-delivered convergence of networking (SD-WAN) and security (SWG, CASB, ZTNA, FWaaS); full SASE is out of scope, Phase 4 ships basics |
| CASB | Cloud Access Security Broker — visibility and policy for SaaS usage (shadow-IT detection, API controls) (Phase 4 basics) |
| SOAR | Security Orchestration, Automation and Response — external playbook engine (Phase 4) |

## HA & Ops

| Term | Meaning |
|---|---|
| VRRP / Keepalived | Active/passive failover with a shared Virtual IP |
| VIP | Virtual IP floating between HA nodes |
| conntrackd | Session-table replication for stateful failover |
| Split-brain | Both HA nodes think they are master — prevented by link tracking + priority |
| Hold-down | Delay before failing back to the preferred node |
| RPZ feed / blocklist | Aggregated domain lists (StevenBlack, OISD, hagezi) for filtering |
| Config version | Snapshot of config at change time (rollback target) |
| Audit trail | Append-only record of every mutation (who/what/when/before/after) |

## Build/Console Terms (this repo)

| Term | Meaning |
|---|---|
| SystemAdapter | Interface abstracting the appliance; implemented by SimulatedAdapter (sandbox) and AgentAdapter (appliance) |
| MockEngine | Deterministic traffic/log/event generator powering Sandbox Mode (seeded PRNG) |
| View | A client "page" inside the single-route SPA, selected by hash (`#/firewall/rules`) |
| viewRegistry | Map from hash path → view component + nav metadata |
| Envelope | API response shape: `{data, meta}` or `{error:{code,message,details}}` |
| Logical reference | Id list stored as JSON string column (no FK), integrity enforced in service layer |
| config:updated | Socket event broadcast after config mutations; clients invalidate query caches |
| Tick | 2-second realtime metrics emission from the realtime service |

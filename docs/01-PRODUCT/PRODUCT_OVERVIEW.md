# Product Overview — Cryptsk UTM / NGFW

> TL;DR: Cryptsk is an open-source-first Unified Threat Management + Next-Gen Firewall
> appliance for small enterprises (10–500 users), branch offices, MSPs, and hospitality.
> It competes on **price, UX, and transparency** — not on proprietary security-engine
> depth — using Debian 13 + nftables/eBPF + Suricata + nDPI + WireGuard under a modern
> API-first console. Known gaps (URL filtering depth, AV quality, sandbox sophistication)
> are documented honestly and compensated over a 24-month phased roadmap.

Source spec: `upload/Cryptsk_UTM_Optimized_Spec (1).md` — **ground truth for product facts**
(features, phases, pricing, honest gaps). These docs govern build contracts and current
state; where they deviate from the spec, the deviation is documented (ADR in
`../00-PROJECT-MEMORY/DECISIONS.md` or the divergence notes in [ROADMAP.md](ROADMAP.md) §5).
Related: [ROADMAP.md](ROADMAP.md) ·
[../02-ARCHITECTURE/ARCHITECTURE.md](../02-ARCHITECTURE/ARCHITECTURE.md) ·
[../00-PROJECT-MEMORY/GLOSSARY.md](../00-PROJECT-MEMORY/GLOSSARY.md) (vocabulary)

---

## 1. What Cryptsk Is

| Field | Value |
|---|---|
| Product name | Cryptsk UTM / NGFW |
| Console deliverable (this repo) | Cryptsk Console — Next.js 16 web management dashboard |
| Category | Unified Threat Management + Next-Gen Firewall |
| Target market | Small enterprises (10–500 users), branch offices, MSPs, hospitality |
| Throughput target | 1–10 Gbps per appliance on commodity x86_64 |
| OS / data plane | Debian 13 (Trixie), nftables + eBPF/XDP + Suricata + nDPI + tc (ADR-001, ADR-003) |
| VPN stack | WireGuard (kernel-native), StrongSwan IKEv2, OpenVPN |
| Network services | Unbound (DNS), Kea (DHCP), Squid/Coraza (proxy/WAF, Phase 2), FreeRADIUS, FRR |
| Control plane | Database-driven config (PostgreSQL on appliance), Go API + config generators + agent |
| Delivery | Software (Community/Professional/Enterprise/MSP) + pre-built hardware appliance |

Phase 1 delivers a deployable UTM: firewall, NAT, IPS, VPN, DNS security, DHCP,
identity, QoS, logging, HA, REST API. Phases 2–4 add SSL inspection, WAF, SD-WAN,
AI detection, and multi-site/SASE capabilities (see [ROADMAP.md](ROADMAP.md)).

### 1.1 Capability Snapshot (end of Phase 1)

| Capability group | Included |
|---|---|
| Perimeter security | Zone-based firewall, address/service/schedule objects, GeoIP + FQDN + app-aware rules, connection/rate limits, SYN-flood protection |
| NAT | SNAT/masquerade, DNAT/port-forward, 1:1, hairpin, exemption (no-NAT) |
| Intrusion prevention | Suricata inline (nftables NFQUEUE — see ADR-003), Emerging Threats free rules, policy profiles, exceptions/thresholds/suppression |
| VPN | WireGuard site-to-site + remote access, IPSec IKEv2 (StrongSwan), OpenVPN SSL VPN, client bundles, session management |
| DNS / DHCP | Unbound resolver with RPZ filtering, sinkhole, custom records, DoT; Kea pools, reservations, leases |
| Identity | Local users/groups, RADIUS/AD integration, captive portal (clickthrough/credentials/voucher), password/lockout policy |
| QoS | HTB + FQ_CoDel shaping, DSCP marking, per-interface/user/app rules, templates |
| Operations | Logging + live tail + reports, config versioning + diff + rollback, backup/restore, HA (VRRP active/passive), audit trail |
| Automation | Full versioned REST API, API keys, WebSocket realtime events, webhook event callbacks (spec Phase 1 custom engineering; the console build ships stubs — ROADMAP §2 divergence note) |

## 2. Target Market and Personas

| Persona | Profile | What they need from Cryptsk | Where the console serves them |
|---|---|---|---|
| Small enterprise admin | IT generalist or office manager, 10–200 users, no dedicated SOC | Works out of the box with sensible defaults; quick answers to "who/what is blocked" | Dashboard defaults, policy templates, wizard, simple rule editor |
| MSP operator | Manages 5–100 customer sites, remote, multi-tenant | Central visibility, per-tenant isolation, licensing per tenant, remote fleet ops | Multi-tenant schema (ADR-009), API keys, Phase 4 central manager |
| Hospitality IT | Hotels, cafés, campuses with guest Wi-Fi | Captive portal, vouchers, bandwidth caps, content filtering for guests | Captive portal profiles, guest vouchers, QoS templates (M07/M08) |

Small enterprise admins are **not security experts**. The product thesis: give them a
console that is dramatically easier than FortiOS/Sophos, with defaults that are safe
without tuning.

### 2.1 Console Experience Pillars

| Pillar | Promise |
|---|---|
| See it in 10 seconds | Dashboard answers "is the network OK and what is it doing" without navigating menus |
| Explain every drop | Any blocked flow is traceable to a rule/SID/policy in at most two clicks (logs ↔ rules ↔ objects) |
| Safe defaults | Seed policies follow least-privilege patterns (LAN→WAN allow, WAN→LAN implicit deny, DMZ isolated); templates per vertical |
| Touch-friendly | 44px targets, mobile-usable shell, dark-first UI — an admin should fix a firewall rule from a phone |
| Automatable | Everything the UI does is a documented REST call; API keys are first-class |

## 3. Differentiation vs Fortinet / Sophos

| Advantage | Fortinet / Sophos reality | Cryptsk position |
|---|---|---|
| Price / licensing | Per-user, per-feature, per-Gbps licensing; subscription renewals | No per-user licensing; free core + support contract; predictable edition pricing (§6) |
| WireGuard | WireGuard absent or second-class in commercial stacks | WireGuard-native (kernel module), first-class in VPN module (M05) |
| Modern UI | FortiOS/Sophos UIs are dense, legacy, inconsistent | Next.js 16 console designed mobile-first with 44px touch targets, dark default |
| API-first | Full API often gated behind higher tiers | Every UI action calls the same `/api/v1` REST API from day 1; API keys included |
| Transparency | Closed engines; telemetry; trust required | Open-source components; auditable; no telemetry, no data harvesting |
| No vendor lock-in | Proprietary config formats and ASICs | Standard protocols and formats (nftables, StrongSwan, WireGuard, FRR); export configs anytime |
| Hardware freedom | Vendor appliance or certified models | Any x86_64 hardware; three reference tiers (§7) |
| Feature velocity | 6–12 month commercial release cycles | Open-source component velocity + own console cadence |
| Multi-tenancy | Often an upsell | Multi-tenant from day 1 (schema-level), MSP edition later |

## 4. Honest Limitations and Mitigations

Stated with severity words (severity applies to competitiveness against commercial
vendors, not to fitness for the small-enterprise threat profile):

| Limitation | Commercial equivalent | Severity | Mitigation |
|---|---|---|---|
| URL filtering coverage ~60–70% of commercial categorization DB (aggregated free lists: StevenBlack, OISD, hagezi, … vs 300M+ domain commercial DBs) | FortiGuard Web, Sophos Web | Critical | Aggregate 5–8 free blocklists with categories; custom block/allow lists; AI-based uncategorized-URL classification (Phase 3); optional paid categorization API for customers who need more |
| AV engine quality: ClamAV is signature-only, ~60–70% effective | Fortinet AV, Sophos LiveProtect | Critical | Do not compete on file-scanning AV; rely on Suricata IPS + behavioral detection + sandbox (Phase 3); recommend endpoint AV as a separate product |
| Sandbox sophistication: Cuckoo + YARA + AI ≈ 50–60% of commercial zero-day catch rate | FortiSandbox, Sophos Sandstorm | Medium | Accept for small-enterprise threat profile; weight behavioral IPS + anomaly detection over detonation; human-in-the-loop feedback |
| Application control granularity: nDPI ~300 protocols vs 7000+ apps | Fortinet App Control | Medium | Top 50–100 apps (YouTube, Netflix, Facebook, BitTorrent, Zoom, Teams) well covered; most small sites need fewer than 20 app rules; no sub-app granularity ("allow video, block chat") |
| IPS signature coverage: Emerging Threats (free) vs ET Pro / vendor research | ET Pro, Fortinet IPS | Medium | Category tuning, custom rules, threshold/suppression workflows (M04); AI false-positive reduction (Phase 3) |
| DLP depth: regex + keyword matching only; no EDM/IDM fingerprint matching | Symantec DLP, Forcepoint | Medium | Position as pattern-based DLP (cards, SSN, keywords); file-type control; incident workflow |
| Threat intelligence depth: free feeds (Abuse.ch, AlienVault OTX, Spamhaus), no 24/7 SOC research team | Recorded Future, Mandiant | Medium | Free feeds cover the threats small enterprises actually face; AI-assisted triage |
| Cold-start AI: no training data until units are deployed | Vendor billion-flow datasets | Medium | Rule-based + statistical detection first; models trained on public datasets (DGA) then own traffic after 3–6 months deployed |
| Browser isolation (RBI) | Menlo Security, Cloudflare | Not applicable | Dropped — not feasible with open source; documented as out of scope |
| Endpoint agent / integration | FortiClient, Sophos Endpoint | Not applicable | Dropped — separate product; partner with existing endpoint solutions |

## 5. Where the Gaps Do Not Matter for Small Enterprises

| Commercial "requirement" | Why it does not matter here |
|---|---|
| 40–100 Gbps throughput | Small enterprises run 1–5 Gbps; eBPF + nftables handles 10 Gbps on commodity hardware |
| 7000+ application signatures | The apps users care about blocking (YouTube, Facebook, Netflix, BitTorrent, gaming) are all nDPI-covered |
| Zero-day sandbox catch rate above 90% | Small enterprises are not APT targets; Suricata + good firewall rules + DNS security covers the overwhelming majority of their threat surface |
| 24/7 SOC-backed threat research | Product is self-managed; admins get alerts and respond; AI assists triage |

## 6. Editions and Pricing

| Edition | Price | Includes |
|---|---|---|
| Community | Free | All Phase 1 features; no SLA; community support |
| Professional | $99–199 / appliance / month | Phase 1 + Phase 2 features; email support; update channel |
| Enterprise | $299–499 / appliance / month | All features; priority support; SLA; training |
| MSP | Per-tenant pricing | Central management, white-label, per-tenant billing |
| Hardware appliance | Hardware cost + edition | Pre-built appliance (Supermicro / Intel NUC class) with Cryptsk pre-installed |

License management UI is deferred to Phase 2 (the business model must exist first —
spec §1.14 cut list). Pricing figures are the spec's strategy suggestion, not a
committed price book.

## 7. Hardware Tiers (Reference Builds)

| Tier | Users | Throughput | CPU | RAM | Storage | NIC | Approx cost |
|---|---|---|---|---|---|---|---|
| Starter | 10–50 | 500 Mbps | Intel i3 / AMD Ryzen 3 (4C/8T) | 8 GB | 128 GB SSD + 500 GB HDD (logs) | 2x 1GbE | $300–500 |
| Standard | 50–200 | 2 Gbps | Intel i5 / AMD Ryzen 5 (6C/12T) | 16 GB | 256 GB SSD + 1 TB HDD (logs) | 4x 1GbE | $600–1000 |
| Performance | 200–500 | 5–10 Gbps | Intel Xeon E / AMD Ryzen 7 (8C/16T) | 32 GB | 512 GB NVMe + 2 TB HDD (logs) | 2x 10GbE + 4x 1GbE | $1500–3000 |

NIC guidance (from spec): Intel i225 (1GbE) and Intel X710 (10GbE) have the best Linux
eBPF/XDP support; avoid Realtek NICs in production; for 10 Gbps prefer Intel X710 or
Mellanox ConnectX-4/5.

## 8. Key Principles

| Principle | Meaning |
|---|---|
| Compete on UX, not security depth | A console 10x easier than FortiOS is a genuine advantage; small-enterprise admins want working defaults, not knobs |
| Open source is the advantage | Fortinet/Sophos invest millions in proprietary engines; we integrate the best free ones and sell integration + price + transparency |
| API-first, always | Every console action is a REST call; automation and MSP tooling come free |
| Honesty with customers | Limitations (§4) are stated in sales conversations; trust is the product |
| AI is a marathon | Start rule-based + statistical; add ML only when deployed units produce training data; 3 models in Phase 3, more later |
| 24-month roadmap, not 6 | Phase 1 alone (6 months) yields a deployable product; each phase stands on its own |

## 9. Where to Go Next

| Topic | Doc |
|---|---|
| Phased feature plan + console build status tracker | [ROADMAP.md](ROADMAP.md) |
| System architecture (dual-mode, container diagrams) | [../02-ARCHITECTURE/ARCHITECTURE.md](../02-ARCHITECTURE/ARCHITECTURE.md) |
| Packet pipeline deep dive | [../02-ARCHITECTURE/DATA_PLANE.md](../02-ARCHITECTURE/DATA_PLANE.md) |
| Config/control flow deep dive | [../02-ARCHITECTURE/CONTROL_PLANE.md](../02-ARCHITECTURE/CONTROL_PLANE.md) |
| Auth/RBAC design | [../07-SECURITY/AUTH_AND_RBAC.md](../07-SECURITY/AUTH_AND_RBAC.md) |
| Full product spec (source of truth for WHAT) | `upload/Cryptsk_UTM_Optimized_Spec (1).md` |

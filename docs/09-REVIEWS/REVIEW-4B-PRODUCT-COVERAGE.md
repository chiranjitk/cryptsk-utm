# REVIEW-4B — Product-Level Spec Coverage (Phase 2–4 + §2–§9 Facts)

> **Lane:** Product Assurance 4B · **Date:** 2026-11-05 · **Auditor:** Senior Product Assurance
> **Rule under audit:** owner **ZERO-FEATURE-LOSS** ruling (2026-11-05): nothing in
> `docs/SPEC.md` (1562 lines) may be missing from the doc suite.
> **Scope of this lane:** product-level coverage of ALL spec Phase 2/3/4 features and the
> §2–§9 product facts, as reflected in ROADMAP.md, PRODUCT_OVERVIEW.md, PROJECT_MEMORY.md
> (§1–§5, §9–§14), GLOSSARY.md, DECISIONS.md, README.md.
> **Out of lane (untouched, per task):** module docs, SCHEMA, ENDPOINTS, FRONTEND,
> ARCHITECTURE, SECURITY docs (lane 4A), PROJECT_MEMORY §6–§8 and §15, no new ADRs.

---

## (a) Method

1. Read `docs/SPEC.md` in full (3 passes over 1562 lines) and extracted:
   - the **Phase 2 workstreams** (§2.1–2.13, months 7–12), **Phase 3** (§3.1–3.6, months
     13–18) incl. the AI-infrastructure table and the "deferred to Phase 4+" model list,
     and **Phase 4** (§4.1–4.6, months 18–24+);
   - every **"Cut from original … (Phase N)"** bullet in the Phase 1 tables (these are
     Phase 2/3/4/deferred commitments and must not vanish);
   - the **§2 OS analysis**, **§3 tech stack**, **§4 architecture**, **§5 phase timing**,
     **§6 honest-gap summary**, **§7 schema sketch**, **§8 competitive positioning +
     pricing**, hardware recommendations, and the six **FINAL NOTES**.
2. Read each assigned file end-to-end and built a coverage matrix
   (feature/fact → covered where → status → fix needed).
3. Verified phase **numbering and months** alignment (P1 1–6, P2 7–12, P3 13–18,
   P4 18–24+) — all consistent between SPEC.md and ROADMAP §1.
4. Fixed gaps **in place with minimal edits**, keeping the honest-gaps narrative intact
   (no overclaiming; Phase 2–4 rows are product commitments with design explicitly
   deferred to phase start — no schema/endpoints invented for them).
5. Rewrote the ROADMAP §5 console-deferral row per the owner ruling (section (d)).

---

## (b) Phase 2 / 3 / 4 Feature Coverage Matrix

Legend: **OK** = already covered, no edit · **FIXED** = gap found, fixed this pass ·
Where = primary doc locations post-fix.

### Phase 2 — Growth (spec §2, months 7–12)

| Spec area | Feature set | Where covered | Status | Fix applied |
|---|---|---|---|---|
| 2.1 SSL/TLS inspection | MITM proxy, TLS 1.2/1.3, selective bypass, pinning/HSTS handling, error policy, cert-expiry monitoring, CRL/OCSP, root CA export | ROADMAP §1 + §1.1 row 2.1; PRODUCT_OVERVIEW §1 + phase paragraph; GLOSSARY (SSL/TLS inspection, MITM/SSL bump, HSTS, Step-CA, OCSP/CRL); PROJECT_MEMORY §3 (Step-CA) | FIXED | ROADMAP 2.1 row was missing SSL error-handling policy, cert-expiry monitoring, CRL/OCSP — added |
| 2.2 App control (enhanced) | Block/allow by nDPI app, per-app bandwidth, unknown-app policy, SaaS detection (partial), ~300-protocol honest scope | ROADMAP §1.1 row 2.2; PRODUCT_OVERVIEW §4 (300 vs 7000+ row, no sub-app granularity); GLOSSARY (nDPI) | OK | — |
| 2.3 Web security / URL filtering | Explicit+transparent proxy, category blocking via aggregated free lists, custom lists, safe search, file-type control, HTTPS inspection; **honest scope ≈60–70% of commercial DBs** | ROADMAP §1.1 row 2.3; PRODUCT_OVERVIEW §4 (critical-gap row + §5); GLOSSARY (RPZ feed/blocklist) | FIXED | ROADMAP 2.3 row now states the 60–70% figure, custom block/allow lists, HTTPS inspection |
| 2.4 WAF | Reverse proxy, OWASP CRS, anomaly scoring, FP exclusions, custom rules, rate limiting, per-vhost policies, geo-blocking, learning mode, basic API protection | ROADMAP §1.1 row 2.4; GLOSSARY (WAF, CRS, Coraza) | FIXED | ROADMAP 2.4 row was missing rate limiting, geo-blocking, API protection — added |
| 2.5 SD-WAN (basic) | SLA monitoring (latency/jitter/loss), SLA thresholds, app-aware path selection, path scoring, hub-spoke, per-path stats, QoS integration, brownout handling, overlay encryption — *entirely custom, hardest Phase 2 build (spec)* | ROADMAP §1.1 row 2.5; GLOSSARY (SD-WAN, SLA probe) | FIXED | ROADMAP 2.5 row now names per-path stats + overlay encryption and carries the "hardest Phase 2 build, entirely custom" honesty note |
| 2.6 Dynamic routing | BGP (v4+v6), OSPFv2/v3, route maps, prefix lists, community lists, BFD, graceful restart | ROADMAP §1.1 row 2.6; GLOSSARY (BGP, OSPF, BFD — added) | FIXED | Added community lists to the row; added BGP/OSPF/BFD/VRF/VXLAN glossary terms |
| 2.7 IPv6 dual-stack | v6 firewall, NPTv6, routing, DHCPv6, v6 VPN, v6 QoS, SLAAC | ROADMAP §1.1 row 2.7; GLOSSARY (NPTv6, SLAAC, DHCPv6 — added) | FIXED | Glossary terms added (workstream row was already complete) |
| 2.8 Email security (basic) | SMTP proxy, anti-spam, anti-phishing, DKIM/SPF/DMARC, routing rules, blocked extensions, ClamAV attachment scan; *honest gaps: no attachment sandbox, no click-time URL rewrite, no archiving/continuity* | ROADMAP §1.1 row 2.8; GLOSSARY (Postfix/Rspamd/ClamAV, DKIM/SPF/DMARC — added) | FIXED | ROADMAP 2.8 row was missing routing rules + blocked extensions + the honest-gap note — added |
| 2.9 Advanced identity | SAML 2.0, OIDC, RADIUS CoA, dynamic VLAN, Kerberos/NTLM (incl. constrained delegation), user activity timeline | ROADMAP §1.1 row 2.9 + §5 identity row (extended); GLOSSARY (SAML 2.0, OIDC, Kerberos/NTLM — added) | FIXED | §5 identity row now lists Kerberos-NTLM incl. constrained delegation + user activity timeline; glossary terms added |
| 2.10 NAC (basic) | 802.1X, MAB, dynamic VLAN, device profiling, rogue detection, BYOD onboarding | ROADMAP §1.1 row 2.10; GLOSSARY (NAC, BYOD — added; 802.1X/MAB/CoA/Dynamic VLAN already present) | FIXED | Glossary terms added (workstream row complete) |
| 2.11 Threat intelligence | Feed ingestion (Abuse.ch/OTX/Spamhaus), IOC management, reputation scoring, auto-block, STIX/TAXII | ROADMAP §1.1 row 2.11; GLOSSARY (IOC, STIX/TAXII); PRODUCT_OVERVIEW §4 (threat-intel depth row) | OK | — |
| 2.12 PKI / certificates | Internal CA (root+subordinate), lifecycle/ACME, OCSP/CRL, auto-renew, export | ROADMAP §1.1 row 2.12; PRODUCT_OVERVIEW §1 (new "Phase 2+ security services" row); GLOSSARY (Step-CA, OCSP/CRL — added) | FIXED | Glossary + overview rows added |
| 2.13 Enhanced logging | Full-text search, CEF/LEEF, compliance templates (PCI/HIPAA/GDPR), anonymization, scheduled reports, executive summaries | ROADMAP §1.1 row 2.13 + §5 row (extended); PROJECT_MEMORY §3 (ClickHouse/Meilisearch noted) | FIXED | Executive summary reports were missing from both the 2.13 row and §5 — added |

**Phase 2 deferrals originating from Phase 1 "cut" lists** (all must appear with a phase
tag): ROADMAP §5 now carries every one of them after this pass. Newly added/extended §5
rows: firewall rule versioning + asymmetric-routing + fragment policy + per-tenant rule
count limits; IPS stream-reassembly/protocol-decoding UIs; DNS failover/LB + DNS
rewriting + DHCP client classification; QoS per-class dashboard + burst allowance;
log-integrity hash chain + executive summaries; Vault + change-approval + license
management; VRF/route-leaking + ring redundancy; NAT with route-map; dashboard threat
heatmap (P2). Previously present (verified): BGP/OSPF, DNSSEC, DHCP failover,
SSO/SAML/OIDC, RADIUS CoA/VLAN, L2TP/VPN LB, post-connect hooks, JA3/JA4, PCAP-on-match
+ dry-run, blackhole/mirror, bond tuning, API sandbox + idempotency keys, VRF/VXLAN/
MACVLAN/MACsec/QinQ/ERPS, PPPoE-server/cellular/satellite, LUKS, Snap.

### Phase 3 — Intelligence (spec §3, months 13–18)

| Spec area | Feature set | Where covered | Status | Fix applied |
|---|---|---|---|---|
| 3.1 AI engine — 3 models | DGA detection (high feasibility), network anomaly UEBA-lite (medium), encrypted-traffic classification via JA3/JA4+flow features (medium) | ROADMAP §1.1 phase row + §1.2 row 3.1 (feasibility notes); GLOSSARY (DGA, UEBA, ONNX Runtime — ONNX added); PRODUCT_OVERVIEW §8 ("3 models in Phase 3") | FIXED | ONNX Runtime glossary term added; ROADMAP §1.2 deferred-model list completed (see below) |
| 3.1 AI infrastructure | scikit-learn features, PyTorch offline training, ONNX inference served by Go, model registry (PostgreSQL), confidence thresholds, human-in-the-loop, drift detection | ROADMAP §1.2 AI-infrastructure note; PROJECT_MEMORY §3 (ONNX/PyTorch added to appliance stack) | FIXED | PROJECT_MEMORY §3 appliance-stack note extended |
| 3.1 deferred models | C2 beaconing, lateral movement, phishing NLP, **malware classification (sandbox results)**, IPS FP reduction, DLP NLP, config anomaly, **capacity prediction** | ROADMAP §1.2 note ("Eight further models…") | FIXED | Note now names all 8 (previously truncated with "…") and ties 6 of them to spec §4.5 |
| 3.2 ATP sandbox | Cuckoo detonation, YARA scanning, Suricata file extraction, auto-quarantine, sandbox reports; *honest scope ≈50–60% of commercial quality* | ROADMAP §1.1 phase row + §1.2 row 3.2; PRODUCT_OVERVIEW §4; GLOSSARY (ATP, YARA, Cuckoo Sandbox — Cuckoo added) | FIXED | Cuckoo glossary term added (with the 50–60% honesty figure) |
| 3.3 DLP | Regex patterns (cards/SSN/email/phone/IBAN), Aho-Corasick keywords, file-type control, protocol-aware scanning, incident workflow, user notification, severity levels, granularity; *no EDM/IDM, no OCR, NLP deferred* | ROADMAP §1.2 row 3.3 (honest "No EDM/IDM" note); PRODUCT_OVERVIEW §4 DLP row | OK | — |
| 3.4 DNS tunneling detection | Entropy-based detection, volume/frequency analysis, DGA model correlation | ROADMAP §1.2 row 3.4; GLOSSARY (DNS tunneling, DGA) | OK | — |
| 3.5 Incident response (basic) | Incident creation from alerts, workflow (new→investigating→resolved), timeline, manual block/quarantine, assignment | ROADMAP §1.2 row 3.5 | OK | — |
| 3.6 IoT device management | Fingerprinting (OUI/DHCP/nDPI), inventory, rogue detection, quarantine, risk scoring | ROADMAP §1.2 row 3.6 | OK | — |
| Phase 3 deferrals | Active/Active HA + IPS state sync; SSL P3 cuts (client-cert auth/mTLS, per-tenant CA trust store, unsupported-cipher UI); WAF P3 cuts (bot management, API schema validation, virtual patching); custom report builder; AI URL categorization; DPDK/AF_XDP; dashboard AI risk + posture scores | ROADMAP §5 (new rows this pass; Active/Active row pre-existing) | FIXED | 5 new §5 rows + dashboard-score row added; DPDK/AF_XDP and custom-report-builder/AI-URL-categorization rows added |

### Phase 4 — Platform (spec §4, months 18–24+)

| Spec area | Feature set | Where covered | Status | Fix applied |
|---|---|---|---|---|
| 4.1 Multi-site central manager | Central dashboard, policy push, log aggregation (ClickHouse), firmware management, site templates, per-site limits | ROADMAP §1.1 phase row + §1.3 row 4.1; GLOSSARY (Central Manager — added); PRODUCT_OVERVIEW §2 (MSP persona → Phase 4 central manager) | FIXED | Central Manager glossary term added |
| 4.2 SASE basics | Cloud firewall nodes (same codebase in cloud VM), central controller, WireGuard mesh, identity-aware routing; *full-SASE framing note* | ROADMAP §1.1 phase row + §1.3 row 4.2 + framing note under §1; GLOSSARY (SASE) | OK | — |
| 4.3 CASB basics | SaaS visibility via nDPI, shadow-IT detection, API controls for top 5–10 SaaS (Google, Microsoft, Salesforce, Dropbox, Slack); *full-CASB note* | ROADMAP §1.3 row 4.3; GLOSSARY (CASB) | OK | — |
| 4.4 ZTNA basics | Identity-based access (user→resource), basic device posture checks, continuous re-validation | ROADMAP §1.3 row 4.4; GLOSSARY (ZTNA) | OK | — |
| 4.5 Advanced AI (6 models) | C2 beaconing, lateral movement (graph), phishing NLP, IPS FP reduction, DLP NLP, config anomaly | ROADMAP §1.3 row 4.5; GLOSSARY (C2 beaconing) | OK | — |
| 4.6 SOAR integration | Webhook triggers, REST integration with Cortex XSOAR / Splunk SOAR, basic response playbooks | ROADMAP §1.3 row 4.6 + §5 row ("SOAR playbooks, threat hunting UI — Phase 4"); GLOSSARY (SOAR) | OK | — |
| Threat hunting UI | Phase 4 (spec §3.5 cut note) | ROADMAP §5 row 262 | OK | — |

**Phase/month alignment:** verified — ROADMAP §1 shows P1 1–6, P2 7–12, P3 13–18,
P4 18–24+, matching SPEC.md §5 headers exactly. **Phase 2–4 rows deliberately carry
honest capability scope only** (no schema/endpoints/UI design) — ROADMAP §1 now states
this scope rule explicitly ("design deferred to each phase's start"), so the absence of
design detail is documented policy, not a coverage gap.

---

## (c) §2–§9 Fact-Coverage Matrix

| Spec fact | Where reflected | Status | Fix applied |
|---|---|---|---|
| §1 Product facts (name, category, 10–500 users, 1–10 Gbps, differentiation, honest limitation) | PRODUCT_OVERVIEW §1/TL;DR; PROJECT_MEMORY §1; README §1 | OK | — |
| §2 OS selection rationale | DECISIONS ADR-001 (accepted); PRODUCT_OVERVIEW §1 **OS rationale** row; ROADMAP §5 Snap row | FIXED | PRODUCT_OVERVIEW now carries the full rationale: Ubuntu 24.04 close second, Rocky/Alpine not recommended, FreeBSD disqualified, Debian 12 fallback, pfSense-CE/OPNsense lineage |
| §3 Tech stack (Go Gin/Fiber, Next.js, PostgreSQL, Redis, ClickHouse/Meilisearch v2, Prometheus+Grafana+node_exporter, ONNX Runtime, PyTorch offline, scikit-learn, Step-CA, Coraza/Caddy, Postfix/Rspamd/ClamAV; Java→Go, Kafka→Redis, TF→ONNX, Netdata→Prometheus, 10–100G→1–10G) | PROJECT_MEMORY §3; PRODUCT_OVERVIEW §1; ROADMAP §5 Superseded rows; DECISIONS ADR-002/003/010 | FIXED | PROJECT_MEMORY §3 appliance-stack note extended with the full Phase 2–4 stack; PRODUCT_OVERVIEW §1 gained "Phase 2+ security services" and "AI / observability" rows |
| §4 Architecture (XDP→nftables→conntrack→TPROXY→nDPI→Suricata→tc; DB-driven config; Redis pub/sub; AI layer) | ARCHITECTURE/DATA_PLANE/CONTROL_PLANE (2A lane — verified present, not edited); PRODUCT_OVERVIEW §1 control-plane row; ADR-003/004 | OK | — |
| §5 Phase timing (months) | ROADMAP §1 | OK | — |
| §6 Honest gaps (URL 60–70%, ClamAV 60–70%, sandbox 50–60%, nDPI ~300, ET free vs ET Pro, no EDM/IDM, free feeds, RBI dropped, endpoint agent dropped, cold-start AI) | PRODUCT_OVERVIEW §4 (all 10 rows, same severities) + §5 (4 "doesn't matter" rows); ROADMAP §5 (RBI/endpoint-agent rows); GLOSSARY (ClamAV/Cuckoo percentages) | OK | — |
| §7 DB schema sketch | SCHEMA.md + ER_DIAGRAM (2B lane — verified consistent; `ips_logs`→`ips_events` handled by ADR-015); Phase 2+ table list = design deferred to phase start (documented) | OK | — |
| §8 Competitive positioning (9 win rows vs Fortinet/Sophos; lose rows with mitigations; pfSense/OPNsense context) | PRODUCT_OVERVIEW §3 (win) + §4/§5 (lose + "doesn't matter") | FIXED | pfSense/OPNsense lineage clause added to the OS-rationale row (was only in spec §2) |
| §8 Pricing (Community free / Professional $99–199 / Enterprise $299–499 / MSP per-tenant / hardware pre-built) | PRODUCT_OVERVIEW §6 (exact figures + "spec strategy suggestion, not a committed price book" + license-UI Phase 2 note) | OK | — |
| Hardware tiers (Starter $300–500 / Standard $600–1000 / Performance $1500–3000; Intel i225/X710, Mellanox; avoid Realtek) | PRODUCT_OVERVIEW §7 (full table + NIC guidance) | OK | — |
| FINAL NOTES (24-month roadmap; open-source advantage; AI marathon; URL-gap + Webshrinker hybrid; Go not Java; UX over depth) | PRODUCT_OVERVIEW §8 Key Principles (all 6); §4 mitigation (optional paid categorization API); ADR-002 + ROADMAP §5 (Go) | OK | — |

Also updated: **README.md** — the doc-map now states the zero-loss rule over the WHOLE
spec (Phase-1 items via SCHEMA/ENDPOINTS/module docs; Phase 2–4 + §2–§9 facts via
ROADMAP/PRODUCT_OVERVIEW/memory docs), and §4.1 gained the two coverage lanes:

| Doc group | Review | Status |
|---|---|---|
| Spec coverage — Phase 1 zero-loss (module docs, SCHEMA, ENDPOINTS; console-deferred features restored) | Product assurance (4A) | In progress — owner zero-feature-loss ruling 2026-11-05; coordinator finalizes |
| Spec coverage — Phase 2–4 features + §2–§9 product facts | Product assurance (4B) | In progress — see this report; coordinator finalizes |

---

## (d) ROADMAP §5 Restoration Edits (owner ruling, REVIEW-4A reference)

1. **The "console-deferred spec-Phase-1" row was rewritten.** Old row deferred LLDP,
   IGMP snooping, MAC table, SPAN, L2/L3 toggle, PBR, BFD, IPS auto-update/presets, VPN
   user groups, session-limit UIs to "Console Phase 2 (build decision)". New row reads:
   > **Spec-Phase-1 features formerly deferred by the console build:** policy-based
   > routing (PBR), DHCP relay, conditional forwarding, basic DHCPv6, per-user/per-app
   > bandwidth hard limits, LLDP neighbor view, IGMP snooping, MAC table,
   > SPAN/port-mirroring, L2/L3 mode toggle, BFD route monitoring, IPS auto-update
   > scheduler UI + one-click preset profiles, VPN user groups, per-user/per-group
   > session-limit & timeout UIs → **RESTORED to Phase 1 per owner zero-feature-loss
   > ruling (2026-11-05, REVIEW-4A)** — no build-down of spec Phase 1 scope is
   > permitted; detailed implementation lives in the module docs
   > (M02/M03/M04/M05/M06/M08), see REVIEW-4A.
   (DHCP relay, conditional forwarding, and basic DHCPv6 — named in the ruling's list —
   were already mapped to M06 in ROADMAP §2; they are now explicit in the restored row.)
2. **§5 preamble** now records the exception convention: restored items carry the ruling
   reference instead of a new ADR.
3. **§5 closing paragraph** now states that owner-ruling restorations are mandated
   re-adds, not discretionary re-introductions, and need no new ADR.
4. **ROADMAP §1.4 exit-criterion 1** updated: former console-level deferrals were
   RESTORED to Phase 1 — Phase 1 exit requires them to ship.
5. **ROADMAP §1** gained the Phase 2–4 scope rule (zero loss, honest scope, design
   deferred to phase start).
6. PROJECT_MEMORY §2 and README §4.1 now carry the in-progress 4A/4B audit status;
   PRODUCT_OVERVIEW and GLOSSARY untouched by the restoration (no deferral text there).

---

## (e) Flagged Items for Coordinator

1. **ADR-018 needed (owner ruling record).** DECISIONS.md is append-only and no new ADRs
   were created in this lane. Recommend the coordinator either accept the ROADMAP §5
   "ruling-reference" convention (as now written) or author **ADR-018 — "Zero-feature-loss
   ruling: spec-Phase-1 features restored to Phase 1; no console build-down"** citing
   REVIEW-4A/4B.
2. **PROJECT_MEMORY §15 stale note.** The 2026-11-05 three-lane-review entry still says
   the console-deferred features "stay tracked in ROADMAP §5 with product sign-off
   required." That is now superseded by the restoration. §15 is coordinator-owned
   (not appended here) — please note the supersession in the next §15 entry.
3. **Two remaining build-level deferrals of spec-Phase-1 scope in ROADMAP §5** (not
   restored — outside this lane's explicit instruction): "Scheduled reports + PDF/HTML
   rendering → Phase 2 (build decision)" and "Webhook real delivery/dispatch → Console
   Phase 2 (build decision)." Both carry documented divergence notes and Phase-1
   substitutes, but the coordinator should confirm whether the owner ruling extends to
   them (restore) or the documented divergences stand.
4. **Spec §1.14 "Service isolation via containers (can use systemd first)"** has no §5
   row or ADR. Spec §3 keeps Docker for appliance service isolation while Phase 1 uses
   systemd. Suggest a one-line §5 row or a Phase-2-start ADR.
5. **Phase-start decisions to record as ADRs when those phases begin** (flagged only):
   ClickHouse vs Meilisearch (spec §1.12/2.13); optional paid URL-categorization API
   (Webshrinker hybrid, spec FINAL NOTE 4); license-management/business model (spec
   §1.14 + PRODUCT_OVERVIEW §6); SD-WAN controller architecture (spec §2.5, hardest
   Phase 2 build).
6. **Minor, accepted:** spec §4.5 lists 6 advanced-AI models while §3.1's deferred list
   has 8 (adds "malware classification", "capacity prediction") — ROADMAP §1.2 now names
   all 8 and notes the §4.5 subset, so no fact is lost. Spec §8's competitor set is
   Fortinet/Sophos; pfSense/OPNsense/Untangle appear only in OS-selection context —
   PRODUCT_OVERVIEW now reflects that context; no separate competitor table exists in
   the spec to cover.

---

## (f) Attestation

I audited every Phase 2 (13 spec areas + all Phase-1 "cut to Phase 2/3" bullets),
Phase 3 (6 areas + AI infrastructure + 8 deferred models + Phase 3 cuts), and Phase 4
(6 areas) features of `docs/SPEC.md`, plus the §2–§9 product facts, against ROADMAP.md,
PRODUCT_OVERVIEW.md, PROJECT_MEMORY.md (§1–§5, §9–§14 only), GLOSSARY.md, DECISIONS.md,
and README.md. After the fixes recorded in sections (b)–(d), **every Phase 2/3/4 feature
row and every §2–§9 fact has a documented, correctly phase-tagged home in the doc suite,
with honest capability wording and no overclaiming**; the ROADMAP §5 deferral row now
reflects **RESTORATION to Phase 1** per the owner's zero-feature-loss ruling (2026-11-05,
REVIEW-4A). Edits were confined to the six assigned files; no module docs, SCHEMA,
ENDPOINTS, FRONTEND, ARCHITECTURE, or SECURITY docs were touched; PROJECT_MEMORY §6–§8
and §15 were not modified; no new ADRs were created (needs flagged in (e)).

— Senior Product Assurance Auditor, lane 4B, 2026-11-05

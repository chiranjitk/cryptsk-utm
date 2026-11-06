# REVIEW 2C — Solution Architecture / Product Strategy Review

> **Reviewer:** Senior Solution Design Architect & Product Strategist (UTM/NGFW/SASE background)
> **Date:** 2026-11-05 · **Lane:** product coherence, strategic consistency, decision integrity, terminology accuracy
> **Scope (assigned docs only):** `docs/README.md`, `00-PROJECT-MEMORY/` (PROJECT_MEMORY, DECISIONS, GLOSSARY), `01-PRODUCT/` (PRODUCT_OVERVIEW, ROADMAP), `06-MODULES/M02-NETWORK.md`, `M04-IPS.md`, `M05-VPN.md` (product/scope lens), `08-OPERATIONS/DEVELOPMENT_GUIDE.md`
> **Ground truth:** `docs/SPEC.md` (1562 lines, read in full). Spec wins on contradictions unless a doc has a sound, explicitly-justified improvement.

---

## (a) Executive Summary

The documentation suite is **architecturally sound and unusually disciplined** for a pre-code project: the memory pack, locked contracts, ADRs, module specs, and honest-gap positioning are all present and mostly spec-faithful. Phase boundaries, pricing, hardware tiers, honest limitations, the 3-model AI scope, and the 8-role RBAC list are all correctly carried over from the spec.

The review found **15 issues (4 CRITICAL, 6 MAJOR, 5 MINOR)**. None required a strategy change; all were fixed in place. The dominant failure mode was **stale contract references after the 2026-11-05 "contract reconciliation pass"** — module docs (M02/M04/M05) still described gaps that had already been resolved elsewhere (PPP password, `vpn:status` event, `?category=` param, suppress-`forever` semantics), which would have caused future AI agents to re-implement, block, or build against the wrong contract. The second failure mode was **authority inversion**: three docs claimed "docs supersede the spec where they differ" without qualification, which is unacceptable for a doc set that future agents treat as the single source of truth. The third was **phase-attribution drift**: console build deferrals of spec-Phase-1 features were labeled "Phase 2 (spec)" in several places, which would silently shrink the product scope.

Post-fix state: all ten assigned documents are mutually consistent and spec-aligned. Cross-agent reconciliation items (§c) remain for the 04-API doc group (ENDPOINTS.md lags PROJECT_MEMORY on three pinned contracts) and for role/enum naming hygiene in doc groups not covered by this lane.

---

## (b) Issues Found and Fixed

Severity: **CRITICAL** = would cause an AI agent to build the wrong thing or contradict a locked contract · **MAJOR** = would corrupt scope, phase, or decision integrity · **MINOR** = misleading wording, accuracy, or completeness.

### CRITICAL

1. **README.md — §3 Documentation Map.** The `09-REVIEWS/` folder did not exist in the doc map at all, and there were no review-status labels; review findings were undiscoverable. **Fixed:** added `09-REVIEWS/` to the file tree (with this report), added a new **§4.1 Review Status** table marking this lane reviewed ✓ 2026-11-05 and other lanes pending, and added a "Verify a claim / check known doc issues → 09-REVIEWS" row to the §2 reading matrix. §5 status paragraph updated honestly (reviews performed; repo currently docs + scaffold only).

2. **M05-VPN.md — §8 first bullet (stale open question).** Claimed "No tunnel-state realtime event … a `vpn:status` event would be the clean fix — needs a PROJECT_MEMORY §7.3 decision before build." This directly contradicted M05 §6 (which consumes `vpn:status`), PROJECT_MEMORY §7.3 (event locked), and the session log ("Added `vpn:status` socket event"). An agent would have re-proposed a locked event or blocked on a decision already made. **Fixed:** stale bullet removed; §6/§7.3 are now the single source on tunnel-state delivery.

3. **M04-IPS.md — §3, §5, §8 (two contract contradictions).**
   (a) §3/§8 claimed `?category=` was "not yet in the locked param list" — PROJECT_MEMORY §7.2 already includes it. (b) §5/§8 claimed `forever` suppression stores "a far-future timestamp … pinned in ENDPOINTS.md" — ENDPOINTS.md actually pins `duration:"forever"` → `suppressedUntil = null` + `action = "suppressed"`. Both would have produced divergent implementations of the same API. **Fixed:** §3 param list updated to the locked set including `?category=`; §5 rewritten to the ENDPOINTS.md convention; §8 bullets converted to RESOLVED-with-pointer (ENDPOINTS.md mirroring still pending — see §c-1).

4. **M02-NETWORK.md — §2 + §8 (stale schema shape).** `NetworkInterface.config` (physical) showed `pppoe?: { user, service? }` with no password, while SCHEMA.md (post-reconciliation) defines `pppoe?: { user, password, service? }`; §8 still carried the resolved "PPP password storage" open question. **Fixed:** §2 shape updated to match SCHEMA.md verbatim; stale open question removed (§4 editor description already said "user/password/service" and is now consistent).

### MAJOR

5. **PROJECT_MEMORY.md — §1 "Full product spec" row.** Said "read once; docs here supersede it where they differ" — an unqualified authority inversion of the ground-truth spec. **Fixed:** spec is now stated as ground truth for product facts (features, phases, pricing, honest gaps); docs govern build contracts; every deviation must be documented (ADR or ROADMAP §5 divergence note) and "the spec wins on product facts unless an ADR explicitly justifies otherwise."

6. **PRODUCT_OVERVIEW.md — source-spec note.** Same supersession claim ("these docs supersede it where build contracts differ"). **Fixed** with the same qualified authority model (spec = WHAT, docs = HOW, deviations documented).

7. **ROADMAP.md — §2 row 1.15 + §5 (webhook phase misattribution).** Webhooks were labeled "webhooks (Phase 2)" and "webhook triggers | Phase 2 **(spec)**". The spec keeps webhook support in **Phase 1** (§1.15, 🟡 custom engineering; also referenced by Phase 4 §4.6 "Webhook triggers to external SOAR | Webhook (Phase 1 API)"). Attributing a spec phase that the spec does not assign is decision-integrity corruption. **Fixed:** §2 row corrected; a second spec-divergence blockquote added (console M11 ships the stub surface; real delivery deferred as a **build** decision; webhooks are NOT a Phase 2 product feature); §5 row split into "API sandbox console, idempotency keys | Phase 2 (spec)" and "Webhook real delivery/dispatch | Console Phase 2 (build decision)". PRODUCT_OVERVIEW §1.1 "webhooks (stubs)" wording aligned (issue 12 below).

8. **ROADMAP.md — §5 (console deferrals misattributed to spec phases) + M02/M04/M05 §1 (same class).** "IGMP snooping UI | Phase 2 **(spec)**" was wrong (spec §1.2 keeps IGMP snooping in Phase 1, ✅ Ready). Worse, several spec-Phase-1 items deferred by the console build (LLDP, MAC table, SPAN, L2/L3 mode toggle, PBR, BFD route monitoring, IPS auto-update scheduler UI, IPS one-click presets, VPN user groups, VPN session-limit/timeout UIs) were not tracked anywhere as build divergences — a future agent could conclude the product dropped them. **Fixed:** bond row corrected (bond tuning *is* spec Phase 2); a consolidated "Console Phase 1 UI deferrals (build decision, not a spec phase change)" row added to ROADMAP §5 naming every deferred item and stating the appliance-side spec scope is unchanged; M02 §1, M04 §1, M05 §1 rows reworded from "OUT — Phase 2" to "OUT of console Phase 1 (build decision, ROADMAP §5)" with explicit "spec keeps them Phase 1 appliance-side" where true. M05's "VPN user groups → Phase 2 (§2.9 Advanced Identity)" attribution (a phase the spec never assigns) corrected.

9. **DECISIONS.md — ADR-008 (incomplete locked-event list).** The realtime ADR listed "metrics:tick, logs:tail, alerts:new, sessions:update, wan:status, config:updated" — omitting `vpn:status`, which the reconciliation pass locked into PROJECT_MEMORY §7.3. An ADR describing a locked contract incompletely invites agents to "fix" one of the two. **Fixed:** `vpn:status` added to the ADR-008 event list. Also (minor) the header format line now records that alternatives are captured in Context (all 14 ADRs do this; ADR IDs ADR-001…ADR-014 verified sequential and correctly referenced from PROJECT_MEMORY §3/§4, ROADMAP, module docs).

10. **ROADMAP.md — missing measurable Phase 1 exit criteria.** The checklist gate "Phase 1 exit criteria measurable" existed only as per-milestone console DoD; the product-level gate was undefined. **Fixed:** added **§1.4 Phase 1 Exit Criteria (product)** — 9 measurable criteria derived strictly from spec §1.1–1.15 (default-denial firewall at boot, Suricata inline block demonstrably stopping a test attack, all three VPN types passing traffic, multi-WAN failover, Keepalived HA failover + conntrackd state preservation, RBAC matrix verification, wizard from factory defaults, all milestones DONE), flagged with an explicit Architect note that the spec defines no gate and this is the 2C review's proposal.

### MINOR

11. **GLOSSARY.md — accuracy and coverage.** (a) RBAC entry said "8 roles (super_admin … auditor)", visually dropping the 8th role `api_service` — replaced with the full enumerated list matching PROJECT_MEMORY §6 and AUTH_AND_RBAC. (b) "SASE / CASB" was one conflated row — split into accurate SASE (SD-WAN + SWG/CASB/ZTNA/FWaaS convergence; Phase 4 basics only) and CASB (SaaS visibility/shadow-IT/API controls) entries. (c) No IDS-vs-IPS entry although M04's mode semantics depend on the distinction — added (`passive` = IDS; `inline_drop` = the only blocking mode). (d) No "shadow rule" entry although M03/PROJECT_MEMORY §7.2 use it — added. (e) TPROXY definition ("redirects marked packets") was technically loose — replaced with the policy-routing-to-local-socket description. (f) Zone entry now explicitly names "zone-based firewall". Verified accurate, no change: XDP, conntrack, nDPI (~300), ET, VRRP/Keepalived, DGA, UEBA, ZTNA, SD-WAN, RPZ, sinkhole, NAT family, DPD/PFS.

12. **PRODUCT_OVERVIEW.md — §1.1 Automation row.** "webhooks (stubs)" understated the spec (Phase 1 webhooks are a custom-engineering feature, not a stub product). **Fixed:** "webhook event callbacks (spec Phase 1 custom engineering; the console build ships stubs — ROADMAP §2 divergence note)."

13. **PROJECT_MEMORY.md — §14 doc map.** Count ignored the new `09-REVIEWS/` folder. **Fixed:** count line now includes review reports.

14. **DEVELOPMENT_GUIDE.md — missing current-state statement.** Nothing told an agent that the repo currently hosts only docs + Next.js scaffold (no app code), or clarified the console-vs-appliance split (spec's Go control plane is out-of-repo and simulated here). **Fixed:** added a "Current repo state (2026-11-05)" note to the TL;DR: docs suite + scaffold only; M0+ build contract; explicit split-brain note (this repo = Next.js console UI+BFF; Go Gin/Fiber control plane per spec/ADR-002; simulated via ADR-004 adapter layer). Verified against reality: `package.json` (Next 16.1.1, no socket.io/jose/bcryptjs yet — matches §7's "not yet installed" list), scaffold Prisma `User`/`Post` + `env("DATABASE_URL")` (matches §2's warnings).

15. **DECISIONS.md — header format line.** "Format: Context → Decision → Consequences" did not say where alternatives live (the checklist requires alternatives considered per ADR; all ADRs put them in Context). **Fixed:** "Context (problem + alternatives considered)".

### Verified spec-faithful (no change needed)

- **Phase table** (§1) matches spec exactly: P1 months 1–6 exact scope; P2 7–12; P3 13–18 (3 models only: DGA / UEBA-lite / encrypted-traffic classification; ONNX Runtime inference; PyTorch offline); P4 18–24+ (central manager, SASE/CASB/ZTNA basics, SOAR). §1.2/§1.3 workstream tables trace to spec §2.x/§3.x. Eight deferred models in Phase 3 §3.1 match the spec's deferred list.
- **Pricing:** Community free / Professional $99–199 / Enterprise $299–499 / MSP per-tenant / hardware appliance — matches spec; "figures are the spec's strategy suggestion" caveat present. License-management Phase 2 deferral matches spec §1.14 cut list.
- **Hardware tiers:** Starter/Standard/Performance rows match the spec's table verbatim (users, throughput, CPU/RAM/storage, NIC, $300–500 / $600–1000 / $1500–3000); NIC guidance (Intel i225/X710, avoid Realtek for XDP, Mellanox for 10G) matches.
- **Honest gaps:** URL filtering ~60–70% (Critical), ClamAV ~60–70% signature-only (Critical), sandbox 50–60% (Medium), nDPI ~300 vs 7000+ (Medium), ET-free vs ET Pro, no EDM/IDM DLP, cold-start AI, RBI/endpoint-agent N/A — all match spec's gap summary; no marketing overclaims found; "compete on UX not security depth" positioning intact.
- **Personas** (SMB admin / MSP operator / hospitality) consistent with spec target market and captive-portal/QoS features.
- **Stack decisions:** Debian 13 (ADR-001), Go not Java/Spring (ADR-002), Redis Streams not Kafka (ADR-010), data-plane pipeline order matches spec (NIC → XDP → nftables → conntrack → TPROXY/Squid → nDPI → Suricata → tc), Prometheus + node_exporter + Grafana not Netdata (ROADMAP §5), Unbound/Kea/Squid/FreeRADIUS, WireGuard + StrongSwan IKEv2 + OpenVPN + FRR(P2), Coraza/Rspamd/Step-CA in Phase 2 — all consistent.
- **RBAC:** exact 8 role names used consistently in PROJECT_MEMORY §6 and referenced docs; the docs' `User.role` default `helpdesk` (replacing spec's self-inconsistent `DEFAULT 'viewer'` — 'viewer' is not in the spec's own role list) is a **sound, justified improvement**, retained.
- **Multi-tenant from day 1:** ADR-009 + tenant-scoped schema consistent with spec.
- **M04 product scope:** Phase 1 = Suricata inline/ET/categories/exceptions/thresholds/suppression ✓; threat-intel correctly OUT to Phase 2 §2.11; honest §8 limitation ("custom rules stored/echoed, never evaluated — simulation") present.
- **M05 product scope:** Phase 1 = WireGuard s2s+remote, IPSec IKEv2 (EAP-MSCHAPv2/EAP-TLS), OpenVPN, split tunnel, DPD, PFS, client bundles ✓; IKEv1/L2TP/SSTP correctly excluded per spec cut list; honest limitations (no real crypto, placeholder-grade `.ovpn`) present.

---

## (c) Items Needing Cross-Agent Reconciliation

Canonical values other doc groups must honor (flag if contradicted):

1. **ENDPOINTS.md (04-API): `GET /api/v1/ips/events` param list must become `?severity=&sid=&q=&since=&until=&category=&page=`** — the locked set in PROJECT_MEMORY §7.2 and M04 §3 now includes `?category=`; the ENDPOINTS.md row (line ~326) still shows the old set. (M04 §8 tracks it.)
2. **ENDPOINTS.md (04-API): pin that `PUT /api/v1/vpn/configs/{id}` ignores/keeps engine-owned `status`/`statusMessage`** (M05 §8 pending) — agents must never "set" tunnel status via PUT.
3. **ENDPOINTS.md (04-API): document the default-IPS-policy convention** for firewall rules without `ipsPolicyId` (first enabled policy by seed order — simulation-only determinism rule, M04 §5/§8).
4. **ENDPOINTS.md (04-API): pin the live-stats shape of `GET /api/v1/interfaces`** ("with live stats" — per-row `rxKbps/txKbps`?) vs. reliance on `metrics:tick` (M02 §8 pending).
5. **Canonical RBAC role names (8, exact):** `super_admin`, `tenant_admin`, `security_admin`, `network_admin`, `soc_analyst`, `helpdesk`, `auditor`, `api_service`. Default user role = `helpdesk`. The spec's `DEFAULT 'viewer'` is a spec bug; any doc using other names (e.g., "admin", "viewer", "operator") must be corrected to these.
6. **Webhooks phase label:** product = **Phase 1 (custom engineering)** per spec §1.15; console = M11 ships stubs (build decision). No doc may call webhooks a "Phase 2 product feature."
7. **Console-deferred spec-Phase-1 items (ROADMAP §5 consolidated row):** LLDP neighbor view, IGMP snooping, MAC table, SPAN/port-mirroring, L2/L3 mode toggle, policy-based routing, BFD route monitoring, IPS auto-update scheduler UI, IPS one-click preset profiles (seeded presets serve instead), VPN user groups, VPN per-user/per-group session-limit & timeout UIs. Appliance-side docs must keep these as spec Phase 1 scope.
8. **Suppress-`forever` convention:** `suppressedUntil = null` + `action = "suppressed"` (ENDPOINTS.md pinned; M04 §5 aligned). No far-future-sentinel implementations.
9. **notifications.type enum:** docs extend the spec's `threat, system, vpn, ha` with `config` — 03-DATABASE/SCHEMA.md and 05-FRONTEND doc owners should confirm they carry the same 5-value enum (deliberate additive deviation, PROJECT_MEMORY §6).
10. **Hardware tier naming:** spec tier names are **Starter / Standard / Performance** (prices $300–500 / $600–1000 / $1500–3000). If any doc says "Entry" tier, correct it to "Starter."
11. **Phase-label convention for module docs:** M01–M11 are **console Phase 1** modules implementing **product Phase 1**; "Phase 2" in module docs means *console* Phase 2 only where explicitly marked "(build decision, ROADMAP §5)". M02/M04/M05 §1 now follow this wording — other module docs (M01, M03, M06–M11, owned by other lanes) should be swept for the same "OUT — Phase 2 (spec)" misattribution pattern.
12. **Socket event set (7, locked):** `metrics:tick`, `logs:tail`, `alerts:new`, `sessions:update`, `wan:status`, `vpn:status`, `config:updated` — ADR-008 and PROJECT_MEMORY §7.3 now agree; SIMULATION_LAYER/mini-service docs should be verified against the same list.

---

## (d) Residual Risks / Open Questions

1. **Exit criteria §1.4 needs owner sign-off.** It is an Architect-note proposal, not a spec fact — especially criteria 2/5/6/8 (boot-time default deny, failover behavior, wizard), which depend on appliance-side engineering detail the spec leaves open.
2. **Simulation-drift risk (inherent to ADR-004).** The generator contracts (SIMULATION_LAYER §6) are the mitigation, but the appliance-side review lane must verify that generated `nftables`/Suricata/unbound config outputs are actually valid — M04 custom rules and M05 `.ovpn` bundles are placeholder-grade by documented design (honest disclaimers now mandatory in editor copy).
3. **M02 open questions remain open (by design):** `wan1` seeded-disabled enable path for failover demos; live-stats payload shape; centralizing probe-target defaults in validators.
4. **M04 residual:** suppress-vs-threshold events are indistinguishable in the table (accepted for Phase 1); default-policy convention needs ENDPOINTS documentation (§c-3).
5. **M05 residual:** generated peers mutate configs on repeated bundle downloads (suggest `generated: true` marker or Phase 2 peer-management UI); `ipsec_remote` EAP wiring is appliance-side (FreeRADIUS).
6. **`next-auth` remains in `package.json`** (scaffold) although ADR-007 chose custom JWT (jose). Harmless, but an agent could mistakenly reach for it — recommend deleting the dependency at M0 (build decision, needs a session-log justification per DEVELOPMENT_GUIDE §7).
7. **Pricing figures are the spec's suggestion**, not a committed price book — sales-facing docs must keep that caveat (PRODUCT_OVERVIEW §6 does).
8. **Untangle/pfSense/OPNsense competitive framing:** the spec's competitive analysis names only Fortinet/Sophos (pfSense/OPNsense appear only in the OS section). Docs correctly follow the spec; if product/marketing later adds open-source-competitor positioning, that is a new decision requiring an ADR.
9. **Hospitality vertical** has personas and features (captive portal, vouchers, QoS templates) but no dedicated vertical template doc; default policy templates "per vertical" are spec Phase 1 (🟡) — confirm coverage when M03/M07 seed templates are designed.

---

*Review performed 2026-11-05 by lane 2C. All fixes were applied in place with minimal surgical edits; structure preserved; no new features or decisions invented beyond the spec (proposals are flagged "Architect note").*

# REVIEW 2-B — Full-Stack Developer & Database Architect

> Reviewer scope: docs/03-DATABASE (3), docs/04-API (2), docs/05-FRONTEND (3),
> docs/06-MODULES M01/M03/M07/M09/M10/M11 (6) — 14 files, reviewed line-by-line against
> the product spec (`upload/Cryptsk_UTM_Optimized_Spec (1).md`, 1562 lines) and the
> LOCKED build contracts in PROJECT_MEMORY / DECISIONS (ADRs).
>
> Precedence used throughout: **PROJECT_MEMORY §"if this file and any other doc disagree,
> this file wins"** → spec for product-level facts → ADRs for accepted build-level
> deviations (SQLite/Prisma, hash views, socket.io, page pagination) → then internal
> consistency. Review date: 2026-11-05.

---

## (a) Executive summary

The doc suite is in good shape structurally: schema, API surface, views, and module specs
agree on the big picture (envelope, enums, view map, dual-mode architecture, phase
discipline — no Phase 2 tables leak into the Phase 1 schema). The real defects were
concentrated in five clusters:

1. **One schema-breaking bug** — `WanPolicy.interface` FK referenced the non-unique
   `interfaces.name` column (Prisma would refuse to `db:push`). Fixed with a compound FK
   matching `@@unique([tenantId, name])`.
2. **Multi-tenancy uniqueness holes** — three `@@unique` constraints were global instead
   of tenant/subnet-scoped (`dhcp_reservations.mac`, `dhcp_leases.ip`,
   `identity_sessions.sourceIp`), which would make cross-tenant collisions impossible to
   express and break MSP tenancy (ADR-009). Fixed to compound uniques.
3. **RBAC drift** — ENDPOINTS floors and the API_STANDARDS capability matrix contradicted
   the authoritative matrix in `07-SECURITY/AUTH_AND_RBAC.md` §4 (objects/DNS-policies
   owners inverted, VPN config vs VPN-session-ops split missing, api-key create/revoke
   role wrong, "L3 peer passes any L3 floor" rule over-granting). Reconciled all six
   assigned module/API docs to the authority, and replaced the broken peer-floor rule
   with an explicit "matrix wins over floors" precedence rule.
4. **Stale "gap/proposed expansion" notes** — six endpoint gaps had already been locked
   into PROJECT_MEMORY §7.2 (hits/reset, NAT toggle+reorder, vouchers, session-expire,
   export, backups download, read-all) but module docs still described them as missing
   or under different paths (`/radius-profiles/{id}/secret` vs locked `/reveal`;
   `{reachable,...}` vs locked `{ok, latencyMs}`). Resolved everywhere.
5. **Enum/copy drift** — notification severity (3-level vs 5-level), HA priority
   direction (lower vs higher wins), ConfigSection list (missing `routing`/`identity`),
   the invented `wan` section, badge color maps (M09 vs UI_DESIGN_SYSTEM), and a
   miscounted seed list.

Counts: **CRITICAL 3 · MAJOR 14 · MINOR 15 · informational notes 5.** All fixes are in
place; residual items are listed in (c)/(d).

---

## (b) Issues found and fixed

Severity: CRITICAL = code would be wrong/broken if built as written; MAJOR = contract
contradiction that would propagate into implementation; MINOR = clarity/typo/derivable.

### CRITICAL

1. **CRITICAL — SCHEMA.md §3 (`WanPolicy`)** — relation `interface NetworkInterface?
   @relation(fields: [interfaceName], references: [name])` referenced a column that is
   only unique as `(tenantId, name)`; Prisma rejects non-unique relation targets, so the
   "copy verbatim into schema.prisma" instruction produced an unpushable schema (and a
   required/optional mismatch: non-nullable FK fields with an optional relation).
   **Fixed:** compound relation `fields: [tenantId, interfaceName] → references:
   [tenantId, name]` (matches the compound unique, field order included), relation made
   required, `onDelete: Restrict`; ER_DIAGRAM cardinality corrected to
   `NETWORKINTERFACE ||--o| WANPOLICY`.

2. **CRITICAL — SCHEMA.md §3 (tenant scoping)** — §2 promised "every tenant-scoped model
   … + relation to Tenant", but `VpnSession`, `DhcpReservation`, `DhcpLease`, `QosRule`,
   `IdentitySession` had a bare `tenantId` with no relation (no back-relation on
   `Tenant` either) — an invalid/incomplete Prisma graph vs the doc's own rule (the spec
   has real `REFERENCES tenants(id)` on all four config tables). **Fixed:** added the
   tenant relation to those five models + five back-relations on `Tenant`; the three
   append-heavy log models (`FirewallLog`, `IpsEvent`, `AuditLog`) keep `tenantId` as a
   plain indexed column **by documented exception** (mirrors the spec's log tables,
   which deliberately have no FK; retention deletes must not fight FKs). Exception now
   stated in SCHEMA §2 and the ER_DIAGRAM note.

3. **CRITICAL — SCHEMA.md §3 (multi-tenant uniqueness)** — `DhcpReservation
   @@unique([mac])`, `DhcpLease @@unique([ip])`, `IdentitySession @@unique([sourceIp])`
   were globally unique across tenants, contradicting ADR-009 multi-tenancy (two tenants
   legitimately reuse the same MAC/RFC1918 IP). **Fixed:** `@@unique([tenantId, mac])`,
   `@@unique([subnetId, ip])`, `@@unique([tenantId, sourceIp])`; ENDPOINTS error text and
   M07 notes updated to match.

### MAJOR

4. **MAJOR — API_STANDARDS §2 capability matrix** — contradicted the authoritative
   `AUTH_AND_RBAC.md` §4: security_admin was granted VPN *config* + DNS-policies writes
   (authority: read); network_admin was granted zones/objects + captive-portal writes
   (authority: read / none); tenant_admin was granted api-key create/revoke (authority:
   super_admin only); auditor "fails every mutation" contradicted the notifications
   edit. **Fixed:** matrix rewritten to mirror AUTH_AND_RBAC §4 exactly, with a stated
   precedence rule ("where a floor would admit a role the matrix denies, the matrix
   wins — the handler enforces the matrix").

5. **MAJOR — API_STANDARDS §2 + ENDPOINTS legend ("L3 is peer level")** — the rule
   "security_admin satisfies any network_admin floor and vice versa" mechanically
   contradicts the area-specific matrix (e.g. VPN config edit is network_admin-only,
   objects edit security_admin-only). **Fixed:** peer status now applies "to the ladder
   only"; floors are a coarse summary, the matrix is the enforcement truth (stated in
   both files).

6. **MAJOR — ENDPOINTS §4 objects floors** — `network_admin` write floor on
   zones/address/service/schedule objects (24 rows) contradicted the matrix
   (network_admin = read in the firewall/objects area). **Fixed:** all object
   POST/PUT/DELETE floors → `security_admin` (network_admin keeps read).

7. **MAJOR — ENDPOINTS §7 VPN floors** — VPN config create/update/delete +
   client-bundle floored at `security_admin`, but the matrix gives VPN *config* to
   `network_admin` (security_admin = read) and VPN *session disconnect* to
   security_admin + soc_analyst. **Fixed:** config floors → `network_admin`; disconnect
   → `security_admin / soc_analyst`.

8. **MAJOR — ENDPOINTS §8 DNS policy floors** — dns/policies CRUD floored at
   `security_admin`; matrix puts all DNS/DHCP config with `network_admin`. **Fixed:** →
   `network_admin` (4 rows).

9. **MAJOR — ENDPOINTS §9 identity-area floors** — radius-profiles/{id}/test floored at
   `network_admin` (matrix: network_admin has no Identity-area rights); captive-portal
   GET/PUT + vouchers floored at `network_admin` (matrix: identity area is
   security_admin edit). **Fixed:** test → `security_admin`; captive-portal + voucher
   endpoints → `security_admin`.

10. **MAJOR — ENDPOINTS §13 api-keys floors** — create/revoke floored at
    `tenant_admin`; matrix + AUTH_AND_RBAC §4.1 say super_admin only (tenant_admin =
    read). **Fixed:** POST/DELETE → `super_admin`; example response status 200 → `201`
    (creation); error text updated.

11. **MAJOR — ENDPOINTS §11/§13 read floors** — `/logs/audit` floored at
    `tenant_admin` (matrix grants audit read to soc/security/network/auditor) and
    `/config-versions*` at `network_admin`. **Fixed:** both → `soc_analyst`.

12. **MAJOR — ENDPOINTS §5 + M03 (validate response shape)** — M03 specified
    `{warnings:[{kind,…}]}` with verdicts shadow/redundant/conflict/generalizes;
    ENDPOINTS pins `{ok, conflicts:[{ruleId, ruleName, reason, withRuleId,
    withRuleName}]}` with `shadowed_by|conflicts_with`. **Fixed:** M03 rewritten to the
    ENDPOINTS shape; `redundant` (same-scope duplicate, warning severity) added to
    ENDPOINTS reason list; M03 acceptance wording updated.

13. **MAJOR — ENDPOINTS §13 Notification severity note (inverted "fix me")** — claimed
    `notifications.severity` = `info|low|medium|high|critical` and called SCHEMA's
    `info|warning|critical` stale. PROJECT_MEMORY §6 has a **dedicated**
    `notifications.severity` row (`info|warning|critical`), and the spec agrees.
    **Fixed:** ENDPOINTS note corrected; M10 §2/§5.5/§7/§8 (which had repeated the
    wrong claim in four places) corrected; M09 badge map gained a `warning` row.

14. **MAJOR — M10 HA priority direction** — M10 said "lower wins master election" in
    four places; SCHEMA.md (corrected per PROJECT_MEMORY session log) says **higher
    wins** (Keepalived semantics). **Fixed:** §2, §4 help text, §5.1, §8 (open question
    marked resolved).

15. **MAJOR — STATE_AND_DATA_FLOW §2 invalidation table** — listed an invented `wan`
    section (not in the LOCKED `ConfigSection` union) and omitted `identity`; system row
    wrongly invalidated identity resources. **Fixed:** wan-policies fold into
    `routing` (multi-WAN is spec §1.3 routing), `identity` row added (users, groups,
    radius, auth-settings, captive-portal, identity-sessions), system row trimmed; a
    pointer to the ARCHITECTURE §5 ConfigSection union added.

16. **MAJOR — M07 §3 API surface** — listed reveal/test/expire/vouchers as "PROPOSED
    EXPANSIONS" with a **wrong reveal path** (`GET …/{id}/secret` vs locked
    `POST …/{id}/reveal`), wrong test payload (`{reachable, latencyMs, message}` vs
    locked `{ok, latencyMs}`), voucher body `note?` vs locked `bandwidthKbps?`, and
    omitted `DELETE /captive-portal/vouchers/{id}`. **Fixed:** all five endpoints moved
    into the main locked table with locked paths/payloads; §4/§5.3/§5.5/§7/§8 aligned;
    M07 helpdesk role row no longer claims user read (matrix: none).

17. **MAJOR — M09 §3/§8 stale expansions** — CSV export still marked "PROPOSED" (it is
    locked); §4 reports built on an invented `/logs/stats` payload
    (`trafficTrend/topApps/topTalkers/threatMix/actionMix`) that the locked endpoint
    does not return (`series` + `ipsBySeverity` only). **Fixed:** export listed as a
    locked endpoint; reports section rewritten to the locked payload (action trend/mix +
    ipsBySeverity; range-scoped top apps/talkers explicitly a Phase 2 expansion);
    PAGE_MAP `#/logs/reports` blueprint updated to match.

### MINOR

18. MINOR — SCHEMA.md §2: "Money/none." fragment; replaced with "No money columns." and
    the delete/tenant-relation bullets rewritten (see #2).
19. MINOR — SCHEMA.md `ConfigVersion.section` comment listed 10 sections; PM §12 +
    ARCHITECTURE §5 lock **12** (adds `routing`, `identity`). Fixed.
20. MINOR — SCHEMA.md `SystemSetting.category` comment omitted `dns` — but SCHEMA §6
    itself stores DNS resolver settings under category `dns`. Fixed.
21. MINOR — SCHEMA.md `FirewallRule`: added note that the spec's `nat_type/nat_target/
    nat_port` columns are intentionally consolidated into `nat_rules` (prevents an AI
    builder from "restoring" them).
22. MINOR — SCHEMA.md Zone membership dual-source (`zones.interfaceNames` JSON +
    `interfaces.zoneId` FK): M03 acceptance already requires both to stay in sync;
    M03/ER now describe zoneId as the FK side and interfaceNames as the generator-facing
    denormalization (kept; spec uses interface_names).
23. MINOR — DATA_LIFECYCLE §2.3: service-objects list had 7 items but said "(8)". Fixed
    to (7).
24. MINOR — DATA_LIFECYCLE §4: added an explicit note that the audit_log cap is
    housekeeping-only and audit stays append-only at the API layer (ADR-011), plus an
    **appliance-mode** note (PostgreSQL monthly partitioning for firewall_logs/
    ips_events, ClickHouse archival v2 per spec) so the sandbox doc bridges to the spec's
    lifecycle requirements.
25. MINOR — API_STANDARDS §7 config-version section list missing `routing`/`identity`.
    Fixed (12 sections).
26. MINOR — API_STANDARDS §10 realtime event list omitted the locked `vpn:status` event.
    Fixed; also fixed in STATE_AND_DATA_FLOW §4, PAGE_MAP `#/vpn/configs`, and
    M11 §6 (all had 6-of-7 lists).
27. MINOR — API_STANDARDS §9 login throttle wording ("per username") aligned to
    AUTH_AND_RBAC §2 ("per (username, source IP), 5/min"); M11 rate-limit table (600/
    1200/10-per-min proposals) reconciled to the API_STANDARDS authority (60 / 300 /
    5 per min).
28. MINOR — M11 §5.1 api-key create response shape was `{data:{key, item}}`; ENDPOINTS
    pins a flat `{data:{…fields…, key}}`. Fixed. M11 §3.1 scope matrix gave `admin`
    keys api-key create/revoke; AUTH_AND_RBAC says **keys can never manage keys** —
    removed, with an explicit note (only interactive super_admin).
29. MINOR — M07 §2 IdentitySession uniqueness note and §5.5 updated to
    `@@unique([tenantId, sourceIp])` (see #3).
30. MINOR — M09 §5.4 color map contradicted UI_DESIGN_SYSTEM §2.3/§2.4 (high=orange vs
    rose, medium=amber vs orange, low=teal vs amber, info=zinc vs violet, deny=amber vs
    rose). **Fixed to the canonical UI map** (critical rose-600 solid, high rose outline,
    medium orange, low amber, info violet, warning amber, deny/drop rose, reject orange,
    failure rose, denied rose outline); M09 §4 firewall table + M03 §4 badge colors
    aligned (reject=orange-500); audit result badges now success=emerald,
    failure=rose solid, denied=rose outline.
31. MINOR — PAGE_MAP `#/identity/users` realtime section said `system`; identity
    mutations broadcast section `identity` (locked ConfigSection). Fixed.
32. MINOR — PAGE_MAP `#/identity/sessions` said "read-only" though the locked
    `POST /identity/sessions/{id}/expire` exists; force-expire action added.
    `#/identity/portal` blueprint referenced a "branding" field that doesn't exist in
    `CaptivePortalProfile` — replaced with the real fields; voucher endpoints wired
    (previously "ride the portal payload"). `#/dns-dhcp/dhcp` gained the locked
    lease-release action; `#/logs/firewall` export action wired to the locked path;
    `#/system/backups` gained the locked download endpoint.
33. MINOR — UI_DESIGN_SYSTEM §2.4 severity ladder clarified: 5-level scale is
    `ips_events.severity`; `notifications.severity` is the 3-level `info|warning|
    critical` (both locked in PROJECT_MEMORY §6).
34. MINOR — API_STANDARDS §1 sequence diagram: the `config:updated` broadcast was drawn
    from the SystemAdapter to the client as if the adapter emitted socket events;
    relabeled "SystemAdapter / realtime svc" with the realtime service named as the
    broadcaster.

### Informational (kept with justification — no change)

35. **SQLite/Prisma instead of PostgreSQL (SCHEMA.md, ADR-005)** — explicit, justified
    build-level deviation; PostgreSQL stays the appliance store; mapping rules are
    locked and shape-compatible. Kept.
36. **Page-based pagination instead of the spec's cursor-based (API_STANDARDS §6,
    M11 §5.4)** — LOCKED in PROJECT_MEMORY §7.1; API_STANDARDS documents cursor as
    "reserved, not implemented" with the appliance-rate rationale. Kept; flagged to
    coordinator (see (c) #1).
37. **`ips_events` instead of the spec's `ips_logs` table name** — rename is consistent
    across SCHEMA/ER/PM/ENDPOINTS/modules and matches the event semantics (plus
    `suppressedUntil`/`message` additions). Kept.
38. **`User.role` default `helpdesk` instead of the spec's `viewer`** — the spec's own
    role list has no `viewer`; fix recorded in the PM session log. Kept.
39. **M03 console-phase trims** — app-aware/user-based/MAC-filtering rule *editors*
    deferred (columns exist + validated), rule groups reduced to tags, NAT pools/port
    ranges deferred, 1:1 NAT composed from snat+dnat. All documented as explicit
    decisions with the spec as source; kept (M03 §1 table).

---

## (c) Items needing cross-agent reconciliation

Facts in my set that docs **outside** my set may still contradict:

1. **Pagination style** — spec §1.15 says "API pagination (cursor-based)"; the build
   contract (PROJECT_MEMORY §7.1) is page-based. PROJECT_MEMORY wins internally, but
   PRODUCT_OVERVIEW/ROADMAP wording should keep crediting the spec and marking the
   deviation (M11 §5.4 and API_STANDARDS §6 already do; ROADMAP row reviewed by 2-C
   says "Phase 2 (spec)" for idempotency keys — fine — but cursor wording should be
   double-checked there).
2. **RBAC floors in module docs I do not own** — M02/M04/M05/M06/M08 endpoint tables
   may still carry the old floors (objects=`network_admin`, DNS policies=
   `security_admin`, VPN config=`security_admin`). The corrected authority is
   AUTH_AND_RBAC §4 as now mirrored in API_STANDARDS §2 and ENDPOINTS.md; those module
   docs must be swept with the same rule ("matrix wins over floors").
3. **M06 stale PROPOSED EXPANSION** — `M06-DNS-DHCP.md` §(line ~99) still marks
   `POST /api/v1/dhcp/leases/{id}/release` as a proposed expansion; it is LOCKED
   (PROJECT_MEMORY §7.2, ENDPOINTS §8, PAGE_MAP). M06 owner should promote it into the
   main table.
4. **Notification severity** — any doc outside my set that says notifications use the
   5-level scale should switch to `info|warning|critical` (5-level is ips_events only).
5. **`config:updated` section values** — the union is exactly `firewall | nat |
   interfaces | routing | dns | dhcp | vpn | ips | qos | ha | identity | system`; no
   `wan` section. Any other doc emitting/consuming `section: "wan"` must switch to
   `routing` (STATE_AND_DATA_FLOW §2 now states this).
6. **Realtime event set** — 7 locked events including `vpn:status`; any doc listing 6
   (or using SSE/polling for these) should be aligned.
7. **Tenant-scoped uniqueness** — `dhcp_reservations(tenantId,mac)`,
   `dhcp_leases(subnetId,ip)`, `identity_sessions(tenantId,sourceIp)`,
   `wan_policies(tenantId,interfaceName)` compound uniques: any doc quoting "globally
   unique MAC/IP" should be updated.
8. **Role names** — exactly 8: `super_admin tenant_admin security_admin network_admin
   soc_analyst helpdesk auditor api_service`. No `viewer` role anywhere; seed user
   `viewer` has role `auditor` (DATA_LIFECYCLE §2.1 is correct).
9. **API-key management role** — create/revoke = interactive `super_admin` only
   (tenant_admin read; machine keys can never manage keys, even with `admin` scope).

---

## (d) Residual risks / open questions

1. **Error envelope has no `requestId`** — the review brief asked for
   code/message/details/requestId; PROJECT_MEMORY §7.1 locks `{code, message, details?}`
   and I kept consistency with the locked contract. If the coordinator wants requestId
   for support correlation, it is a one-field additive change to PROJECT_MEMORY §7.1 +
   API_STANDARDS §4/§5 (additive, non-breaking) — recommend doing it before M0 code so
   logs can be correlated.
2. **Restore broadcast sentinel** — M10 §5.3 proposes `config:updated { section: "all" }`
   which is not in the ConfigSection union; flagged in M10 §8. Either add a documented
   sentinel or emit per-section events — needs a decision before the realtime service is
   built.
3. **`config_versions` unbounded growth** — retention never prunes it (DATA_LIFECYCLE
   §4); fine for sandbox, but appliance mode needs a policy (e.g. keep N per section).
4. **Offset pagination on live log tables** can skip/repeat rows across pages (M11 §8);
   acceptable in Phase 1, revisit with cursors at appliance rates.
5. **Webhooks** — spec lists webhook support as Phase 1; the locked console surface has
   no webhook endpoints (documented non-goal in M11 §1/§8). Appliance-mode work must
   not "discover" this as a gap — it is a recorded deferral (2-C's review reached the
   same conclusion from the ROADMAP side).
6. **SCHEMA.md is the copy-source for `prisma/schema.prisma`** — my edits (compound FK,
   new relations/uniques, Restrict on optional rule references) must be copied verbatim
   at M0 bootstrap; the schema has not been pushed yet (no `db/cryptsk.db` exists), so
   there is no drift risk today — but the first `bun run db:push` should be validated
   against this file, and any Prisma-version quirk (e.g. compound-relation ordering)
   resolved there first, then mirrored back into the doc per PROJECT_MEMORY §11.14.
7. **Seed contract detail** — DATA_LIFECYCLE §2.4 seeds `wan1` with an HTTP probe while
   the interface is disabled; harmless for demos but MockEngine should skip probes for
   disabled ifaces (consistent with SIMULATION_LAYER §6 metrics rule). Left as build
   guidance, not changed.

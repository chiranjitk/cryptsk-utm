# M08 — QoS (Traffic Shaping)

> TL;DR: Bandwidth shaping policies and per-policy rules (priority, guaranteed/max rates, DSCP
> marking, app/user/address matchers) rendered as tc HTB + fq_codel on the appliance; in the
> sandbox the metrics generator honors the caps so utilization series visibly flatten at the limit.

Related: ../00-PROJECT-MEMORY/PROJECT_MEMORY.md (§6 enums, §7.2 API, §7.3 realtime, §8 views) ·
../03-DATABASE/SCHEMA.md · ../03-DATABASE/ER_DIAGRAM.md · ../02-ARCHITECTURE/SIMULATION_LAYER.md ·
../02-ARCHITECTURE/DATA_PLANE.md (tc pipeline) · ../04-API/ENDPOINTS.md · ../04-API/API_STANDARDS.md ·
../05-FRONTEND/UI_DESIGN_SYSTEM.md · ../05-FRONTEND/PAGE_MAP.md · ../05-FRONTEND/STATE_AND_DATA_FLOW.md ·
../01-PRODUCT/ROADMAP.md · siblings: M03-FIREWALL.md (rules attach `qosPolicyId`), M02-NETWORK.md (interfaces), M07-IDENTITY.md (users)

---

## 1. Purpose & Scope (Phase 1)

This module defines egress traffic shaping: policies (a total shaper, optionally attached to a
WAN interface, seeded from a template) containing ordered rules that classify traffic
(app/user/address matchers) into priority classes with guaranteed/maximum rates and DSCP
marks. A policy can be attached to firewall rules via `FirewallRule.qosPolicyId` (M03).

**In scope (Phase 1):** policy CRUD (name, template `voip|video|gaming|bulk|custom`,
`bandwidthKbps`, optional `ifaceName`), per-policy rule CRUD with validation, priority-based
ordering (0 highest – 7 lowest), enable/disable, an effect-explanation panel ("what tc does
with this"), a simulated utilization preview demonstrating cap flattening, and **per-user /
per-application hard bandwidth limits** (spec §1.11 — first-class: a rule whose only matchers are
`matchUsers`/`matchApps` with a `maxKbps` is a dedicated hard-limit class; the view offers
"Limit user…" / "Limit application…" quick-create actions, restored REVIEW-4A).

**Out of scope (spec's own phase assignments — not deferrals):** CAKE qdisc,
ingress/reverse-path shaping (ifb), hierarchical parent-child classes beyond one level,
per-class monitoring dashboard (beyond the §4 sparkline), burst allowance, QoS template
marketplace/custom template editor.

---

## 2. Data Model

From ../03-DATABASE/SCHEMA.md §3 (names verbatim).

| Model | Fields used here | Notes |
|---|---|---|
| `QosPolicy` | `name`, `enabled` (default true), `template` (`voip\|video\|gaming\|bulk\|custom`, nullable), `bandwidthKbps` (total shaper), `ifaceName?` (optional attachment; logical ref to `interfaces.name`) | `@@unique([tenantId, name])`; deleting a policy **cascades** its `QosRule` rows (ER_DIAGRAM §2) but is **RESTRICT-ed** while any `FirewallRule.qosPolicyId` references it → `409 CONFLICT` with rule names |
| `QosRule` | `policyId` (FK, cascade), `name`, `priority` (0 highest .. 7 lowest), `guaranteedKbps?`, `maxKbps?`, `dscpMark?` (0–63), `matchApps` (JSON array of nDPI label ids), `matchUsers` (JSON array of `User.id`), `matchAddresses` (JSON array of `AddressObject.id`) | Index `(tenantId, policyId)`; **no position column — ordering is by `priority` (ties: `id` asc)** |

Logical references (ER_DIAGRAM §3): `matchApps` → app-catalog labels (strings, not ints);
`matchUsers` → `User.id`; `matchAddresses` → `AddressObject.id`. Service layer validates
existence in-tenant on save (`400 VALIDATION_ERROR` listing unknown ids).

---

## 3. API Surface

Paths verbatim from PROJECT_MEMORY §7.2. Rules are scoped by `?policyId=`.

| METHOD | Path | Purpose | Triggering UI action |
|---|---|---|---|
| GET | `/api/v1/qos/policies` | List policies (incl. per-policy rule counts + attached iface state) | Open `#/qos/policies` |
| POST | `/api/v1/qos/policies` | Create policy (template seeds starter rules, §5.1) | "Add Policy" dialog submit |
| PUT | `/api/v1/qos/policies/{id}` | Update policy (name, bandwidth, iface, template note, enabled) | Policy editor submit / card toggle |
| DELETE | `/api/v1/qos/policies/{id}` | Delete policy (+ cascade rules) | Row action "Delete" (ConfirmDialog) |
| GET | `/api/v1/qos/rules` | List rules (`?policyId=` required by the view; returns rules ordered by priority) | Select/open a policy |
| POST | `/api/v1/qos/rules` | Create rule in a policy (`policyId` in body) | "Add Rule" dialog submit |
| PUT | `/api/v1/qos/rules/{id}` | Update rule (priority slider re-orders; validation §5.2) | Rule editor submit / enable toggle |
| DELETE | `/api/v1/qos/rules/{id}` | Delete rule | Row action "Delete" (ConfirmDialog) |

**Expected error cases:** `VALIDATION_ERROR` 400 (priority outside 0–7; `guaranteedKbps >
maxKbps`; `sum(guaranteed)` of enabled rules > `bandwidthKbps` — error names the offending
sum; `dscpMark` outside 0–63; unknown app/user/address ids; `bandwidthKbps < 1000`);
`CONFLICT` 409 (duplicate policy name; deleting a policy referenced by firewall rules — body
lists referencing rule names per ER_DIAGRAM §2 rule-of-thumb); `NOT_FOUND` 404.

---

## 4. Views & Interactions

Single hash view (LOCKED §8): `#/qos/policies`. Master-detail layout per
../05-FRONTEND/PAGE_MAP.md; tokens per ../05-FRONTEND/UI_DESIGN_SYSTEM.md (emerald primary,
rose for caps exceeded, amber warnings; no indigo/blue anywhere, including the sparkline).

### Left: policy list

- Cards or DataTable: name, template badge, `bandwidthKbps` (humanized, e.g. "50 Mbps"),
  attached iface chip (or "all WAN"), enabled switch (inline toggle → `PUT`), rule count.
- Actions: Add Policy, Edit, Delete (ConfirmDialog shows cascade + reference warning), toggle.
- **Policy editor dialog:** name; template Select — choosing a template shows the
  **template explanation table** (§5.1) inline and (on create) seeds starter rules;
  `bandwidthKbps` number input with Mbps helper; `ifaceName` optional Select from
  `/api/v1/interfaces` (wan-role options first); enabled switch.

### Right: selected policy detail

- **Rules table** (ordered by priority): priority (0–7 badge), name, matchers (apps chips /
  users avatars-initials / addresses mono), guaranteed → max kbps, DSCP badge (e.g. `EF 46`),
  **hard-limit badge** (rose "limit" chip when the rule is a per-user/per-app hard limit — exactly one
  matcher dimension + `maxKbps` set + no `guaranteedKbps`), enabled toggle, edit/delete.
  "Add Rule" opens the **rule editor dialog**; toolbar quick-actions **"Limit user…"** and
  **"Limit application…"** open the same dialog prefilled (single matcher + `maxKbps`, priority 5
  suggestion, hard-limit badge preview):
  - name; priority **Slider 0–7** (with caption "0 = highest precedence; ties break by creation order");
  - guaranteed/max kbps pair with live validation message (§5.2);
  - DSCP mark picker: Select of well-known values (table below) + "Custom…" numeric entry 0–63;
  - match pickers via shared `ObjectPicker`: **Apps** (from the app catalog used by M03
    `applicationIds`), **Users** (from `/api/v1/users`), **Addresses** (address objects;
    groups not selectable here — `matchAddresses` references `AddressObject.id` only).
- **Effect explanation panel** ("what tc does with this") — generated from the current rules,
  rendered as a static explanation card + ordered list: root `htb` qdisc at `bandwidthKbps`
  on the attached iface (or the policy's aggregate), one child class per enabled rule with
  `rate = guaranteedKbps`, `ceil = maxKbps`, `prio = priority`, `fq_codel` leaf per class,
  nftables classify/mark rules for app/user/address matchers, DSCP mark set on matching
  packets. A footnote links ../02-ARCHITECTURE/DATA_PLANE.md (tc stage) and states that the
  sandbox does **not** run tc — this panel is documentation of the would-be appliance config,
  not a live config viewer.
- **Utilization sparkline** (optional, one per policy): last ~60 s of the attached iface
  `txKbps` from `metrics:tick` (§6), with the policy cap drawn as a rose dashed line — the
  visible proof that the generator honors caps (§5.4). If no iface is attached, plot the
  aggregate of wan-role iface series.

### Well-known DSCP values (picker table)

| Value | Name | Typical use |
|---|---|---|
| 46 | EF | Voice (RTP) |
| 34 | AF41 | Interactive video |
| 32 | CS4 | Real-time interactive / gaming |
| 26 | AF31 | Multimedia streaming |
| 24 | CS3 | Signaling |
| 18 | AF21 | High-throughput data |
| 8 | CS1 | Bulk / scavenger (backups, sync) |
| 0 | BE (CS0) | Best effort (default) |

### States

- Loading: skeleton cards + skeleton table.
- Empty: EmptyState with "Add Policy" CTA and one-line template pitch.
- Error: inline error card with Retry (../05-FRONTEND/STATE_AND_DATA_FLOW.md).
- Validation errors from the API render inside the dialogs, field-level where `details` maps.

---

## 5. Business Logic & Validation

### 5.1 Templates (seed starter rules on create; editable afterwards)

| Template | Starter rules seeded | Default `bandwidthKbps` hint | Intent |
|---|---|---|---|
| `voip` | Rule "Voice" — priority 0, guaranteed 10% of bw, max 30%, DSCP 46 (EF), matchApps `sip`/`rtp` | 10 000 | Protect call quality first |
| `video` | Rule "Conferencing" — priority 2, guaranteed 30%, max 70%, DSCP 34 (AF41), matchApps video-conferencing labels; Rule "Streaming" — priority 5, max 50%, DSCP 26 (AF31) | 50 000 | Cap bulk streaming, protect calls |
| `gaming` | Rule "Game traffic" — priority 1, guaranteed 15%, max 50%, DSCP 32 (CS4); Rule "Updates" — priority 7, max 20%, DSCP 8 (CS1) | 30 000 | Low latency for game flows, starve downloads |
| `bulk` | Rule "Backups" — priority 7, max 80%, DSCP 8 (CS1); everything else BE | 100 000 | One fat, deprioritized lane |
| `custom` | No rules | — | Blank canvas |

Template choice is a **creation-time seed**: after create, `template` is informational only
(editing rules never re-syncs the template). Changing template on an existing policy shows a
confirm note that it will not rewrite existing rules.

### 5.2 Rule validation (zod + service checks)

- `priority` int 0–7 (slider snaps). `guaranteedKbps`/`maxKbps` optional ints ≥ 0.
- `guaranteedKbps ≤ maxKbps` when both set (`VALIDATION_ERROR` otherwise).
- **Sum check:** `sum(guaranteedKbps)` over the policy's **enabled** rules must be
  `≤ bandwidthKbps`; the API error reports current sum vs budget. `sum(maxKbps)` may exceed
  the budget (statistical multiplexing is intended; the panel notes it).
- `dscpMark` 0–63. `matchApps/matchUsers/matchAddresses` arrays of known ids in-tenant; a rule
  with **no matcher at all** is the catch-all class — allowed only once per policy (else 409)
  and the UI labels it "Any traffic (catch-all)".
- **Hard-limit semantics (spec §1.11 per-user / per-application limits):** a rule matching exactly
  one dimension (`matchUsers` xor `matchApps`, single-valued or a small group) with `maxKbps` and no
  `guaranteedKbps` is a **hard limit class** — traffic of that user/app cannot exceed `maxKbps`
  regardless of spare capacity (HTB `ceil = maxKbps` with no borrow above the cap). The generator
  clamps the matching user's/app's series at the cap. Overlapping hard limits: the most specific
  (single user) wins over the app-level class.
- Enabling a rule re-runs the sum check; disable relaxes it.

### 5.3 Ordering & attachment semantics

- Evaluation/queue order = `priority` asc (0 first), ties by `id` asc; there is no manual DnD
  order for QoS rules (unlike firewall rules) — the priority slider *is* the ordering control.
- `ifaceName` optional: set → shaper binds to that interface (one policy per iface, enforced
  with `409 CONFLICT` if another enabled policy claims it); unset → aggregate shaper across
  wan-role egress in simulation. Multiple enabled policies on different ifaces are fine.
- Policy disable → its classes are removed from the effect panel and the generator stops
  honoring its caps on the next tick.

### 5.4 Simulated effect (SimulatedAdapter / MockEngine)

Per ../02-ARCHITECTURE/SIMULATION_LAYER.md §3 (`qos` row) and §4: there is no real tc in the
sandbox. The SimulatedAdapter records the applied policy (version snapshot + `config:updated`
{section:"qos"}); the **metrics generator honors per-policy bandwidth caps — series flatten at
the cap** (§6 metrics contract). Concretely: for the attached (or aggregated wan) iface,
generated `rxKbps/txKbps` are clamped to the policy budget with the highest-priority rules'
guarantees effectively reserved first; priority-7 bulk caps show as a visibly squashed series.
Charts must use the locked palette (ADR-013); the cap line is rose.

---

## 6. Realtime

| Event (§7.3, verbatim) | Reaction in this module |
|---|---|
| `metrics:tick` `{ ts, ifaces: [{name, rxKbps, txKbps}], cpuPct, memPct, conntrackCount }` | Feeds the optional utilization sparkline(s); the cap line makes cap-flattening visible; no table changes |
| `config:updated` `{ section: "qos" }` | Invalidate `['qos', …]` query keys; refetch policies + rules; toast "QoS applied" |
| `logs:tail`, `alerts:new`, `sessions:update`, `wan:status` | Not consumed here |

---

## 7. Acceptance Criteria (checklist)

- [ ] `#/qos/policies` renders master-detail; deep link opens with first policy selected.
- [ ] Creating a policy with template `voip` pre-creates the Voice rule (priority 0, DSCP 46, 10% guaranteed) per the template table.
- [ ] Priority slider is limited to 0–7 and re-orders the rules table immediately (order = priority asc, ties by id).
- [ ] Setting `guaranteedKbps > maxKbps` is rejected inline before submit and by the API with `VALIDATION_ERROR`.
- [ ] Enabling rules whose guaranteed sum exceeds `bandwidthKbps` fails with an error naming sum vs budget; disabling one rule makes the save pass.
- [ ] DSCP picker offers the §4 well-known table plus custom 0–63 entry; the badge renders e.g. `EF 46`.
- [ ] App/user/address pickers only accept catalog ids; an unknown id in a hand-crafted API call returns `VALIDATION_ERROR` listing it.
- [ ] Deleting a policy referenced by a firewall rule returns `409 CONFLICT` with the referencing rule names, and the UI surfaces them.
- [ ] Deleting a policy without firewall references cascades its rules after ConfirmDialog.
- [ ] Attaching the same enabled iface to a second policy returns `409 CONFLICT`.
- [ ] With a 50 000 kbps cap attached to `wan0`, the sparkline's tx series flattens at ~50 000 within ticks and the cap line is visible.
- [ ] "Limit user…" prefills the rule dialog with a single-user matcher + maxKbps; after save the rule renders the rose "limit" badge and the generator clamps that user's series at the cap (per-user hard limit, spec §1.11).
- [ ] "Limit application…" does the same for an app label; a user-level limit wins over an app-level limit on overlapping flows.
- [ ] Effect panel lists one HTB child class per enabled rule with rate/ceil/prio and an fq_codel leaf, and states clearly that tc is not executed in sandbox.
- [ ] Every mutation writes an audit row and a `config_versions` snapshot (section `qos`) and broadcasts `config:updated`.
- [ ] `bun run lint` passes; no new Next.js routes; charts use only the locked palette (no indigo/blue).

---

## 8. Open Questions & Risks

- **Template seeding is defined here for the first time** (starter rules on create). Alternative: template only pre-fills the dialog without persisting until first save — pick one and mirror it in ENDPOINTS.md examples.
- **One-policy-per-iface conflict rule** (409) is proposed, not contract-locked; confirm with M02 interface semantics.
- Catch-all rule ("no matchers") uniqueness is a service-layer rule; verify it does not fight the appliance renderer's implicit default class (DATA_PLANE.md) when that doc lands.
- The utilization sparkline is a UI affordance beyond the strict table spec — keep it strictly derived from `metrics:tick`, never a second stats endpoint (none exists in §7.2).
- `bandwidthKbps` units are kbps everywhere; guard against a Mbps typo in the seed (`WAN-SHAPER` = 50 000 kbps, DATA_LIFECYCLE §2.4).
- Generator cap-clamping is approximate (per-tick clamping, not token-bucket); demos should not claim exact throughput fidelity (SIMULATION_LAYER §9).
- ~~**Per-user/per-app hard limits deferred**~~ RESOLVED (REVIEW-4A): hard-limit classes are first-class (§5.2 semantics + §4 quick-create actions); no schema change was needed (`matchUsers`/`matchApps` + `maxKbps` already express them).

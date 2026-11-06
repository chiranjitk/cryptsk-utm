# Endpoints — Cryptsk Console

> TL;DR: Complete Phase 1 endpoint catalog. Paths are **LOCKED** from PROJECT_MEMORY §7.2 — expand here,
> never rename. Every response uses the shared envelope; every mutation is audited and version-snapshotted
> by `lib/api/handler.ts` (see [./API_STANDARDS.md](./API_STANDARDS.md)).

Related: [../00-PROJECT-MEMORY/PROJECT_MEMORY.md](../00-PROJECT-MEMORY/PROJECT_MEMORY.md) §7 (contract of record) ·
[./API_STANDARDS.md](./API_STANDARDS.md) (envelope, errors, RBAC matrix) ·
[../03-DATABASE/SCHEMA.md](../03-DATABASE/SCHEMA.md) (field names + JSON shapes) ·
[../02-ARCHITECTURE/ARCHITECTURE.md](../02-ARCHITECTURE/ARCHITECTURE.md)

**Legend**

- Role floors come from the RBAC matrix in API_STANDARDS §2 (authoritative source:
  `../07-SECURITY/AUTH_AND_RBAC.md` §4). Ladder:
  `helpdesk < soc_analyst < network_admin = security_admin < tenant_admin < super_admin`.
  L3 is peer level **on the ladder only** — the capability matrix is area-specific, and where a floor
  would admit a role the matrix denies (e.g. `network_admin` writing firewall objects, `security_admin`
  editing VPN configs), the matrix wins: the handler enforces the matrix; floors below are a coarse
  summary. `auditor` may call any GET regardless of floor; its only mutation is notification mark-read.
  `api_service` needs a key scope covering the capability (`read`/`write`/`admin`).
- `Audit?` = yes means the shared handler writes an `audit_log` row (`<objectType>.<verb>`) plus a
  `config_versions` snapshot for the affected section. Reads are never audited.
- All timestamps are ISO-8601 UTC. All bodies camelCase, matching SCHEMA.md TS field names. Flat JSON
  objects in examples are wrapped across lines for readability; every example is complete JSON.

---

## 1. Auth

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| POST | `/api/v1/auth/login` | Authenticate `{username, password}`, sets `cryptsk_token` cookie | public | yes |
| POST | `/api/v1/auth/logout` | Clear session cookie | helpdesk | yes |
| GET | `/api/v1/auth/me` | Current user + permissions | helpdesk | no |

`POST /api/v1/auth/login` — request, then `200`:

```json
{ "username": "admin", "password": "CorrectHorse1!" }
```

```json
{
  "data": {
    "user": {
      "id": 1, "tenantId": 1, "username": "admin", "role": "super_admin",
      "email": "admin@corp.local", "isActive": true, "totpEnabled": false,
      "lastLoginAt": "2026-11-04T18:22:31.000Z"
    },
    "permissions": { "read": true, "write": true, "admin": true }
  }
}
```

The login body optionally carries `totpCode` — required only when the user has enrolled TOTP
(M07 §5.6): a missing/invalid code is `401 UNAUTHORIZED` with `details: { totpRequired: true }`;
when the tenant-level enforce switch (`auth-settings` → `totp.required`) is on, every login needs
the code. `totpEnabled` is derived from a non-null `totpSecret` (not a column).
Wrong credentials → `401 UNAUTHORIZED` and an audit row with `result: "failure"`.

Response carries `Set-Cookie: cryptsk_token=<jwt>; HttpOnly; Path=/; Max-Age=28800; SameSite=Lax` —
httpOnly, never parsed in client JS.

Errors worth expecting: `401` bad credentials; `401` with `details.totpRequired` when a TOTP-enrolled
user omits `totpCode`; `429` login throttled by the auth-settings lockout policy.

---

## 2. Dashboard

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/dashboard/summary` | Health, throughput, sessions, alerts24h, topApps, topTalkers, wanStatus, vpnStatus | helpdesk | no |

`GET /api/v1/dashboard/summary` — `200` (full payload; throughput shape mirrors realtime `metrics:tick`):

```json
{
  "data": {
    "health": { "cpuPct": 34, "memPct": 58, "diskPct": 41, "tempC": 52, "uptimeSec": 983412 },
    "throughput": {
      "ts": "2026-11-05T09:30:00.000Z",
      "ifaces": [
        { "name": "wan0", "rxKbps": 700100, "txKbps": 198400 },
        { "name": "lan0", "rxKbps": 112300, "txKbps": 33400 }
      ]
    },
    "sessions": { "active": 1287, "conntrackCount": 1287 },
    "alerts24h": { "total": 17, "bySeverity": { "info": 6, "low": 5, "medium": 4, "high": 1, "critical": 1 } },
    "topApps": [
      { "app": "HTTPS", "bytes": 8423110000 },
      { "app": "YouTube", "bytes": 2310550000 }
    ],
    "topTalkers": [
      { "ip": "192.168.10.24", "userName": "jdoe", "bytes": 1540200000 },
      { "ip": "192.168.10.51", "userName": null, "bytes": 880240000 }
    ],
    "wanStatus": [
      { "iface": "wan0", "state": "up", "rxKbps": 700100, "txKbps": 198400 },
      { "iface": "wan1", "state": "degraded", "rxKbps": 9820, "txKbps": 4310 }
    ],
    "vpnStatus": [
      { "id": 3, "name": "wg-remote-access", "type": "wireguard_remote", "status": "up", "activeSessions": 12 },
      { "id": 5, "name": "ipsec-hq-branch", "type": "ipsec_s2s", "status": "connecting", "activeSessions": 0 }
    ]
  }
}
```

`activeSessions` is derived live by the adapter (not a stored column). No AI risk score / posture score in
Phase 1 (spec §1.1). The summary degrades gracefully field-by-field; the adapter never fails the whole payload.

---

## 3. Network — Interfaces, Routes, WAN Policies

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/interfaces` | List interfaces (with live stats) | soc_analyst | no |
| POST | `/api/v1/interfaces` | Create logical interface (vlan/bridge/bond/gre/ipip/loopback) | network_admin | yes |
| GET | `/api/v1/interfaces/{id}` | Interface detail | soc_analyst | no |
| PUT | `/api/v1/interfaces/{id}` | Update (ip config, mtu, role, zone…) | network_admin | yes |
| DELETE | `/api/v1/interfaces/{id}` | Delete (non-physical only) | network_admin | yes |
| GET | `/api/v1/interfaces/{id}/stats` | Per-interface counters | soc_analyst | no |
| GET | `/api/v1/network/lldp-neighbors` | Derived LLDP neighbor table (live, engine ring) | soc_analyst | no |
| GET | `/api/v1/network/mac-table` | Derived bridge FDB view `?iface=&vlan=&q=` | soc_analyst | no |
| GET | `/api/v1/network/port-mirrors` | List SPAN/mirror sessions | soc_analyst | no |
| POST | `/api/v1/network/port-mirrors` | Create mirror session (src/dst iface + direction) | network_admin | yes |
| PUT | `/api/v1/network/port-mirrors/{id}` | Update mirror session | network_admin | yes |
| DELETE | `/api/v1/network/port-mirrors/{id}` | Delete mirror session | network_admin | yes |
| GET | `/api/v1/network/app-catalog` | nDPI app-label catalog (feeds app pickers) | soc_analyst | no |
| GET | `/api/v1/routes` | Static routes list | soc_analyst | no |
| POST | `/api/v1/routes` | Create static route | network_admin | yes |
| PUT | `/api/v1/routes/{id}` | Update static route | network_admin | yes |
| DELETE | `/api/v1/routes/{id}` | Delete static route | network_admin | yes |
| GET | `/api/v1/pbr-rules` | Policy-based routing rules (ordered) | soc_analyst | no |
| POST | `/api/v1/pbr-rules` | Create PBR rule (match → forced egress/next hop) | network_admin | yes |
| PUT | `/api/v1/pbr-rules/{id}` | Update PBR rule | network_admin | yes |
| DELETE | `/api/v1/pbr-rules/{id}` | Delete PBR rule | network_admin | yes |
| PATCH | `/api/v1/pbr-rules/{id}/toggle` | `{enabled}` — optimistic toggle | network_admin | yes |
| GET | `/api/v1/wan-policies` | Multi-WAN policies + probe states | helpdesk | no |
| POST | `/api/v1/wan-policies` | Create WAN policy | network_admin | yes |
| PUT | `/api/v1/wan-policies/{id}` | Update WAN policy | network_admin | yes |
| DELETE | `/api/v1/wan-policies/{id}` | Delete WAN policy | network_admin | yes |
| POST | `/api/v1/wan-policies/{id}/probe` | Force probe now | network_admin | yes |

`POST /api/v1/interfaces` — create a VLAN (`config` shape per type, SCHEMA.md §4):

```json
{ "name": "vlan10", "type": "vlan", "role": "lan", "vlanId": 10, "config": { "parent": "lan0" }, "mtu": 1500, "enabled": true, "description": "Guest VLAN 10" }
```

The create dialog also accepts `type: "loopback"` (address-only logical iface) and `type: "ipip"`
(`config: { local, remote }`). Every interface carries `mode: "l2"\|"l3"` (default `l3`; when `l2`,
IP/WAN config fields are hidden — L2/L3 mode toggle, spec §1.2). Bridge configs additionally accept
`stpMode` (`stp\|rstp`) and `igmpSnooping` (boolean); physical configs accept `lldp` (boolean).

`201` response (list/detail responses embed the same adapter-provided `stats` block):

```json
{
  "data": {
    "id": 9, "tenantId": 1, "name": "vlan10", "type": "vlan", "role": "lan",
    "parentName": "lan0", "vlanId": 10, "mtu": 1500, "mssClamp": null, "enabled": true,
    "config": { "parent": "lan0" }, "description": "Guest VLAN 10", "zoneId": null,
    "stats": { "state": "down", "rxKbps": 0, "txKbps": 0, "rxPackets": 0, "txPackets": 0, "errors": 0, "drops": 0 }
  }
}
```

Errors worth expecting: `409` duplicate interface name; `409` deleting a `physical` interface; `400` invalid
CIDR/gateway in `config`; `409` deleting an interface referenced by a WAN policy or zone.

`POST /api/v1/pbr-rules` — policy-based routing (source/dest match → forced egress). `srcAddrIds`/
`dstAddrIds`/`serviceIds` follow the mixed object+group id semantics of firewall rules; set **either**
`outgoingIface` **or** `gateway` (not both):

```json
{ "name": "voip-via-wan1", "position": 1, "enabled": true, "srcAddrIds": [2], "dstAddrIds": [], "serviceIds": [7], "outgoingIface": "wan1", "gateway": null, "description": "SIP egress on backup link" }
```

Appliance rendering: fwmark on matching connections (`ip rule fwmark <mark> lookup <table>`, one table
per WAN) — same mechanism the multi-WAN modes use (M02 §5).

---

## 4. Objects — Zones, Address, Services, Schedules

All six resources share the same CRUD shape. `GET` floor `soc_analyst`; `POST`/`PUT`/`DELETE` floor
`security_admin` (objects are part of the firewall/security domain per the RBAC matrix — `network_admin`
gets read); all mutations audited and snapshotted under section `firewall`.

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/zones` | List zones (with member interface names) | soc_analyst | no |
| POST | `/api/v1/zones` | Create zone | security_admin | yes |
| PUT | `/api/v1/zones/{id}` | Update zone | security_admin | yes |
| DELETE | `/api/v1/zones/{id}` | Delete zone | security_admin | yes |
| GET | `/api/v1/address-objects` | List address objects (`?type=` filter) | soc_analyst | no |
| POST | `/api/v1/address-objects` | Create (ip/range/subnet/fqdn/geo/wildcard) | security_admin | yes |
| PUT | `/api/v1/address-objects/{id}` | Update | security_admin | yes |
| DELETE | `/api/v1/address-objects/{id}` | Delete (CONFLICT if referenced) | security_admin | yes |
| GET | `/api/v1/address-groups` | List address groups | soc_analyst | no |
| POST | `/api/v1/address-groups` | Create group of address-object ids | security_admin | yes |
| PUT | `/api/v1/address-groups/{id}` | Update | security_admin | yes |
| DELETE | `/api/v1/address-groups/{id}` | Delete | security_admin | yes |
| GET | `/api/v1/service-objects` | List service objects | soc_analyst | no |
| POST | `/api/v1/service-objects` | Create (tcp/udp/icmp/any + ports) | security_admin | yes |
| PUT | `/api/v1/service-objects/{id}` | Update | security_admin | yes |
| DELETE | `/api/v1/service-objects/{id}` | Delete | security_admin | yes |
| GET | `/api/v1/service-groups` | List service groups | soc_analyst | no |
| POST | `/api/v1/service-groups` | Create group of service-object ids | security_admin | yes |
| PUT | `/api/v1/service-groups/{id}` | Update | security_admin | yes |
| DELETE | `/api/v1/service-groups/{id}` | Delete | security_admin | yes |
| GET | `/api/v1/schedule-objects` | List schedules | soc_analyst | no |
| POST | `/api/v1/schedule-objects` | Create (always/recurring/onetime) | security_admin | yes |
| PUT | `/api/v1/schedule-objects/{id}` | Update | security_admin | yes |
| DELETE | `/api/v1/schedule-objects/{id}` | Delete | security_admin | yes |

`POST /api/v1/address-groups` — request, then `201` (`memberIds` are `address_objects.id`; groups do not nest):

```json
{ "name": "guest-subnets", "memberIds": [3, 4, 7], "description": "All guest ranges" }
```

```json
{ "data": { "id": 6, "tenantId": 1, "name": "guest-subnets", "memberIds": [3, 4, 7], "description": "All guest ranges" } }
```

Schedule `recurrence` JSON shape: `{ "days": [1,2,3,4,5], "start": "09:00", "end": "17:00" }` (1 = Monday),
with `timezone` an IANA name; one-time schedules use `startsAt`/`endsAt`.

Errors worth expecting: `409` duplicate object name; `409` delete with `details.referencedBy` listing the
firewall/NAT rule names that still use the object (service-layer integrity check, SCHEMA.md §5).

---

## 5. Firewall — Rules & NAT

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/firewall-rules` | Ordered list (`?zone=&search=`) | soc_analyst | no |
| POST | `/api/v1/firewall-rules` | Create rule | security_admin | yes |
| GET | `/api/v1/firewall-rules/{id}` | Rule detail | soc_analyst | no |
| PUT | `/api/v1/firewall-rules/{id}` | Replace rule (echo `updatedAt`) | security_admin | yes |
| DELETE | `/api/v1/firewall-rules/{id}` | Delete rule | security_admin | yes |
| PATCH | `/api/v1/firewall-rules/{id}/toggle` | Enable/disable, body `{enabled}` | security_admin | yes |
| POST | `/api/v1/firewall-rules/reorder` | Full order write, body `{orderedIds}` | security_admin | yes |
| GET | `/api/v1/firewall-rules/{id}/hits` | Hit counters | soc_analyst | no |
| POST | `/api/v1/firewall-rules/{id}/hits/reset` | Reset per-rule counters | security_admin | yes |
| POST | `/api/v1/firewall-rules/validate` | Shadow/conflict check, no persist | security_admin | no |
| POST | `/api/v1/firewall-rules/import` | `{format: "json"\|"csv", payload}` | security_admin | yes |
| GET | `/api/v1/firewall-rules/export?format=` | Export json/csv | soc_analyst | no |
| GET | `/api/v1/nat-rules` | List NAT rules | soc_analyst | no |
| POST | `/api/v1/nat-rules` | Create NAT rule | security_admin | yes |
| PUT | `/api/v1/nat-rules/{id}` | Update NAT rule | security_admin | yes |
| DELETE | `/api/v1/nat-rules/{id}` | Delete NAT rule | security_admin | yes |
| PATCH | `/api/v1/nat-rules/{id}/toggle` | `{enabled}` — optimistic toggle | security_admin | yes |
| POST | `/api/v1/nat-rules/reorder` | `{orderedIds: number[]}` full order | security_admin | yes |

`POST /api/v1/firewall-rules` — `srcAddrIds`/`dstAddrIds` mix address-object and address-group ids;
`serviceIds` mixes service-object and service-group ids (logical references, service-layer integrity).
`applicationIds` holds nDPI app-label strings from `GET /api/v1/network/app-catalog` (app-aware rules,
spec §1.4); `userIds` holds `User.id` (user-based rules via the identity map); `srcMacs` holds MAC
strings for MAC filtering rules (appliance: nftables `ether saddr`). Omitted `position` appends the
rule last (explicit placement goes through `/reorder`):

```json
{
  "name": "block-guest-to-corp", "description": "Guests must not reach corp subnets",
  "enabled": true, "position": 4,
  "srcZoneIds": [3], "dstZoneIds": [1],
  "srcAddrIds": [6, 12], "dstAddrIds": [2, 14],
  "serviceIds": [1, 8], "applicationIds": ["youtube"], "userIds": [], "srcMacs": ["aa:bb:cc:dd:ee:01"], "scheduleId": null,
  "action": "deny", "logging": "summary",
  "connLimit": 500, "rateLimit": 100, "synProtection": false, "synThreshold": null,
  "ipsPolicyId": null, "qosPolicyId": null,
  "tags": ["guest", "guardrail"], "comment": "SOC ticket 4412"
}
```

`201` response:

```json
{
  "data": {
    "id": 12, "tenantId": 1,
    "name": "block-guest-to-corp", "description": "Guests must not reach corp subnets",
    "enabled": true, "position": 4,
    "srcZoneIds": [3], "dstZoneIds": [1],
    "srcAddrIds": [6, 12], "dstAddrIds": [2, 14],
    "serviceIds": [1, 8], "applicationIds": ["youtube"], "userIds": [], "srcMacs": ["aa:bb:cc:dd:ee:01"], "scheduleId": null,
    "action": "deny", "logging": "summary",
    "connLimit": 500, "rateLimit": 100, "synProtection": false, "synThreshold": null,
    "ipsPolicyId": null, "qosPolicyId": null,
    "tags": ["guest", "guardrail"], "comment": "SOC ticket 4412",
    "hitCount": 0, "lastHitAt": null,
    "createdAt": "2026-11-05T09:05:00.000Z", "updatedAt": "2026-11-05T09:05:00.000Z"
  }
}
```

`POST /api/v1/firewall-rules/validate` — candidate rule body (same shape, no `id`); optional `excludeRuleId`
when re-validating an edit of an existing rule. `200` with conflict list; `ok` is `true` when `conflicts` is
empty. `reason` is `"shadowed_by"` (candidate made unreachable by an earlier rule), `"conflicts_with"`
(overlapping match, contradictory action) or `"redundant"` (same scope, same action — duplicate; warning
severity in UI):

```json
{
  "data": {
    "ok": false,
    "conflicts": [
      { "ruleId": 7, "ruleName": "allow-guest-web", "reason": "shadowed_by", "withRuleId": 3, "withRuleName": "permit-all-lan" },
      { "ruleId": 12, "ruleName": "block-guest-to-corp", "reason": "conflicts_with", "withRuleId": 9, "withRuleName": "guest-web-allow" }
    ]
  }
}
```

`POST /api/v1/firewall-rules/reorder` — full ordered id array, then `200`:

```json
{ "orderedIds": [12, 3, 7, 9, 1] }
```

```json
{
  "data": {
    "rules": [
      { "id": 12, "position": 1 }, { "id": 3, "position": 2 }, { "id": 7, "position": 3 }, { "id": 9, "position": 4 }, { "id": 1, "position": 5 }
    ]
  }
}
```

`POST /api/v1/nat-rules` — DNAT port forward; `201` wraps the created `NatRule` row (same fields plus
`id`, `tenantId`, `hitCount`, `createdAt`) in `data`. SNAT rules may carry `translatedSrcPool` (array of
ips — NAT pool with `overload`) and DNAT rules may carry `translatedPortRange` (`"5000-5100,6000"`)
instead of the single `translatedPort`; `logging` (`none|summary|detail`) turns on NAT translation
logging (spec §1.5). Mutually exclusive pairs are validated (`translatedPort` xor `translatedPortRange`):

```json
{
  "name": "web-portal-forward", "position": 2, "type": "dnat", "enabled": true,
  "srcAddrIds": [], "dstAddrIds": [5], "serviceIds": [2], "outgoingIface": "wan0",
  "translatedSrc": null, "translatedSrcPool": [], "overload": true,
  "translatedDst": "192.168.10.60", "translatedPort": 8080, "translatedPortRange": null,
  "logging": "summary", "comment": "Portal reverse proxy"
}
```

A 1:1 (static) NAT is created with the **1:1 helper** in the NAT editor: it emits the paired `dnat`
(no port) + `snat` rows atomically — same API, two rows, one audit entry.

Rule hit counters are resettable via `POST /{id}/hits/reset` (audited); NAT rules support the same
`PATCH /{id}/toggle` + `POST /reorder` pattern as firewall rules.

Errors worth expecting: `400` invalid action/logging enums, malformed reorder array (missing/duplicate ids);
`409` stale `updatedAt` on PUT (optimistic concurrency, API_STANDARDS §8); `409` deleting an object still
referenced by rules via `srcAddrIds`-style arrays.

---

## 6. IPS

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/ips/policies` | List IPS policies | soc_analyst | no |
| POST | `/api/v1/ips/policies` | Create policy | security_admin | yes |
| PUT | `/api/v1/ips/policies/{id}` | Update policy | security_admin | yes |
| DELETE | `/api/v1/ips/policies/{id}` | Delete policy (409 if attached to rules) | security_admin | yes |
| GET | `/api/v1/ips/rule-categories` | ET category list + enabled state | soc_analyst | no |
| GET | `/api/v1/ips/events` | `?severity=&sid=&q=&since=&until=&category=&page=` | soc_analyst | no |
| POST | `/api/v1/ips/events/{id}/suppress` | `{duration: "24h"\|"7d"\|"forever"}` | soc_analyst | yes |
| POST | `/api/v1/ips/policies/apply-preset` | `{preset: "conservative"\|"balanced"\|"aggressive", name?}` → creates/updates a policy from the preset bundle | security_admin | yes |
| GET | `/api/v1/ips/update-settings` | Auto-update scheduler config (`SystemSetting` `ips/auto_update`) | soc_analyst | no |
| PUT | `/api/v1/ips/update-settings` | Save scheduler (enabled, interval daily\|weekly, time) | security_admin | yes |

Conventions (pinned, see ADR-017): `duration: "forever"` → `suppressedUntil = null` + `action = "suppressed"` (permanence is carried by the action, not a far-future date). Traffic on firewall rules **without** an attached `ipsPolicyId` is evaluated by the engine-level default policy = first enabled policy by seed order (`id` ascending) — simulation-only convention, documented so demos/tests are deterministic.

`POST /api/v1/ips/events/8841/suppress` — request, then `200` (full `IpsEvent` row back):

```json
{ "duration": "24h" }
```

```json
{
  "data": {
    "id": 8841, "tenantId": 1, "timestamp": "2026-11-05T09:12:44.000Z",
    "srcIp": "203.0.113.44", "srcPort": 51344, "dstIp": "192.168.10.24", "dstPort": 443,
    "action": "alert", "sid": "2027865", "severity": "high", "category": "web_attack",
    "message": "ET WEB_ATTACK SQLi attempt", "suppressedUntil": "2026-11-06T09:12:44.000Z"
  }
}
```

`duration: "forever"` sets `suppressedUntil` to `null` and `action` to `"suppressed"` (the action value
carries permanent suppression).

Errors worth expecting: `404` unknown event id; `400` invalid duration; `409` deleting a policy still
referenced by `FirewallRule.ipsPolicyId`; `400` unknown `preset` value (enum: `conservative`,
`balanced`, `aggressive`).

---

## 7. VPN

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/vpn/configs` | List tunnel configs | soc_analyst | no |
| POST | `/api/v1/vpn/configs` | Create config (`type` per §6 enum) | network_admin | yes |
| PUT | `/api/v1/vpn/configs/{id}` | Update config (name, type, config, enabled). **Never sets `status`/`statusMessage`** — those are engine-owned (set by tunnel bring-up/teardown and broadcast via `vpn:status`); the handler ignores them if present | network_admin | yes |
| DELETE | `/api/v1/vpn/configs/{id}` | Delete config (cascades sessions) | network_admin | yes |
| GET | `/api/v1/vpn/configs/{id}/status` | Tunnel state, DPD, handshakes | soc_analyst | no |
| POST | `/api/v1/vpn/configs/{id}/client-bundle` | Client config download payload | network_admin | yes |
| GET | `/api/v1/vpn/sessions` | Active sessions | helpdesk | no |
| POST | `/api/v1/vpn/sessions/{id}/disconnect` | Kill a session | security_admin / soc_analyst | yes |
| GET | `/api/v1/vpn/user-groups` | List VPN user groups (pools, timeouts, limits, members) | soc_analyst | no |
| POST | `/api/v1/vpn/user-groups` | Create group | network_admin | yes |
| PUT | `/api/v1/vpn/user-groups/{id}` | Update group (incl. `memberUsernames` replace-all) | network_admin | yes |
| DELETE | `/api/v1/vpn/user-groups/{id}` | Delete group | network_admin | yes |

`POST /api/v1/vpn/configs/3/client-bundle` — `200` with the full file as text; the client triggers a
download from `{filename}`/`{contentType}`/`{content}`:

```json
{
  "data": {
    "filename": "wg-remote-access-alice.conf",
    "contentType": "text/plain",
    "content": "[Interface]\nPrivateKey = <client-private-key>\nAddress = 10.99.0.24/32\nDNS = 10.10.0.1\n\n[Peer]\nPublicKey = <server-public-key>\nEndpoint = vpn.corp.example:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
  }
}
```

Available for WireGuard and OpenVPN remote-access types (`wireguard_remote`, `openvpn`); other types
→ `409` (IPSec remote uses EAP provisioning, not downloadable bundles — M05 §4).
`GET /vpn/configs/{id}/status` returns
`{data: {status, statusMessage, peers: [{name, handshakeSec, transferIn, transferOut}], dpdSec}}` for s2s types.

`POST /api/v1/vpn/user-groups` — VPN user groups (spec §1.7): per-group pool override, pushed DNS,
idle/max session timeouts and session limits; members are remote usernames (logical refs):

```json
{ "name": "contractors", "description": "Limited vendor access", "pool": "10.99.1.0/24", "dns": "10.10.0.1", "idleTimeoutMin": 30, "maxSessionMin": 480, "maxSessionsPerUser": 1, "memberUsernames": ["c.reyes"] }
```

The engine applies group policy at connect time: `assignedIp` comes from the group pool when the
connecting `userName` is a member, and the session carries `groupName`; idle/max limits feed the
session churn (M05 §5).

Errors worth expecting: `409` client-bundle on a s2s-only config; `400` invalid `VpnConfig.config` JSON for
the declared `type` (zod shape per SCHEMA.md §4); `404` unknown session id on disconnect; `409` duplicate
VPN user-group name; `400` overlapping group pool with a remote-access config pool.

---

## 8. DNS & DHCP

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/dns/settings` | Resolver config | soc_analyst | no |
| PUT | `/api/v1/dns/settings` | Update resolver config | network_admin | yes |
| GET | `/api/v1/dns/policies` | List DNS filter policies | soc_analyst | no |
| POST | `/api/v1/dns/policies` | Create policy | network_admin | yes |
| PUT | `/api/v1/dns/policies/{id}` | Update policy | network_admin | yes |
| DELETE | `/api/v1/dns/policies/{id}` | Delete policy | network_admin | yes |
| GET | `/api/v1/dns/records` | List local records (`?zone=`) | soc_analyst | no |
| POST | `/api/v1/dns/records` | Create record | network_admin | yes |
| PUT | `/api/v1/dns/records/{id}` | Update record | network_admin | yes |
| DELETE | `/api/v1/dns/records/{id}` | Delete record | network_admin | yes |
| GET | `/api/v1/dns/query-logs` | `?q=&blocked=` query log | soc_analyst | no |
| GET | `/api/v1/dhcp/subnets` | List DHCP subnets | soc_analyst | no |
| POST | `/api/v1/dhcp/subnets` | Create subnet | network_admin | yes |
| PUT | `/api/v1/dhcp/subnets/{id}` | Update subnet | network_admin | yes |
| DELETE | `/api/v1/dhcp/subnets/{id}` | Delete subnet (cascades reservations + leases) | network_admin | yes |
| GET | `/api/v1/dhcp/reservations` | List reservations | soc_analyst | no |
| POST | `/api/v1/dhcp/reservations` | Create reservation | network_admin | yes |
| PUT | `/api/v1/dhcp/reservations/{id}` | Update reservation | network_admin | yes |
| DELETE | `/api/v1/dhcp/reservations/{id}` | Delete reservation | network_admin | yes |
| GET | `/api/v1/dhcp/leases` | `?state=active\|expired` | soc_analyst | no |
| POST | `/api/v1/dhcp/leases/{id}/release` | Force-release a lease | network_admin | yes |
| GET | `/api/v1/dhcp/relay` | DHCP relay (ip-helper) config | soc_analyst | no |
| PUT | `/api/v1/dhcp/relay` | Save relay config (enabled, servers, interfaces) | network_admin | yes |

`POST /api/v1/dhcp/subnets` — request, then `201` (`dnsServers`/`options` are real JSON in the API):

```json
{
  "interfaceName": "lan0", "subnetCidr": "192.168.10.0/24",
  "rangeStart": "192.168.10.100", "rangeEnd": "192.168.10.200", "gateway": "192.168.10.1",
  "dnsServers": ["192.168.10.1"], "leaseTime": 86400,
  "options": { "42": "192.168.10.1" }, "enabled": true
}
```

`201` wraps the created `DhcpSubnet` row (same fields plus `id`, `tenantId`) in `data`.

`/dns/settings` persists as a `SystemSetting` row (category `dns`, key `resolver`) and `/dns/query-logs`
is MockEngine runtime data — neither has a dedicated Prisma model by design (SCHEMA.md §6
Pseudo-Resources). The resolver JSON additionally carries `forwardZones` (per-domain conditional
forwarding — Unbound `forward-zone` blocks, spec §1.8) and the `doh` server toggle; the subnet rows
carry `family` (`ipv4\|ipv6`) for basic DHCPv6 (kea-dhcp6.conf rendering, spec §1.9).

`GET/PUT /api/v1/dhcp/relay` — singleton relay (ip-helper) config persisted as `SystemSetting`
(category `dhcp`, key `relay`): `{ "enabled": false, "servers": ["192.168.10.254"], "interfaces": ["lan0"] }`.
The appliance renders `dhcrelay`/Kea relay config per interface; in sandbox the relay is recorded and
shown in the Relay tab.

Errors worth expecting: `409` duplicate reservation MAC (unique per tenant); `409` lease IP collision
(unique per subnet, `@@unique([subnetId, ip])`); `400` `rangeEnd` outside `subnetCidr`.

---

## 9. Identity — Users, Groups, Auth, RADIUS, Portal, Sessions

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/users` | List users | tenant_admin | no |
| POST | `/api/v1/users` | Create user | tenant_admin | yes |
| PUT | `/api/v1/users/{id}` | Update user (role, active, password reset) | tenant_admin | yes |
| DELETE | `/api/v1/users/{id}` | Delete user | tenant_admin | yes |
| GET | `/api/v1/user-groups` | List groups with member counts | tenant_admin | no |
| POST | `/api/v1/user-groups` | Create group | tenant_admin | yes |
| PUT | `/api/v1/user-groups/{id}` | Update group/members | tenant_admin | yes |
| DELETE | `/api/v1/user-groups/{id}` | Delete group (members unlinked) | tenant_admin | yes |
| GET | `/api/v1/auth-settings` | Password policy, lockout, TOTP | tenant_admin | no |
| PUT | `/api/v1/auth-settings` | Update auth settings | tenant_admin | yes |
| GET | `/api/v1/radius-profiles` | List RADIUS profiles | tenant_admin | no |
| POST | `/api/v1/radius-profiles` | Create profile | tenant_admin | yes |
| PUT | `/api/v1/radius-profiles/{id}` | Update profile | tenant_admin | yes |
| DELETE | `/api/v1/radius-profiles/{id}` | Delete profile | tenant_admin | yes |
| POST | `/api/v1/radius-profiles/{id}/test` | Simulated connectivity test → `{ok, latencyMs}` | security_admin | yes |
| POST | `/api/v1/radius-profiles/{id}/reveal` | Clear `sharedSecret` (audited, super_admin/tenant_admin) | tenant_admin | yes |
| GET | `/api/v1/captive-portal` | Portal profile (singleton) | security_admin | no |
| PUT | `/api/v1/captive-portal` | Update portal profile | security_admin | yes |
| GET | `/api/v1/captive-portal/vouchers` | List vouchers (in-memory) | security_admin | no |
| POST | `/api/v1/captive-portal/vouchers` | `{count, ttlHours?, bandwidthKbps?}` batch generate | security_admin | yes |
| DELETE | `/api/v1/captive-portal/vouchers/{id}` | Revoke one voucher | security_admin | yes |
| GET | `/api/v1/identity/sessions` | Live ip→user session map | helpdesk | no |
| POST | `/api/v1/identity/sessions/{id}/expire` | Force-expire a session | security_admin | yes |
| GET | `/api/v1/directory-sources` | List LDAP/AD directory sources (bindPassword masked) | tenant_admin | no |
| POST | `/api/v1/directory-sources` | Create directory source | tenant_admin | yes |
| PUT | `/api/v1/directory-sources/{id}` | Update (omit `bindPassword` to keep) | tenant_admin | yes |
| DELETE | `/api/v1/directory-sources/{id}` | Delete directory source | tenant_admin | yes |
| POST | `/api/v1/directory-sources/{id}/test` | Simulated LDAP/AD connectivity test → `{ok, latencyMs, userCount?}` | tenant_admin | yes |

`POST /api/v1/users` — `password` is accepted in the request, hashed server-side into `passwordHash`, and
never returned; `groupIds` writes `user_group_members`:

```json
{ "username": "jdoe", "password": "Temp!Pass2026", "role": "helpdesk", "email": "jdoe@corp.local", "isActive": true, "groupIds": [2] }
```

`201` response (no `passwordHash`, no `totpSecret` in any response):

```json
{
  "data": {
    "id": 7, "tenantId": 1, "username": "jdoe", "role": "helpdesk",
    "email": "jdoe@corp.local", "isActive": true, "totpEnabled": false,
    "groups": [ { "id": 2, "name": "helpdesk-team" } ],
    "lastLoginAt": null, "createdAt": "2026-11-05T09:40:12.000Z"
  }
}
```

`RadiusProfile.sharedSecret` is masked in responses; it is only settable via POST/PUT.
`GET /identity/sessions` returns paginated `IdentitySession` rows (`userName`, `sourceIp`,
`method` ∈ `local|radius|captive_portal|vpn`, `deviceMac`, `startedAt`, `lastSeen`, `state`).

Voucher endpoints (list / batch-generate / revoke) and the identity-session kill endpoint
(`POST /identity/sessions/{id}/expire`) are both part of the locked §7.2 surface; vouchers live in the
MockEngine in-memory store (SCHEMA.md §6 Pseudo-Resources).

Errors worth expecting: `409` duplicate username (unique per tenant); `403` attempting to create/modify a
`super_admin` without being `super_admin`; `400` role not in the §6 enum (`viewer` is not a role — valid low-privilege role is `helpdesk`).

---

## 10. QoS

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/qos/policies` | List shaper policies | soc_analyst | no |
| POST | `/api/v1/qos/policies` | Create policy | network_admin | yes |
| PUT | `/api/v1/qos/policies/{id}` | Update policy | network_admin | yes |
| DELETE | `/api/v1/qos/policies/{id}` | Delete policy (cascades its rules) | network_admin | yes |
| GET | `/api/v1/qos/rules` | List rules, scoped `?policyId=` | soc_analyst | no |
| POST | `/api/v1/qos/rules` | Create rule in a policy | network_admin | yes |
| PUT | `/api/v1/qos/rules/{id}` | Update rule | network_admin | yes |
| DELETE | `/api/v1/qos/rules/{id}` | Delete rule | network_admin | yes |

`POST /api/v1/qos/rules` — `matchApps` holds nDPI label ids (strings); `matchAddresses` holds
address-object ids. `201` wraps the created `QosRule` row in `data`:

```json
{
  "policyId": 1, "name": "voip-priority", "priority": 1,
  "guaranteedKbps": 20000, "maxKbps": 50000, "dscpMark": 46,
  "matchApps": ["sip", "rtp"], "matchUsers": [], "matchAddresses": [8]
}
```

Errors worth expecting: `404` `policyId` does not exist; `400` `priority` outside 0–7;
`409` deleting a policy attached to `FirewallRule.qosPolicyId`.

---

## 11. Logs

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/logs/firewall` | `?q=&action=&src=&dst=&since=&until=&page=` | soc_analyst | no |
| GET | `/api/v1/logs/firewall/export` | CSV of current filter (same params, no page) | soc_analyst | no |
| GET | `/api/v1/logs/ips` | `?severity=&category=&page=` | soc_analyst | no |
| GET | `/api/v1/logs/audit` | `?user=&objectType=&page=` | soc_analyst | no |
| GET | `/api/v1/logs/stats` | Chart aggregates `?range=1h\|24h\|7d` | soc_analyst | no |
| GET | `/api/v1/logs/reports/export` | Report export `?range=1h\|24h\|7d&format=csv\|json` | soc_analyst | no |
| GET | `/api/v1/logs/syslog-targets` | List syslog forwarding targets | soc_analyst | no |
| POST | `/api/v1/logs/syslog-targets` | Create syslog target (host, port, protocol, minSeverity) | network_admin | yes |
| PUT | `/api/v1/logs/syslog-targets/{id}` | Update target | network_admin | yes |
| DELETE | `/api/v1/logs/syslog-targets/{id}` | Delete target | network_admin | yes |
| GET | `/api/v1/logs/netflow-targets` | List NetFlow/IPFIX export targets | soc_analyst | no |
| POST | `/api/v1/logs/netflow-targets` | Create NetFlow target (host, port, version, samplingRate) | network_admin | yes |
| PUT | `/api/v1/logs/netflow-targets/{id}` | Update target | network_admin | yes |
| DELETE | `/api/v1/logs/netflow-targets/{id}` | Delete target | network_admin | yes |
| GET | `/api/v1/logs/report-schedules` | List scheduled reports | soc_analyst | no |
| POST | `/api/v1/logs/report-schedules` | Create schedule (range, format, sections, recipients) | security_admin | yes |
| PUT | `/api/v1/logs/report-schedules/{id}` | Update schedule | security_admin | yes |
| DELETE | `/api/v1/logs/report-schedules/{id}` | Delete schedule | security_admin | yes |
| POST | `/api/v1/logs/report-schedules/{id}/run` | Generate the report now (simulated delivery) | security_admin / soc_analyst | yes |

`GET /api/v1/logs/firewall?action=drop&src=203.0.113.44&since=2026-11-05T00:00:00Z&page=2&limit=25&sort=-timestamp`
— `src`/`dst` filter on exact IP. `200` (rows carry the full `FirewallLog` shape):

```json
{
  "data": [
    {
      "id": 248312, "tenantId": 1, "timestamp": "2026-11-05T09:28:41.000Z",
      "srcIp": "203.0.113.44", "dstIp": "192.168.10.24", "srcPort": 51344, "dstPort": 23,
      "protocol": "tcp", "action": "drop", "ruleName": "block-inbound-management",
      "appName": "TELNET", "bytes": 512, "packets": 6, "userName": null
    }
  ],
  "meta": { "page": 2, "limit": 25, "total": 1184, "totalPages": 48 }
}
```

`GET /api/v1/logs/stats?range=24h` — `200` with chart-ready series (each `points` array holds one entry per
bucket; two buckets shown here for brevity — real responses are complete):

```json
{
  "data": {
    "range": "24h", "from": "2026-11-04T09:30:00.000Z", "to": "2026-11-05T09:30:00.000Z", "bucketMinutes": 30,
    "series": [
      { "key": "allow", "points": [ { "ts": "2026-11-04T09:30:00.000Z", "count": 4120 }, { "ts": "2026-11-04T10:00:00.000Z", "count": 3985 } ] },
      { "key": "deny", "points": [ { "ts": "2026-11-04T09:30:00.000Z", "count": 118 }, { "ts": "2026-11-04T10:00:00.000Z", "count": 96 } ] },
      { "key": "drop", "points": [ { "ts": "2026-11-04T09:30:00.000Z", "count": 61 }, { "ts": "2026-11-04T10:00:00.000Z", "count": 74 } ] },
      { "key": "reject", "points": [ { "ts": "2026-11-04T09:30:00.000Z", "count": 9 }, { "ts": "2026-11-04T10:00:00.000Z", "count": 11 } ] }
    ],
    "ipsBySeverity": [
      { "key": "critical", "count": 2 }, { "key": "high", "count": 14 }, { "key": "medium", "count": 41 },
      { "key": "low", "count": 87 }, { "key": "info", "count": 210 }
    ]
  }
}
```

Live tails come from the socket.io `logs:tail` event, never from these endpoints (API_STANDARDS §10).
Errors worth expecting: `400` `range` outside `1h|24h|7d`; `400` malformed `since`/`until`.

Forwarding targets (spec §1.12: syslog forwarding, NetFlow/IPFIX export) are CRUD config rows
(`syslog_targets`, `netflow_targets`, SCHEMA.md §3). Reliability (buffer on disconnect) is per-target:
the view shows a `bufferedRows` counter for a target the engine marks unreachable; queued rows flush
when the target returns (appliance: rsyslog queue semantics).

`POST /api/v1/logs/report-schedules` — scheduled reports (spec §1.12):

```json
{ "name": "daily-traffic", "range": "daily", "format": "pdf", "sections": ["traffic", "threats"], "recipients": "ops@corp.local", "enabled": true }
```

`POST /api/v1/logs/report-schedules/{id}/run` generates the report immediately: the response carries
`{data: {format, content|downloadUrl, generatedAt}}` — csv/json stream as downloads; html/pdf use the
print-friendly report view in sandbox (browser print = PDF; the appliance renders via wkhtmltopdf).
The engine also fires schedules on their window (bumps `lastRunAt`, DATA_LIFECYCLE §4).

---

## 12. HA

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/ha/status` | Local + peer state (simulated in sandbox) | soc_analyst | no |
| GET | `/api/v1/ha/config` | Read HA config | soc_analyst | no |
| PUT | `/api/v1/ha/config` | Update HA config | network_admin | yes |

`PUT /api/v1/ha/config` — request, then `200` (matches `HaConfig` fields; `trackedInterfaces` is a JSON
array of iface names for Keepalived link monitoring, `sessionSync` toggles conntrackd replication):

```json
{
  "enabled": true, "role": "active", "priority": 100, "virtualIp": "192.168.10.1/24",
  "ifaceName": "lan0", "peerIp": "192.168.10.2", "syncConfig": true,
  "sessionSync": true, "trackedInterfaces": ["wan0", "wan1"],
  "failAfterSec": 10, "holdDownSec": 60
}
```

```json
{
  "data": {
    "id": 1, "tenantId": 1, "enabled": true, "role": "active", "priority": 100,
    "virtualIp": "192.168.10.1/24", "ifaceName": "lan0", "peerIp": "192.168.10.2",
    "syncConfig": true, "sessionSync": true, "trackedInterfaces": ["wan0", "wan1"],
    "failAfterSec": 10, "holdDownSec": 60
  }
}
```

`GET /ha/status` returns
`{data: {local: {role, state, priority, virtualIp, ifaceName}, peer: {ip, role, state, lastSeenSec, configSynced, sessionSynced}, trackedInterfaces: [{name, state}]}}`
— peer data is simulated in Sandbox Mode.

Errors worth expecting: `400` `virtualIp` not a CIDR; `409` enabling HA on an interface with no WAN/LAN role.

---

## 13. System — Status, Settings, Backups, Notifications, Config Versions, API Keys

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/system/status` | cpu/ram/disk/temp/uptime/services | helpdesk | no |
| GET | `/api/v1/system/settings` | Grouped settings by category | tenant_admin | no |
| PUT | `/api/v1/system/settings` | Update settings | tenant_admin | yes |
| GET | `/api/v1/system/backups` | List backups | tenant_admin | no |
| POST | `/api/v1/system/backups` | Create backup | tenant_admin | yes |
| POST | `/api/v1/system/backups/{id}/restore` | Restore backup | tenant_admin | yes |
| GET | `/api/v1/system/backups/{id}/download` | JSON backup download | tenant_admin | no |
| GET | `/api/v1/notifications` | `?unread=true` filter | helpdesk | no |
| POST | `/api/v1/notifications/{id}/read` | Mark one notification read | helpdesk | yes |
| POST | `/api/v1/notifications/read-all` | Mark all read | helpdesk | yes |
| GET | `/api/v1/config-versions` | `?page=` list | soc_analyst | no |
| GET | `/api/v1/config-versions/{id}` | One version + full snapshot | soc_analyst | no |
| GET | `/api/v1/api-keys` | List keys (prefix + metadata only) | tenant_admin | no |
| POST | `/api/v1/api-keys` | Create key (full key shown once) | super_admin | yes |
| DELETE | `/api/v1/api-keys/{id}` | Revoke key (`revoked = true`) | super_admin | yes |
| POST | `/api/v1/system/services/{name}/restart` | Restart a running service (simulated; audited) | tenant_admin | yes |
| GET | `/api/v1/system/firmware` | Firmware state: current, channel, lastCheck, available, history | tenant_admin | no |
| POST | `/api/v1/system/firmware/check` | Simulated update check (sets `available`) | tenant_admin | yes |
| POST | `/api/v1/system/firmware/upgrade` | Staged upgrade — safety backup first, then version bump (simulated) | tenant_admin | yes |
| POST | `/api/v1/system/firmware/rollback` | Roll back to the previous version in history (simulated) | tenant_admin | yes |
| GET | `/api/v1/system/policy-templates` | Per-vertical default policy templates (catalog) | soc_analyst | no |
| POST | `/api/v1/system/policy-templates/{id}/apply` | Apply a template's starter config (audited, snapshot `section: "all"`) | tenant_admin | yes |
| GET | `/api/v1/system/ssh-keys` | List SSH management keys (public material only) | tenant_admin | no |
| POST | `/api/v1/system/ssh-keys` | Add SSH public key (fingerprint derived server-side) | tenant_admin | yes |
| DELETE | `/api/v1/system/ssh-keys/{id}` | Remove SSH key | tenant_admin | yes |
| POST | `/api/v1/system/setup/complete` | Mark the first-time-setup wizard done (sets `setup.completed`) | tenant_admin | yes |

`GET /api/v1/system/status` — `200` (service names mirror the appliance stack; MockEngine simulates them):

```json
{
  "data": {
    "cpuPct": 34, "cpuCores": 8, "loadAvg": [0.42, 0.38, 0.35],
    "memTotalMb": 16384, "memUsedMb": 9506, "memPct": 58,
    "diskTotalGb": 512, "diskUsedGb": 210, "diskPct": 41,
    "tempC": 52, "uptimeSec": 983412,
    "services": [
      { "name": "firewall (nftables)", "status": "running" },
      { "name": "ips (suricata)", "status": "running" },
      { "name": "dns (unbound)", "status": "running" },
      { "name": "dhcp (kea)", "status": "running" },
      { "name": "vpn (wireguard)", "status": "degraded", "detail": "peer hq-branch handshake stale 6m" },
      { "name": "realtime", "status": "running" }
    ]
  }
}
```

`service.status` ∈ `running | stopped | degraded`. Continuous metrics stream via `metrics:tick`, not via
polling this endpoint.

`POST /api/v1/api-keys` with body `{ "name": "grafana-readonly", "scopes": ["read"], "expiresAt": "2027-01-31T00:00:00.000Z" }`
returns `201` with the full key **exactly once** (only `prefix` + sha256 `hashedKey` are stored); later GETs
return metadata only, and DELETE marks `revoked` (no key update endpoint — revoke and recreate):

```json
{
  "data": {
    "id": 4, "tenantId": 1, "name": "grafana-readonly", "prefix": "ck_9f3a21c4",
    "key": "ck_9f3a21c4_Rt7xQ2mLpV8sZnB4wKdH6yTa",
    "scopes": ["read"], "expiresAt": "2027-01-31T00:00:00.000Z",
    "revoked": false, "createdAt": "2026-11-05T09:52:03.000Z"
  }
}
```

`GET /api/v1/config-versions` returns paginated `ConfigVersion` rows; `configSnapshot` holds the full
section JSON. Example row (section `ha`):

```json
{
  "data": [
    {
      "id": 118, "tenantId": 1, "version": 42, "section": "ha",
      "configSnapshot": {
        "enabled": true, "role": "active", "priority": 100, "virtualIp": "192.168.10.1/24", "ifaceName": "lan0",
        "peerIp": "192.168.10.2", "syncConfig": true, "failAfterSec": 10, "holdDownSec": 60
      },
      "changeSummary": "ha_config.update", "createdBy": 1, "createdAt": "2026-11-05T09:11:02.000Z"
    }
  ],
  "meta": { "page": 1, "limit": 25, "total": 118, "totalPages": 5 }
}
```

`Notification` rows use `type` ∈ `threat|system|vpn|ha|config` and `severity` ∈ `info|warning|critical`
(PROJECT_MEMORY §6 has a **separate** `notifications.severity` row — the 5-level
`info|low|medium|high|critical` scale applies to `ips_events` only). SCHEMA.md's inline
`Notification.severity` comment is correct as written.

By design in Phase 1 (not gaps): `/system/backups` persists as filesystem JSON files, not a Prisma model
(SCHEMA.md §6 Pseudo-Resources); config-version rollback is not exposed (snapshots are read-only history
in Phase 1 — restore a backup instead); `/auth-settings` and `/system/settings` persist as
`SystemSetting` rows whose JSON value shapes are owned by the zod validators (SCHEMA.md §6, M10).
Settings-backed features restored in REVIEW-4A ride these shapes: NTP (category `general`, key `ntp`),
SNMP (`advanced`/`snmp`), hardening (`advanced`/`hardening`), resource-alert thresholds
(`notifications`/`thresholds`), firmware (`advanced`/`firmware`).

Errors worth expecting: `404` backup id on restore; `409` restore refused while HA is active with
`syncConfig` enabled; `403` api-key create/revoke without `super_admin` (or a key without `admin` scope —
listing is `tenant_admin`).

---

## 14. API Platform — Webhooks, OpenAPI, Setup

| METHOD | Path | Purpose | Role floor | Audit? |
|---|---|---|---|---|
| GET | `/api/v1/webhooks` | List webhook registrations (`secret` masked, never returned) | security_admin | no |
| POST | `/api/v1/webhooks` | Register webhook `{name, url, events, secret?}` | security_admin | yes |
| PUT | `/api/v1/webhooks/{id}` | Update (omit `secret` to keep) | security_admin | yes |
| DELETE | `/api/v1/webhooks/{id}` | Delete registration | security_admin | yes |
| POST | `/api/v1/webhooks/{id}/test` | Simulated delivery → `{ok, status, latencyMs}`; updates `lastDeliveryAt`/`lastStatus` | security_admin | yes |
| GET | `/api/v1/openapi.json` | OpenAPI 3.1 artifact generated from the zod validators + §7.2 route table | helpdesk | no |

Webhook registrations (spec §1.15, custom engineering) subscribe to the event names in the locked
`webhooks.events` enum (PROJECT_MEMORY §6: `alerts.new`, `config.updated`, `wan.status`, `vpn.status`,
`sessions.update` — dot-form of the realtime events; `logs.tail` is deliberately excluded to protect
log volume). Delivery is **simulated** in sandbox: the realtime-service marks deliveries
(`lastDeliveryAt`, `lastStatus`, `failureCount`) instead of performing real HTTP calls; the appliance
sender signs payloads with the HMAC `secret`.

`GET /api/v1/openapi.json` — machine-readable API docs (spec §1.15 "OpenAPI/Swagger docs"): generated
at build time from `src/lib/validators/*` + the LOCKED route table (M11 §4.2 strategy), served as a
static artifact. Human-readable docs remain ENDPOINTS.md; no swagger UI bundle is shipped in Phase 1.

Errors worth expecting: `409` duplicate webhook name; `400` invalid `url` (https only) or event outside
the enum; `404` unknown webhook id; `403` webhooks/openapi mutations from machine keys without `write`
(webhook registration is interactive-admin-only, mirroring api-keys).

---

## Cross-Links

- Contract of record (paths locked): [../00-PROJECT-MEMORY/PROJECT_MEMORY.md](../00-PROJECT-MEMORY/PROJECT_MEMORY.md) §7.2
- Standards (envelope, errors, RBAC, audit): [./API_STANDARDS.md](./API_STANDARDS.md)
- Schema + JSON field shapes: [../03-DATABASE/SCHEMA.md](../03-DATABASE/SCHEMA.md)
- Architecture (dual mode, adapters): [../02-ARCHITECTURE/ARCHITECTURE.md](../02-ARCHITECTURE/ARCHITECTURE.md)

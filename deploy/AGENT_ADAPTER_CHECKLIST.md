# AGENT_ADAPTER_CHECKLIST — Appliance Mode wiring (ADR-004 → Go agent on :8080)

> The console (`SystemAdapter`, `src/lib/adapters/types.ts`) was built once
> against this contract. The Debian 13 data plane implements it service by
> service. Check off as the Go agent lands each group; `ADAPTER_MODE=agent`
> requires **all Phase-1 rows**; Phase-2 rows gate their modules only.

## Phase 1 (gate: ADAPTER_MODE=agent)

| # | Adapter surface | Appliance backing | Console consumer |
|---|---|---|---|
| 1 | `getDashboardSummary` | `/proc`, conntrack, nfstat aggregates | M01 dashboard |
| 2 | metrics tick stream (2 s) | eBPF/nfstat sampler → Redis pubsub | M01 chart, realtime service |
| 3 | interfaces CRUD + status | `ip`/nftables + `/etc/systemd/network` | M02 Interfaces |
| 4 | static routes + PBR | `ip route`, `ip rule`, nftables marks | M02 Routing |
| 5 | WAN policies + probe state | `ping`/`curl` probes, policy routing | M02 Multi-WAN |
| 6 | zones + firewall rules | nftables tables/chains per zone | M03 Firewall |
| 7 | NAT (snat/dnat/1:1/hairpin/exempt) | nftables nat chains | M03 NAT |
| 8 | objects/groups/schedules | console-authoritative → nftables sets | M03 Objects |
| 9 | IPS policies/events | Suricata via NFQUEUE (`queue num 1-4 fanout bypass`), eve.json → agent | M04 IPS |
| 10 | VPN configs/sessions (WG/IPSec/OpenVPN) | wg-quick, strongSwan, openvpn + status sockets | M05 VPN |
| 11 | DNS policies/records/Query log | Unbound (RPZ, DoT, sinkhole), unbound-control | M06 DNS |
| 12 | DHCP subnets/reservations/leases/relay | Kea CTRL agent + lease DB | M06 DHCP |
| 13 | users/groups/auth policy/RADIUS | FreeRADIUS rest module + console JWT | M07 Identity |
| 14 | captive portal + vouchers | nftables + mini portal on agent | M07 Portal |
| 15 | QoS policies/classes | `tc` HTB + FQ_CoDel | M08 QoS |
| 16 | log store + live tail | journald/eve/conntrack → Redis streams | M09 Logs |
| 17 | syslog/NetFlow forwarding | rsyslog + nfcapd | M09 Forwarding |
| 18 | HA config + failover state | keepalived + conntrackd | M10 HA |
| 19 | backups/restore/firmware | agent REST + `apt` staged upgrade | M10 System |
| 20 | notifications engine | agent events → console SSE | M10 Notifications |
| 21 | API keys → agent scope enforcement | agent validates `X-API-Key` hash | M11 API |

## Phase 2 (per-module gates)

| Module | Agent surface | Backing service |
|---|---|---|
| M12 logging/reports | log search/aggregation | ClickHouse or Meilisearch (Phase-2 decision, ROADMAP §5) |
| M13 threat intel | feed fetch + nftables auto-block sets | cron + nftables named sets |
| M14 PKI | Step-CA client (issue/revoke/CRL) | Step-CA |
| M15 SSL inspection | Squid MITM bundle + bypass SNI lists | Squid + Step-CA |
| M16 URL filtering | Squid url_rewrite + blocklists | Squid |
| M17 WAF | Coraza + Caddy reverse proxy per vhost | Coraza SPOA |
| M18 app control | nDPI mark → nftables verdict maps | nDPI + nftables |
| M19 dynamic routing | FRR VTYsh (BGP/OSPF/BFD) | FRR |
| M20 SD-WAN | probe engine + policy routing + WG mesh | custom Go + WireGuard |
| M21 IPv6 | v6 firewall/NAT66/DHCPv6/RA | nftables inet family, Kea DHCPv6, radvd |
| M22 email security | Postfix before-queue filter + Rspamd + ClamAV | Postfix, Rspamd, ClamAV |
| M23 identity/NAC | FreeRADIUS 802.1X/MAB + CoA + dynamic VLAN | FreeRADIUS, hostapd/wired |

## Transport contract

- Console → agent: `POST {AGENT_BASE_URL}<path>` with `X-Agent-Auth: <AGENT_SHARED_SECRET>`.
- Agent responses use the console envelope: `{ data, meta? }` / `{ error: { code, message, details? } }`.
- Agent → console push: socket.io events on the realtime service (7 locked events, ADR-008) + webhook fan-out for `alerts.new`.
- Timeouts: reads 5 s, mutations 30 s, IPS/log streams streaming.
- Every mutation the agent executes is idempotent keyed by `X-Request-Id` (ULID from the handler middleware).

## Rollout order (recommended)

1. Items 1–2 (dashboard read-only) → flip staging box to `ADAPTER_MODE=agent` for observability.
2. Items 3–8 (network + firewall core) with a lab switch.
3. Items 9–12 (IPS/VPN/DNS/DHCP) — spec §1.4 exit-criteria attacks replayed.
4. Items 13–21 to complete Phase-1 gate; Phase-2 modules follow their own services.

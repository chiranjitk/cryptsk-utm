/**
 * VPN service layer (M05 §5) — business logic shared by the /api/v1/vpn routes.
 * Handlers stay thin. Engine-owned status (M05 §8 / ENDPOINTS §7): PUT never
 * writes status/statusMessage — transitions come from enable/disable and the
 * tunnel state machine. Integrity: config delete cascades sessions (ER §2);
 * port collisions → 409; remote-access pool overlaps (config or group) → 400.
 * Key/PSK generation is REAL crypto since the OS integration: WireGuard keys
 * are X25519 (lib/vpn/crypto.ts), PSKs are CSPRNG 256-bit — client bundles
 * carry material that works against real swanctl / wg / openvpn instances.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson } from "@/lib/json";
import { emitEvent } from "@/lib/engine/events";
import type {
  ClientBundleDto,
  IpsecConfig,
  OpenVpnConfig,
  VpnConfigDto,
  VpnConfigPayload,
  VpnSessionDto,
  VpnStatusDetailDto,
  VpnType,
  WgRemoteConfig,
  WgS2sConfig,
} from "./types";
import type { VpnConfigCreateInput, VpnConfigUpdateInput, VpnSessionsQuery, VpnUserGroupCreateInput, VpnUserGroupUpdateInput } from "@/lib/validators/vpn";
import type { PageMeta } from "@/lib/api/envelope";
import { generateWgKeypair, wgPublicKeyFromPrivate } from "./crypto";
import {
  readVpnOsFacts,
  tunnelOsStatus,
  readOpenVpnCaCert,
  readOpenVpnTaKey,
  connName,
  convergeVpnOs,
  type VpnOsConfigInput,
} from "./os";

/** Serialized converge queue — concurrent mutations (double PUT, PUT+DELETE)
 *  would otherwise race: a stale plan built from old facts can RE-START a
 *  service the newer plan just stopped (observed live). Each converge now
 *  runs to completion before the next reads facts. */
let convergeChain: Promise<unknown> = Promise.resolve();

/** Fire-and-forget OS converge after a config mutation (never blocks, never throws). */
function convergeAfterMutation(): void {
  convergeChain = convergeChain
    .then(() => convergeVpnOs())
    .catch(() => {});
}

/** toVpnOsConfigInput for the os layer. */
function osInput(row: NonNullable<VpnRow>): VpnOsConfigInput {
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    enabled: row.enabled,
    config: parseJson<VpnConfigPayload>(row.config, {} as VpnConfigPayload),
  };
}

type VpnRow = Awaited<ReturnType<typeof db.vpnConfig.findFirst>>;

// ── shaping ─────────────────────────────────────────────────────────────────

/** Strip the create/update envelope from a validated config (validators key by type). */
export function configOfPayload(type: VpnType, raw: unknown): VpnConfigPayload {
  // validators already deep-validated against the same shapes; here we only
  // normalize optional empty strings → undefined so the JSON stays clean.
  const cfg = (raw ?? {}) as Record<string, unknown>;
  const out: Record<string, unknown> = { ...cfg };
  for (const key of ["dns", "remoteIp"]) {
    if (out[key] === "") delete out[key];
  }
  if (type === "ipsec_s2s" || type === "ipsec_remote") {
    out.pfs = out.pfs !== false; // M05 §5: pfs defaults true on save
    out.authMethod = out.authMethod ?? "psk";
    if (type === "ipsec_s2s") out.authMethod = "psk";
    delete out.dns;
  }
  if (type === "wireguard_s2s") {
    delete out.dns;
    delete out.pool;
    delete out.keepaliveSec;
  }
  return out as unknown as VpnConfigPayload;
}

function shapeConfig(row: NonNullable<VpnRow>, sessionCount: number): VpnConfigDto {
  return {
    id: row.id,
    name: row.name,
    type: row.type as VpnType,
    enabled: row.enabled,
    config: parseJson<VpnConfigPayload>(row.config, {} as VpnConfigPayload),
    status: row.status as VpnConfigDto["status"],
    statusMessage: row.statusMessage,
    sessionCount,
  };
}

function portOf(type: VpnType, cfg: VpnConfigPayload): number | null {
  if (type === "wireguard_s2s" || type === "wireguard_remote") return (cfg as WgS2sConfig).listenPort ?? null;
  if (type === "openvpn") return (cfg as OpenVpnConfig).port ?? null;
  return null;
}

function poolOf(type: VpnType, cfg: VpnConfigPayload): string | null {
  if (type === "wireguard_remote") return (cfg as WgRemoteConfig).pool ?? null;
  if (type === "openvpn") return (cfg as OpenVpnConfig).pool ?? null;
  return null;
}

// ── CIDR / pool math (IPv4, integer ranges) ─────────────────────────────────

function ipToInt(ip: string): number {
  const [a, b, c, d] = ip.split(".").map(Number);
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function cidrRange(cidr: string): { start: number; end: number } {
  const [ip, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipToInt(ip) & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  return { start: network, end: network + size - 1 };
}

function cidrsOverlap(a: string, b: string): boolean {
  const ra = cidrRange(a);
  const rb = cidrRange(b);
  return ra.start <= rb.end && rb.start <= ra.end;
}

/** First free /32 host inside `pool`, not claimed by peers or live sessions. */
function nextFreeIp(pool: string, used: Iterable<string>): string {
  const { start, end } = cidrRange(pool);
  const usedSet = new Set<string>();
  for (const u of used) {
    const ip = u.split("/")[0];
    if (ip.includes(".")) usedSet.add(ip);
  }
  for (let n = start + 10; n < end; n++) {
    const ip = intToIp(n);
    if (!usedSet.has(ip)) return ip;
  }
  return intToIp(start + 2);
}

// ── collision / overlap checks ──────────────────────────────────────────────

async function assertPortFree(tenantId: number, port: number, excludeId?: number): Promise<void> {
  const rows = await db.vpnConfig.findMany({ where: { tenantId }, select: { id: true, name: true, type: true, config: true } });
  for (const r of rows) {
    if (excludeId != null && r.id === excludeId) continue;
    const cfg = parseJson<VpnConfigPayload>(r.config, {} as VpnConfigPayload);
    if (portOf(r.type as VpnType, cfg) === port) {
      throw ApiError.conflict(`Port ${port} is already used by tunnel "${r.name}"`);
    }
  }
}

/** Remote-access pools must not overlap each other, other configs or group pools. */
async function assertPoolFree(tenantId: number, pool: string, opts: { excludeConfigId?: number; excludeGroupId?: number } = {}): Promise<void> {
  const [configs, groups] = await Promise.all([
    db.vpnConfig.findMany({ where: { tenantId, type: { in: ["wireguard_remote", "openvpn"] } }, select: { id: true, name: true, type: true, config: true } }),
    db.vpnUserGroup.findMany({ where: { tenantId, pool: { not: null } }, select: { id: true, name: true, pool: true } }),
  ]);
  for (const c of configs) {
    if (opts.excludeConfigId != null && c.id === opts.excludeConfigId) continue;
    const other = poolOf(c.type as VpnType, parseJson<VpnConfigPayload>(c.config, {} as VpnConfigPayload));
    if (other && cidrsOverlap(pool, other)) {
      throw ApiError.validation(`Pool ${pool} overlaps tunnel "${c.name}" (${other})`);
    }
  }
  for (const g of groups) {
    if (opts.excludeGroupId != null && g.id === opts.excludeGroupId) continue;
    if (g.pool && cidrsOverlap(pool, g.pool)) {
      throw ApiError.validation(`Pool ${pool} overlaps user group "${g.name}" (${g.pool})`);
    }
  }
}

// ── config CRUD ─────────────────────────────────────────────────────────────

export async function listConfigs(tenantId: number): Promise<VpnConfigDto[]> {
  const [rows, counts] = await Promise.all([
    db.vpnConfig.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.vpnSession.groupBy({ by: ["vpnId"], where: { tenantId, status: { not: "disconnected" } }, _count: { _all: true } }),
  ]);
  const countBy = new Map(counts.map((c) => [c.vpnId, c._count._all]));
  return rows.map((r) => shapeConfig(r, countBy.get(r.id) ?? 0));
}

export async function createConfig(tenantId: number, body: VpnConfigCreateInput): Promise<VpnConfigDto> {
  const dup = await db.vpnConfig.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A tunnel named "${body.name}" already exists`);

  const config = configOfPayload(body.type, body.config);
  const port = portOf(body.type, config);
  if (port != null) await assertPortFree(tenantId, port);
  const pool = poolOf(body.type, config);
  if (pool) await assertPoolFree(tenantId, pool);

  // enabling a brand-new tunnel starts the state machine (DOWN → CONNECTING)
  const created = await db.vpnConfig.create({
    data: {
      tenantId,
      name: body.name,
      type: body.type,
      enabled: body.enabled,
      config: JSON.stringify(config),
      status: body.enabled ? "connecting" : "down",
      statusMessage: body.enabled ? "IKE/DPD negotiation in progress" : null,
    },
  });
  if (body.enabled) {
    emitEvent({ type: "vpn:status", payload: { vpnId: created.id, status: "connecting", statusMessage: "IKE/DPD negotiation in progress" } });
  }
  convergeAfterMutation();
  return shapeConfig(created, 0);
}

export async function updateConfig(tenantId: number, id: number, body: VpnConfigUpdateInput): Promise<VpnConfigDto> {
  const existing = await db.vpnConfig.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("VPN config not found");

  if (body.name !== undefined && body.name !== existing.name) {
    const dup = await db.vpnConfig.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A tunnel named "${body.name}" already exists`);
  }

  // M05 §5: PUT config must match the ROW's type — reject a wrong-family shape.
  let configJson: string | undefined;
  if (body.config !== undefined) {
    const config = configOfPayload(existing.type as VpnType, body.config);
    const port = portOf(existing.type as VpnType, config);
    if (port != null) await assertPortFree(tenantId, port, id);
    const pool = poolOf(existing.type as VpnType, config);
    if (pool) await assertPoolFree(tenantId, pool, { excludeConfigId: id });
    configJson = JSON.stringify(config);
  }

  // status/statusMessage are engine-owned — EXCEPT the enable/disable apply
  // edge (M05 §5 state machine: DOWN → CONNECTING on enable, → DOWN on disable).
  const enabling = body.enabled === true && !existing.enabled;
  const disabling = body.enabled === false && existing.enabled;
  const updated = await db.vpnConfig.update({
    where: { id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(configJson !== undefined ? { config: configJson } : {}),
      ...(enabling ? { status: "connecting", statusMessage: "IKE/DPD negotiation in progress" } : {}),
      ...(disabling ? { status: "down", statusMessage: "Disabled by operator" } : {}),
    },
  });
  if (enabling) emitEvent({ type: "vpn:status", payload: { vpnId: id, status: "connecting", statusMessage: "IKE/DPD negotiation in progress" } });
  if (disabling) emitEvent({ type: "vpn:status", payload: { vpnId: id, status: "down", statusMessage: "Disabled by operator" } });
  convergeAfterMutation();
  const live = await db.vpnSession.count({ where: { vpnId: id, status: { not: "disconnected" } } });
  return shapeConfig(updated, live);
}

export async function deleteConfig(tenantId: number, id: number): Promise<void> {
  const existing = await db.vpnConfig.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("VPN config not found");
  // sessions cascade via the FK (schema onDelete: Cascade)
  await db.vpnConfig.delete({ where: { id } });
  // orphan sweep: unload conn / wg-quick down / stop openvpn unit
  convergeAfterMutation();
}

// ── tunnel status detail (M05 §4) ───────────────────────────────────────────

function hash32(seed: string): number {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967296;
}

/** Deterministic, slowly-growing transfer counter (simulation, monotonic per minute). */
function simulatedTransfer(id: number, label: string): { inBytes: number; outBytes: number } {
  const frac = hash32(`${id}:${label}`);
  const minutes = Math.floor(Date.now() / 60_000);
  const rateIn = 40_000 + Math.floor(frac * 400_000);
  const rateOut = Math.floor(rateIn * 0.6);
  return { inBytes: rateIn * minutes + Math.floor(frac * 5_000_000), outBytes: rateOut * minutes };
}

export async function statusDetail(tenantId: number, id: number): Promise<VpnStatusDetailDto> {
  const row = await db.vpnConfig.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("VPN config not found");

  const type = row.type as VpnType;
  const cfg = parseJson<VpnConfigPayload>(row.config, {} as VpnConfigPayload);

  // ── OS-backed status (real swanctl/wg/openvpn facts) ──────────────────────
  // Applied whenever the host plane is observable — sandbox (no tools) falls
  // through to the engine-simulated view below.
  try {
    const osCfg = osInput(row);
    const facts = await readVpnOsFacts([connName(row.name).slice(4)]);
    if (facts.available && (facts.charonRunning || facts.wgIfaces.length > 0 || facts.openvpnServices.some((s) => s.active))) {
      const v = tunnelOsStatus(osCfg, facts);
      const sessions = await db.vpnSession.findMany({
        where: { vpnId: id, tenantId },
        select: { status: true, bytesIn: true, bytesOut: true },
      });
      const active = sessions.filter((s) => s.status === "active").length;
      const idle = sessions.filter((s) => s.status === "idle").length;
      const detail: VpnStatusDetailDto = {
        status: v.status,
        statusMessage: v.statusMessage,
        dpdSec: null,
        lastHandshakeSec: v.lastHandshakeSec,
        transferIn: v.transferIn,
        transferOut: v.transferOut,
        peers: [],
      };
      if (type === "wireguard_s2s" || type === "wireguard_remote") {
        const c = cfg as WgS2sConfig;
        detail.dpdSec = (c as WgRemoteConfig).keepaliveSec ?? c.peers[0]?.keepaliveSec ?? 25;
        detail.peers = c.peers.map((p) => ({
          name: p.name,
          handshakeSec: v.lastHandshakeSec,
          transferIn: c.peers.length ? Math.floor(v.transferIn / c.peers.length) : 0,
          transferOut: c.peers.length ? Math.floor(v.transferOut / c.peers.length) : 0,
        }));
        if (type === "wireguard_remote") detail.sessions = { active, idle, total: sessions.filter((s) => s.status !== "disconnected").length };
        detail.lastHandshakeSec = v.lastHandshakeSec;
      } else if (type === "ipsec_s2s" || type === "ipsec_remote") {
        const c = cfg as IpsecConfig;
        detail.dpdSec = c.dpdSec ?? 30;
        detail.antiReplayWindow = c.replayWindow ?? 128;
        detail.authMethod = c.authMethod ?? "psk";
        detail.localSubnets = c.localSubnets;
        detail.remoteSubnets = c.remoteSubnets;
        detail.remoteIp = c.remoteIp ?? null;
        if (v.status === "up") {
          detail.peers = [{ name: c.remoteIp ?? "trap-policy", handshakeSec: null, transferIn: v.transferIn, transferOut: v.transferOut }];
        }
        detail.lastHandshakeSec = null;
      } else if (type === "openvpn") {
        const c = cfg as OpenVpnConfig;
        detail.dpdSec = c.keepaliveSec ?? 10;
        detail.sessions = { active, idle, total: sessions.filter((s) => s.status !== "disconnected").length };
      }
      return detail;
    }
  } catch {
    /* fall through to the engine view */
  }

  // ── engine-simulated status (no OS plane observable) ──────────────────────
  const up = row.status === "up";
  const { inBytes, outBytes } = simulatedTransfer(id, row.name);
  const lastHandshakeSec = up ? 5 + Math.floor(hash32(`${id}-${Math.floor(Date.now() / 30_000)}`) * 50) : null;

  const sessions = await db.vpnSession.findMany({
    where: { vpnId: id, tenantId },
    select: { status: true, bytesIn: true, bytesOut: true },
  });
  const active = sessions.filter((s) => s.status === "active").length;
  const idle = sessions.filter((s) => s.status === "idle").length;

  const detail: VpnStatusDetailDto = {
    status: row.status as VpnStatusDetailDto["status"],
    statusMessage: row.statusMessage,
    dpdSec: null,
    lastHandshakeSec,
    transferIn: inBytes + sessions.reduce((acc, s) => acc + s.bytesIn, 0),
    transferOut: outBytes + sessions.reduce((acc, s) => acc + s.bytesOut, 0),
    peers: [],
  };

  if (type === "wireguard_s2s") {
    const c = cfg as WgS2sConfig;
    detail.dpdSec = c.peers[0]?.keepaliveSec ?? 25;
    detail.peers = c.peers.map((p, i) => ({
      name: p.name,
      handshakeSec: up && i === 0 ? lastHandshakeSec : up ? lastHandshakeSec! + i * 7 : null,
      transferIn: Math.floor(inBytes / Math.max(1, c.peers.length)),
      transferOut: Math.floor(outBytes / Math.max(1, c.peers.length)),
    }));
  } else if (type === "wireguard_remote") {
    const c = cfg as WgRemoteConfig;
    detail.dpdSec = c.keepaliveSec ?? 25;
    detail.sessions = { active, idle, total: sessions.filter((s) => s.status !== "disconnected").length };
    detail.peers = c.peers.slice(0, 50).map((p, i) => ({
      name: p.name,
      handshakeSec: up ? (lastHandshakeSec ?? 10) + i * 3 : null,
      transferIn: Math.floor(inBytes / Math.max(1, c.peers.length)),
      transferOut: Math.floor(outBytes / Math.max(1, c.peers.length)),
    }));
  } else if (type === "ipsec_s2s" || type === "ipsec_remote") {
    const c = cfg as IpsecConfig;
    detail.dpdSec = c.dpdSec ?? 30;
    detail.antiReplayWindow = c.replayWindow ?? 128;
    detail.authMethod = c.authMethod ?? "psk";
    detail.localSubnets = c.localSubnets;
    detail.remoteSubnets = c.remoteSubnets;
    detail.remoteIp = c.remoteIp ?? null;
    detail.peers = c.remoteIp
      ? [{ name: c.remoteIp, handshakeSec: up ? lastHandshakeSec : null, transferIn: Math.floor(inBytes / 2), transferOut: Math.floor(outBytes / 2) }]
      : [];
  } else {
    const c = cfg as OpenVpnConfig;
    detail.dpdSec = c.keepaliveSec ?? 10;
    detail.sessions = { active, idle, total: sessions.filter((s) => s.status !== "disconnected").length };
  }

  return detail;
}

// ── client bundles (M05 §4/§5 — server-generated, REAL key material) ────────

function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || "tunnel";
}

async function applianceWanIp(): Promise<string> {
  // OS truth first: the REAL address on the default-route (WAN) interface —
  // the config plane can hold seed placeholders (203.0.113.2) that would
  // produce useless client bundles on a live appliance
  try {
    const { readInterfaces } = await import("@/lib/host/proc");
    const ifaces = await readInterfaces();
    const wanOs = ifaces.find((i) => i.isDefaultRoute) ?? ifaces.find((i) => i.ipv4?.some((a) => a && !a.startsWith("127.")));
    const osIp = wanOs?.ipv4?.find((a) => a && !a.startsWith("127."));
    if (osIp) return osIp.split("/")[0];
  } catch {
    /* fall through to the config plane */
  }
  const wan = await db.networkInterface.findFirst({ where: { tenantId: 1, role: "wan" }, select: { config: true } });
  const cfg = wan ? parseJson<{ ip?: string }>(wan.config, {}) : {};
  return cfg.ip ?? "203.0.113.2";
}

export async function clientBundle(tenantId: number, id: number, peerName?: string): Promise<ClientBundleDto> {
  const row = await db.vpnConfig.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("VPN config not found");
  const type = row.type as VpnType;
  // ENDPOINTS §7: bundles exist only for WireGuard/OpenVPN; ipsec_* → 409
  if (type === "ipsec_s2s" || type === "ipsec_remote") {
    throw ApiError.conflict("Client bundles are not available for IPSec tunnels (EAP provisioning instead)");
  }

  const cfg = parseJson<VpnConfigPayload>(row.config, {} as VpnConfigPayload);
  const notice = row.enabled ? undefined : "Offline config — the tunnel is disabled, the bundle reflects the stored config.";

  if (type === "wireguard_s2s") {
    const c = cfg as WgS2sConfig;
    const peer = peerName ? c.peers.find((p) => p.name === peerName) : c.peers[0];
    if (!peer) throw ApiError.validation(peerName ? `Peer "${peerName}" not found on this tunnel` : "Tunnel has no peers");
    const hubPub = wgPublicKeyFromPrivate(c.privateKey);
    if (!hubPub) {
      throw ApiError.validation(
        "Stored private key is not a valid WireGuard base64 key — regenerate it (editor → generate) before issuing bundles",
      );
    }
    const wan = await applianceWanIp();
    const content = [
      `# WireGuard peer bundle for ${peer.name} — tunnel ${row.name}`,
      `# The private key stays on the peer appliance; import this file there.`,
      `[Interface]`,
      `PrivateKey = <PEER_PRIVATE_KEY>`,
      `Address = ${peer.allowedIps[0] ?? c.address}`,
      ``,
      `[Peer]`,
      `PublicKey = ${hubPub}`,
      `Endpoint = ${wan}:${c.listenPort}`,
      `AllowedIPs = ${c.address}`,
      ...(peer.keepaliveSec ? [`PersistentKeepalive = ${peer.keepaliveSec}`] : []),
      ``,
    ].join("\n");
    return { filename: `${slug(row.name)}-${slug(peer.name)}.conf`, contentType: "text/plain", content, notice };
  }

  if (type === "wireguard_remote") {
    const c = cfg as WgRemoteConfig;
    const hubPub = wgPublicKeyFromPrivate(c.privateKey);
    if (!hubPub) {
      throw ApiError.validation(
        "Stored private key is not a valid WireGuard base64 key — regenerate it (editor → generate) before issuing bundles",
      );
    }
    const client = generateWgKeypair();
    const assigned = nextFreeIp(c.pool, [
      ...c.peers.flatMap((p) => p.allowedIps),
      ...(await db.vpnSession.findMany({ where: { vpnId: id, status: { not: "disconnected" } }, select: { assignedIp: true } })).map((s) => s.assignedIp ?? ""),
    ]);
    const peerName2 = `${slug(row.name)}-client-${Math.random().toString(36).slice(2, 6)}`;
    // bundle generation appends a provisioned peer to the config (M05 §5)
    const nextPeers = [
      ...c.peers,
      { name: peerName2, publicKey: client.publicKey, allowedIps: [`${assigned}/32`] },
    ];
    const nextCfg: WgRemoteConfig = { ...c, peers: nextPeers };
    await db.vpnConfig.update({ where: { id }, data: { config: JSON.stringify(nextCfg) } });
    // push the new peer live so the hub accepts it without a manual re-apply
    convergeAfterMutation();

    const wan = await applianceWanIp();
    const content = [
      `[Interface]`,
      `PrivateKey = ${client.privateKey}`,
      `Address = ${assigned}/32`,
      ...(c.dns ? [`DNS = ${c.dns}`] : []),
      ``,
      `[Peer]`,
      `PublicKey = ${hubPub}`,
      `Endpoint = ${wan}:${c.listenPort}`,
      `AllowedIPs = ${c.pool}`,
      `PersistentKeepalive = ${c.keepaliveSec ?? 25}`,
      ``,
    ].join("\n");
    return {
      filename: `${slug(row.name)}-client.conf`,
      contentType: "text/plain",
      content,
      notice: notice ?? `Peer ${peerName2} (${assigned}/32) appended to the hub config.`,
    };
  }

  // openvpn — REAL PKI material once the tunnel is applied to the OS
  const c = cfg as OpenVpnConfig;
  const wan = await applianceWanIp();
  // the OS dir follows the IFNAMSIZ-truncated conn name (utm-<slug> ≤ 15),
  // NOT the plain name slug — they diverge for names longer than 11 chars
  const vpnSlug = connName(row.name).slice(4);
  const ca = await readOpenVpnCaCert(vpnSlug);
  const ta = c.tls ? await readOpenVpnTaKey(vpnSlug) : null;
  const content = [
    `client`,
    `proto ${c.proto}`,
    `remote ${wan} ${c.port}`,
    `dev tun`,
    `data-ciphers ${c.cipher}`,
    `auth ${c.auth}`,
    ...(c.dns ? [`dhcp-option DNS ${c.dns}`] : []),
    `remote-cert-tls server`,
    ...(ca
      ? [
          `<ca>`,
          ca.trim(),
          `</ca>`,
          ...(ta ? [`<tls-crypt>`, ta, `</tls-crypt>`] : []),
          `<key>`,
          `# client key — issue per-client certificates via the PKI module`,
          `</key>`,
        ]
      : [
          `<ca>`,
          `# CA not present — apply this tunnel to the OS (VPN → OS sync) to`,
          `# bootstrap the managed PKI, then re-download this bundle.`,
          `</ca>`,
        ]),
    ``,
  ].join("\n");
  return { filename: `${slug(row.name)}-client.ovpn`, contentType: "text/plain", content, notice: ca ? notice : notice ?? "PKI not bootstrapped yet — see notice in bundle." };
}

// ── sessions ────────────────────────────────────────────────────────────────

function shapeSession(row: Awaited<ReturnType<typeof db.vpnSession.findFirst>>, vpnName: string | null): VpnSessionDto {
  return {
    id: row!.id,
    vpnId: row!.vpnId,
    vpnName,
    userName: row!.userName,
    sourceIp: row!.sourceIp,
    assignedIp: row!.assignedIp,
    groupName: row!.groupName,
    bytesIn: row!.bytesIn,
    bytesOut: row!.bytesOut,
    connectedAt: row!.connectedAt.toISOString(),
    lastActivity: row!.lastActivity.toISOString(),
    status: row!.status as VpnSessionDto["status"],
  };
}

export async function listSessions(tenantId: number, q: VpnSessionsQuery): Promise<{ data: VpnSessionDto[]; meta: PageMeta }> {
  const where = {
    tenantId,
    ...(q.vpnId ? { vpnId: q.vpnId } : {}),
    ...(q.status ? { status: q.status } : {}),
    ...(q.q
      ? {
          OR: [{ userName: { contains: q.q } }, { sourceIp: { contains: q.q } }, { assignedIp: { contains: q.q } }],
        }
      : {}),
  };
  const [rows, total, configs] = await Promise.all([
    db.vpnSession.findMany({ where, orderBy: { lastActivity: "desc" }, skip: (q.page - 1) * q.limit, take: q.limit }),
    db.vpnSession.count({ where }),
    db.vpnConfig.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  const nameById = new Map(configs.map((c) => [c.id, c.name]));
  return {
    data: rows.map((r) => shapeSession(r, nameById.get(r.vpnId) ?? null)),
    meta: { page: q.page, limit: q.limit, total, totalPages: Math.max(1, Math.ceil(total / q.limit)) },
  };
}

export async function disconnectSession(tenantId: number, id: number): Promise<VpnSessionDto> {
  const row = await db.vpnSession.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("Session not found");
  if (row.status === "disconnected") return shapeSession(row, null); // idempotent
  const now = new Date();
  const updated = await db.vpnSession.update({
    where: { id },
    data: { status: "disconnected", lastActivity: now },
  });
  return shapeSession(updated, null);
}

// ── VPN user groups ─────────────────────────────────────────────────────────

function shapeGroup(row: NonNullable<Awaited<ReturnType<typeof db.vpnUserGroup.findFirst>>>) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    pool: row.pool,
    dns: row.dns,
    idleTimeoutMin: row.idleTimeoutMin,
    maxSessionMin: row.maxSessionMin,
    maxSessionsPerUser: row.maxSessionsPerUser,
    memberUsernames: parseJson<string[]>(row.memberUsernames, []),
  };
}

export async function listGroups(tenantId: number) {
  const rows = await db.vpnUserGroup.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(shapeGroup);
}

export async function createGroup(tenantId: number, body: VpnUserGroupCreateInput) {
  const dup = await db.vpnUserGroup.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A user group named "${body.name}" already exists`);
  if (body.pool) await assertPoolFree(tenantId, body.pool);
  const created = await db.vpnUserGroup.create({
    data: {
      tenantId,
      name: body.name,
      description: body.description ?? null,
      pool: body.pool ?? null,
      dns: body.dns ?? null,
      idleTimeoutMin: body.idleTimeoutMin ?? null,
      maxSessionMin: body.maxSessionMin ?? null,
      maxSessionsPerUser: body.maxSessionsPerUser ?? null,
      memberUsernames: JSON.stringify(body.memberUsernames),
    },
  });
  return shapeGroup(created);
}

export async function updateGroup(tenantId: number, id: number, body: VpnUserGroupUpdateInput) {
  const existing = await db.vpnUserGroup.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("VPN user group not found");
  if (body.name !== undefined && body.name !== existing.name) {
    const dup = await db.vpnUserGroup.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A user group named "${body.name}" already exists`);
  }
  if (body.pool) await assertPoolFree(tenantId, body.pool, { excludeGroupId: id });
  const updated = await db.vpnUserGroup.update({
    where: { id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.description !== undefined ? { description: body.description ?? null } : {}),
      ...(body.pool !== undefined ? { pool: body.pool ?? null } : {}),
      ...(body.dns !== undefined ? { dns: body.dns ?? null } : {}),
      ...(body.idleTimeoutMin !== undefined ? { idleTimeoutMin: body.idleTimeoutMin ?? null } : {}),
      ...(body.maxSessionMin !== undefined ? { maxSessionMin: body.maxSessionMin ?? null } : {}),
      ...(body.maxSessionsPerUser !== undefined ? { maxSessionsPerUser: body.maxSessionsPerUser ?? null } : {}),
      ...(body.memberUsernames !== undefined ? { memberUsernames: JSON.stringify(body.memberUsernames) } : {}),
    },
  });
  return shapeGroup(updated);
}

export async function deleteGroup(tenantId: number, id: number): Promise<void> {
  const existing = await db.vpnUserGroup.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("VPN user group not found");
  await db.vpnUserGroup.delete({ where: { id } });
}

// ── engine state loader (MockEngine churn) ──────────────────────────────────

export interface VpnTunnelRuntime {
  id: number;
  name: string;
  type: string;
  enabled: boolean;
  status: string;
  /** first peer name / remoteIp for handshake statusMessage */
  peerLabel: string | null;
}

export interface VpnGroupRuntime {
  name: string;
  pool: string | null;
  dns: string | null;
  idleTimeoutMin: number | null;
  maxSessionMin: number | null;
  maxSessionsPerUser: number | null;
  members: string[];
}

export interface VpnRemoteRuntime {
  id: number;
  name: string;
  type: "wireguard_remote" | "ipsec_remote" | "openvpn";
  enabled: boolean;
  pool: string | null;
}

export async function loadVpnRuntime(tenantId: number): Promise<{
  tunnels: VpnTunnelRuntime[];
  groups: VpnGroupRuntime[];
  remote: VpnRemoteRuntime[];
}> {
  const [configs, groups] = await Promise.all([
    db.vpnConfig.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.vpnUserGroup.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
  ]);
  const tunnels: VpnTunnelRuntime[] = configs.map((c) => {
    const cfg = parseJson<VpnConfigPayload>(c.config, {} as VpnConfigPayload);
    let peerLabel: string | null = null;
    if (c.type === "wireguard_s2s" || c.type === "wireguard_remote") peerLabel = (cfg as WgS2sConfig).peers?.[0]?.name ?? null;
    else if (c.type === "ipsec_s2s" || c.type === "ipsec_remote") peerLabel = (cfg as IpsecConfig).remoteIp ?? null;
    else peerLabel = "ssl-clients";
    return { id: c.id, name: c.name, type: c.type, enabled: c.enabled, status: c.status, peerLabel };
  });
  return {
    tunnels,
    groups: groups.map((g) => ({
      name: g.name,
      pool: g.pool,
      dns: g.dns,
      idleTimeoutMin: g.idleTimeoutMin,
      maxSessionMin: g.maxSessionMin,
      maxSessionsPerUser: g.maxSessionsPerUser,
      members: parseJson<string[]>(g.memberUsernames, []),
    })),
    remote: configs
      .filter((c) => c.type === "wireguard_remote" || c.type === "ipsec_remote" || c.type === "openvpn")
      .map((c) => ({
        id: c.id,
        name: c.name,
        type: c.type as VpnRemoteRuntime["type"],
        enabled: c.enabled,
        pool: poolOf(c.type as VpnType, parseJson<VpnConfigPayload>(c.config, {} as VpnConfigPayload)),
      })),
  };
}

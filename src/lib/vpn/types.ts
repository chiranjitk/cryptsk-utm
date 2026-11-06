/**
 * M05 shared VPN types — single source for the per-type config shapes
 * (SCHEMA.md §4, exact) and API DTOs. The frontend api layer re-exports from
 * here; the service layer + engine import these directly (no lib → components
 * dependency).
 */

export type VpnType = "wireguard_s2s" | "wireguard_remote" | "ipsec_s2s" | "ipsec_remote" | "openvpn";
export type VpnStatus = "up" | "down" | "connecting" | "error";
export type VpnSessionStatus = "active" | "idle" | "disconnected";
export type IpsecAuthMethod = "psk" | "eap_mschapv2" | "eap_tls";

// ── per-type config shapes (SCHEMA.md §4 — exact) ───────────────────────────

export interface WgPeer {
  name: string;
  publicKey: string;
  allowedIps: string[];
  endpoint?: string;
  keepaliveSec?: number;
}

export interface WgS2sConfig {
  privateKey: string;
  listenPort: number;
  peers: WgPeer[];
  address: string;
}

export interface WgRemoteConfig {
  privateKey: string;
  listenPort: number;
  address: string;
  pool: string;
  dns?: string;
  keepaliveSec?: number;
  peers: WgPeer[];
}

export interface IpsecConfig {
  localIp: string;
  remoteIp?: string;
  localSubnets: string[];
  remoteSubnets: string[];
  psk: string;
  ike: string;
  esp: string;
  dpdSec?: number;
  pfs?: boolean;
  authMethod?: IpsecAuthMethod;
  replayWindow?: number;
  dns?: string;
}

export interface OpenVpnConfig {
  proto: "udp" | "tcp";
  port: number;
  cipher: string;
  auth: string;
  pool: string;
  tls?: boolean;
  dns?: string;
  keepaliveSec?: number;
}

export type VpnConfigPayload = WgS2sConfig | WgRemoteConfig | IpsecConfig | OpenVpnConfig;

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface VpnConfigDto {
  id: number;
  name: string;
  type: VpnType;
  enabled: boolean;
  config: VpnConfigPayload;
  status: VpnStatus;
  statusMessage: string | null;
  /** additive — live session count (remote-access configs) */
  sessionCount: number;
}

export interface VpnStatusPeer {
  name: string;
  handshakeSec: number | null;
  transferIn: number;
  transferOut: number;
}

export interface VpnStatusDetailDto {
  status: VpnStatus;
  statusMessage: string | null;
  dpdSec: number | null;
  lastHandshakeSec: number | null;
  transferIn: number;
  transferOut: number;
  peers: VpnStatusPeer[];
  /** remote-access types */
  sessions?: { active: number; idle: number; total: number };
  /** ipsec_* */
  antiReplayWindow?: number;
  authMethod?: string;
  localSubnets?: string[];
  remoteSubnets?: string[];
  remoteIp?: string | null;
}

export interface ClientBundleDto {
  filename: string;
  contentType: string;
  content: string;
  notice?: string;
}

export interface VpnSessionDto {
  id: number;
  vpnId: number;
  vpnName: string | null;
  userName: string | null;
  sourceIp: string;
  assignedIp: string | null;
  groupName: string | null;
  bytesIn: number;
  bytesOut: number;
  connectedAt: string;
  lastActivity: string;
  status: VpnSessionStatus;
}

export interface VpnUserGroupDto {
  id: number;
  name: string;
  description: string | null;
  pool: string | null;
  dns: string | null;
  idleTimeoutMin: number | null;
  maxSessionMin: number | null;
  maxSessionsPerUser: number | null;
  memberUsernames: string[];
}

export interface VpnConfigBody {
  name?: string;
  type?: VpnType;
  enabled?: boolean;
  config?: VpnConfigPayload;
}

export interface VpnUserGroupBody {
  name?: string;
  description?: string | null;
  pool?: string | null;
  dns?: string | null;
  idleTimeoutMin?: number | null;
  maxSessionMin?: number | null;
  maxSessionsPerUser?: number | null;
  memberUsernames?: string[];
}

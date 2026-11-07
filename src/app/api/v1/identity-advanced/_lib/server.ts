/**
 * M23 shared server helpers — DTO types/mappers, the deterministic fnv-1a hash
 * used by the simulated IdP test + profiling rescan, and cross-table
 * assertions. Lives in a `_lib` private folder so the App Router never treats
 * it as a route. Routes + the client api import it via the "@/..." alias
 * (never relative across dirs).
 */

import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import type {
  ByodEnrollment,
  FederatedIdp,
  IdentityActivityEvent,
  NacDevice,
  NacProfile,
  RadiusCoaProfile,
} from "@prisma/client";

// ── locked enums (mirror the M23 schema comment values) ─────────────────────

export type IdpProtocol = "saml2" | "oidc";
export type IdpStatus = "untested" | "ok" | "error";
export type CoaAction = "reauth" | "disconnect" | "vlan";
export type NacMethod = "802.1x" | "mab" | "both";
export type EapType = "peap" | "ttls" | "tls";
export type DeviceType = "printer" | "phone" | "camera" | "workstation" | "mobile" | "iot" | "unknown";
export type NacState = "authenticated" | "mab" | "quarantine" | "pending" | "denied";
export type ByodStatus = "pending" | "approved" | "enrolled" | "expired" | "revoked";

// ── deterministic simulation hash (FNV-1a 32-bit) ───────────────────────────

export function fnv1a(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

// ── DTOs (structurally identical to identity-advanced-api.ts) ───────────────

export interface IdpDTO {
  id: number;
  name: string;
  protocol: IdpProtocol;
  entityId: string | null;
  metadataUrl: string | null;
  ssoUrl: string | null;
  clientId: string | null;
  /** Write-only secret rule — never echo the value itself. */
  hasSecret: boolean;
  idpCertId: number | null;
  idpCertName: string | null;
  redirectUri: string | null;
  status: IdpStatus;
  enabled: boolean;
  createdAt: string;
}

export function toIdpDTO(row: FederatedIdp, certName: string | null = null): IdpDTO {
  return {
    id: row.id,
    name: row.name,
    protocol: row.protocol as IdpProtocol,
    entityId: row.entityId,
    metadataUrl: row.metadataUrl,
    ssoUrl: row.ssoUrl,
    clientId: row.clientId,
    hasSecret: row.clientSecret !== null && row.clientSecret !== "",
    idpCertId: row.idpCertId,
    idpCertName: certName,
    redirectUri: row.redirectUri,
    status: row.status as IdpStatus,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

export interface CoaProfileDTO {
  id: number;
  name: string;
  radiusProfileId: number | null;
  radiusProfileName: string | null;
  coaEnabled: boolean;
  dynamicVlan: boolean;
  vlanPoolStart: number | null;
  vlanPoolEnd: number | null;
  sessionTimeoutMin: number;
  enabled: boolean;
  createdAt: string;
}

export function toCoaProfileDTO(row: RadiusCoaProfile, radiusProfileName: string | null): CoaProfileDTO {
  return {
    id: row.id,
    name: row.name,
    radiusProfileId: row.radiusProfileId,
    radiusProfileName,
    coaEnabled: row.coaEnabled,
    dynamicVlan: row.dynamicVlan,
    vlanPoolStart: row.vlanPoolStart,
    vlanPoolEnd: row.vlanPoolEnd,
    sessionTimeoutMin: row.sessionTimeoutMin,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

export interface NacProfileDTO {
  id: number;
  name: string;
  method: NacMethod;
  eapType: EapType;
  dynamicVlan: boolean;
  guestVlan: number | null;
  authFailVlan: number | null;
  profiling: boolean;
  byodOnboarding: boolean;
  enabled: boolean;
  deviceCount: number;
  createdAt: string;
}

export function toNacProfileDTO(row: NacProfile, deviceCount: number): NacProfileDTO {
  return {
    id: row.id,
    name: row.name,
    method: row.method as NacMethod,
    eapType: row.eapType as EapType,
    dynamicVlan: row.dynamicVlan,
    guestVlan: row.guestVlan,
    authFailVlan: row.authFailVlan,
    profiling: row.profiling,
    byodOnboarding: row.byodOnboarding,
    enabled: row.enabled,
    deviceCount,
    createdAt: row.createdAt.toISOString(),
  };
}

export interface DeviceDTO {
  id: number;
  macAddress: string;
  ip: string;
  hostname: string | null;
  vendor: string | null;
  deviceType: DeviceType;
  osGuess: string | null;
  nacState: NacState;
  vlanId: number | null;
  riskScore: number;
  nacProfileId: number | null;
  nacProfileName: string | null;
  firstSeen: string;
  lastSeen: string;
}

export function toDeviceDTO(row: NacDevice, nacProfileName: string | null): DeviceDTO {
  return {
    id: row.id,
    macAddress: row.macAddress,
    ip: row.ip,
    hostname: row.hostname,
    vendor: row.vendor,
    deviceType: row.deviceType as DeviceType,
    osGuess: row.osGuess,
    nacState: row.nacState as NacState,
    vlanId: row.vlanId,
    riskScore: row.riskScore,
    nacProfileId: row.nacProfileId,
    nacProfileName,
    firstSeen: row.firstSeen.toISOString(),
    lastSeen: row.lastSeen.toISOString(),
  };
}

export interface ByodDTO {
  id: number;
  userName: string;
  deviceId: number | null;
  /** One-time secret rule — lists never carry the token. */
  hasToken: true;
  status: ByodStatus;
  expiresAt: string;
  createdAt: string;
}

/** Effective status: pending/approved rows past expiresAt read as "expired". */
export function byodEffectiveStatus(row: ByodEnrollment): ByodStatus {
  if ((row.status === "pending" || row.status === "approved") && row.expiresAt.getTime() < Date.now()) {
    return "expired";
  }
  return row.status as ByodStatus;
}

export function toByodDTO(row: ByodEnrollment): ByodDTO {
  return {
    id: row.id,
    userName: row.userName,
    deviceId: row.deviceId,
    hasToken: true,
    status: byodEffectiveStatus(row),
    expiresAt: row.expiresAt.toISOString(),
    createdAt: row.createdAt.toISOString(),
  };
}

export interface ActivityDTO {
  id: number;
  userName: string;
  event: string;
  sourceIp: string | null;
  detail: Record<string, unknown>;
  createdAt: string;
}

export function toActivityDTO(row: IdentityActivityEvent): ActivityDTO {
  let detail: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(row.detail);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      detail = parsed as Record<string, unknown>;
    }
  } catch {
    detail = { raw: row.detail };
  }
  return {
    id: row.id,
    userName: row.userName,
    event: row.event,
    sourceIp: row.sourceIp,
    detail,
    createdAt: row.createdAt.toISOString(),
  };
}

// ── cross-table assertions ──────────────────────────────────────────────────

/** idpCertId must reference an existing ACTIVE certificate (M23 spec 2.9). */
export async function assertIdpCertUsable(tenantId: number, certId: number | null | undefined): Promise<void> {
  if (certId == null) return;
  const cert = await db.certificate.findFirst({ where: { id: certId, tenantId } });
  if (!cert || cert.status !== "active") {
    throw ApiError.validation("idpCertId must reference an active certificate");
  }
}

/** radiusProfileId is a logical ref into radius_profiles (M07). */
export async function assertRadiusProfileExists(
  tenantId: number,
  radiusProfileId: number | null | undefined,
): Promise<void> {
  if (radiusProfileId == null) return;
  const row = await db.radiusProfile.findFirst({ where: { id: radiusProfileId, tenantId } });
  if (!row) {
    throw ApiError.validation("radiusProfileId must reference an existing RADIUS profile");
  }
}

/** deviceId is a logical ref into nac_devices. */
export async function assertNacDeviceExists(tenantId: number, deviceId: number | null | undefined): Promise<void> {
  if (deviceId == null) return;
  const row = await db.nacDevice.findFirst({ where: { id: deviceId, tenantId } });
  if (!row) {
    throw ApiError.validation("deviceId must reference an existing NAC device");
  }
}

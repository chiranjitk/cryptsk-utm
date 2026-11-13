/**
 * M23 seed — Advanced Identity & NAC (spec 2.9 + 2.10). Idempotent,
 * tenantId=1: two federated IdPs ("Okta SAML" saml2/ok, "Azure OIDC"
 * oidc/untested), the "corporate-coa" CoA profile (dynamic VLAN pool
 * 100-199, 480 min sessions, linked to the M07 "CORP-RADIUS" profile when
 * present), two NAC profiles ("corp-8021x" both/peap with profiling + BYOD,
 * "iot-mab" mab with guest VLAN 900), ten profiled endpoint devices
 * (printer/phone/camera/workstations/mobile, 2 unknown for the rescan demo,
 * 1 quarantined on VLAN 900), one pending BYOD enrollment (deterministic
 * token) and twelve identity activity events spread over the last 24h.
 * Run via: bun prisma/seed-phase2.ts
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── federated IdPs ──────────────────────────────────────────────────────────
  await prisma.federatedIdp.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "Okta SAML" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "Okta SAML",
      protocol: "saml2",
      entityId: "https://idp.okta.example/sso",
      metadataUrl: "https://idp.okta.example/.well-known/saml-metadata",
      ssoUrl: "https://idp.okta.example/sso/saml",
      redirectUri: "https://fw.cryptsk.local/api/v1/sso/callback",
      status: "ok",
      enabled: true,
    },
  });

  await prisma.federatedIdp.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "Azure OIDC" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "Azure OIDC",
      protocol: "oidc",
      clientId: "cryptsk-console",
      redirectUri: "https://fw.cryptsk.local/api/v1/sso/callback",
      status: "untested",
      enabled: true,
    },
  });

  // ── RADIUS CoA profile (logical ref to the M07 RADIUS profile when seeded) ─
  const corpRadius = await prisma.radiusProfile.findFirst({
    where: { tenantId: TENANT, name: "CORP-RADIUS" },
    select: { id: true },
  });
  await prisma.radiusCoaProfile.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "corporate-coa" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "corporate-coa",
      radiusProfileId: corpRadius?.id ?? null,
      coaEnabled: true,
      dynamicVlan: true,
      vlanPoolStart: 100,
      vlanPoolEnd: 199,
      sessionTimeoutMin: 480,
      enabled: true,
    },
  });

  // ── NAC profiles ────────────────────────────────────────────────────────────
  const corpNac = await prisma.nacProfile.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "corp-8021x" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "corp-8021x",
      method: "both",
      eapType: "peap",
      dynamicVlan: true,
      profiling: true,
      byodOnboarding: true,
      enabled: true,
    },
  });

  const iotNac = await prisma.nacProfile.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "iot-mab" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "iot-mab",
      method: "mab",
      eapType: "peap",
      dynamicVlan: true,
      guestVlan: 900,
      profiling: true,
      byodOnboarding: false,
      enabled: true,
    },
  });

  // ── NAC devices (10) ────────────────────────────────────────────────────────
  const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000);
  const devices: Array<{
    macAddress: string;
    ip: string;
    hostname: string | null;
    vendor: string | null;
    deviceType: string;
    osGuess: string | null;
    nacState: string;
    vlanId: number | null;
    riskScore: number;
    profileId: number | null;
    lastSeenH: number;
  }> = [
    { macAddress: "00:1E:4F:2A:7B:C1", ip: "192.168.10.41", hostname: "prn-hq-01", vendor: "HP", deviceType: "printer", osGuess: "embedded print server", nacState: "authenticated", vlanId: 10, riskScore: 35, profileId: corpNac.id, lastSeenH: 1 },
    { macAddress: "F0:18:98:5C:11:D2", ip: "192.168.10.87", hostname: "iphone-mk", vendor: "Apple", deviceType: "phone", osGuess: "iOS 17", nacState: "authenticated", vlanId: 30, riskScore: 25, profileId: corpNac.id, lastSeenH: 0.2 },
    { macAddress: "AC:CC:8E:09:44:F3", ip: "192.168.20.52", hostname: "cam-parking", vendor: "Axis", deviceType: "camera", osGuess: "camera firmware 10.x", nacState: "mab", vlanId: 40, riskScore: 55, profileId: iotNac.id, lastSeenH: 0.5 },
    { macAddress: "3C:22:FB:71:09:AA", ip: "192.168.10.24", hostname: "ws-finance-02", vendor: "Dell", deviceType: "workstation", osGuess: "Windows 11 Pro", nacState: "authenticated", vlanId: 10, riskScore: 20, profileId: corpNac.id, lastSeenH: 0.1 },
    { macAddress: "84:7B:57:3D:62:0E", ip: "192.168.10.31", hostname: "ws-eng-07", vendor: "Lenovo", deviceType: "workstation", osGuess: "Windows 11 Pro", nacState: "authenticated", vlanId: 10, riskScore: 20, profileId: corpNac.id, lastSeenH: 0.3 },
    { macAddress: "A4:83:E7:90:1C:55", ip: "192.168.10.63", hostname: "ipad-sales", vendor: "Apple", deviceType: "mobile", osGuess: "iPadOS 17", nacState: "authenticated", vlanId: 30, riskScore: 30, profileId: corpNac.id, lastSeenH: 2 },
    { macAddress: "D8:3A:DD:41:7E:12", ip: "192.168.20.77", hostname: null, vendor: null, deviceType: "unknown", osGuess: null, nacState: "pending", vlanId: null, riskScore: 60, profileId: iotNac.id, lastSeenH: 0.05 },
    { macAddress: "9C:8E:99:C2:05:B7", ip: "192.168.20.78", hostname: null, vendor: "Raspberry Pi Trading", deviceType: "unknown", osGuess: null, nacState: "pending", vlanId: null, riskScore: 65, profileId: iotNac.id, lastSeenH: 0.07 },
    { macAddress: "B8:27:EB:6F:3A:90", ip: "192.168.20.90", hostname: "sensor-rack-3", vendor: "Raspberry Pi Trading", deviceType: "iot", osGuess: "embedded Linux", nacState: "mab", vlanId: 40, riskScore: 70, profileId: iotNac.id, lastSeenH: 0.4 },
    { macAddress: "E0:63:DA:18:52:C4", ip: "192.168.99.14", hostname: "tv-lobby", vendor: "Samsung", deviceType: "iot", osGuess: "Tizen", nacState: "quarantine", vlanId: 900, riskScore: 88, profileId: iotNac.id, lastSeenH: 0.02 },
  ];

  for (const d of devices) {
    await prisma.nacDevice.upsert({
      where: { tenantId_macAddress: { tenantId: TENANT, macAddress: d.macAddress } },
      update: {},
      create: {
        tenantId: TENANT,
        macAddress: d.macAddress,
        ip: d.ip,
        hostname: d.hostname,
        vendor: d.vendor,
        deviceType: d.deviceType,
        osGuess: d.osGuess,
        nacState: d.nacState,
        vlanId: d.vlanId,
        riskScore: d.riskScore,
        nacProfileId: d.profileId,
        firstSeen: hoursAgo(72),
        lastSeen: hoursAgo(d.lastSeenH),
      },
    });
  }

  // ── BYOD enrollment (one pending, deterministic token for idempotency) ─────
  await prisma.byodEnrollment.upsert({
    where: { tenantId_token: { tenantId: TENANT, token: "B7E4C1A09D835F62" } },
    update: {},
    create: {
      tenantId: TENANT,
      userName: "socuser",
      deviceId: null,
      token: "B7E4C1A09D835F62",
      status: "pending",
      expiresAt: new Date(Date.now() + 24 * 3_600_000),
    },
  });

  // ── Identity activity events (12 over the last 24h; no unique key → fill
  //    once) ───────────────────────────────────────────────────────────────────
  const eventCount = await prisma.identityActivityEvent.count({ where: { tenantId: TENANT } });
  if (eventCount === 0) {
    const events: Array<{
      userName: string;
      event: string;
      sourceIp: string | null;
      detail: Record<string, unknown>;
      agoH: number;
    }> = [
      { userName: "j.doe", event: "login", sourceIp: "192.168.10.24", detail: { method: "local", result: "success" }, agoH: 23.5 },
      { userName: "c.reyes", event: "vpn", sourceIp: "10.99.1.10", detail: { tunnel: "wg-hub", connected: true }, agoH: 21 },
      { userName: "a.smith", event: "nac_auth", sourceIp: "192.168.10.31", detail: { method: "802.1x", eap: "peap", vlan: 10 }, agoH: 19 },
      { userName: "j.doe", event: "idp_sso", sourceIp: "192.168.10.24", detail: { idp: "Okta SAML", protocol: "saml2" }, agoH: 17.5 },
      { userName: "m.lee", event: "portal", sourceIp: "192.168.20.101", detail: { portal: "GUEST-PORTAL", voucher: true }, agoH: 15 },
      { userName: "netops", event: "login", sourceIp: "192.168.10.8", detail: { method: "local", result: "success" }, agoH: 12.2 },
      { userName: "a.smith", event: "coa", sourceIp: "192.168.10.31", detail: { action: "reauth", profile: "corporate-coa" }, agoH: 9.4 },
      { userName: "j.doe", event: "logout", sourceIp: "192.168.10.24", detail: { reason: "session-timeout" }, agoH: 7.1 },
      { userName: "tv-lobby", event: "vlan_change", sourceIp: "192.168.99.14", detail: { quarantined: true, vlanId: 900 }, agoH: 5.6 },
      { userName: "m.lee", event: "nac_auth", sourceIp: "192.168.10.51", detail: { method: "mab", vlan: 40 }, agoH: 3.8 },
      { userName: "socuser", event: "login", sourceIp: "192.168.10.19", detail: { method: "totp", result: "success" }, agoH: 1.9 },
      { userName: "c.reyes", event: "vpn", sourceIp: "10.99.1.10", detail: { tunnel: "wg-hub", connected: false }, agoH: 0.6 },
    ];
    await prisma.identityActivityEvent.createMany({
      data: events.map((e) => ({
        tenantId: TENANT,
        userName: e.userName,
        event: e.event,
        sourceIp: e.sourceIp,
        detail: JSON.stringify(e.detail),
        createdAt: hoursAgo(e.agoH),
      })),
    });
  }

  return "M23: 2 IdPs, 2 CoA+NAC profiles, 10 devices, 1 BYOD, 12 events";
}

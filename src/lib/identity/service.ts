/**
 * Identity service (M07) — users, groups, auth policy, RADIUS profiles,
 * directory sources, captive portal + vouchers, identity sessions.
 * Per M07-IDENTITY.md §2/§3/§5 + SCHEMA.md §3 (names verbatim).
 *
 * Masking rule (STRICT, ADR-011): sharedSecret / bindPassword read back as the
 * fixed literal MASK; totpSecret + passwordHash are NEVER serialized. Reveal is
 * an explicit, audited, role-gated endpoint (routes layer). Password strength
 * is checked against the stored auth policy here (DB state, not a zod grammar).
 * Vouchers are MockEngine in-memory state (SCHEMA.md §6 pseudo-resource).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { hashPassword } from "@/lib/auth/password";
import { generateTotpSecret } from "@/lib/auth/totp";
import type {
  AuthSettings,
  CaptivePortalUpdate,
  DirectorySourceCreate,
  DirectorySourceUpdate,
  IdentitySessionQuery,
  RadiusProfileCreate,
  RadiusProfileUpdate,
  UserCreate,
  UserGroupCreate,
  UserGroupUpdate,
  UserQuery,
  UserUpdate,
} from "@/lib/validators/identity";

/** Fixed-length masked literal — never leaks real length (M07 §5.3). */
export const MASK = "••••••••";

// ── DTOs (API consumers never see passwordHash / totpSecret / clear secrets) ─

export type UserGroupRef = { id: number; name: string };

export type UserDTO = {
  id: number;
  username: string;
  email: string | null;
  role: string;
  isActive: boolean;
  totpEnrolled: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  groups: UserGroupRef[];
};

export type UserGroupDTO = {
  id: number;
  name: string;
  description: string | null;
  memberIds: number[];
  memberCount: number;
};

export type RadiusProfileDTO = {
  id: number;
  name: string;
  serverIp: string;
  authPort: number;
  sharedSecret: typeof MASK;
  timeoutSec: number;
  retries: number;
};

export type DirectorySourceDTO = {
  id: number;
  name: string;
  type: string;
  serverIp: string;
  port: number;
  baseDn: string;
  bindDn: string | null;
  bindPassword: typeof MASK | null;
  userFilter: string | null;
  enabled: boolean;
};

export type CaptivePortalDTO = {
  id: number;
  name: string;
  enabled: boolean;
  mode: string;
  interfaceName: string;
  sessionTimeoutMin: number;
  bandwidthKbps: number | null;
  redirectUrl: string | null;
  voucherTtlHours: number;
};

export type IdentitySessionDTO = {
  id: number;
  userName: string;
  sourceIp: string;
  method: string;
  deviceMac: string | null;
  startedAt: string;
  lastSeen: string;
  state: string;
};

// ── password policy check (auth policy is DB state — M07 §5.1/§5.2) ─────────

async function assertPasswordPolicy(password: string): Promise<void> {
  const policy = await getAuthSettings();
  const errs: string[] = [];
  if (password.length < policy.password.minLength) {
    errs.push(`Must be at least ${policy.password.minLength} characters`);
  }
  if (policy.password.requireComplexity) {
    if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
      errs.push("Must contain both letters and digits");
    }
  }
  if (errs.length > 0) {
    throw ApiError.validation("Password failed the auth policy", { fieldErrors: { password: errs } });
  }
}

// ── users ───────────────────────────────────────────────────────────────────

type UserRow = {
  id: number;
  username: string;
  email: string | null;
  role: string;
  isActive: boolean;
  totpSecret: string | null;
  lastLoginAt: Date | null;
  createdAt: Date;
};

function toUserDTO(row: UserRow, groups: UserGroupRef[]): UserDTO {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    isActive: row.isActive,
    totpEnrolled: row.totpSecret !== null,
    lastLoginAt: row.lastLoginAt ? row.lastLoginAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
    groups,
  };
}

export async function listUsers(tenantId: number, query: UserQuery): Promise<UserDTO[]> {
  const where = {
    tenantId,
    ...(query.role ? { role: query.role } : {}),
    ...(query.q
      ? {
          OR: [
            { username: { contains: query.q } },
            { email: { contains: query.q } },
          ],
        }
      : {}),
  };
  const rows = await db.user.findMany({
    where,
    orderBy: { username: "asc" },
    include: { groupMembers: { include: { group: { select: { id: true, name: true } } } } },
  });
  let dtos = rows.map((r) =>
    toUserDTO(r, r.groupMembers.map((m) => ({ id: m.group.id, name: m.group.name })).sort((a, b) => a.name.localeCompare(b.name))),
  );
  if (query.groupId) {
    dtos = dtos.filter((u) => u.groups.some((g) => g.id === query.groupId));
  }
  return dtos;
}

async function groupRefsFor(tenantId: number, groupIds: number[]): Promise<UserGroupRef[]> {
  if (groupIds.length === 0) return [];
  const groups = await db.userGroup.findMany({
    where: { tenantId, id: { in: groupIds } },
    select: { id: true, name: true },
  });
  if (groups.length !== new Set(groupIds).size) {
    throw ApiError.validation("Unknown group in groupIds", {
      fieldErrors: { groupIds: ["One or more groups do not exist"] },
    });
  }
  return groups.sort((a, b) => a.name.localeCompare(b.name));
}

async function applyMemberships(userId: number, groupIds: number[]): Promise<void> {
  await db.$transaction([
    db.userGroupMember.deleteMany({ where: { userId, groupId: { notIn: groupIds } } }),
    ...groupIds.map((groupId) =>
      db.userGroupMember.upsert({
        where: { groupId_userId: { groupId, userId } },
        update: {},
        create: { groupId, userId },
      }),
    ),
  ]);
}

export async function createUser(tenantId: number, body: UserCreate): Promise<UserDTO> {
  await assertPasswordPolicy(body.password);
  const dup = await db.user.findFirst({ where: { tenantId, username: body.username } });
  if (dup) throw ApiError.conflict(`A user named "${body.username}" already exists`);
  const refs = await groupRefsFor(tenantId, body.groupIds);
  const row = await db.user.create({
    data: {
      tenantId,
      username: body.username,
      email: body.email ?? null,
      role: body.role,
      isActive: body.isActive,
      passwordHash: await hashPassword(body.password),
    },
  });
  if (body.groupIds.length > 0) await applyMemberships(row.id, body.groupIds);
  return toUserDTO(row, refs);
}

export type TotpEnrollResult = { otpauthUri: string; secret: string };

/**
 * Update user. Special keys:
 *  - `password`  → set/reset (policy-checked, never echoed, never audited)
 *  - `groupIds`  → replace-all memberships
 *  - `totpEnroll`→ true: generate + store secret, return it ONCE;
 *                  false: clear enrollment.
 */
export async function updateUser(
  tenantId: number,
  id: number,
  body: UserUpdate,
): Promise<UserDTO & { totpEnrollment?: TotpEnrollResult }> {
  const existing = await db.user.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("User not found");

  if (body.password !== undefined) await assertPasswordPolicy(body.password);

  // guard: keep at least one enabled super_admin/tenant_admin
  const ADMIN_ROLES = ["super_admin", "tenant_admin"];
  if (body.role && body.role !== existing.role && ADMIN_ROLES.includes(existing.role)) {
    await assertNotLastAdmin(tenantId, existing.id);
  }
  if (body.isActive === false && existing.isActive && ADMIN_ROLES.includes(existing.role)) {
    await assertNotLastAdmin(tenantId, existing.id);
  }

  let totpEnrollment: TotpEnrollResult | undefined;
  if (body.totpEnroll === true) {
    if (!existing.isActive) {
      throw ApiError.conflict("Cannot enroll TOTP for a disabled user");
    }
    const secret = await generateTotpSecret();
    await db.user.update({ where: { id }, data: { totpSecret: secret } });
    totpEnrollment = {
      secret,
      otpauthUri: `otpauth://totp/Cryptsk:${existing.username}?issuer=Cryptsk%20UTM&secret=${secret}`,
    };
  } else if (body.totpEnroll === false) {
    await db.user.update({ where: { id }, data: { totpSecret: null } });
  }

  let refs: UserGroupRef[] | null = null;
  if (body.groupIds !== undefined) {
    refs = await groupRefsFor(tenantId, body.groupIds);
    await applyMemberships(id, body.groupIds);
  }

  const row = await db.user.update({
    where: { id },
    data: {
      email: body.email !== undefined ? (body.email ?? null) : undefined,
      role: body.role ?? undefined,
      isActive: body.isActive ?? undefined,
      passwordHash: body.password !== undefined ? await hashPassword(body.password) : undefined,
    },
    include: { groupMembers: { include: { group: { select: { id: true, name: true } } } } },
  });
  const dto = toUserDTO(
    row,
    refs ?? row.groupMembers.map((m) => ({ id: m.group.id, name: m.group.name })).sort((a, b) => a.name.localeCompare(b.name)),
  );
  return totpEnrollment ? { ...dto, totpEnrollment } : dto;
}

/** 409 when the mutation would remove the last enabled admin (M07 §5.1). */
async function assertNotLastAdmin(tenantId: number, excludeUserId: number): Promise<void> {
  const remaining = await db.user.count({
    where: {
      tenantId,
      id: { not: excludeUserId },
      isActive: true,
      role: { in: ["super_admin", "tenant_admin"] },
    },
  });
  if (remaining === 0) {
    throw ApiError.conflict("Cannot remove the last enabled super_admin/tenant_admin");
  }
}

export async function deleteUser(tenantId: number, actorId: number | undefined, id: number): Promise<void> {
  const existing = await db.user.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("User not found");
  if (actorId !== undefined && actorId === id) {
    throw ApiError.conflict("You cannot delete your own account");
  }
  if (["super_admin", "tenant_admin"].includes(existing.role)) {
    await assertNotLastAdmin(tenantId, id);
  }
  await db.user.delete({ where: { id } });
}

// ── user groups ─────────────────────────────────────────────────────────────

function toGroupDTO(row: {
  id: number;
  name: string;
  description: string | null;
  members: { userId: number }[];
}): UserGroupDTO {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    memberIds: row.members.map((m) => m.userId).sort((a, b) => a - b),
    memberCount: row.members.length,
  };
}

export async function listGroups(tenantId: number): Promise<UserGroupDTO[]> {
  const rows = await db.userGroup.findMany({
    where: { tenantId },
    orderBy: { name: "asc" },
    include: { members: { select: { userId: true } } },
  });
  return rows.map(toGroupDTO);
}

async function assertMembersExist(tenantId: number, memberIds: number[]): Promise<void> {
  if (memberIds.length === 0) return;
  const count = await db.user.count({ where: { tenantId, id: { in: memberIds } } });
  if (count !== new Set(memberIds).size) {
    throw ApiError.validation("Unknown user in memberIds", {
      fieldErrors: { memberIds: ["One or more users do not exist"] },
    });
  }
}

export async function createGroup(tenantId: number, body: UserGroupCreate): Promise<UserGroupDTO> {
  const dup = await db.userGroup.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A group named "${body.name}" already exists`);
  await assertMembersExist(tenantId, body.memberIds);
  const row = await db.userGroup.create({
    data: {
      tenantId,
      name: body.name,
      description: body.description ?? null,
      members: { create: body.memberIds.map((userId) => ({ userId })) },
    },
    include: { members: { select: { userId: true } } },
  });
  return toGroupDTO(row);
}

/** Replace-all member semantics in one tx: delete-missing, create-new (M07 §5.1). */
export async function updateGroup(tenantId: number, id: number, body: UserGroupUpdate): Promise<UserGroupDTO> {
  const existing = await db.userGroup.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Group not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.userGroup.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A group named "${body.name}" already exists`);
  }
  if (body.memberIds !== undefined) await assertMembersExist(tenantId, body.memberIds);

  await db.userGroup.update({
    where: { id },
    data: {
      name: body.name ?? undefined,
      description: body.description !== undefined ? (body.description ?? null) : undefined,
    },
  });
  if (body.memberIds !== undefined) {
    await db.$transaction([
      db.userGroupMember.deleteMany({ where: { groupId: id, userId: { notIn: body.memberIds } } }),
      ...body.memberIds.map((userId) =>
        db.userGroupMember.upsert({
          where: { groupId_userId: { groupId: id, userId } },
          update: {},
          create: { groupId: id, userId },
        }),
      ),
    ]);
  }
  const fresh = await db.userGroup.findUniqueOrThrow({
    where: { id },
    include: { members: { select: { userId: true } } },
  });
  return toGroupDTO(fresh);
}

export async function deleteGroup(tenantId: number, id: number): Promise<void> {
  const existing = await db.userGroup.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Group not found");
  await db.userGroup.delete({ where: { id } }); // memberships cascade; users untouched
}

// ── auth settings (SystemSetting category "auth" — M07 §5.2) ────────────────

export const DEFAULT_AUTH_SETTINGS: AuthSettings = {
  password: { minLength: 8, requireComplexity: true, expiryDays: 90 },
  lockout: { maxAttempts: 5, windowMin: 15 },
  sessionLifetimeHours: 8,
  totp: { required: false },
  sessionLimits: { maxConcurrentPerUser: 4 },
};

export async function getAuthSettings(): Promise<AuthSettings> {
  const rows = await db.systemSetting.findMany({
    where: { tenantId: 1, category: "auth" },
  });
  const byKey = new Map(rows.map((r) => [r.key, parseJson<Record<string, unknown>>(r.value, {})]));

  // canonical merged store wins
  const merged = byKey.get("settings") as Partial<AuthSettings> | undefined;
  if (merged) {
    return {
      password: { ...DEFAULT_AUTH_SETTINGS.password, ...(merged.password ?? {}) },
      lockout: { ...DEFAULT_AUTH_SETTINGS.lockout, ...(merged.lockout ?? {}) },
      sessionLifetimeHours: merged.sessionLifetimeHours ?? DEFAULT_AUTH_SETTINGS.sessionLifetimeHours,
      totp: { ...DEFAULT_AUTH_SETTINGS.totp, ...(merged.totp ?? {}) },
      sessionLimits: { ...DEFAULT_AUTH_SETTINGS.sessionLimits, ...(merged.sessionLimits ?? {}) },
    };
  }

  // seed fallback: granular keys (passwordPolicy / lockout / totp / sessionLimits)
  const pw = byKey.get("passwordPolicy") as { minLength?: number; complexity?: string; expiryDays?: number } | undefined;
  const lk = byKey.get("lockout") as { maxFailures?: number; lockoutMinutes?: number } | undefined;
  const tp = byKey.get("totp") as { required?: boolean } | undefined;
  const sl = byKey.get("sessionLimits") as { maxConcurrentPerUser?: number } | undefined;
  return {
    password: {
      minLength: pw?.minLength ?? DEFAULT_AUTH_SETTINGS.password.minLength,
      requireComplexity: (pw?.complexity ?? "letters_digits") !== "none",
      expiryDays: pw?.expiryDays ?? DEFAULT_AUTH_SETTINGS.password.expiryDays,
    },
    lockout: {
      maxAttempts: lk?.maxFailures ?? DEFAULT_AUTH_SETTINGS.lockout.maxAttempts,
      windowMin: lk?.lockoutMinutes ?? DEFAULT_AUTH_SETTINGS.lockout.windowMin,
    },
    sessionLifetimeHours: DEFAULT_AUTH_SETTINGS.sessionLifetimeHours,
    totp: { required: tp?.required ?? DEFAULT_AUTH_SETTINGS.totp.required },
    sessionLimits: {
      maxConcurrentPerUser: sl?.maxConcurrentPerUser ?? DEFAULT_AUTH_SETTINGS.sessionLimits.maxConcurrentPerUser,
    },
  };
}

export async function putAuthSettings(settings: AuthSettings): Promise<AuthSettings> {
  await db.systemSetting.upsert({
    where: { tenantId_category_key: { tenantId: 1, category: "auth", key: "settings" } },
    update: { value: stringifyJson(settings) },
    create: { tenantId: 1, category: "auth", key: "settings", value: stringifyJson(settings) },
  });
  // keep the granular keys in sync (login flow + generators read them)
  const granular: Array<[string, string]> = [
    ["passwordPolicy", stringifyJson({ minLength: settings.password.minLength, complexity: settings.password.requireComplexity ? "letters_digits" : "none", expiryDays: settings.password.expiryDays, history: 0 })],
    ["lockout", stringifyJson({ maxFailures: settings.lockout.maxAttempts, lockoutMinutes: settings.lockout.windowMin })],
    ["totp", stringifyJson({ required: settings.totp.required })],
    ["sessionLimits", stringifyJson({ maxConcurrentPerUser: settings.sessionLimits.maxConcurrentPerUser })],
  ];
  for (const [key, value] of granular) {
    await db.systemSetting.upsert({
      where: { tenantId_category_key: { tenantId: 1, category: "auth", key } },
      update: { value },
      create: { tenantId: 1, category: "auth", key, value },
    });
  }
  return settings;
}

// ── RADIUS profiles (masked secret — M07 §5.3) ──────────────────────────────

function toRadiusDTO(row: {
  id: number;
  name: string;
  serverIp: string;
  authPort: number;
  timeoutSec: number;
  retries: number;
}): RadiusProfileDTO {
  return {
    id: row.id,
    name: row.name,
    serverIp: row.serverIp,
    authPort: row.authPort,
    sharedSecret: MASK,
    timeoutSec: row.timeoutSec,
    retries: row.retries,
  };
}

export async function listRadiusProfiles(tenantId: number): Promise<RadiusProfileDTO[]> {
  const rows = await db.radiusProfile.findMany({ where: { tenantId }, orderBy: { name: "asc" } });
  return rows.map(toRadiusDTO);
}

export async function createRadiusProfile(tenantId: number, body: RadiusProfileCreate): Promise<RadiusProfileDTO> {
  const dup = await db.radiusProfile.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A RADIUS profile named "${body.name}" already exists`);
  const row = await db.radiusProfile.create({
    data: {
      tenantId,
      name: body.name,
      serverIp: body.serverIp,
      authPort: body.authPort,
      sharedSecret: body.sharedSecret,
      timeoutSec: body.timeoutSec,
      retries: body.retries,
    },
  });
  return toRadiusDTO(row);
}

/** Omitting sharedSecret (or sending the masked literal back) keeps the stored value. */
export async function updateRadiusProfile(tenantId: number, id: number, body: RadiusProfileUpdate): Promise<RadiusProfileDTO> {
  const existing = await db.radiusProfile.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("RADIUS profile not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.radiusProfile.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A RADIUS profile named "${body.name}" already exists`);
  }
  const keepSecret = body.sharedSecret === undefined || body.sharedSecret === MASK;
  const row = await db.radiusProfile.update({
    where: { id },
    data: {
      name: body.name ?? undefined,
      serverIp: body.serverIp ?? undefined,
      authPort: body.authPort ?? undefined,
      sharedSecret: keepSecret ? undefined : body.sharedSecret,
      timeoutSec: body.timeoutSec ?? undefined,
      retries: body.retries ?? undefined,
    },
  });
  return toRadiusDTO(row);
}

export async function deleteRadiusProfile(tenantId: number, id: number): Promise<void> {
  const existing = await db.radiusProfile.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("RADIUS profile not found");
  await db.radiusProfile.delete({ where: { id } });
}

// ── simulated connectivity tests (M07 §5.3) ─────────────────────────────────

/** Documentation ranges are "dead" in the sandbox — everything else answers. */
function isDeadIp(ip: string): boolean {
  return /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|100\.64\.|0\.0\.0\.0$)/.test(ip);
}

export async function testRadiusProfile(tenantId: number, id: number): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
  const row = await db.radiusProfile.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("RADIUS profile not found");
  const latencyMs = 5 + Math.floor(Math.random() * 36);
  if (isDeadIp(row.serverIp)) {
    return { ok: false, latencyMs, error: `No route to ${row.serverIp}:${row.authPort} (timeout after ${row.timeoutSec}s)` };
  }
  return { ok: true, latencyMs };
}

export async function testDirectorySource(
  tenantId: number,
  id: number,
): Promise<{ ok: boolean; latencyMs: number; userCount?: number; error?: string }> {
  const row = await db.directorySource.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("Directory source not found");
  const latencyMs = 5 + Math.floor(Math.random() * 36);
  if (isDeadIp(row.serverIp)) {
    return { ok: false, latencyMs, error: `Connection refused by ${row.serverIp}:${row.port}` };
  }
  return { ok: true, latencyMs, ...(row.enabled ? { userCount: 40 + Math.floor(Math.random() * 360) } : {}) };
}

// ── directory sources (LDAP/AD — masked bindPassword, no reveal) ────────────

function toDirectoryDTO(row: {
  id: number;
  name: string;
  type: string;
  serverIp: string;
  port: number;
  baseDn: string;
  bindDn: string | null;
  bindPassword: string | null;
  userFilter: string | null;
  enabled: boolean;
}): DirectorySourceDTO {
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    serverIp: row.serverIp,
    port: row.port,
    baseDn: row.baseDn,
    bindDn: row.bindDn,
    bindPassword: row.bindPassword ? MASK : null,
    userFilter: row.userFilter,
    enabled: row.enabled,
  };
}

export async function listDirectorySources(tenantId: number): Promise<DirectorySourceDTO[]> {
  const rows = await db.directorySource.findMany({ where: { tenantId }, orderBy: { name: "asc" } });
  return rows.map(toDirectoryDTO);
}

export async function createDirectorySource(tenantId: number, body: DirectorySourceCreate): Promise<DirectorySourceDTO> {
  const dup = await db.directorySource.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A directory source named "${body.name}" already exists`);
  const row = await db.directorySource.create({
    data: {
      tenantId,
      name: body.name,
      type: body.type,
      serverIp: body.serverIp,
      port: body.port,
      baseDn: body.baseDn,
      bindDn: body.bindDn ?? null,
      bindPassword: body.bindPassword || null,
      userFilter: body.userFilter ?? null,
      enabled: body.enabled,
    },
  });
  return toDirectoryDTO(row);
}

/** Omitting bindPassword (or sending the masked literal) keeps the stored value. */
export async function updateDirectorySource(tenantId: number, id: number, body: DirectorySourceUpdate): Promise<DirectorySourceDTO> {
  const existing = await db.directorySource.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Directory source not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.directorySource.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A directory source named "${body.name}" already exists`);
  }
  const keepPw = body.bindPassword === undefined || body.bindPassword === MASK;
  const row = await db.directorySource.update({
    where: { id },
    data: {
      name: body.name ?? undefined,
      type: body.type ?? undefined,
      serverIp: body.serverIp ?? undefined,
      port: body.port ?? undefined,
      baseDn: body.baseDn ?? undefined,
      bindDn: body.bindDn !== undefined ? (body.bindDn ?? null) : undefined,
      bindPassword: keepPw ? undefined : body.bindPassword,
      userFilter: body.userFilter !== undefined ? (body.userFilter ?? null) : undefined,
      enabled: body.enabled ?? undefined,
    },
  });
  return toDirectoryDTO(row);
}

export async function deleteDirectorySource(tenantId: number, id: number): Promise<void> {
  const existing = await db.directorySource.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Directory source not found");
  await db.directorySource.delete({ where: { id } });
}

// ── captive portal (singleton upsert — M07 §5.4) ────────────────────────────

export async function getCaptivePortal(tenantId: number): Promise<CaptivePortalDTO> {
  const row = await db.captivePortalProfile.findFirst({
    where: { tenantId },
    orderBy: { id: "asc" },
  });
  if (!row) {
    return {
      id: 0,
      name: "GUEST-PORTAL",
      enabled: false,
      mode: "clickthrough",
      interfaceName: "lan0",
      sessionTimeoutMin: 240,
      bandwidthKbps: null,
      redirectUrl: null,
      voucherTtlHours: 24,
    };
  }
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    mode: row.mode,
    interfaceName: row.interfaceName,
    sessionTimeoutMin: row.sessionTimeoutMin,
    bandwidthKbps: row.bandwidthKbps,
    redirectUrl: row.redirectUrl,
    voucherTtlHours: row.voucherTtlHours,
  };
}

export async function putCaptivePortal(tenantId: number, body: CaptivePortalUpdate): Promise<CaptivePortalDTO> {
  const existing = await db.captivePortalProfile.findFirst({ where: { tenantId }, orderBy: { id: "asc" } });
  const data = {
    name: body.name,
    enabled: body.enabled,
    mode: body.mode,
    interfaceName: body.interfaceName,
    sessionTimeoutMin: body.sessionTimeoutMin,
    bandwidthKbps: body.bandwidthKbps ?? null,
    redirectUrl: body.redirectUrl ?? null,
    voucherTtlHours: body.voucherTtlHours,
  };
  const row = existing
    ? await db.captivePortalProfile.update({ where: { id: existing.id }, data })
    : await db.captivePortalProfile.create({ data: { tenantId, ...data } });
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    mode: row.mode,
    interfaceName: row.interfaceName,
    sessionTimeoutMin: row.sessionTimeoutMin,
    bandwidthKbps: row.bandwidthKbps,
    redirectUrl: row.redirectUrl,
    voucherTtlHours: row.voucherTtlHours,
  };
}

// ── identity sessions (read + admin expire — M07 §5.5) ──────────────────────

function toSessionDTO(r: {
  id: number;
  userName: string;
  sourceIp: string;
  method: string;
  deviceMac: string | null;
  startedAt: Date;
  lastSeen: Date;
  state: string;
}): IdentitySessionDTO {
  return {
    id: r.id,
    userName: r.userName,
    sourceIp: r.sourceIp,
    method: r.method,
    deviceMac: r.deviceMac,
    startedAt: r.startedAt.toISOString(),
    lastSeen: r.lastSeen.toISOString(),
    state: r.state,
  };
}

export async function listIdentitySessions(
  tenantId: number,
  query: IdentitySessionQuery,
): Promise<{ data: IdentitySessionDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where = {
    tenantId,
    state: query.state,
    ...(query.method ? { method: query.method } : {}),
    ...(query.q
      ? {
          OR: [
            { userName: { contains: query.q } },
            { sourceIp: { contains: query.q } },
            { deviceMac: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [total, rows] = await Promise.all([
    db.identitySession.count({ where }),
    db.identitySession.findMany({
      where,
      orderBy: { lastSeen: "desc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(toSessionDTO),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

export async function expireIdentitySession(tenantId: number, id: number): Promise<IdentitySessionDTO> {
  const row = await db.identitySession.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("Identity session not found");
  if (row.state === "expired") return toSessionDTO(row);
  const updated = await db.identitySession.update({ where: { id }, data: { state: "expired", lastSeen: new Date() } });
  return toSessionDTO(updated);
}

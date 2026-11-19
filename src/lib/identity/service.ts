/**
 * Identity service (M07) — users, groups, auth policy, RADIUS profiles,
 * directory sources, captive portal + vouchers, identity sessions.
 * Per M07-IDENTITY.md §2/§3/§5 + SCHEMA.md §3 (names verbatim).
 *
 * Masking rule (STRICT, ADR-011): sharedSecret / bindPassword read back as the
 * fixed literal MASK; totpSecret + passwordHash are NEVER serialized. Reveal is
 * an explicit, audited, role-gated endpoint (routes layer). Password strength
 * is checked against the stored auth policy here (DB state, not a zod grammar).
 * Vouchers are persistent rows (spec §1.10, T1-d) — see ./vouchers.ts.
 *
 * Audit fixes (F-c):
 *  - #3 role-hierarchy guard: create/update/delete take the actor's role from
 *    the routes (auth context) — no principal may be created/modified by an
 *    actor it outranks, and admin-class roles need admin-class actors. Callers
 *    that omit the actor role (legacy service-level tests) bypass the guard.
 *  - #1 user lifecycle changes (disable / role change / password change /
 *    delete) revoke all of that user's AuthSessions (JWT revocation registry).
 *  - #18 createUser runs user.create + memberships in one transaction.
 *  - #20 the last-admin guard re-counts INSIDE the same transaction as the
 *    guarded role/isActive mutation, which is applied as a conditional
 *    updateMany (lost-update safe — concurrent flips → 409).
 *  - #24 password expiry (policy.password.expiryDays) is INERT in the
 *    console: enforced only by the simulated engine; console login does not
 *    expire passwords yet — kept as stored policy state, no enforcement here.
 *  - #25 BYOD enrollment tokens (identity-advanced/byod) and IdP
 *    clientSecrets (identity-advanced/idps) are stored PLAINTEXT AT REST by
 *    design (schema locked) — redaction-in-response is enforced instead
 *    (tokens/secret never serialized; one-time reveal on create only).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { hashPassword } from "@/lib/auth/password";
import { generateTotpSecret } from "@/lib/auth/totp";
import { revokeAllUserSessions } from "@/lib/auth/session-store";
import type {
  AuthSettings,
  CaptivePortalUpdate,
  DirectorySourceCreate,
  DirectorySourceUpdate,
  IdentitySessionQuery,
  PortalSessionQuery,
  RadiusProfileCreate,
  RadiusProfileUpdate,
  UserCreate,
  UserGroupCreate,
  UserGroupUpdate,
  UserQuery,
  UserUpdate,
} from "@/lib/validators/identity";
import { hashSessionToken, newPortalSessionToken } from "@/lib/identity/vouchers";

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

async function applyMemberships(client: Pick<typeof db, "userGroupMember">, userId: number, groupIds: number[]): Promise<void> {
  await client.userGroupMember.deleteMany({ where: { userId, groupId: { notIn: groupIds } } });
  for (const groupId of groupIds) {
    await client.userGroupMember.upsert({
      where: { groupId_userId: { groupId, userId } },
      update: {},
      create: { groupId, userId },
    });
  }
}

// ── role-hierarchy guard (audit fix #3 — privilege-escalation prevention) ────

/** super_admin > tenant_admin > security_admin > network_admin > soc_analyst > helpdesk.
 *  auditor/api_service sit BELOW the ladder (rank -1) — they can never create
 *  or modify privileged principals (the identity.write matrix already keeps
 *  them out of the area entirely). */
const ROLE_RANK: Record<string, number> = {
  super_admin: 60,
  tenant_admin: 50,
  security_admin: 40,
  network_admin: 30,
  soc_analyst: 20,
  helpdesk: 10,
};
const ADMIN_CLASS_ROLES = ["super_admin", "tenant_admin"];

function rankOf(role: string | undefined): number {
  return ROLE_RANK[role ?? ""] ?? -1;
}

/**
 * Guard the ASSIGNMENT of `newRole` (createUser, or updateUser changing role):
 *  - only super_admin may create/assign the super_admin role;
 *  - only super_admin/tenant_admin may assign admin-class roles;
 *  - nobody may assign a role that outranks their own.
 */
export function assertRoleAssignment(actorRole: string | undefined, newRole: string): void {
  if (newRole === "super_admin" && actorRole !== "super_admin") {
    throw ApiError.forbidden("Only super_admin may create or assign the super_admin role");
  }
  if (ADMIN_CLASS_ROLES.includes(newRole) && rankOf(actorRole) < ROLE_RANK.tenant_admin) {
    throw ApiError.forbidden("Only super_admin or tenant_admin may assign admin-class roles");
  }
  if (rankOf(newRole) > rankOf(actorRole)) {
    throw ApiError.forbidden(`Role '${actorRole ?? "unknown"}' may not assign the higher-ranked '${newRole}' role`);
  }
}

/**
 * Guard MODIFYING an existing principal (update/delete/password reset):
 * the target's role must not outrank the actor's.
 */
export function assertTargetNotOutranking(actorRole: string | undefined, targetRole: string): void {
  if (rankOf(targetRole) > rankOf(actorRole)) {
    throw ApiError.forbidden(`Role '${actorRole ?? "unknown"}' may not modify a '${targetRole}' principal — target outranks the actor`);
  }
}

export async function createUser(tenantId: number, body: UserCreate, actorRole?: string): Promise<UserDTO> {
  // role-hierarchy guard (audit fix #3) — wired from the route's auth context
  assertRoleAssignment(actorRole, body.role);
  await assertPasswordPolicy(body.password);
  const dup = await db.user.findFirst({ where: { tenantId, username: body.username } });
  if (dup) throw ApiError.conflict(`A user named "${body.username}" already exists`);
  const refs = await groupRefsFor(tenantId, body.groupIds);
  // audit fix #18 — user + memberships land atomically (no orphan user when a
  // membership insert fails)
  const row = await db.$transaction(async (tx) => {
    const created = await tx.user.create({
      data: {
        tenantId,
        username: body.username,
        email: body.email ?? null,
        role: body.role,
        isActive: body.isActive,
        passwordHash: await hashPassword(body.password),
      },
    });
    if (body.groupIds.length > 0) await applyMemberships(tx, created.id, body.groupIds);
    return created;
  });
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
  actorRole?: string,
): Promise<UserDTO & { totpEnrollment?: TotpEnrollResult }> {
  const existing = await db.user.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("User not found");

  // role-hierarchy guard (audit fix #3): no password reset / role change /
  // disable / edit against a principal that outranks the actor, and the NEW
  // role must be assignable by the actor
  assertTargetNotOutranking(actorRole, existing.role);
  if (body.role !== undefined && body.role !== existing.role) {
    assertRoleAssignment(actorRole, body.role);
  }

  if (body.password !== undefined) await assertPasswordPolicy(body.password);

  // audit fix #20 — the last-admin guard re-counts INSIDE the same transaction
  // as the guarded role/isActive mutation; the mutation is a conditional
  // updateMany (preconditions role+isActive) so concurrent edits 409 instead
  // of silently racing past the guard.
  const ADMIN_ROLES = ["super_admin", "tenant_admin"];
  let roleActiveApplied = false;
  if (body.role !== undefined || body.isActive !== undefined) {
    await db.$transaction(async (tx) => {
      const current = await tx.user.findFirst({ where: { tenantId, id } });
      if (!current) throw ApiError.notFound("User not found");
      const demotingAdmin =
        (body.role !== undefined && body.role !== current.role && ADMIN_ROLES.includes(current.role)) ||
        (body.isActive === false && current.isActive && ADMIN_ROLES.includes(current.role));
      if (demotingAdmin) {
        const remaining = await tx.user.count({
          where: { tenantId, id: { not: id }, isActive: true, role: { in: ADMIN_ROLES } },
        });
        if (remaining === 0) throw ApiError.conflict("Cannot remove the last enabled super_admin/tenant_admin");
      }
      const flip = await tx.user.updateMany({
        where: { id, tenantId, role: current.role, isActive: current.isActive },
        data: { role: body.role ?? undefined, isActive: body.isActive ?? undefined },
      });
      if (flip.count === 0) {
        throw ApiError.conflict("User was modified concurrently — retry the update");
      }
      roleActiveApplied = true;
    });
  }

  // audit fix #1 — lifecycle changes kill the user's live JWT sessions
  const lifecycleChange =
    (body.isActive === false && existing.isActive) ||
    (body.role !== undefined && body.role !== existing.role) ||
    body.password !== undefined;
  if (lifecycleChange) await revokeAllUserSessions(id);

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
    await applyMemberships(db, id, body.groupIds);
  }

  const row = await db.user.update({
    where: { id },
    data: {
      email: body.email !== undefined ? (body.email ?? null) : undefined,
      // role/isActive were applied by the guarded conditional update above
      role: roleActiveApplied ? undefined : (body.role ?? undefined),
      isActive: roleActiveApplied ? undefined : (body.isActive ?? undefined),
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

export async function deleteUser(tenantId: number, actorId: number | undefined, id: number, actorRole?: string): Promise<void> {
  const existing = await db.user.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("User not found");
  // role-hierarchy guard (audit fix #3) — cannot delete an outranking principal
  assertTargetNotOutranking(actorRole, existing.role);
  if (actorId !== undefined && actorId === id) {
    throw ApiError.conflict("You cannot delete your own account");
  }
  // audit fix #1 — the deleted principal's JWT sessions die with the account
  await revokeAllUserSessions(id);
  // audit fix #20 — last-admin re-count + conditional delete in ONE tx: the
  // deleteMany where carries the role precondition, so a concurrent demotion
  // makes the delete a no-op (409) instead of racing past the guard.
  await db.$transaction(async (tx) => {
    if (ADMIN_CLASS_ROLES.includes(existing.role)) {
      const remaining = await tx.user.count({
        where: { tenantId, id: { not: id }, isActive: true, role: { in: ADMIN_CLASS_ROLES } },
      });
      if (remaining === 0) throw ApiError.conflict("Cannot remove the last enabled super_admin/tenant_admin");
    }
    const del = await tx.user.deleteMany({ where: { id, role: existing.role } }); // memberships cascade (FK)
    if (del.count === 0) throw ApiError.conflict("User was modified concurrently — retry the delete");
  });
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

// ── auth settings (SystemSetting category "auth" — M07 §5.2) ─────────────────

export const DEFAULT_AUTH_SETTINGS: AuthSettings = {
  /**
   * password.expiryDays is INERT in the console (audit fix #24, documented
   * not implemented): it is enforced only by the simulated engine; console
   * login does not expire passwords yet. Stored as policy state so a future
   * enforcement pass can read it.
   */
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

// ── captive portal sessions + guest self-registration (spec §1.10 / §7, T1-d) ─

export type PortalSessionDTO = {
  id: number;
  portalId: number;
  /** voucher | credentials | clickthrough | self-registration */
  kind: string;
  clientMac: string | null;
  clientIp: string;
  userName: string | null;
  /** active | expired | terminated */
  state: string;
  bytesIn: number;
  bytesOut: number;
  startedAt: string;
  expiresAt: string;
};

/** Guest self-registration input (service layer — clientIp is server-derived). */
export type PortalSelfRegisterInput = {
  name: string;
  /** accepted for future notification use — the session schema has no phone column, not persisted */
  phone?: string;
  agree: boolean;
  clientIp: string;
  clientMac?: string;
};

function toPortalSessionDTO(r: {
  id: number;
  portalId: number;
  kind: string;
  clientMac: string | null;
  clientIp: string;
  userName: string | null;
  state: string;
  bytesIn: number;
  bytesOut: number;
  startedAt: Date;
  expiresAt: Date;
}): PortalSessionDTO {
  return {
    id: r.id,
    portalId: r.portalId,
    kind: r.kind,
    clientMac: r.clientMac,
    clientIp: r.clientIp,
    userName: r.userName,
    state: r.state,
    bytesIn: r.bytesIn,
    bytesOut: r.bytesOut,
    startedAt: r.startedAt.toISOString(),
    expiresAt: r.expiresAt.toISOString(),
  };
}

export async function listPortalSessions(
  tenantId: number,
  query: PortalSessionQuery,
): Promise<{ data: PortalSessionDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where = {
    tenantId,
    ...(query.state ? { state: query.state } : {}),
    ...(query.kind ? { kind: query.kind } : {}),
    ...(query.q
      ? {
          OR: [
            { userName: { contains: query.q } },
            { clientIp: { contains: query.q } },
            { clientMac: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [total, rows] = await Promise.all([
    db.captivePortalSession.count({ where }),
    db.captivePortalSession.findMany({
      where,
      orderBy: { startedAt: "desc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(toPortalSessionDTO),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

/** Admin terminate — idempotent (already-terminated rows return unchanged). */
export async function terminatePortalSession(tenantId: number, id: number): Promise<PortalSessionDTO> {
  const row = await db.captivePortalSession.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("Portal session not found");
  if (row.state === "terminated") return toPortalSessionDTO(row);
  const updated = await db.captivePortalSession.update({ where: { id }, data: { state: "terminated" } });
  return toPortalSessionDTO(updated);
}

/**
 * Guest self-registration (spec §1.10) — PUBLIC endpoint path. Allowed for
 * every portal mode, but ONLY while the portal profile exists and is enabled.
 * Opens an active CaptivePortalSession (kind "self-registration") lasting
 * sessionTimeoutMin; the session token is returned ONCE — only sha256(token)
 * is stored (captive_portal_sessions.session_id).
 *
 * Audit fix #23 — abuse cap: at most 3 CONCURRENT active self-registration
 * sessions per source IP (state "active" and not past expiresAt) → 429.
 */
export async function selfRegister(
  tenantId: number,
  input: PortalSelfRegisterInput,
): Promise<{ session: PortalSessionDTO; token: string }> {
  if (!input.agree) {
    throw ApiError.validation("Guest must accept the acceptable-use policy", {
      fieldErrors: { agree: ["Acceptance is required"] },
    });
  }
  const profile = await db.captivePortalProfile.findFirst({ where: { tenantId }, orderBy: { id: "asc" } });
  if (!profile) throw ApiError.forbidden("Captive portal is not configured — guest self-registration is unavailable");
  if (!profile.enabled) throw ApiError.forbidden("Captive portal is disabled — guest self-registration is unavailable");

  const now = new Date();
  const activeSelfRegs = await db.captivePortalSession.count({
    where: { tenantId, kind: "self-registration", clientIp: input.clientIp, state: "active", expiresAt: { gt: now } },
  });
  if (activeSelfRegs >= 3) {
    throw ApiError.rateLimited("Too many active guest sessions from this address — try again later");
  }

  const token = newPortalSessionToken();
  const row = await db.captivePortalSession.create({
    data: {
      tenantId,
      portalId: profile.id,
      sessionId: hashSessionToken(token),
      kind: "self-registration",
      clientMac: input.clientMac ?? null,
      clientIp: input.clientIp,
      userName: input.name,
      state: "active",
      startedAt: now,
      expiresAt: new Date(now.getTime() + profile.sessionTimeoutMin * 60_000),
    },
  });
  return { session: toPortalSessionDTO(row), token };
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

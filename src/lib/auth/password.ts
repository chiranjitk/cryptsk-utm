/**
 * Password hashing — docs/07-SECURITY/AUTH_AND_RBAC.md §2 (bcrypt, cost 12).
 */

import bcrypt from "bcryptjs";

const COST = 12;

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, COST);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

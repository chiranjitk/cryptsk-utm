/** Debug: inspect users + verify admin password against DB hash. */
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const db = new PrismaClient();

async function main() {
  const users = await db.user.findMany({
    select: { id: true, username: true, role: true, isActive: true, totpSecret: true, passwordHash: true },
  });
  console.log(`Total users: ${users.length}`);
  for (const u of users) {
    console.log(
      `#${u.id} ${u.username} role=${u.role} active=${u.isActive} totp=${u.totpSecret ? "YES" : "no"} hash=${u.passwordHash.slice(0, 12)}...`,
    );
  }

  const admin = await db.user.findUnique({
    where: { tenantId_username: { tenantId: 1, username: "admin" } },
  });
  if (!admin) {
    console.log("ADMIN NOT FOUND for tenant 1!");
    return;
  }
  for (const pw of ["admin123", "Admin123!", "admin"]) {
    const ok = await bcrypt.compare(pw, admin.passwordHash);
    console.log(`bcrypt.compare(${JSON.stringify(pw)}) -> ${ok}`);
  }
}

main()
  .catch((e) => {
    console.error("ERROR:", e);
    process.exitCode = 1;
  })
  .finally(() => db.$disconnect());

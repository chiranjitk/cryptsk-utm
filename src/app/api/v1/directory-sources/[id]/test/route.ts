/**
 * Directory source test (M07 §3/§5.3) — simulated LDAP/AD connectivity probe
 * wired to the existing testDirectorySource service (TEST-NET addresses fail
 * in the sandbox; enabled sources report a simulated userCount).
 */

import { route, numericId } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { testDirectorySource } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const row = await db.directorySource.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!row) throw ApiError.notFound("Directory source not found");

  const result = await testDirectorySource(auth.tenantId, id);
  return {
    data: result,
    audit: {
      action: "directory_source.test",
      objectType: "directory_source",
      objectId: id,
      objectName: row.name,
      after: result,
    },
  };
});

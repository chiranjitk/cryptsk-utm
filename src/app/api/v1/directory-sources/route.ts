/** Directory sources — LDAP/AD connectors (M07 §3; spec §1.10). bindPassword is ALWAYS masked. */

import { route } from "@/lib/api/handler";
import { directorySourceCreateSchema } from "@/lib/validators/identity";
import { createDirectorySource, listDirectorySources } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  return { data: await listDirectorySources(auth.tenantId) };
});

export const POST = route(
  { area: "identity", bodySchema: directorySourceCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    const created = await createDirectorySource(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "directory_source.create", objectType: "directory_source", objectId: created.id, objectName: created.name },
    };
  },
);

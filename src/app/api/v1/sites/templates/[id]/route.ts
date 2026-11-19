/**
 * /api/v1/sites/templates/[id] — single site template: GET, PATCH (name,
 * description, version, payload bundle), DELETE. Deployments already pushed
 * from the template keep their payload snapshot — see deleteTemplate.
 */

import { route, numericId } from "@/lib/api/handler";
import { templateUpdateSchema } from "@/lib/validators/sites";
import { deleteTemplate, getTemplate, updateTemplate } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sites" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  return { data: await getTemplate(auth.tenantId, id) };
});

export const PATCH = route(
  { area: "sites", bodySchema: templateUpdateSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateTemplate(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "site_template.update",
        objectType: "site_template",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sites" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteTemplate(auth.tenantId, id);
  return { data: deleted, audit: { action: "site_template.delete", objectType: "site_template", objectId: id } };
});

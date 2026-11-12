/**
 * Quarantine release (M22 §2.8.7) — POST /api/v1/email-security/logs/{id}/release.
 * Only quarantined rows may be released (409 otherwise): creates a follow-up
 * EmailLog row with verdict "delivered" and reasons ["released:<id>"], same
 * from/to. Audit `email.release`, snapshot section `email_security`.
 */

import { route, numericId } from "@/lib/api/handler";
import { z } from "zod";
import { releaseQuarantined } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "email_security", bodySchema: z.object({}).default({}), section: "email_security" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const released = await releaseQuarantined(auth.tenantId, params.id ?? String(id));
    return {
      data: released,
      audit: {
        action: "email.release",
        objectType: "email_log",
        objectId: released.id,
        objectName: released.fromAddr,
        before: { id, verdict: "quarantined" },
        after: { id: released.id, verdict: "delivered" },
      },
    };
  },
);

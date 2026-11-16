/**
 * POST /api/v1/email-security/test — the simulated Rspamd+ClamAV test bench
 * (M22 §2.8.4). MISSING-ROUTE BUG FIX: the GUI Test tab (and
 * emailSecurityApi.testMessage) posts here — previously 404. Validates with
 * the email test schema (from/to/subject/body/attachments/sizeKb), runs the
 * simulated pipeline via service.testMessage (which persists an EmailLog row)
 * and audits `email_security.policy.test` (section email_security, consistent
 * with the other email-security mutation routes).
 */

import { route } from "@/lib/api/handler";
import { emailTestSchema } from "@/lib/validators/email-security";
import { testMessage } from "../service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "email_security", bodySchema: emailTestSchema, section: "email_security" },
  async ({ auth, body }) => {
    const verdict = await testMessage(auth.tenantId, body);
    return {
      data: verdict,
      audit: {
        action: "email_security.policy.test",
        objectType: "email_policy",
        objectName: body.to,
        after: verdict,
      },
    };
  },
);

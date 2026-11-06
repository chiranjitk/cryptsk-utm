/**
 * Auth settings (M07 §5.2) — the login/password policy editor's store.
 * GET merges the canonical `auth/settings` SystemSetting (falls back to the
 * seed's granular keys); PUT writes the canonical key AND re-syncs the
 * granular keys (login flow + session tracker read those).
 */

import { route } from "@/lib/api/handler";
import { authSettingsSchema } from "@/lib/validators/identity";
import { getAuthSettings, putAuthSettings } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async () => {
  return { data: await getAuthSettings() };
});

export const PUT = route(
  { area: "identity", bodySchema: authSettingsSchema, section: "identity" },
  async ({ body }) => {
    const saved = await putAuthSettings(body);
    return {
      data: saved,
      audit: { action: "auth_settings.update", objectType: "auth_settings", after: saved },
    };
  },
);

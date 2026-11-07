/**
 * Static nDPI-style application catalog (M18 §2.2.3) — ~26 known apps with
 * name/category/description, served from catalog.ts. Read-only; drives the UI
 * autocomplete, the test card and rule appName validation.
 */

import { route } from "@/lib/api/handler";
import { APP_CATALOG, APP_CATEGORIES } from "../catalog";

export const dynamic = "force-dynamic";

export const GET = route({ area: "app_control" }, async () => {
  return { data: { apps: APP_CATALOG, categories: APP_CATEGORIES } };
});

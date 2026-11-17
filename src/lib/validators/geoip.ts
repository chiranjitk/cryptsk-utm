/**
 * GeoIP + FQDN refresher validators (spec §1.4) — edge schemas for the
 * /geoip/* and /objects/fqdn/refresh routes (API_STANDARDS §3: zod is the
 * single source of allowed values at the edge).
 */

import { z } from "zod";

/** POST /geoip/sources — load (parse + aggregate) an admin-provided CSV file. */
export const geoipSourceLoadSchema = z.object({
  name: z.string().min(1).max(64),
  filePath: z.string().min(1).max(1024),
});

/** POST /objects/fqdn/refresh — force bypasses the 60s freshness skip. */
export const fqdnRefreshBodySchema = z.object({
  force: z.boolean().optional(),
});

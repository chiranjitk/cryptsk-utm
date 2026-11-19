/**
 * GeoIP + FQDN refresher validators (spec §1.4) — edge schemas for the
 * /geoip/* and /objects/fqdn/refresh routes (API_STANDARDS §3: zod is the
 * single source of allowed values at the edge).
 */

import { z } from "zod";

/**
 * POST /geoip/sources — load (parse + aggregate) an admin-provided CSV file.
 * SECURITY: `filePath` is confined to the managed GeoIP root at the service
 * layer (GEOIP_ROOT: CONSOLE_GEOIP_DIR override, default <cwd>/db/geoip) —
 * relative or absolute paths that resolve inside the root are accepted; raw
 * `..` segments, paths that resolve outside the root and symlinks are
 * rejected with a 400 ("filePath must point inside the managed geoip
 * directory"). The schema only enforces the basic shape; containment is the
 * service's job (it needs the filesystem for the symlink check).
 */
export const geoipSourceLoadSchema = z.object({
  name: z.string().min(1).max(64),
  filePath: z.string().min(1).max(1024),
});

/** POST /objects/fqdn/refresh — force bypasses the 60s freshness skip. */
export const fqdnRefreshBodySchema = z.object({
  force: z.boolean().optional(),
});

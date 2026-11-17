/**
 * DNS tunnel-detection validators (Phase 3 §3.4) — zod is the single source
 * of allowed values at the edge (API_STANDARDS §3). Separate file keeps the
 * M06 validators/dns-dhcp.ts grammar untouched (additive Phase 3 module).
 */

import { z } from "zod";

export const tunnelFindingStatusSchema = z.enum(["open", "acknowledged", "resolved"]);
export const tunnelVerdictSchema = z.enum(["suspicious", "likely_tunnel"]);

/** POST /dns/tunnel-detection/run body — window ≥ step keeps windows sane
 *  (step > window would leave grid gaps the aggregation would honestly skip). */
export const tunnelRunSchema = z
  .object({
    windowMinutes: z.coerce.number().int().min(1, "windowMinutes must be 1-240").max(240, "windowMinutes must be 1-240").default(15),
    stepMinutes: z.coerce.number().int().min(1, "stepMinutes must be 1-60").max(60, "stepMinutes must be 1-60").default(5),
    lookbackMinutes: z.coerce.number().int().min(1, "lookbackMinutes must be 1-1440").max(1440, "lookbackMinutes must be 1-1440").default(60),
  })
  .refine((v) => v.windowMinutes >= v.stepMinutes, { message: "windowMinutes must be ≥ stepMinutes" });

/** GET /dns/tunnel-detection/findings query. */
export const tunnelFindingsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  status: tunnelFindingStatusSchema.optional(),
  verdict: tunnelVerdictSchema.optional(),
  q: z.string().trim().max(64).optional(),
});

/** PATCH /dns/tunnel-detection/findings/[id]/status body. */
export const tunnelFindingStatusUpdateSchema = z.object({
  status: tunnelFindingStatusSchema,
});

export type TunnelRunOptions = z.infer<typeof tunnelRunSchema>;
export type TunnelFindingsQuery = z.infer<typeof tunnelFindingsQuerySchema>;
export type TunnelFindingStatus = z.infer<typeof tunnelFindingStatusSchema>;
export type TunnelVerdictValue = z.infer<typeof tunnelVerdictSchema>;

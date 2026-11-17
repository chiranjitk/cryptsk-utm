/**
 * IoT device management zod schemas (Phase 3 §3.6) — query filters for the
 * /api/v1/iot/* routes. The device type enum is the locked M23 column value
 * set, imported from validators/identity-advanced.ts (never redefined).
 */

import { z } from "zod";
import { deviceTypeSchema } from "./identity-advanced";

export const iotInventoryQuerySchema = z.object({
  deviceType: deviceTypeSchema.optional(),
  vendor: z.string().max(64).optional(),
  /** String tri-state ("true"/"false") — booleans travel in query strings. */
  quarantined: z.enum(["true", "false"]).optional(),
  q: z.string().max(64).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(100),
});

export type IotInventoryQuery = z.infer<typeof iotInventoryQuerySchema>;

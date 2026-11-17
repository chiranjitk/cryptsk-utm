/**
 * Batch operations validators (spec §1.15) — zod is the single source of
 * allowed values at the edge (API_STANDARDS §3). The envelope schema only
 * checks the batch shell (method/path/body trios); per-operation resource
 * bodies are validated against the SAME resource schemas the REST routes use
 * (lib/api/batch.ts dispatch table), so a batch op can never accept a payload
 * the individual endpoints would reject.
 */

import { z } from "zod";

/** Hard cap per spec §1.15 — a batch may carry at most 20 operations. */
export const BATCH_MAX_OPERATIONS = 20;

export const batchMethodSchema = z.enum(["POST", "PUT", "DELETE"]);

export const batchOperationSchema = z
  .object({
    method: batchMethodSchema,
    /** Resource path exactly as on the REST surface, e.g. "/firewall-rules/12". */
    path: z
      .string()
      .min(1)
      .max(200)
      .regex(/^\//, "path must start with /"),
    /** JSON body — required for POST/PUT, ignored for DELETE. */
    body: z.record(z.string(), z.unknown()).nullish(),
  })
  .strict();

export const batchRequestSchema = z
  .object({
    operations: z.array(batchOperationSchema).min(1).max(BATCH_MAX_OPERATIONS),
  })
  .strict();

export type BatchMethod = z.infer<typeof batchMethodSchema>;
export type BatchOperation = z.infer<typeof batchOperationSchema>;
export type BatchRequest = z.infer<typeof batchRequestSchema>;

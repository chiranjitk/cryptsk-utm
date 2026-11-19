/**
 * Bounded open-JSON helpers (audit fix F-d — unbounded payload DoS).
 *
 * Open `z.record(z.unknown())` payloads accept arbitrarily large JSON bodies;
 * these refines cap the SERIALIZED size (JSON.stringify length) so a single
 * request cannot wedge SQLite writes or memory. The cap counts the JSON
 * text (UTF-16 code units ≈ bytes for ASCII payloads — an intentional
 * approximation, documented; multi-byte content can reach the cap faster,
 * which is the safe direction).
 */

import { z } from "zod";

/**
 * An open JSON record whose JSON.stringify stays ≤ maxBytes.
 * Used for template payloads, SOAR webhook/run payloads, incident details,
 * connector configs and site resource limits (see the per-module validators).
 */
export function boundedJson(maxBytes: number, label = "payload") {
  return z
    .record(z.string(), z.unknown())
    .refine((v) => JSON.stringify(v ?? {}).length <= maxBytes, {
      message: `${label} must serialize to ≤ ${maxBytes} bytes of JSON`,
    });
}

/** Alias kept for call-site readability where the schema is record-shaped. */
export const boundedRecord = boundedJson;

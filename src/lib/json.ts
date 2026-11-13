/**
 * JSON helpers for SQLite string-serialized JSON columns (ADR-005).
 * API consumers always send/receive real arrays/objects — these helpers are
 * the only place that touches the raw string form (API_STANDARDS §3).
 */

export function parseJson<T>(raw: string | null | undefined, fallback: T): T {
  if (raw === null || raw === undefined || raw === "") return fallback;
  try {
    const parsed = JSON.parse(raw) as T;
    return parsed;
  } catch {
    return fallback;
  }
}

export function stringifyJson(value: unknown): string {
  return JSON.stringify(value ?? null);
}

export function parseIdArray(raw: string | null | undefined): number[] {
  const v = parseJson<unknown>(raw, []);
  return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : [];
}

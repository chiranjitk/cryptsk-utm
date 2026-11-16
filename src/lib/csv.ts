/**
 * Client-side CSV export (frontend-only). Builds RFC-4180 CSV from rows the
 * view ALREADY has in memory (no additional fetches), then triggers a browser
 * download via Blob + a.download. A UTF-8 BOM is prepended so Excel opens
 * non-ASCII values correctly.
 */

export type CsvColumn = { key: string; label: string };

/** RFC-4180 cell: quote when the value contains comma, quote or newline. */
function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  let s: string;
  if (value instanceof Date) s = value.toISOString();
  else if (typeof value === "object") s = JSON.stringify(value);
  else s = String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * Download `rows` as `<filename>` (recommended: kebab name + YYYY-MM-DD).
 * `rows` may be any typed DTO array — values are looked up by `column.key`.
 */
export function downloadCsv(filename: string, columns: CsvColumn[], rows: readonly object[]): void {
  const lines = [
    columns.map((c) => csvCell(c.label)).join(","),
    ...rows.map((row) => columns.map((c) => csvCell((row as Record<string, unknown>)[c.key])).join(",")),
  ];
  const blob = new Blob(["\uFEFF" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a); // Firefox requires the anchor in the DOM
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** `2025-01-31` — date-stamped export filenames. */
export function csvDateStamp(): string {
  return new Date().toISOString().slice(0, 10);
}

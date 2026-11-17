/**
 * Dependency-free minimal PDF writer (spec §1.12 report formats: PDF).
 *
 * PURE module — node Buffer only, no npm packages, no font embedding:
 * PDF 1.4 with the Helvetica / Helvetica-Bold core 14 fonts (WinAnsiEncoding).
 * Capabilities: title + subtitle, section headings, text paragraphs (wrapped),
 * simple column tables (per-column x offsets — no char-count alignment), A4
 * page breaks (595x842 pt) and "Page i of n" footers. Output is a Buffer with
 * a correct xref table (byte offsets computed during assembly) and %%EOF.
 *
 * Content streams are stored UNCOMPRESSED on purpose: the writer stays
 * dependency-free (no zlib) and the bytes remain greppable for tests.
 */

// ── geometry (A4 portrait, PDF points) ──────────────────────────────────────

const PAGE_W = 595;
const PAGE_H = 842;
const MARGIN_X = 56;
const MARGIN_TOP = 64;
const FOOTER_Y = 36; // footer baseline — body text never enters this band
const BODY_BOTTOM = FOOTER_Y + 26; // lowest body baseline
/** First body baseline (PDF origin is bottom-left — MARGIN_TOP is measured from the top). */
const BODY_TOP = PAGE_H - MARGIN_TOP;

// ── text metrics (Helvetica AFM widths, units per 1000, chars 32..126) ──────

const WIDTHS = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // 32-47
  556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // 48-57  (0-9)
  278, 278, 584, 584, 584, 556, 1015, // 58-64
  667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, // 65-90 (A-Z)
  278, 278, 278, 469, 556, 333, // 91-96
  556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, // 97-122 (a-z)
  334, 260, 334, 584, // 123-126
];

function measure(text: string, size: number): number {
  let w = 0;
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    w += (code >= 32 && code <= 126 ? WIDTHS[code - 32] : 556) * size * 0.001;
  }
  return w;
}

// ── types ───────────────────────────────────────────────────────────────────

export interface PdfTableSpec {
  headers: string[];
  rows: string[][];
}

export interface PdfSectionSpec {
  heading: string;
  text?: string;
  table?: PdfTableSpec;
}

export interface PdfDocSpec {
  title: string;
  subtitle?: string;
  sections: PdfSectionSpec[];
}

// ── text encoding (WinAnsi-safe ASCII subset) ───────────────────────────────

/** Map arbitrary input onto printable ASCII (renderable by core fonts). */
function sanitize(text: string): string {
  let out = "";
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (ch === "\t") out += " ";
    else if (code >= 32 && code <= 126) out += ch;
    else if (ch !== "\n" && ch !== "\r") out += "?";
  }
  return out;
}

/** Escape a sanitized string for a PDF literal `( )` text object. */
function escPdf(text: string): string {
  return text.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

function pdfString(text: string): string {
  return escPdf(sanitize(text));
}

// ── layout ──────────────────────────────────────────────────────────────────

const BODY_FONT_SIZE = 9.5;
const BODY_LINE_H = 13;
const TABLE_FONT_SIZE = 9;
const TABLE_ROW_H = 14;
const HEADER_ROW_H = 17;

const COLOR_TEXT = "0.10 0.10 0.12 rg";
const COLOR_MUTED = "0.45 0.45 0.47 rg";
const COLOR_ACCENT = "0.725 0.110 0.110 rg"; // report brand red (headings)
const COLOR_RULE = "0.85 0.85 0.87 RG";

function fmt(n: number): string {
  return String(Math.round(n * 100) / 100);
}

function wrapText(text: string, size: number, maxWidth: number): string[] {
  const lines: string[] = [];
  for (const paragraph of sanitize(text).split("\n")) {
    const words = paragraph.split(/\s+/).filter(Boolean);
    if (words.length === 0) {
      lines.push("");
      continue;
    }
    let line = "";
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word;
      if (measure(candidate, size) <= maxWidth) {
        line = candidate;
        continue;
      }
      if (line) lines.push(line);
      if (measure(word, size) > maxWidth) {
        // single word wider than the column — hard-split at glyph level
        let chunk = "";
        for (const ch of word) {
          if (chunk && measure(chunk + ch, size) > maxWidth) {
            lines.push(chunk);
            chunk = ch;
          } else {
            chunk += ch;
          }
        }
        line = chunk;
      } else {
        line = word;
      }
    }
    if (line) lines.push(line);
  }
  return lines;
}

/** Truncate a table cell to the column width (ASCII ellipsis). */
function fitCell(text: string, size: number, maxWidth: number): string {
  const clean = sanitize(text);
  if (measure(clean, size) <= maxWidth) return clean;
  let cut = clean;
  while (cut.length > 1 && measure(`${cut}..`, size) > maxWidth) {
    cut = cut.slice(0, -1);
  }
  return `${cut.trimEnd()}..`;
}

interface Page {
  ops: string[];
}

class PdfCanvas {
  pages: Page[] = [];
  private cur: Page | null = null;
  y = BODY_TOP;

  private ensure(): Page {
    if (!this.cur) {
      this.cur = { ops: [] };
      this.pages.push(this.cur);
      this.y = BODY_TOP;
    }
    return this.cur;
  }

  /** Start a new page when `needed` points no longer fit above the footer band. */
  ensureSpace(needed: number): boolean {
    if (this.cur && this.y - needed >= BODY_BOTTOM) return false;
    this.cur = { ops: [] };
    this.pages.push(this.cur);
    this.y = BODY_TOP;
    return true;
  }

  text(str: string, x: number, yv: number, size: number, font: "F1" | "F2", color = COLOR_TEXT): void {
    const page = this.ensure();
    page.ops.push(`BT ${color} /${font} ${size} Tf 1 0 0 1 ${fmt(x)} ${fmt(yv)} Tm (${pdfString(str)}) Tj ET`);
  }

  hline(yv: number, x1: number, x2: number): void {
    const page = this.ensure();
    page.ops.push(`${COLOR_RULE} 0.8 w ${fmt(x1)} ${fmt(yv)} m ${fmt(x2)} ${fmt(yv)} l S`);
  }

  /** Wrapped paragraph at the cursor; returns the vertical space consumed. */
  paragraph(text: string, size = BODY_FONT_SIZE, lineH = BODY_LINE_H, x = MARGIN_X, width = PAGE_W - 2 * MARGIN_X, color = COLOR_TEXT, font: "F1" | "F2" = "F1"): number {
    const lines = wrapText(text, size, width);
    let used = 0;
    for (const line of lines) {
      this.ensureSpace(lineH);
      this.text(line, x, this.y, size, font, color);
      this.y -= lineH;
      used += lineH;
    }
    return used;
  }

  heading(text: string): void {
    this.ensureSpace(26);
    this.text(text, MARGIN_X, this.y, 12, "F2", COLOR_ACCENT);
    this.y -= 8;
    this.hline(this.y, MARGIN_X, PAGE_W - MARGIN_X);
    this.y -= 14;
  }

  table(spec: PdfTableSpec): void {
    const cols = Math.max(1, spec.headers.length);
    const usable = PAGE_W - 2 * MARGIN_X;
    const colW = usable / cols;
    const drawHeader = () => {
      this.ensureSpace(HEADER_ROW_H);
      spec.headers.forEach((h, i) => {
        this.text(fitCell(h, TABLE_FONT_SIZE, colW - 8), MARGIN_X + i * colW + 2, this.y, TABLE_FONT_SIZE, "F2");
      });
      this.y -= 6;
      this.hline(this.y, MARGIN_X, PAGE_W - MARGIN_X);
      this.y -= TABLE_ROW_H;
    };
    drawHeader();
    for (const row of spec.rows) {
      const broke = this.ensureSpace(TABLE_ROW_H);
      if (broke) drawHeader(); // repeat the header row after a page break
      const cells = spec.headers.map((_, i) => row[i] ?? "");
      cells.forEach((c, i) => {
        this.text(fitCell(c, TABLE_FONT_SIZE, colW - 8), MARGIN_X + i * colW + 2, this.y, TABLE_FONT_SIZE, "F1");
      });
      this.y -= TABLE_ROW_H;
    }
    this.y -= 6;
  }
}

/** Emit "Page i of n" footers onto every page (drawn last — body never overlaps the band). */
function appendFooters(pages: Page[], title: string): void {
  const n = pages.length;
  const footerTitle = fitCell(title, 8, (PAGE_W - 2 * MARGIN_X) * 0.7);
  pages.forEach((page, i) => {
    const label = `Page ${i + 1} of ${n}`;
    const x = (PAGE_W - measure(label, 8)) / 2;
    page.ops.push(`BT ${COLOR_MUTED} /F1 8 Tf 1 0 0 1 ${fmt(MARGIN_X)} ${FOOTER_Y} Tm (${pdfString(footerTitle)}) Tj ET`);
    page.ops.push(`BT ${COLOR_MUTED} /F1 8 Tf 1 0 0 1 ${fmt(x)} ${FOOTER_Y} Tm (${pdfString(label)}) Tj ET`);
  });
}

// ── document assembly ───────────────────────────────────────────────────────

export function renderPdf(doc: PdfDocSpec): Buffer {
  const canvas = new PdfCanvas();

  // header block: title, subtitle, rule
  canvas.ensureSpace(40);
  canvas.text(doc.title, MARGIN_X, canvas.y, 19, "F2", COLOR_ACCENT);
  canvas.y -= 24;
  if (doc.subtitle) {
    for (const line of wrapText(doc.subtitle, 9.5, PAGE_W - 2 * MARGIN_X)) {
      canvas.text(line, MARGIN_X, canvas.y, 9.5, "F1", COLOR_MUTED);
      canvas.y -= 13;
    }
    canvas.y -= 2;
  }
  canvas.hline(canvas.y, MARGIN_X, PAGE_W - MARGIN_X);
  canvas.y -= 18;

  for (const section of doc.sections) {
    canvas.ensureSpace(30);
    canvas.heading(section.heading);
    if (section.text !== undefined && section.text !== "") {
      canvas.paragraph(section.text);
      canvas.y -= 6;
    }
    if (section.table) canvas.table(section.table);
    else canvas.y -= 4;
  }

  appendFooters(canvas.pages, doc.title);

  // ── object assembly (1 Catalog, 2 Pages, 3 F1, 4 F2, 5 Info, then page/content pairs) ──
  const pageCount = canvas.pages.length;
  const pageObjIds = canvas.pages.map((_, i) => 6 + i * 2);

  const kids = pageObjIds.map((id) => `${id} 0 R`).join(" ");
  const catalogObj = `<< /Type /Catalog /Pages 2 0 R >>`;
  const pagesObj = `<< /Type /Pages /Kids [${kids}] /Count ${pageCount} >>`;
  const fontRegularObj = `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`;
  const fontBoldObj = `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`;
  const now = new Date();
  const pad = (v: number) => String(v).padStart(2, "0");
  const stamp = `D:${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;
  const infoObj = `<< /Title (${pdfString(doc.title)}) /Producer (Cryptsk UTM Console) /CreationDate (${stamp}) >>`;

  const serialized: Array<{ id: number; body: string }> = [];
  const addObj = (body: string): number => {
    serialized.push({ id: serialized.length + 1, body });
    return serialized.length;
  };
  addObj(catalogObj);
  addObj(pagesObj);
  addObj(fontRegularObj);
  addObj(fontBoldObj);
  addObj(infoObj);
  canvas.pages.forEach((page, i) => {
    const contentId = 7 + i * 2;
    addObj(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentId} 0 R >>`,
    );
    const stream = page.ops.join("\n");
    addObj(`<< /Length ${Buffer.byteLength(stream, "latin1")} >>\nstream\n${stream}\nendstream`);
  });

  // ── serialize with exact xref offsets ──
  const chunks: Buffer[] = [];
  let offset = 0;
  const offsets: number[] = [];

  const writeRaw = (buf: Buffer): void => {
    chunks.push(buf);
    offset += buf.length;
  };
  const writeStr = (s: string): void => writeRaw(Buffer.from(s, "latin1"));

  // header + recommended binary comment line
  writeRaw(Buffer.from("%PDF-1.4\n", "latin1"));
  writeRaw(Buffer.from([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]));

  for (const obj of serialized) {
    offsets[obj.id] = offset;
    writeStr(`${obj.id} 0 obj\n${obj.body}\nendobj\n`);
  }

  const xrefOffset = offset;
  const size = serialized.length + 1;
  let xref = `xref\n0 ${size}\n`;
  xref += `0000000000 65535 f \n`;
  for (let id = 1; id < size; id++) {
    xref += `${String(offsets[id] ?? 0).padStart(10, "0")} 00000 n \n`;
  }
  xref += `trailer\n<< /Size ${size} /Root 1 0 R /Info 5 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  writeStr(xref);

  return Buffer.concat(chunks);
}

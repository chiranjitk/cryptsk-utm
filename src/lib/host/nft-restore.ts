/**
 * Table-scoped nftables restore points (audit fix M3).
 *
 * HISTORY: module backups used to snapshot the WHOLE ruleset behind a
 * `flush ruleset` prologue. The generated APPLY files are correctly
 * table-scoped (`destroy table inet <own>` only), but the RESTORE path
 * replayed the full-ruleset backup — silently destroying every table created
 * after the backup (another module's apply, a re-created fail2ban table) and
 * not re-creating it. A firewall rollback took out `utm_ti_block` and
 * `utm_appctl` enforcement in one shot.
 *
 * FIX: every module's backup now carries ONLY that module's table, in a
 * restore file whose prologue declares the table if missing (so `flush table`
 * can never abort the netlink batch) and flushes ONLY it before merging the
 * pre-apply dump back. Restore therefore touches exactly one table — the one
 * the module's apply actually managed. Other modules' tables (and fail2ban's)
 * were never modified by the apply, so they need no restore.
 *
 * Pure functions only — no db/fs/exec (unit-testable, mirrors nft-gen style).
 */

/** Brace-aware extraction of `table inet <name> { ... }` from a full `nft
 *  list ruleset` dump. Comment lines (`# …`) are ignored during the scan so a
 *  brace inside a comment cannot desync the depth counter. Returns null when
 *  the table is absent from the dump. */
export function extractTableBlock(ruleset: string, tableName: string): string | null {
  const re = new RegExp(`^table inet ${tableName}\\s*\\{`, "m");
  const m = ruleset.match(re);
  if (!m || m.index === undefined) return null;
  let depth = 0;
  let inComment = false;
  const start = m.index;
  for (let i = start; i < ruleset.length; i++) {
    const c = ruleset[i];
    if (inComment) {
      if (c === "\n") inComment = false;
      continue;
    }
    if (c === "#") {
      inComment = true;
      continue;
    }
    if (c === "{") depth += 1;
    else if (c === "}") {
      depth -= 1;
      if (depth === 0) return ruleset.slice(start, i + 1);
    }
  }
  return null; // malformed dump — caller treats as "absent" and refuses
}

/** Compose a table-scoped restore file from a full-ruleset dump. */
export function composeTableScopedBackup(liveRuleset: string, tableName: string): string {
  const block = extractTableBlock(liveRuleset, tableName);
  const body = block ?? `# ${tableName} absent at backup time — restore leaves an empty table`;
  return `#!/usr/sbin/nft -f\ntable inet ${tableName} {}\nflush table inet ${tableName}\n\n${body}\n`;
}

/** A file is a faithful table-scoped restore point ONLY with the full prologue. */
export function isTableScopedRestore(content: string, tableName: string): boolean {
  return content.startsWith(`#!/usr/sbin/nft -f\ntable inet ${tableName} {}\nflush table inet ${tableName}\n`);
}

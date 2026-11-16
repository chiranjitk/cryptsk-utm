"use client";

/**
 * Keyboard-shortcuts help dialog (Feature round 3).
 *   • Opens via "?" (when no input/textarea/select is focused), from the
 *     command-palette footer ("View shortcuts" → 'open-shortcuts' CustomEvent)
 *     and programmatically via openShortcutsDialog().
 *   • useGoToShortcuts hosts the g-then-key sequences (g d → dashboard,
 *     g f → firewall rules, g l → firewall logs) plus the "?" opener. It is
 *     mounted in app-shell with enabled=shellMounted so it never fires on the
 *     login/setup screens. Escape always cancels a pending "g".
 * Open state uses the same module-level external-store pattern as the command
 * palette — hydration-safe, no provider, no context ceremony.
 */

import { useEffect, useRef, useSyncExternalStore } from "react";
import * as Icons from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

// ── tiny external store for the open state ──────────────────────────────────
let shortcutsOpen = false;
const shortcutsListeners = new Set<() => void>();

function setShortcutsOpen(next: boolean): void {
  if (shortcutsOpen === next) return;
  shortcutsOpen = next;
  shortcutsListeners.forEach((notify) => notify());
}

export function openShortcutsDialog(): void {
  setShortcutsOpen(true);
}

const subscribeShortcuts = (onChange: () => void) => {
  shortcutsListeners.add(onChange);
  return () => {
    shortcutsListeners.delete(onChange);
  };
};
const shortcutsSnapshot = () => shortcutsOpen;
const shortcutsServerSnapshot = () => false;

/** [open, setOpen] — external-store backed, hydration-safe. */
export function useShortcutsDialog(): [boolean, (open: boolean) => void] {
  const open = useSyncExternalStore(subscribeShortcuts, shortcutsSnapshot, shortcutsServerSnapshot);
  return [open, setShortcutsOpen];
}

function Kbd({ children, wide }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <kbd
      className={cnk(
        "inline-flex h-6 select-none items-center justify-center rounded-md border border-border bg-muted px-1.5 font-mono text-[11px] font-semibold text-muted-foreground shadow-xs",
        wide ? "min-w-8" : "min-w-6",
      )}
    >
      {children}
    </kbd>
  );
}

// tiny local classnames join (keeps this file dependency-light)
function cnk(...parts: Array<string | false>): string {
  return parts.filter(Boolean).join(" ");
}

const SHORTCUTS: Array<{ keys: string[]; label: string }> = [
  { keys: ["⌘K"], label: "Command palette (Ctrl+K on Windows/Linux)" },
  { keys: ["?"], label: "Shortcuts help (this dialog)" },
  { keys: ["g", "d"], label: "Go to Dashboard" },
  { keys: ["g", "f"], label: "Go to Firewall Rules" },
  { keys: ["g", "l"], label: "Go to Firewall Logs" },
  { keys: ["esc"], label: "Close the current dialog" },
];

export function ShortcutsDialog() {
  const [open, setOpen] = useShortcutsDialog();

  // command-palette footer → "View shortcuts" dispatches 'open-shortcuts'
  useEffect(() => {
    const onOpen = () => openShortcutsDialog();
    window.addEventListener("open-shortcuts", onOpen);
    return () => window.removeEventListener("open-shortcuts", onOpen);
  }, []);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icons.Keyboard className="h-4.5 w-4.5" />
            Keyboard shortcuts
          </DialogTitle>
          <DialogDescription>Drive the console without leaving the keyboard.</DialogDescription>
        </DialogHeader>
        <ul className="grid gap-1.5">
          {SHORTCUTS.map((s) => (
            <li
              key={s.label}
              className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/40 px-3 py-2"
            >
              <span className="text-sm text-foreground">{s.label}</span>
              <span className="flex shrink-0 items-center gap-1">
                {s.keys.map((k, i) => (
                  <Kbd key={`${s.label}-${i}`} wide={k.length > 1}>
                    {k}
                  </Kbd>
                ))}
              </span>
            </li>
          ))}
        </ul>
        <p className="text-[11px] text-muted-foreground">
          Sequences: press <Kbd>g</Kbd> then the key within ~1.2&nbsp;s. Ignore while typing in a field.
        </p>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Global key handling for the shell: "?" opens the help dialog, g-then-key
 * navigates. Listens on window but no-ops while typing in any field or when
 * a modifier is held (keeps ⌘/Ctrl+K and browser combos untouched).
 */
export function useGoToShortcuts(options: { enabled: boolean; onNavigate: (path: string) => void }): void {
  // handlers kept in a ref via effect so re-renders never rebind the listener
  // (same pattern as useRealtime in lib/realtime.ts)
  const ref = useRef(options);
  useEffect(() => {
    ref.current = options;
  });

  useEffect(() => {
    const GOTO: Record<string, string> = { d: "/dashboard", f: "/firewall/rules", l: "/logs/firewall" };
    let pendingG = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const onKey = (e: KeyboardEvent) => {
      if (!ref.current.enabled) return;
      const t = e.target as HTMLElement | null;
      const typing =
        !!t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;

      if (e.key === "Escape") {
        pendingG = false;
        if (timer) clearTimeout(timer);
        return;
      }
      if (pendingG) {
        const path = GOTO[e.key.toLowerCase()];
        pendingG = false;
        if (timer) clearTimeout(timer);
        if (path) {
          e.preventDefault();
          ref.current.onNavigate(path);
        }
        return;
      }
      if (e.key === "g" || e.key === "G") {
        pendingG = true;
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
          pendingG = false;
        }, 1200);
        return;
      }
      if (e.key === "?") {
        e.preventDefault();
        openShortcutsDialog();
      }
    };

    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      if (timer) clearTimeout(timer);
    };
  }, []);
}

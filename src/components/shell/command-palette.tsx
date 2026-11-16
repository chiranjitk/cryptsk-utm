"use client";

/**
 * Command palette — ⌘/Ctrl+K (T17 dk-bar companion). Extracted from app-shell
 * so any surface (topbar button, global ⌘K handler, shortcuts dialog footer)
 * can drive it through one tiny module store.
 *
 * Open state is lifted OUT of the component tree into a module-level external
 * store (same hydration-safe pattern as useRealtimeStatus / the ⌘K platform
 * hint) and exposed via useCommandPalette. Contents:
 *   • every console view from NAV_GROUPS/VIEWS — selecting sets the location
 *     hash exactly like the dock does (app-shell's navigateTo)
 *   • Actions group: Go to Dashboard · Toggle dark/light theme (next-themes)
 *     · Sign out (reuses the shell's logout callback)
 *   • footer: keyboard hints + "View shortcuts" (opens the shortcuts dialog
 *     via the 'open-shortcuts' CustomEvent — no circular import)
 * Keyboard: ⌘/Ctrl+K toggles (bound in app-shell while the shell is mounted),
 * Escape closes (Radix Dialog), arrows/Enter are cmdk defaults.
 */

import { useSyncExternalStore } from "react";
import { useTheme } from "next-themes";
import * as Icons from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { NAV_GROUPS, viewFor } from "./nav-config";

// ── tiny external store for the open state ──────────────────────────────────
let paletteOpen = false;
const paletteListeners = new Set<() => void>();

function setPaletteOpen(next: boolean): void {
  if (paletteOpen === next) return;
  paletteOpen = next;
  paletteListeners.forEach((notify) => notify());
}

export function openCommandPalette(): void {
  setPaletteOpen(true);
}

export function closeCommandPalette(): void {
  setPaletteOpen(false);
}

export function toggleCommandPalette(): void {
  setPaletteOpen(!paletteOpen);
}

const subscribePalette = (onChange: () => void) => {
  paletteListeners.add(onChange);
  return () => {
    paletteListeners.delete(onChange);
  };
};
const paletteSnapshot = () => paletteOpen;
const paletteServerSnapshot = () => false;

/** [open, setOpen] — external-store backed, hydration-safe. */
export function useCommandPalette(): [boolean, (open: boolean) => void] {
  const open = useSyncExternalStore(subscribePalette, paletteSnapshot, paletteServerSnapshot);
  return [open, setPaletteOpen];
}

// lucide icon resolver — mirrors the shell's private Icon helper
function Icon({ name, className }: { name: string; className?: string }) {
  const C = (Icons as unknown as Record<string, React.ComponentType<{ className?: string }>>)[name] ?? Icons.Circle;
  return <C className={className} />;
}

function FooterKbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="pointer-events-none inline-flex h-4.5 select-none items-center gap-0.5 rounded border border-border bg-muted px-1 font-mono text-[10px] font-medium text-muted-foreground">
      {children}
    </kbd>
  );
}

export function CommandPalette({ onNavigate, onLogout }: { onNavigate: (path: string) => void; onLogout: () => void }) {
  const [open, setOpen] = useCommandPalette();
  const { resolvedTheme, setTheme } = useTheme();

  return (
    <CommandDialog open={open} onOpenChange={setOpen} title="Command palette" description="Search views and run actions">
      <CommandInput placeholder="Search views and commands…" />
      <CommandList>
        <CommandEmpty>No matching view or command.</CommandEmpty>
        {NAV_GROUPS.map((group) => (
          <CommandGroup key={group.label} heading={group.label}>
            {group.paths.map((p) => {
              const paletteView = viewFor(p)!;
              return (
                <CommandItem key={p} value={`${paletteView.title} ${p}`} onSelect={() => onNavigate(p)}>
                  <Icon name={paletteView.icon} className="h-4 w-4 shrink-0" />
                  <span className="truncate">{paletteView.title}</span>
                </CommandItem>
              );
            })}
          </CommandGroup>
        ))}
        <CommandSeparator />
        <CommandGroup heading="Actions">
          <CommandItem value="Go to Dashboard home" onSelect={() => onNavigate("/dashboard")}>
            <Icons.LayoutDashboard className="h-4 w-4 shrink-0" />
            <span>Go to Dashboard</span>
          </CommandItem>
          <CommandItem
            value="Toggle dark light theme"
            onSelect={() => {
              setTheme(resolvedTheme === "dark" ? "light" : "dark");
              setOpen(false);
            }}
          >
            {resolvedTheme === "dark" ? <Icons.Sun className="h-4 w-4 shrink-0" /> : <Icons.Moon className="h-4 w-4 shrink-0" />}
            <span>Toggle dark / light theme</span>
          </CommandItem>
          <CommandItem
            value="Sign out logout"
            className="text-rose-600 focus:text-rose-600 dark:text-rose-400"
            onSelect={() => {
              setOpen(false);
              onLogout();
            }}
          >
            <Icons.LogOut className="h-4 w-4 shrink-0" />
            <span>Sign out</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
      {/* footer — keyboard parity hints + shortcuts help entry point */}
      <div className="flex items-center gap-3 border-t px-3 py-2 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1">
          <FooterKbd>↑</FooterKbd>
          <FooterKbd>↓</FooterKbd> navigate
        </span>
        <span className="flex items-center gap-1">
          <FooterKbd>↵</FooterKbd> select
        </span>
        <span className="flex items-center gap-1">
          <FooterKbd>esc</FooterKbd> close
        </span>
        <button
          type="button"
          className="ml-auto flex items-center gap-1 rounded px-1 py-0.5 font-medium transition-colors hover:text-foreground"
          onClick={() => {
            setOpen(false);
            window.dispatchEvent(new CustomEvent("open-shortcuts"));
          }}
        >
          View shortcuts
          <FooterKbd>?</FooterKbd>
        </button>
      </div>
    </CommandDialog>
  );
}

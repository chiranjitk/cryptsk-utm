"use client";

/**
 * Shared UI atoms for the M03 firewall views — composed only from
 * src/components/ui primitives. Blue theme per UI_DESIGN_SYSTEM §2 (ADR-019):
 * allow = blue soft, deny = rose solid, drop = rose outline, reject = orange
 * soft; emerald is reserved for true health/active badges only.
 */

import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast as showToast } from "@/hooks/use-toast";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import { useRealtime } from "@/lib/realtime";
import { referencedByOf, type FwAction, type NatType, type RefRow } from "./fw-api";

// ── toasts (use-toast radix toaster — wired in providers.tsx) ───────────────

export function toastOk(title: string, description?: string) {
  showToast({ title, description });
}

export function toastErr(err: unknown, fallback: string) {
  const message = err instanceof Error ? err.message : fallback;
  showToast({ variant: "destructive", title: fallback, description: message });
}

// ── realtime invalidation (scoped per-view, config channel) ─────────────────

export function useFwConfigInvalidation(): void {
  const queryClient = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "firewall") void queryClient.invalidateQueries({ queryKey: ["firewall"] });
      if (c.section === "nat") void queryClient.invalidateQueries({ queryKey: ["nat"] });
    },
  });
}

// ── action badge (UI_DESIGN_SYSTEM §2.3 — canonical recipes) ────────────────

const ACTION_BADGE: Record<FwAction, { cls: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  allow: {
    cls: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
    icon: Icons.ShieldCheck,
    label: "allow",
  },
  deny: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.Ban, label: "deny" },
  drop: { cls: "border-rose-600/60 bg-transparent text-rose-500", icon: Icons.CircleX, label: "drop" },
  reject: {
    cls: "border-orange-500/40 bg-orange-500/10 text-orange-500",
    icon: Icons.CircleMinus,
    label: "reject",
  },
};

export function ActionBadge({ action, className }: { action: FwAction; className?: string }) {
  const def = ACTION_BADGE[action] ?? ACTION_BADGE.deny;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, className)}>
      <Icon className="h-3 w-3" />
      {def.label}
    </Badge>
  );
}

export function NatTypeChip({ type }: { type: NatType }) {
  return (
    <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-zinc-600 uppercase dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      {type}
    </Badge>
  );
}

// ── confirm + conflict dialogs ──────────────────────────────────────────────

export function ConfirmDialog(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel?: string;
  loading?: boolean;
  onConfirm: () => void;
}) {
  return (
    <AlertDialog open={props.open} onOpenChange={props.onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{props.title}</AlertDialogTitle>
          <AlertDialogDescription>{props.description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={props.loading}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            className="bg-rose-600 text-white hover:bg-rose-700 focus-visible:ring-rose-600"
            disabled={props.loading}
            onClick={(e) => {
              e.preventDefault();
              props.onConfirm();
            }}
          >
            {props.loading ? "Deleting…" : (props.confirmLabel ?? "Delete")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** 409 CONFLICT — renders details.referencedBy rule names with a link to #/firewall/rules. */
export function ConflictDialog(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  message: string;
  error: unknown;
}) {
  const refs: RefRow[] = referencedByOf(props.error);
  const hasNatRef = refs.some((r) => r.ruleType === "nat");
  return (
    <AlertDialog open={props.open} onOpenChange={props.onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <Icons.TriangleAlert className="h-5 w-5 text-amber-500" />
            {props.title}
          </AlertDialogTitle>
          <AlertDialogDescription>{props.message}</AlertDialogDescription>
        </AlertDialogHeader>
        {refs.length > 0 && (
          <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <p className="mb-2 text-xs font-medium text-zinc-500">Referenced by these rules:</p>
            <div className="flex flex-wrap gap-1.5">
              {refs.map((r, i) => (
                <a key={`${r.ruleName}-${i}`} href={r.ruleType === "nat" ? "#/firewall/nat" : "#/firewall/rules"} className="inline-flex">
                  <Badge
                    variant="outline"
                    className="border-zinc-600/40 bg-zinc-600/10 text-zinc-700 hover:bg-zinc-600/20 dark:text-zinc-500"
                  >
                    <Icons.ShieldCheck className="mr-1 h-3 w-3" />
                    {r.ruleName}
                    <span className="ml-1 text-[10px] uppercase text-zinc-400">{r.ruleType}</span>
                  </Badge>
                </a>
              ))}
            </div>
          </div>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Close</AlertDialogCancel>
          <AlertDialogAction
            className="bg-zinc-700 text-white hover:bg-zinc-800 focus-visible:ring-zinc-700"
            onClick={(e) => {
              e.preventDefault();
              if (hasNatRef) {
                window.location.hash = "#/firewall/nat";
              } else {
                window.location.hash = "#/firewall/rules";
              }
              props.onOpenChange(false);
            }}
          >
            {hasNatRef ? "Open NAT rules" : "Open firewall rules"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

// ── table states ────────────────────────────────────────────────────────────

export function TableSkeleton({ rows = 6, cols = 7 }: { rows?: number; cols?: number }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {Array.from({ length: cols }).map((_, i) => (
            <TableHead key={i}>
              <Skeleton className="h-3.5 w-16" />
            </TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {Array.from({ length: rows }).map((_, r) => (
          <TableRow key={r}>
            {Array.from({ length: cols }).map((_, c) => (
              <TableCell key={c}>
                <Skeleton className="h-4 w-full max-w-24" />
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function EmptyBlock(props: {
  icon: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-zinc-500/10 text-zinc-600 dark:text-zinc-400">
        {props.icon}
      </div>
      <p className="text-sm font-medium">{props.title}</p>
      {props.description ? <p className="max-w-md text-xs text-zinc-500">{props.description}</p> : null}
      {props.action ? <div className="mt-2">{props.action}</div> : null}
    </div>
  );
}

export function QueryError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const message = error instanceof Error ? error.message : "Request failed";
  return (
    <Alert variant="destructive" className="border-rose-600/40 bg-rose-600/5">
      <Icons.TriangleAlert className="h-4 w-4" />
      <AlertTitle>Load failed</AlertTitle>
      <AlertDescription className="flex items-center justify-between gap-2">
        <span>{message}</span>
        <Button size="sm" variant="outline" onClick={onRetry}>
          Retry
        </Button>
      </AlertDescription>
    </Alert>
  );
}

// ── small form atoms ────────────────────────────────────────────────────────

export function FieldLabel({ children, hint }: { children: React.ReactNode; hint?: string }) {
  return (
    <div className="mb-1.5 flex items-baseline justify-between gap-2">
      <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">{children}</span>
      {hint ? <span className="text-[11px] text-zinc-400">{hint}</span> : null}
    </div>
  );
}

/** Toggleable chip row for multi-select of zones (empty selection = any). */
export function MultiChips({
  options,
  selected,
  onToggle,
  emptyLabel = "any",
}: {
  options: Array<{ id: number; label: string }>;
  selected: number[];
  onToggle: (id: number) => void;
  emptyLabel?: string;
}) {
  if (options.length === 0) return <p className="text-xs text-zinc-400">No options yet</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => {
        const active = selected.includes(o.id);
        return (
          <button
            key={o.id}
            type="button"
            onClick={() => onToggle(o.id)}
            aria-pressed={active}
            className={cn(
              "rounded-full border px-2.5 py-1 text-xs transition-colors",
              active
                ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
            )}
          >
            {o.label}
          </button>
        );
      })}
      {selected.length === 0 ? <span className="self-center text-xs text-zinc-400">({emptyLabel})</span> : null}
    </div>
  );
}

/** Popover multi-select used for Applications (nDPI labels) and Users. */
export function PopoverMulti({
  options,
  selected,
  onChange,
  placeholder,
  triggerLabel,
  icon,
}: {
  options: Array<{ id: string; label: string; sub?: string }>;
  selected: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  triggerLabel: string;
  icon?: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" size="sm" className="gap-1.5">
          {icon}
          {triggerLabel}
          {selected.length > 0 && (
            <Badge variant="outline" className="ml-1 border-zinc-500/30 bg-zinc-500/10 px-1.5 text-[10px] text-zinc-600 dark:text-zinc-300">
              {selected.length}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-64 p-0" align="start">
        <Command>
          <CommandInput placeholder={placeholder ?? "Search…"} />
          <CommandList>
            <CommandEmpty>No matches.</CommandEmpty>
            <CommandGroup>
              {options.map((o) => {
                const active = selected.includes(o.id);
                return (
                  <CommandItem
                    key={o.id}
                    value={o.label}
                    onSelect={() => onChange(active ? selected.filter((s) => s !== o.id) : [...selected, o.id])}
                  >
                    <Icons.Check className={cn("mr-1.5 h-4 w-4", active ? "text-zinc-500 dark:text-zinc-400" : "opacity-0")} />
                    <span className="text-sm">{o.label}</span>
                    {o.sub ? <span className="ml-auto text-[10px] text-zinc-400">{o.sub}</span> : null}
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

/**
 * ObjectPicker — mixed object+group semantics (ER_DIAGRAM §3): selecting a
 * group stores the GROUP id. Selected ids render as removable chips where
 * groups show `NAME +N`.
 */
export function ObjectPicker(props: {
  kind: "address" | "service";
  objects: Array<{ id: number; name: string; sub: string }>;
  groups: Array<{ id: number; name: string; memberCount: number }>;
  value: number[];
  onChange: (next: number[]) => void;
  triggerLabel: string;
}) {
  const [open, setOpen] = useState(false);
  const byId = useMemo(() => {
    const m = new Map<number, { name: string; sub: string; isGroup: boolean; memberCount: number }>();
    props.objects.forEach((o) => m.set(o.id, { name: o.name, sub: o.sub, isGroup: false, memberCount: 0 }));
    props.groups.forEach((g) => m.set(g.id, { name: g.name, sub: `group of ${g.memberCount}`, isGroup: true, memberCount: g.memberCount }));
    return m;
  }, [props.objects, props.groups]);

  return (
    <div className="space-y-1.5">
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button type="button" variant="outline" size="sm" className="gap-1.5">
            <Icons.ListPlus className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            {props.triggerLabel}
            {props.value.length > 0 && (
              <Badge variant="outline" className="ml-1 border-zinc-500/30 bg-zinc-500/10 px-1.5 text-[10px] text-zinc-600 dark:text-zinc-300">
                {props.value.length}
              </Badge>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-72 p-0" align="start">
          <Command>
            <CommandInput placeholder={`Filter ${props.kind} objects…`} />
            <CommandList>
              <CommandEmpty>No matches.</CommandEmpty>
              {props.groups.length > 0 && (
                <CommandGroup heading="Groups">
                  {props.groups.map((g) => {
                    const active = props.value.includes(g.id);
                    return (
                      <CommandItem
                        key={`g-${g.id}`}
                        value={`${g.name} group`}
                        onSelect={() =>
                          props.onChange(active ? props.value.filter((v) => v !== g.id) : [...props.value, g.id])
                        }
                      >
                        <Icons.Check className={cn("mr-1.5 h-4 w-4", active ? "text-zinc-500 dark:text-zinc-400" : "opacity-0")} />
                        <Icons.FolderOpen className="mr-1 h-3.5 w-3.5 text-zinc-400" />
                        <span className="text-sm font-medium">{g.name}</span>
                        <span className="ml-auto text-[10px] text-zinc-400">+{g.memberCount}</span>
                      </CommandItem>
                    );
                  })}
                </CommandGroup>
              )}
              <CommandGroup heading="Objects">
                {props.objects.map((o) => {
                  const active = props.value.includes(o.id);
                  return (
                    <CommandItem
                      key={`o-${o.id}`}
                      value={`${o.name} ${o.sub}`}
                      onSelect={() =>
                        props.onChange(active ? props.value.filter((v) => v !== o.id) : [...props.value, o.id])
                      }
                    >
                      <Icons.Check className={cn("mr-1.5 h-4 w-4", active ? "text-zinc-500 dark:text-zinc-400" : "opacity-0")} />
                      <span className="text-sm">{o.name}</span>
                      <span className="ml-auto max-w-28 truncate font-mono text-[10px] text-zinc-400">{o.sub}</span>
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>

      {props.value.length > 0 && (
        <div className="flex flex-wrap gap-1">
          <TooltipProvider delayDuration={150}>
            {props.value.map((id) => {
              const info = byId.get(id);
              return (
                <Tooltip key={id}>
                  <TooltipTrigger asChild>
                    <Badge variant="outline" className="gap-1 border-zinc-300 pr-1 dark:border-zinc-700">
                      {info?.isGroup ? <Icons.FolderOpen className="h-3 w-3 text-zinc-400" /> : null}
                      {info ? `${info.name}${info.isGroup ? ` +${info.memberCount}` : ""}` : `#${id}`}
                      <button
                        type="button"
                        aria-label={`Remove ${info?.name ?? id}`}
                        className="ml-0.5 rounded-sm p-0.5 hover:bg-zinc-200 dark:hover:bg-zinc-700"
                        onClick={() => props.onChange(props.value.filter((v) => v !== id))}
                      >
                        <Icons.X className="h-3 w-3" />
                      </button>
                    </Badge>
                  </TooltipTrigger>
                  {info ? <TooltipContent className="text-xs">{info.sub}</TooltipContent> : null}
                </Tooltip>
              );
            })}
          </TooltipProvider>
        </div>
      )}
    </div>
  );
}

/** Transfer list for group editors (two columns, click to move, search). */
export function TransferList({
  all,
  value,
  onChange,
  availableTitle,
  chosenTitle,
}: {
  all: Array<{ id: number; label: string; sub?: string }>;
  value: number[];
  onChange: (next: number[]) => void;
  availableTitle: string;
  chosenTitle: string;
}) {
  const [availQ, setAvailQ] = useState("");
  const [chosenQ, setChosenQ] = useState("");

  const chosen = useMemo(() => all.filter((a) => value.includes(a.id)), [all, value]);
  const available = useMemo(() => all.filter((a) => !value.includes(a.id)), [all, value]);
  const availFiltered = available.filter((a) => a.label.toLowerCase().includes(availQ.toLowerCase()));
  const chosenFiltered = chosen.filter((a) => a.label.toLowerCase().includes(chosenQ.toLowerCase()));

  const move = (id: number, dir: "in" | "out") =>
    onChange(dir === "in" ? [...value, id] : value.filter((v) => v !== id));

  return (
    <div className="grid grid-cols-2 gap-2">
      {[
        { title: availableTitle, items: availFiltered, q: availQ, setQ: setAvailQ, dir: "in" as const, empty: "Nothing available" },
        { title: chosenTitle, items: chosenFiltered, q: chosenQ, setQ: setChosenQ, dir: "out" as const, empty: "No members yet" },
      ].map((col) => (
        <div key={col.title} className="rounded-lg border border-zinc-200 dark:border-zinc-800">
          <p className="border-b border-zinc-200 px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-zinc-500 dark:border-zinc-800">
            {col.title} ({col.items.length})
          </p>
          <div className="p-1.5">
            <Input
              value={col.q}
              onChange={(e) => col.setQ(e.target.value)}
              placeholder="Search…"
              className="mb-1.5 h-7 text-xs"
            />
            <ScrollArea className="h-40">
              <div className="space-y-0.5 pr-2">
                {col.items.length === 0 ? (
                  <p className="px-1 py-3 text-center text-xs text-zinc-400">{col.empty}</p>
                ) : (
                  col.items.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => move(item.id, col.dir)}
                      className="flex w-full items-center justify-between gap-1 rounded-md px-2 py-1.5 text-left text-xs hover:bg-zinc-500/10"
                    >
                      <span className="truncate font-medium">{item.label}</span>
                      <span className="shrink-0 font-mono text-[10px] text-zinc-400">{item.sub}</span>
                    </button>
                  ))
                )}
              </div>
            </ScrollArea>
          </div>
        </div>
      ))}
    </div>
  );
}

/** Section heading inside editor dialogs. */
export function EditorSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">{title}</h3>
      {children}
    </section>
  );
}

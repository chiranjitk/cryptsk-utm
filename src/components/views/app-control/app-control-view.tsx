"use client";

/**
 * #/web/app-control — Application Control (M18, spec 2.2). Master-detail
 * layout: policy cards (left) with default/unknown-app actions + toggles,
 * per-policy nDPI app rules table (inline action/bandwidth/direction editing,
 * user-group scoping), a simulated "Test app" decision card and a 24h stats
 * strip + recent decision log table. Theme: allow = blue, block = rose,
 * limited = amber (blue-600 enterprise).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DIRECTIONS,
  LOG_ACTIONS,
  POLICY_ACTIONS,
  RULE_ACTIONS,
  UNKNOWN_APP_ACTIONS,
  appControlApi,
  categoryLabel,
  fmtRelative,
  humanBytes,
  qs,
  referencedByOf,
  type AppCatalogEntryDTO,
  type AppLogAction,
  type AppPolicyDTO,
  type AppRuleDTO,
  type Direction,
  type PolicyAction,
  type RuleAction,
  type UnknownAppAction,
} from "./app-control-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, MultiChips, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const CATALOG_KEY = ["app-control", "catalog"] as const;
const GROUPS_KEY = ["app-control", "user-groups"] as const;

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ["app-control"] });
}

// ── badge recipes (UI_DESIGN_SYSTEM: allow=blue soft, block=rose, limit=amber) ──

const DECISION_CLS: Record<AppLogAction, string> = {
  allowed: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  blocked: "border-transparent bg-rose-600 text-white",
  limited: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
};

const DECISION_ICON: Record<AppLogAction, React.ComponentType<{ className?: string }>> = {
  allowed: Icons.ShieldCheck,
  blocked: Icons.Ban,
  limited: Icons.Gauge,
};

function DecisionBadge({ decision, mbps }: { decision: AppLogAction; mbps?: number }) {
  const Icon = DECISION_ICON[decision] ?? Icons.Shapes;
  return (
    <Badge variant="outline" className={`gap-1 font-medium ${DECISION_CLS[decision] ?? ""}`}>
      <Icon className="h-3 w-3" />
      {decision}
      {decision === "limited" && mbps !== undefined ? ` ${mbps} Mbps` : ""}
    </Badge>
  );
}

function DefaultActionBadge({ action }: { action: PolicyAction }) {
  return (
    <Badge
      variant="outline"
      className={
        action === "block"
          ? "gap-1 border-transparent bg-rose-600 font-medium text-white"
          : "gap-1 border-blue-500/40 bg-blue-500/10 font-medium text-blue-600 dark:text-blue-400"
      }
    >
      {action === "block" ? <Icons.Ban className="h-3 w-3" /> : <Icons.ShieldCheck className="h-3 w-3" />}
      default {action}
    </Badge>
  );
}

function UnknownActionChip({ action }: { action: UnknownAppAction }) {
  const cls =
    action === "block"
      ? "border-rose-600/60 bg-transparent text-rose-500"
      : action === "allow"
        ? "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400"
        : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
  return (
    <Badge variant="outline" className={`gap-1 text-[10px] ${cls}`}>
      <Icons.HelpCircle className="h-3 w-3" />
      unknown: {action}
    </Badge>
  );
}

function CategoryChip({ category }: { category: string }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {categoryLabel(category)}
    </Badge>
  );
}

const DIRECTION_ICON: Record<Direction, React.ComponentType<{ className?: string }>> = {
  both: Icons.ArrowUpDown,
  upload: Icons.ArrowUp,
  download: Icons.ArrowDown,
};

function DirectionBadge({ direction }: { direction: Direction }) {
  const Icon = DIRECTION_ICON[direction] ?? Icons.ArrowUpDown;
  return (
    <Badge
      variant="outline"
      className="gap-1 border-zinc-300 text-[10px] text-zinc-500 dark:border-zinc-700 dark:text-zinc-400"
    >
      <Icon className="h-3 w-3" />
      {direction}
    </Badge>
  );
}

// ── shared catalog + group lookups ──────────────────────────────────────────

function useAppCatalog() {
  const query = useQuery({ queryKey: CATALOG_KEY, queryFn: appControlApi.getCatalog });
  return { apps: query.data?.apps ?? [], query };
}

function useGroupMap() {
  const query = useQuery({ queryKey: GROUPS_KEY, queryFn: () => appControlApi.listUserGroups() });
  const map = useMemo(() => new Map((query.data ?? []).map((g) => [g.id, g.name])), [query.data]);
  return { groups: query.data ?? [], groupMap: map };
}

// ── app combobox (catalog autocomplete) ─────────────────────────────────────

function AppCombobox(props: { apps: AppCatalogEntryDTO[]; value: string; onSelect: (name: string) => void }) {
  const [open, setOpen] = useState(false);
  const selected = props.apps.find((a) => a.name === props.value);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-label="Application"
          className="w-full justify-between font-mono text-xs"
        >
          <span className="truncate">{selected ? selected.name : "Select app…"}</span>
          <Icons.ChevronsUpDown className="ml-2 h-3.5 w-3.5 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-72 p-0" align="start">
        <Command>
          <CommandInput placeholder="Filter apps…" />
          <CommandList>
            <CommandEmpty>No app matches.</CommandEmpty>
            <CommandGroup>
              {props.apps.map((app) => (
                <CommandItem
                  key={app.name}
                  value={`${app.name} ${app.description}`}
                  onSelect={() => {
                    props.onSelect(app.name);
                    setOpen(false);
                  }}
                >
                  <Icons.Check className={`mr-1.5 h-4 w-4 ${props.value === app.name ? "text-blue-600 dark:text-blue-400" : "opacity-0"}`} />
                  <span className="font-mono text-xs">{app.name}</span>
                  <span className="ml-auto max-w-32 truncate text-[10px] text-zinc-400">{app.description}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

// ── policy editor dialog (create + edit) ────────────────────────────────────

function PolicyEditor(props: { policy: AppPolicyDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.policy !== null;
  const [name, setName] = useState(props.policy?.name ?? "");
  const [defaultAction, setDefaultAction] = useState<PolicyAction>(props.policy?.defaultAction ?? "allow");
  const [unknownAppAction, setUnknownAppAction] = useState<UnknownAppAction>(props.policy?.unknownAppAction ?? "log");
  const [enabled, setEnabled] = useState(props.policy?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.policy?.id;
      if (isEdit && id !== undefined) return appControlApi.updatePolicy(id, body);
      return appControlApi.createPolicy(body);
    },
    onSuccess: (p) => {
      toastOk(isEdit ? "Policy updated" : "Policy created", p.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    setErr(null);
    save.mutate({ name: name.trim(), defaultAction, unknownAppAction, enabled });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit policy" : "New app control policy"}</DialogTitle>
          <DialogDescription>
            The default action applies to known apps without a rule; unknown-app handling covers traffic nDPI cannot classify.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Branch Office Control" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="no rule matched">Default action</FieldLabel>
              <Select value={defaultAction} onValueChange={(v) => setDefaultAction(v as PolicyAction)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {POLICY_ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="not in nDPI catalog">Unknown apps</FieldLabel>
              <Select value={unknownAppAction} onValueChange={(v) => setUnknownAppAction(v as UnknownAppAction)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {UNKNOWN_APP_ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Policy enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Policy enabled" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-blue-600 text-white hover:bg-blue-700"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── add rule dialog ─────────────────────────────────────────────────────────

function AddRuleDialog(props: { policyId: number; onClose: () => void }) {
  const queryClient = useQueryClient();
  const { apps } = useAppCatalog();
  const { groups } = useGroupMap();

  const [appName, setAppName] = useState("");
  const [action, setAction] = useState<RuleAction>("block");
  const [bandwidth, setBandwidth] = useState("10");
  const [direction, setDirection] = useState<Direction>("both");
  const [groupIds, setGroupIds] = useState<number[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const catalogApp = apps.find((a) => a.name === appName);

  const save = useMutation({
    mutationFn: () =>
      appControlApi.createRule(props.policyId, {
        appName,
        action,
        bandwidthLimitMbps: action === "limit" ? Number(bandwidth) || null : null,
        direction,
        userGroupIds: groupIds,
        enabled,
      }),
    onSuccess: (created) => {
      toastOk("Rule created", created.appName);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    if (!appName) {
      setErr("Pick an application from the catalog");
      return;
    }
    if (action === "limit") {
      const n = Number(bandwidth);
      if (!Number.isInteger(n) || n < 1 || n > 10000) {
        setErr("Bandwidth limit must be 1–10000 Mbps");
        return;
      }
    }
    setErr(null);
    save.mutate();
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">Add application rule</DialogTitle>
          <DialogDescription>
            Matched apps take the rule action; leave the group list empty to apply to everyone.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel hint="nDPI catalog">Application</FieldLabel>
            <AppCombobox apps={apps} value={appName} onSelect={setAppName} />
            {catalogApp && (
              <p className="mt-1.5 flex items-center gap-2 text-[11px] text-zinc-500">
                <CategoryChip category={catalogApp.category} />
                {catalogApp.description}
              </p>
            )}
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Action</FieldLabel>
              <Select value={action} onValueChange={(v) => setAction(v as RuleAction)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {RULE_ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Direction</FieldLabel>
              <Select value={direction} onValueChange={(v) => setDirection(v as Direction)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DIRECTIONS.map((d) => (
                    <SelectItem key={d} value={d}>
                      {d}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {action === "limit" && (
            <div>
              <FieldLabel hint="1–10000">Bandwidth limit (Mbps)</FieldLabel>
              <Input
                type="number"
                min={1}
                max={10000}
                value={bandwidth}
                onChange={(e) => setBandwidth(e.target.value)}
                className="font-mono text-xs"
                aria-label="Bandwidth limit in Mbps"
              />
            </div>
          )}
          <div>
            <FieldLabel hint="empty = all groups">User groups</FieldLabel>
            <MultiChips
              options={groups.map((g) => ({ id: g.id, label: g.name }))}
              selected={groupIds}
              onToggle={(id) => setGroupIds((prev) => (prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]))}
            />
          </div>
          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Rule enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Rule enabled" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 text-white hover:bg-blue-700" disabled={save.isPending || !appName} onClick={submit}>
            {save.isPending ? "Saving…" : "Add rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── rules table (selected policy) ───────────────────────────────────────────

function RulesTable({ policyId }: { policyId: number }) {
  const queryClient = useQueryClient();
  const { groupMap } = useGroupMap();
  const [addOpen, setAddOpen] = useState(false);
  const [deleting, setDeleting] = useState<AppRuleDTO | null>(null);

  const rulesQuery = useQuery({
    queryKey: ["app-control", "rules", policyId],
    queryFn: () => appControlApi.listRules(policyId),
  });
  const rows = rulesQuery.data ?? [];

  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Record<string, unknown> }) => appControlApi.updateRule(id, body),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Rule update failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => appControlApi.deleteRule(id),
    onSuccess: () => {
      toastOk("Rule deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  const changeAction = (rule: AppRuleDTO, action: RuleAction) => {
    if (action === rule.action) return;
    update.mutate(
      action === "limit"
        ? { id: rule.id, body: { action, bandwidthLimitMbps: rule.bandwidthLimitMbps ?? 10 } }
        : { id: rule.id, body: { action } },
    );
  };

  const commitBandwidth = (rule: AppRuleDTO, raw: string) => {
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > 10000 || n === rule.bandwidthLimitMbps) return;
    update.mutate({ id: rule.id, body: { bandwidthLimitMbps: n } });
  };

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-zinc-200 p-4 dark:border-zinc-800">
        <span className="text-xs text-zinc-400">{rows.length} rules</span>
        <div className="ml-auto">
          <Button size="sm" className="h-8 bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
            <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add rule
          </Button>
        </div>
      </div>

      {rulesQuery.isError ? (
        <div className="p-4">
          <QueryError error={rulesQuery.error} onRetry={() => void rulesQuery.refetch()} />
        </div>
      ) : rulesQuery.isLoading ? (
        <TableSkeleton rows={5} cols={8} />
      ) : rows.length === 0 ? (
        <EmptyBlock
          icon={<Icons.Shapes className="h-6 w-6" />}
          title="No application rules"
          description="Add per-app allow / block / limit rules — apps without a rule fall through to the policy default."
        />
      ) : (
        <div className="max-h-96 overflow-y-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>App</TableHead>
                <TableHead className="w-28">Category</TableHead>
                <TableHead className="w-28">Action</TableHead>
                <TableHead className="w-24">Limit</TableHead>
                <TableHead className="w-24">Direction</TableHead>
                <TableHead className="max-w-40">Groups</TableHead>
                <TableHead className="w-16 text-right">Hits</TableHead>
                <TableHead className="w-20">Enabled</TableHead>
                <TableHead className="w-12 text-right">Del</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((rule) => (
                <TableRow key={rule.id} className={rule.enabled ? undefined : "opacity-70"}>
                  <TableCell>
                    <span className="font-mono text-xs font-medium">{rule.appName}</span>
                  </TableCell>
                  <TableCell>
                    <CategoryChip category={rule.category} />
                  </TableCell>
                  <TableCell>
                    <Select value={rule.action} onValueChange={(v) => changeAction(rule, v as RuleAction)}>
                      <SelectTrigger className="h-8 w-24" aria-label={`Action for ${rule.appName}`}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RULE_ACTIONS.map((a) => (
                          <SelectItem key={a} value={a}>
                            {a}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell>
                    {rule.action === "limit" ? (
                      <Input
                        type="number"
                        min={1}
                        max={10000}
                        defaultValue={rule.bandwidthLimitMbps ?? 10}
                        key={`bw-${rule.id}-${rule.bandwidthLimitMbps ?? "x"}`}
                        onBlur={(e) => commitBandwidth(rule, e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") (e.target as HTMLInputElement).blur();
                        }}
                        className="h-8 w-20 font-mono text-xs"
                        aria-label={`Bandwidth limit for ${rule.appName}`}
                      />
                    ) : (
                      <span className="text-xs text-zinc-300 dark:text-zinc-600">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <DirectionBadge direction={rule.direction} />
                  </TableCell>
                  <TableCell className="max-w-40">
                    {rule.userGroupIds.length === 0 ? (
                      <span className="text-xs text-zinc-400">all</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {rule.userGroupIds.map((id) => (
                          <Badge
                            key={id}
                            variant="outline"
                            className="border-blue-500/40 bg-blue-500/10 text-[10px] text-blue-600 dark:text-blue-400"
                          >
                            {groupMap.get(id) ?? `#${id}`}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right text-xs tabular-nums text-zinc-500">{rule.hitCount}</TableCell>
                  <TableCell>
                    <Switch
                      checked={rule.enabled}
                      disabled={update.isPending && update.variables?.id === rule.id}
                      onCheckedChange={(enabled) => update.mutate({ id: rule.id, body: { enabled } })}
                      aria-label={`Toggle ${rule.appName}`}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-rose-500 hover:text-rose-600"
                        aria-label={`Delete ${rule.appName} rule`}
                        onClick={() => setDeleting(rule)}
                      >
                        <Icons.Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {update.isPending && (
        <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
          Saving rule…
        </p>
      )}

      {addOpen && <AddRuleDialog policyId={policyId} onClose={() => setAddOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete rule for ${deleting?.appName ?? ""}?`}
        description="The app falls back to the policy default action immediately."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

// ── policy delete conflict dialog (409 → referencedBy rules) ────────────────

function PolicyConflictDialog(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  error: unknown;
}) {
  const refs = referencedByOf(props.error);
  return (
    <AlertDialog open={props.open} onOpenChange={props.onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <Icons.TriangleAlert className="h-5 w-5 text-amber-500" />
            Policy is still referenced
          </AlertDialogTitle>
          <AlertDialogDescription>
            Delete its application rules first — this policy still defines rules for the apps below.
          </AlertDialogDescription>
        </AlertDialogHeader>
        {refs.length > 0 && (
          <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <p className="mb-2 text-xs font-medium text-zinc-500">Referenced by these app rules:</p>
            <div className="flex flex-wrap gap-1.5">
              {refs.map((r, i) => (
                <Badge
                  key={`${r.ruleName}-${i}`}
                  variant="outline"
                  className="border-blue-500/40 bg-blue-500/10 font-mono text-[11px] text-blue-600 dark:text-blue-400"
                >
                  <Icons.Shapes className="mr-1 h-3 w-3" />
                  {r.ruleName}
                </Badge>
              ))}
            </div>
          </div>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Close</AlertDialogCancel>
          <AlertDialogAction
            className="bg-blue-600 text-white hover:bg-blue-700 focus-visible:ring-blue-600"
            onClick={(e) => {
              e.preventDefault();
              props.onOpenChange(false);
            }}
          >
            Got it
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

// ── test app card ───────────────────────────────────────────────────────────

function TestAppCard({ policy }: { policy: AppPolicyDTO }) {
  const queryClient = useQueryClient();
  const { apps } = useAppCatalog();
  const [appName, setAppName] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () => appControlApi.testApp(policy.id, appName),
    onSuccess: () => {
      setErr(null);
      invalidateAll(queryClient); // test persists a log row + bumps hitCount
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Test failed"),
  });

  const result = run.data;
  const sortedApps = useMemo(() => [...apps].sort((a, b) => a.name.localeCompare(b.name)), [apps]);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.FlaskConical className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Test app
          <span className="text-xs font-normal text-zinc-400">simulated decision for “{policy.name}”</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 p-4 pt-0">
        <div className="flex flex-col gap-2 sm:flex-row">
          <Select value={appName} onValueChange={setAppName}>
            <SelectTrigger className="flex-1 font-mono text-xs sm:w-64" aria-label="Application to test">
              <SelectValue placeholder="Select an app…" />
            </SelectTrigger>
            <SelectContent className="max-h-72">
              {sortedApps.map((app) => (
                <SelectItem key={app.name} value={app.name} className="font-mono text-xs">
                  {app.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            className="h-9 bg-blue-600 px-5 text-white hover:bg-blue-700"
            disabled={run.isPending || !appName}
            onClick={() => run.mutate()}
          >
            {run.isPending ? <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Icons.Play className="mr-1 h-3.5 w-3.5" />}
            Run
          </Button>
        </div>

        {err && <p className="text-xs text-rose-600">{err}</p>}

        {result && (
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <DecisionBadge decision={result.decision} mbps={result.bandwidthLimitMbps} />
            <Badge
              variant="outline"
              className="border-zinc-300 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:text-zinc-300"
            >
              reason: {result.reason}
            </Badge>
            {result.ruleId !== undefined && (
              <span className="text-[11px] text-zinc-400">rule #{result.ruleId}</span>
            )}
            <span className="text-[11px] text-zinc-400">logged to app control logs</span>
          </div>
        )}

        {!result && !err && (
          <p className="text-xs text-zinc-400">
            Pick a catalog app — rules win first, then the unknown-app handling, then the policy default.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ── stats strip + logs ──────────────────────────────────────────────────────

function StatCard(props: { label: string; value: number | string; icon: React.ReactNode; tone: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-zinc-500">{props.label}</span>
          <span className={props.tone}>{props.icon}</span>
        </div>
        <p className="mt-1 text-2xl font-semibold tabular-nums">{props.value}</p>
      </CardContent>
    </Card>
  );
}

function StatsStrip() {
  const statsQuery = useQuery({ queryKey: ["app-control", "stats"], queryFn: appControlApi.getStats });
  const stats = statsQuery.data;

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label="Allowed (24h)"
        value={stats?.allowed24h ?? "—"}
        tone="text-blue-600 dark:text-blue-400"
        icon={<Icons.ShieldCheck className="h-4 w-4" />}
      />
      <StatCard
        label="Blocked (24h)"
        value={stats?.blocked24h ?? "—"}
        tone="text-rose-500"
        icon={<Icons.Ban className="h-4 w-4" />}
      />
      <StatCard
        label="Limited (24h)"
        value={stats?.limited24h ?? "—"}
        tone="text-amber-500"
        icon={<Icons.Gauge className="h-4 w-4" />}
      />
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-zinc-500">Top apps (24h)</span>
            <Icons.TrendingUp className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          </div>
          {stats && stats.topApps.length > 0 ? (
            <ul className="mt-2 space-y-1">
              {stats.topApps.map((t) => (
                <li key={t.appName} className="flex items-center justify-between gap-2 text-xs">
                  <span className="truncate font-mono text-zinc-600 dark:text-zinc-300" title={t.appName}>
                    {t.appName}
                  </span>
                  <span className="shrink-0 tabular-nums text-zinc-500">
                    {t.count} · {humanBytes(t.bytes)}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-xs text-zinc-400">No app activity in the last 24h</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function LogsCard() {
  const queryClient = useQueryClient();
  const [action, setAction] = useState<"all" | AppLogAction>("all");

  const params = useMemo(() => qs({ limit: 25, action: action === "all" ? undefined : action }), [action]);
  const logsQuery = useQuery({
    queryKey: ["app-control", "logs", params],
    queryFn: () => appControlApi.listLogs(params),
    refetchInterval: 15_000,
  });
  const rows = logsQuery.data?.data ?? [];
  const meta = logsQuery.data?.meta;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.ScrollText className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Recent app control activity
        </CardTitle>
        <div className="flex items-center gap-2">
          <Select
            value={action}
            onValueChange={(v) => {
              setAction(v as "all" | AppLogAction);
              void queryClient.invalidateQueries({ queryKey: ["app-control", "logs"] });
            }}
          >
            <SelectTrigger className="h-8 w-32" aria-label="Action filter">
              <SelectValue placeholder="All actions" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All actions</SelectItem>
              {LOG_ACTIONS.map((a) => (
                <SelectItem key={a} value={a}>
                  {a}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Refresh logs" onClick={() => void logsQuery.refetch()}>
            <Icons.RefreshCw className={`h-3.5 w-3.5 ${logsQuery.isFetching ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {logsQuery.isError ? (
          <div className="p-4">
            <QueryError error={logsQuery.error} onRetry={() => void logsQuery.refetch()} />
          </div>
        ) : logsQuery.isLoading ? (
          <TableSkeleton rows={5} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.ScrollText className="h-6 w-6" />}
            title="No log entries"
            description="Run an app test or wait for appliance traffic to populate the log."
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Action</TableHead>
                  <TableHead>App</TableHead>
                  <TableHead className="w-32">Client IP</TableHead>
                  <TableHead className="w-24 text-right">Bytes</TableHead>
                  <TableHead className="w-24 text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      <DecisionBadge decision={log.action} />
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">{log.appName}</span>
                      {log.ruleId !== null && (
                        <span className="ml-2 text-[10px] text-zinc-400">rule #{log.ruleId}</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-500">{log.clientIp}</TableCell>
                    <TableCell className="text-right text-xs tabular-nums text-zinc-500">
                      {humanBytes(log.bytes)}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right text-xs text-zinc-500">
                      {fmtRelative(log.createdAt)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {meta && meta.total > 0 && (
          <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
            {rows.length} of {meta.total} log entries (newest first)
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ── policy master list (left column) ────────────────────────────────────────

function PolicyCard(props: {
  policy: AppPolicyDTO;
  selected: boolean;
  onSelect: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: (enabled: boolean) => void;
  toggling: boolean;
}) {
  const { policy } = props;
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={props.onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onSelect();
        }
      }}
      aria-pressed={props.selected}
      className={`w-full cursor-pointer rounded-xl border p-4 text-left transition-colors ${
        props.selected
          ? "border-blue-500/50 bg-blue-500/5 ring-1 ring-blue-500/30"
          : "border-zinc-200 hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-800/50"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold">{policy.name}</p>
          <div className="mt-1.5">
            <DefaultActionBadge action={policy.defaultAction} />
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-zinc-400 hover:text-blue-600"
            aria-label={`Edit ${policy.name}`}
            onClick={(e) => {
              e.stopPropagation();
              props.onEdit();
            }}
          >
            <Icons.Pencil className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-zinc-400 hover:text-rose-600"
            aria-label={`Delete ${policy.name}`}
            onClick={(e) => {
              e.stopPropagation();
              props.onDelete();
            }}
          >
            <Icons.Trash2 className="h-3.5 w-3.5" />
          </Button>
          <span onClick={(e) => e.stopPropagation()} className="pl-0.5">
            <Switch
              checked={policy.enabled}
              disabled={props.toggling}
              onCheckedChange={props.onToggle}
              aria-label={`Toggle ${policy.name}`}
            />
          </span>
        </div>
      </div>

      <div className="mt-3">
        <UnknownActionChip action={policy.unknownAppAction} />
      </div>

      <p className="mt-2 text-[11px] text-zinc-400">{policy.ruleCount} app rules</p>
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function AppControlView() {
  const queryClient = useQueryClient();
  const policiesQuery = useQuery({ queryKey: ["app-control", "policies"], queryFn: appControlApi.listPolicies });
  const policies = policiesQuery.data ?? [];

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const selected = policies.find((p) => p.id === selectedId) ?? policies[0] ?? null;

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<AppPolicyDTO | null>(null);
  const [deleting, setDeleting] = useState<AppPolicyDTO | null>(null);
  const [conflict, setConflict] = useState<unknown>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => appControlApi.updatePolicy(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => appControlApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Policy deleted");
      setDeleting(null);
      setSelectedId(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      if (referencedByOf(e).length > 0) {
        setDeleting(null);
        setConflict(e);
      } else {
        toastErr(e, "Delete failed");
      }
    },
  });

  return (
    <div className="space-y-4">
      <StatsStrip />

      <div className="grid items-start gap-4 lg:grid-cols-[340px_1fr]">
        {/* master list */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm">Policies</CardTitle>
            <Button
              size="sm"
              className="h-8 bg-blue-600 text-white hover:bg-blue-700"
              onClick={() => setAddOpen(true)}
            >
              <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add
            </Button>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            {policiesQuery.isError ? (
              <QueryError error={policiesQuery.error} onRetry={() => void policiesQuery.refetch()} />
            ) : policiesQuery.isLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="h-28 animate-pulse rounded-xl bg-zinc-100 dark:bg-zinc-800" />
                ))}
              </div>
            ) : policies.length === 0 ? (
              <EmptyBlock
                icon={<Icons.Shapes className="h-6 w-6" />}
                title="No policies yet"
                description="Create an app control policy to manage per-application allow, block and bandwidth rules."
                action={
                  <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
                    <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New policy
                  </Button>
                }
              />
            ) : (
              <div className="max-h-96 space-y-3 overflow-y-auto pr-1">
                {policies.map((policy) => (
                  <PolicyCard
                    key={policy.id}
                    policy={policy}
                    selected={selected?.id === policy.id}
                    onSelect={() => setSelectedId(policy.id)}
                    onEdit={() => {
                      setSelectedId(policy.id);
                      setEditing(policy);
                    }}
                    onDelete={() => setDeleting(policy)}
                    onToggle={(enabled) => toggle.mutate({ id: policy.id, enabled })}
                    toggling={toggle.isPending && toggle.variables?.id === policy.id}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* detail */}
        <div className="space-y-4">
          {selected ? (
            <>
              <Card>
                <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <Icons.Shapes className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                    {selected.name}
                    {!selected.enabled && (
                      <Badge
                        variant="outline"
                        className="border-zinc-300 text-[10px] uppercase text-zinc-400 dark:border-zinc-700"
                      >
                        disabled
                      </Badge>
                    )}
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <UnknownActionChip action={selected.unknownAppAction} />
                    <Button variant="outline" size="sm" className="h-8 gap-1 text-xs" onClick={() => setEditing(selected)}>
                      <Icons.Pencil className="h-3.5 w-3.5" /> Edit
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <RulesTable key={`rules-${selected.id}`} policyId={selected.id} />
                </CardContent>
              </Card>

              <TestAppCard key={`test-${selected.id}`} policy={selected} />
            </>
          ) : (
            !policiesQuery.isLoading &&
            !policiesQuery.isError && (
              <Card>
                <CardContent className="p-0">
                  <EmptyBlock
                    icon={<Icons.Shapes className="h-6 w-6" />}
                    title="No policy selected"
                    description="Select or create a policy to manage its per-application rules."
                  />
                </CardContent>
              </Card>
            )
          )}
        </div>
      </div>

      <LogsCard />

      {addOpen && <PolicyEditor policy={null} onClose={() => setAddOpen(false)} />}
      {editing && <PolicyEditor policy={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete policy “${deleting?.name ?? ""}”?`}
        description="Policies with application rules cannot be deleted — remove their rules first. Log rows are kept."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
      <PolicyConflictDialog open={conflict !== null} onOpenChange={(open) => !open && setConflict(null)} error={conflict} />
    </div>
  );
}

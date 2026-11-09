"use client";

/**
 * #/threat-intel/auto-block — automatic blocking (M13 §2.11 tab 3).
 * Top: rules table (manual + auto-feed, action chip, direction, hitCount,
 * enabled switch, delete) with a manual "Add rule" dialog. Bottom: live-ish
 * "Recent matches" list (refetch every 10s) from /hits with severity dots.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
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
  IOC_TYPES,
  fmtRelative,
  threatIntelApi,
  type AutoBlockRuleDTO,
  type IocType,
} from "./threat-intel-api";
import { ActionChip, DirectionChip, HitActionChip, SeverityDot, SourceBadge, TypeBadge } from "./ti-ui";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const RULES_KEY = ["threat-intel", "auto-block-rules"] as const;
const HITS_KEY = ["threat-intel", "hits"] as const;

const ACTIONS = ["drop", "reject", "quarantine_vlan"] as const;
const DIRECTIONS = ["in", "out", "both"] as const;

// ── add-rule dialog (manual rules only — auto-feed rules come from sync) ────

function RuleEditor(props: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [matchType, setMatchType] = useState<IocType>("ip");
  const [matchValue, setMatchValue] = useState("");
  const [action, setAction] = useState<(typeof ACTIONS)[number]>("drop");
  const [direction, setDirection] = useState<(typeof DIRECTIONS)[number]>("both");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => threatIntelApi.createAutoBlockRule(body),
    onSuccess: (created) => {
      toastOk(`Rule created`, created.name);
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Add auto-block rule</DialogTitle>
          <DialogDescription>
            Matches traffic against the value and enforces the action at the edge. Rule hits are shown below.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Block ransomware net" />
          </div>
          <div className="grid grid-cols-[110px_1fr] gap-4">
            <div>
              <FieldLabel>Match type</FieldLabel>
              <Select value={matchType} onValueChange={(v) => setMatchType(v as IocType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {IOC_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Match value</FieldLabel>
              <Input
                value={matchValue}
                onChange={(e) => setMatchValue(e.target.value)}
                placeholder={matchType === "cidr" ? "185.222.57.0/24" : "45.155.205.233"}
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Action</FieldLabel>
              <Select value={action} onValueChange={(v) => setAction(v as (typeof ACTIONS)[number])}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a === "quarantine_vlan" ? "quarantine_vlan" : a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Direction</FieldLabel>
              <Select value={direction} onValueChange={(v) => setDirection(v as (typeof DIRECTIONS)[number])}>
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
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={save.isPending || !name.trim() || !matchValue.trim()}
            onClick={() => save.mutate({ name: name.trim(), matchType, matchValue: matchValue.trim(), action, direction, enabled: true })}
          >
            {save.isPending ? "Saving…" : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── recent matches (live-ish) ───────────────────────────────────────────────

function RecentMatches() {
  const hitsQuery = useQuery({
    queryKey: HITS_KEY,
    queryFn: () => threatIntelApi.listHits("limit=50"),
    refetchInterval: 10_000,
  });
  const hits = hitsQuery.data ?? [];

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Icons.Activity className="h-4 w-4 text-red-700 dark:text-red-500" />
          Recent matches
        </CardTitle>
        <span className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-zinc-500 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-zinc-500" />
          </span>
          refreshes every 10s
        </span>
      </CardHeader>
      <CardContent className="p-0">
        {hitsQuery.isError ? (
          <div className="p-4">
            <QueryError error={hitsQuery.error} onRetry={() => void hitsQuery.refetch()} />
          </div>
        ) : hitsQuery.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Icons.Loader2 key={i} className="h-4 w-4 animate-spin text-zinc-300" />
            ))}
          </div>
        ) : hits.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Radar className="h-6 w-6" />}
            title="No IOC matches yet"
            description="Hits appear as soon as traffic matches an enabled IOC or auto-block rule."
          />
        ) : (
          <ul className="max-h-96 divide-y divide-zinc-100 overflow-y-auto dark:divide-zinc-800">
            {hits.map((h) => (
              <li key={h.id} className="flex items-center gap-3 px-4 py-2.5 text-xs hover:bg-zinc-50 dark:hover:bg-zinc-900">
                <SeverityDot severity={h.ioc.severity} />
                <span className="min-w-0 flex-1 truncate font-mono" title={h.ioc.value}>
                  {h.ioc.value}
                </span>
                <span className="hidden font-mono text-[11px] text-zinc-400 sm:inline">{h.sourceIp}</span>
                <span className="hidden font-mono text-[11px] text-zinc-400 md:inline">→ {h.destIp ?? "—"}</span>
                <HitActionChip action={h.action} />
                <span className="w-14 shrink-0 text-right text-[11px] tabular-nums text-zinc-400">{fmtRelative(h.createdAt)}</span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function AutoBlockView() {
  const queryClient = useQueryClient();
  const rulesQuery = useQuery({ queryKey: RULES_KEY, queryFn: threatIntelApi.listAutoBlockRules });
  const rules = rulesQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [deleting, setDeleting] = useState<AutoBlockRuleDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => threatIntelApi.updateAutoBlockRule(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: RULES_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => threatIntelApi.deleteAutoBlockRule(id),
    onSuccess: () => {
      toastOk("Rule deleted");
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div className="space-y-4">
      {/* ── rules table ────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-xs text-zinc-500">
          Rules block, reject or quarantine traffic matching an indicator. &quot;auto-feed&quot; rules are created by feed sync
          for new critical IOCs; manual rules are curated here.
        </p>
        <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-1 h-4 w-4" /> Add rule
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {rulesQuery.isError ? (
            <div className="p-4">
              <QueryError error={rulesQuery.error} onRetry={() => void rulesQuery.refetch()} />
            </div>
          ) : rulesQuery.isLoading ? (
            <TableSkeleton rows={5} cols={8} />
          ) : rules.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ShieldBan className="h-6 w-6" />}
              title="No auto-block rules"
              description="Enable auto-block on a threat feed or add a manual rule to start blocking matches at the edge."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-16">Type</TableHead>
                  <TableHead>Match value</TableHead>
                  <TableHead className="w-28">Action</TableHead>
                  <TableHead className="w-16">Dir</TableHead>
                  <TableHead className="w-28">Source</TableHead>
                  <TableHead className="w-16 text-right">Hits</TableHead>
                  <TableHead className="w-24 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id} className={rule.enabled ? undefined : "opacity-60"}>
                    <TableCell className="max-w-44">
                      <span className="block truncate text-xs font-medium" title={rule.name}>
                        {rule.name}
                      </span>
                    </TableCell>
                    <TableCell>
                      <TypeBadge type={rule.matchType} />
                    </TableCell>
                    <TableCell className="max-w-56">
                      <span className="block truncate font-mono text-xs" title={rule.matchValue}>
                        {rule.matchValue}
                      </span>
                    </TableCell>
                    <TableCell>
                      <ActionChip action={rule.action} />
                    </TableCell>
                    <TableCell>
                      <DirectionChip direction={rule.direction} />
                    </TableCell>
                    <TableCell>
                      <SourceBadge source={rule.source} />
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-zinc-500">{rule.hitCount}</TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Switch
                          checked={rule.enabled}
                          onCheckedChange={(enabled) => toggle.mutate({ id: rule.id, enabled })}
                          aria-label={`Toggle rule ${rule.name}`}
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete rule ${rule.name}`}
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
          )}
          {rules.length > 0 && (
            <div className="border-t border-zinc-200 px-4 py-2.5 text-xs text-zinc-500 dark:border-zinc-800">
              {rules.length} rule{rules.length === 1 ? "" : "s"} · {rules.filter((r) => r.enabled).length} enabled
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── recent matches (10s polling) ───────────────────────────────── */}
      <RecentMatches />

      {addOpen && <RuleEditor onClose={() => setAddOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete rule "${deleting?.name ?? ""}"?`}
        description={
          deleting?.source === "auto-feed"
            ? "This rule was created by a threat feed. It may be re-created on the next sync if the IOC is still new and critical."
            : "Traffic matching this value will no longer be blocked by the auto-block engine."
        }
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

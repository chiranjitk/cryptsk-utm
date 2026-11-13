"use client";

/**
 * Backups view (M10 §4 `#/system/backups`) — snapshot table (id / createdAt +
 * age chip / type badge / size / note / actions), id/note/type search, create
 * dialog (note length pre-check) + RESTORE flow: destructive AlertDialog that
 * requires typing `RESTORE` to enable confirm; dialog text states what is
 * overwritten, the safety backup, and the audit.
 * Download uses the locked file endpoint (cryptsk-backup-<id>.json).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import { INVALID_CLS } from "../network/net-ui";
import { usePermissions, BackupTypeBadge, fmtDateTime, humanizeBytes } from "./system-ui";
import { systemApi, type BackupDTO } from "./system-api";

function CreateBackupDialog(props: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const queryClient = useQueryClient();
  const [type, setType] = useState<"config" | "full">("config");
  const [note, setNote] = useState("");
  const [noteErr, setNoteErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => systemApi.createBackup({ type, note: note.trim() || undefined }),
    onSuccess: (b) => {
      toastOk("Backup created", `${b.id} (${humanizeBytes(b.sizeBytes)}, ${b.type}).`);
      setNote("");
      setNoteErr(null);
      props.onOpenChange(false);
      void queryClient.invalidateQueries({ queryKey: ["system", "backups"] });
    },
    onError: (err) => toastErr(err, "Create failed"),
  });

  const submit = () => {
    // client pre-check mirrors the server zod grammar (M10 §5.5) — server stays authoritative
    if (note.trim().length > 200) {
      setNoteErr("Note must be at most 200 characters");
      return;
    }
    setNoteErr(null);
    create.mutate();
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create backup</DialogTitle>
          <DialogDescription>
            <span className="font-medium">config</span> snapshots configuration tables;{" "}
            <span className="font-medium">full</span> additionally embeds the volatile-table dump (logs, leases,
            sessions, notifications).
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label>Type</Label>
            <Select value={type} onValueChange={(v) => setType(v as "config" | "full")}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="config">config — configuration tables</SelectItem>
                <SelectItem value="full">full — config + volatile tables</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="backup-note">Note (optional)</Label>
            <Input
              id="backup-note"
              value={note}
              onChange={(e) => {
                setNote(e.target.value);
                setNoteErr(null);
              }}
              placeholder="before firmware upgrade"
              aria-invalid={!!noteErr}
              aria-describedby={noteErr ? "backup-note-err" : undefined}
              className={cn(noteErr && INVALID_CLS)}
            />
            {noteErr ? (
              <p id="backup-note-err" role="alert" className="text-[11px] text-rose-600 dark:text-rose-400">
                {noteErr}
              </p>
            ) : null}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={create.isPending} onClick={submit}>
            {create.isPending ? "Creating…" : "Create backup"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Destructive restore dialog — typed `RESTORE` gates the confirm button. */
function RestoreDialog(props: {
  backup: BackupDTO | null;
  onOpenChange: (o: boolean) => void;
  onConfirm: () => void;
  loading: boolean;
}) {
  const [typed, setTyped] = useState("");
  const enabled = typed === "RESTORE" && !props.loading;

  return (
    <AlertDialog
      open={props.backup !== null}
      onOpenChange={(o) => {
        if (!o) setTyped("");
        props.onOpenChange(o);
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <Icons.TriangleAlert className="h-5 w-5 text-rose-600" />
            Restore backup {props.backup?.id}?
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2 text-sm">
              <p>
                Restoring overwrites the current configuration with the snapshot{" "}
                {props.backup?.type === "full" ? "(a full restore also RESETS the volatile tables — logs, leases, sessions, notifications)" : "(configuration tables)"}.
              </p>
              <p>A safety backup of the current state is created automatically first, and the restore is audited.</p>
              <p className="font-medium text-rose-600 dark:text-rose-400">
                Type <span className="font-mono">RESTORE</span> to enable the confirm button.
              </p>
              <Input
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                placeholder="RESTORE"
                aria-label="Type RESTORE to confirm"
                className="font-mono"
              />
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel
            disabled={props.loading}
            onClick={() => {
              setTyped("");
              props.onOpenChange(false);
            }}
          >
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            className="bg-rose-600 text-white hover:bg-rose-700 focus-visible:ring-rose-600"
            disabled={!enabled}
            onClick={(e) => {
              e.preventDefault();
              props.onConfirm();
            }}
          >
            {props.loading ? "Restoring…" : "Restore snapshot"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** Backup age chip: fresh (<24 h) emerald, 1-6d zinc, ≥7d amber (rotate reminder). */
function AgeBadge({ createdAt }: { createdAt: string }) {
  const ageSec = Math.max(0, Math.floor((Date.now() - Date.parse(createdAt)) / 1000));
  const days = Math.floor(ageSec / 86_400);
  const label = ageSec < 3600 ? "<1h old" : ageSec < 86_400 ? `${Math.floor(ageSec / 3600)}h old` : `${days}d old`;
  const tone =
    ageSec < 86_400
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
      : ageSec < 7 * 86_400
        ? "border-zinc-300 text-zinc-500 dark:border-zinc-700"
        : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  return (
    <Badge variant="outline" className={cn("mt-0.5 gap-1 text-[10px]", tone)} title={`Snapshot from ${fmtDateTime(createdAt)}`}>
      <Icons.Clock className="h-3 w-3" /> {label}
    </Badge>
  );
}

export function BackupsView() {
  const { canWrite } = usePermissions();
  const queryClient = useQueryClient();
  const backups = useQuery({ queryKey: ["system", "backups"], queryFn: () => systemApi.listBackups() });
  const [q, setQ] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [restoreId, setRestoreId] = useState<string | null>(null);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return backups.data ?? [];
    return (backups.data ?? []).filter(
      (b) => b.id.toLowerCase().includes(needle) || (b.note ?? "").toLowerCase().includes(needle) || b.type.includes(needle),
    );
  }, [backups.data, q]);

  const restore = useMutation({
    mutationFn: (id: string) => systemApi.restoreBackup(id),
    onSuccess: (r) => {
      toastOk("Restore complete", `${r.rows} rows re-applied${r.skipped ? `, ${r.skipped} skipped` : ""} — safety backup ${r.safetyBackupId}.`);
      setRestoreId(null);
      // section "all" sentinel — invalidate everything (M10 §5.3)
      void queryClient.invalidateQueries();
    },
    onError: (err) => toastErr(err, "Restore failed"),
  });

  const restoreTarget = useMemo(() => backups.data?.find((b) => b.id === restoreId) ?? null, [backups.data, restoreId]);

  return (
    <div className="grid gap-4">
      <Card>
        <CardContent className="p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <h2 className="flex items-center gap-2 text-base font-semibold">
                  <Icons.DatabaseBackup className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
                  Backup snapshots
                </h2>
                <p className="text-xs text-zinc-500">JSON files under db/backups — restore replays config rows through validation (audited)</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" className="h-11 lg:h-8" onClick={() => void backups.refetch()}>
                  <Icons.RefreshCw className="mr-2 h-4 w-4" /> Refresh
                </Button>
                <Button size="sm" className="h-11 lg:h-8" disabled={!canWrite("backups")} onClick={() => setCreateOpen(true)}>
                  <Icons.Plus className="mr-2 h-4 w-4" /> Create backup
                </Button>
              </div>
            </div>

            <div className="relative mt-3 mb-1">
              <Icons.Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search id, note or type…"
                className="h-11 pl-8 lg:h-9"
                aria-label="Search backups"
              />
            </div>

          {backups.isError ? (
            <QueryError error={backups.error} onRetry={() => void backups.refetch()} />
          ) : backups.isLoading ? (
            <TableSkeleton rows={4} cols={6} />
          ) : (backups.data?.length ?? 0) === 0 ? (
            <EmptyBlock
              icon={<Icons.DatabaseBackup className="h-6 w-6" />}
              title="No backups yet — create your first"
              description="Snapshots are JSON files under db/backups; full backups also embed the volatile-table dump."
              action={
                <Button size="sm" disabled={!canWrite("backups")} onClick={() => setCreateOpen(true)}>
                  <Icons.Plus className="mr-2 h-4 w-4" /> Create backup
                </Button>
              }
            />
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Search className="h-6 w-6" />}
              title="No backups match the search"
              description="Search matches the snapshot id, the note and the type. Clear the search to see all snapshots."
              action={
                <Button size="sm" variant="outline" onClick={() => setQ("")}>
                  Clear search
                </Button>
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <Table className="min-w-[760px]">
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Note</TableHead>
                    <TableHead className="w-44 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((b) => (
                    <TableRow key={b.id}>
                      <TableCell className="font-mono text-xs">{b.id}</TableCell>
                      <TableCell>
                        <span className="flex flex-col">
                          <span className="text-xs">{fmtDateTime(b.createdAt)}</span>
                          <AgeBadge createdAt={b.createdAt} />
                        </span>
                      </TableCell>
                      <TableCell>
                        <BackupTypeBadge type={b.type} />
                      </TableCell>
                      <TableCell className="text-xs tabular-nums">{humanizeBytes(b.sizeBytes)}</TableCell>
                      <TableCell className="max-w-56 truncate text-xs text-zinc-500">{b.note ?? "—"}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button size="sm" variant="outline" className="h-11 lg:h-8" asChild>
                            <a href={systemApi.backupDownloadUrl(b.id)} download={`cryptsk-backup-${b.id}.json`}>
                              <Icons.Download className="mr-1.5 h-3.5 w-3.5" /> Download
                            </a>
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-11 border-rose-500/40 text-rose-600 hover:bg-rose-500/10 lg:h-8 dark:text-rose-400"
                            disabled={!canWrite("backups") || restore.isPending}
                            onClick={() => setRestoreId(b.id)}
                          >
                            <Icons.History className="mr-1.5 h-3.5 w-3.5" /> Restore
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <CreateBackupDialog open={createOpen} onOpenChange={setCreateOpen} />
      <RestoreDialog
        backup={restoreTarget}
        onOpenChange={(o) => !o && setRestoreId(null)}
        loading={restore.isPending}
        onConfirm={() => restoreId !== null && restore.mutate(restoreId)}
      />
    </div>
  );
}

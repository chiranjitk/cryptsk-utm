"use client";

/**
 * User Groups tab on #/vpn/configs — VpnUserGroup CRUD (M05 §4, REVIEW-4A
 * restore): per-group pool override, pushed DNS, idle/max timeouts, per-user
 * session limits and member usernames (logical refs matched against
 * VpnSession.userName at connect time by the engine).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { vpnApi, fieldErrorsOf, type VpnUserGroupDto } from "./vpn-api";
import { TagInput } from "./vpn-ui";
import { ConfirmDialog, EditorSection, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const GROUPS_KEY = ["vpn", "user-groups"] as const;

interface GroupForm {
  name: string;
  description: string;
  pool: string;
  dns: string;
  idleTimeoutMin: string;
  maxSessionMin: string;
  maxSessionsPerUser: string;
  members: string[];
}

function formFrom(g: VpnUserGroupDto | null): GroupForm {
  if (!g) return { name: "", description: "", pool: "", dns: "", idleTimeoutMin: "", maxSessionMin: "", maxSessionsPerUser: "", members: [] };
  return {
    name: g.name,
    description: g.description ?? "",
    pool: g.pool ?? "",
    dns: g.dns ?? "",
    idleTimeoutMin: g.idleTimeoutMin?.toString() ?? "",
    maxSessionMin: g.maxSessionMin?.toString() ?? "",
    maxSessionsPerUser: g.maxSessionsPerUser?.toString() ?? "",
    members: [...g.memberUsernames],
  };
}

function optInt(v: string): number | null {
  const t = v.trim();
  if (!t) return null;
  const n = Number(t);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
}

export function GroupsPanel() {
  const queryClient = useQueryClient();
  const groupsQuery = useQuery({ queryKey: GROUPS_KEY, queryFn: vpnApi.listGroups });
  const sessionsQuery = useQuery({ queryKey: ["vpn", "sessions"], queryFn: () => vpnApi.listSessions("limit=100"), staleTime: 10_000 });

  const groups = useMemo(() => groupsQuery.data ?? [], [groupsQuery.data]);
  const knownUsers = useMemo(() => {
    const names = new Set<string>();
    for (const s of sessionsQuery.data?.data ?? []) if (s.userName) names.add(s.userName);
    return [...names].sort();
  }, [sessionsQuery.data]);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<VpnUserGroupDto | null>(null);
  const [deleting, setDeleting] = useState<VpnUserGroupDto | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: GROUPS_KEY });

  const deleteMut = useMutation({
    mutationFn: (id: number) => vpnApi.deleteGroup(id),
    onSuccess: () => {
      toastOk("User group deleted", "Member sessions keep their current pool until they reconnect.");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      setDeleting(null);
      toastErr(err, "Delete failed");
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          Group policy applies at connect time: members draw IPs from the group pool and honor its timeouts and session limits.
        </p>
        <Button
          size="sm"
          className="gap-1.5"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Icons.Plus className="h-4 w-4" /> Add group
        </Button>
      </div>

      {groupsQuery.isError ? (
        <QueryError error={groupsQuery.error} onRetry={() => void groupsQuery.refetch()} />
      ) : groupsQuery.isLoading ? (
        <Card>
          <CardContent className="pt-6">
            <TableSkeleton rows={2} cols={7} />
          </CardContent>
        </Card>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Users className="h-6 w-6" />}
              title="No VPN user groups yet"
              description="Groups assign per-group pools, DNS, timeouts and per-user session limits to remote users."
              action={
                <Button
                  size="sm"
                  className="gap-1.5"
                  onClick={() => {
                    setEditing(null);
                    setEditorOpen(true);
                  }}
                >
                  <Icons.Plus className="h-4 w-4" /> Add group
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Group</TableHead>
                  <TableHead>Pool override</TableHead>
                  <TableHead>Pushed DNS</TableHead>
                  <TableHead>Timeouts</TableHead>
                  <TableHead>Limit / user</TableHead>
                  <TableHead>Members</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {groups.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell>
                      <p className="font-medium">{g.name}</p>
                      {g.description ? <p className="text-[11px] text-zinc-400">{g.description}</p> : null}
                    </TableCell>
                    <TableCell>
                      {g.pool ? <span className="font-mono text-xs">{g.pool}</span> : <span className="text-xs text-zinc-400">config pool</span>}
                    </TableCell>
                    <TableCell>
                      {g.dns ? <span className="font-mono text-xs">{g.dns}</span> : <span className="text-xs text-zinc-400">—</span>}
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-zinc-500">
                        {g.idleTimeoutMin != null ? `idle ${g.idleTimeoutMin}m` : "idle —"}
                        {" · "}
                        {g.maxSessionMin != null ? `max ${g.maxSessionMin}m` : "max —"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs tabular-nums">{g.maxSessionsPerUser ?? "—"}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300">
                        <Icons.User className="mr-1 h-3 w-3" />
                        {g.memberUsernames.length}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit group ${g.name}`} onClick={() => { setEditing(g); setEditorOpen(true); }}>
                        <Icons.Pencil className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <GroupEditor
        open={editorOpen}
        editing={editing}
        suggestions={knownUsers}
        onClose={() => {
          setEditorOpen(false);
          setEditing(null);
        }}
        onSaved={() => {
          setEditorOpen(false);
          setEditing(null);
          invalidate();
        }}
      />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete group ${deleting?.name ?? ""}?`}
        description="Members will fall back to the tunnel's own pool and default timeouts at their next connect. Existing sessions are not kicked."
        confirmLabel="Delete group"
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

function GroupEditor(props: {
  open: boolean;
  editing: VpnUserGroupDto | null;
  suggestions: string[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const { open, editing } = props;
  const [form, setForm] = useState<GroupForm>(() => formFrom(editing));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const seedKey = editing?.id ?? "new";
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setForm(formFrom(editing));
  }

  const mut = useMutation({
    mutationFn: () => {
      const body = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        pool: form.pool.trim() || null,
        dns: form.dns.trim() || null,
        idleTimeoutMin: optInt(form.idleTimeoutMin),
        maxSessionMin: optInt(form.maxSessionMin),
        maxSessionsPerUser: optInt(form.maxSessionsPerUser),
        memberUsernames: form.members,
      };
      return editing ? vpnApi.updateGroup(editing.id, body) : vpnApi.createGroup(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Group updated" : "Group created", "Policy applies at the next connect.");
      props.onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, editing ? "Save failed" : "Create failed");
    },
  });

  const err = (path: string): string | undefined => serverErrors[path]?.join("; ");

  return (
    <Dialog open={open} onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit group ${editing.name}` : "New VPN user group"}</DialogTitle>
          <DialogDescription>
            A per-user limit can be expressed as a single-member group. Leave pool empty to use the tunnel&apos;s pool.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <EditorSection title="Identity">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <FieldLabel>Name</FieldLabel>
                <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="CONTRACTORS" />
                {err("name") ? <p className="mt-1 text-[11px] text-rose-500">{err("name")}</p> : null}
              </div>
              <div className="sm:col-span-2">
                <FieldLabel>Description</FieldLabel>
                <Input
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  placeholder="Limited vendor access"
                />
                {err("description") ? <p className="mt-1 text-[11px] text-rose-500">{err("description")}</p> : null}
              </div>
            </div>
          </EditorSection>

          <EditorSection title="Policy">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel hint="CIDR, optional">Pool override</FieldLabel>
                <Input value={form.pool} onChange={(e) => setForm((f) => ({ ...f, pool: e.target.value }))} className="font-mono text-xs" placeholder="10.99.1.128/25" />
                {err("pool") ? <p className="mt-1 text-[11px] text-rose-500">{err("pool")}</p> : null}
              </div>
              <div>
                <FieldLabel hint="optional">Pushed DNS</FieldLabel>
                <Input value={form.dns} onChange={(e) => setForm((f) => ({ ...f, dns: e.target.value }))} className="font-mono text-xs" placeholder="192.168.10.1" />
                {err("dns") ? <p className="mt-1 text-[11px] text-rose-500">{err("dns")}</p> : null}
              </div>
              <div>
                <FieldLabel hint="minutes">Idle timeout</FieldLabel>
                <Input
                  type="number"
                  min={1}
                  value={form.idleTimeoutMin}
                  onChange={(e) => setForm((f) => ({ ...f, idleTimeoutMin: e.target.value }))}
                  placeholder="30"
                />
                {err("idleTimeoutMin") ? <p className="mt-1 text-[11px] text-rose-500">{err("idleTimeoutMin")}</p> : null}
              </div>
              <div>
                <FieldLabel hint="minutes">Max session duration</FieldLabel>
                <Input
                  type="number"
                  min={1}
                  value={form.maxSessionMin}
                  onChange={(e) => setForm((f) => ({ ...f, maxSessionMin: e.target.value }))}
                  placeholder="480"
                />
                {err("maxSessionMin") ? <p className="mt-1 text-[11px] text-rose-500">{err("maxSessionMin")}</p> : null}
              </div>
              <div>
                <FieldLabel hint="sessions">Max sessions / user</FieldLabel>
                <Input
                  type="number"
                  min={1}
                  value={form.maxSessionsPerUser}
                  onChange={(e) => setForm((f) => ({ ...f, maxSessionsPerUser: e.target.value }))}
                  placeholder="1"
                />
                {err("maxSessionsPerUser") ? <p className="mt-1 text-[11px] text-rose-500">{err("maxSessionsPerUser")}</p> : null}
              </div>
            </div>
          </EditorSection>

          <EditorSection title={`Members (${form.members.length})`}>
            <TagInput
              values={form.members}
              onChange={(members) => setForm((f) => ({ ...f, members }))}
              placeholder="remote username + Enter"
              suggestions={props.suggestions}
            />
            {err("memberUsernames") ? <p className="mt-1 text-[11px] text-rose-500">{err("memberUsernames")}</p> : null}
          </EditorSection>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={props.onClose}>
            Cancel
          </Button>
          <Button disabled={mut.isPending || !form.name.trim()} onClick={() => { setServerErrors({}); mut.mutate(); }}>
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create group"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

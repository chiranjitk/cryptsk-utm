"use client";

/**
 * Identity secondary panels (M07 §4) — RADIUS Profiles, Directory Sources
 * (LDAP/AD) and the Auth Settings policy editor. Rendered as tabs inside
 * #/identity/users. Masking is server-side: sharedSecret / bindPassword read
 * back as "••••••••"; reveal is a super_admin/tenant_admin-only, audited,
 * auto-hiding second-click action. Directory bindPassword has no reveal.
 */

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import {
  authSettingsApi,
  directoryApi,
  fieldErrorsOf,
  radiusApi,
  type AuthSettings,
  type DirectorySourceDTO,
  type RadiusProfileDTO,
} from "./identity-api";
import { DirectoryTypeChip, InfoNote, TestResultPill } from "./identity-ui";
import { cn } from "@/lib/utils";

// ── RADIUS profiles ─────────────────────────────────────────────────────────

export function RadiusTab() {
  const queryClient = useQueryClient();
  const [editor, setEditor] = useState<{ open: boolean; profile: RadiusProfileDTO | null }>({ open: false, profile: null });
  const [del, setDel] = useState<RadiusProfileDTO | null>(null);

  const listQ = useQuery({ queryKey: ["radius", "list"], queryFn: radiusApi.list });

  const delMut = useMutation({
    mutationFn: (id: number) => radiusApi.delete(id),
    onSuccess: () => {
      toastOk("RADIUS profile deleted");
      void queryClient.invalidateQueries({ queryKey: ["radius"] });
      setDel(null);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Server className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          RADIUS Profiles
          {listQ.data ? (
            <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 px-1.5 text-[10px] text-zinc-600 dark:text-zinc-300">
              {listQ.data.length}
            </Badge>
          ) : null}
        </CardTitle>
        <Button size="sm" className="h-9" onClick={() => setEditor({ open: true, profile: null })}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add Profile
        </Button>
      </CardHeader>
      <CardContent className="px-0">
        {listQ.isLoading ? (
          <div className="px-6">
            <TableSkeleton rows={3} cols={6} />
          </div>
        ) : listQ.isError ? (
          <QueryError error={listQ.error} onRetry={() => void listQ.refetch()} />
        ) : (listQ.data?.length ?? 0) === 0 ? (
          <EmptyBlock
            icon={<Icons.Server className="h-6 w-6" />}
            title="No RADIUS profiles"
            description="Add an external RADIUS server for 802.1X/Wi-Fi and admin authentication."
          />
        ) : (
          <div className="max-h-96 overflow-x-auto overflow-y-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead>Timeout / Retries</TableHead>
                  <TableHead>Shared secret</TableHead>
                  <TableHead>Test</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data!.map((p) => (
                  <RadiusRow key={p.id} profile={p} onEdit={() => setEditor({ open: true, profile: p })} onDelete={() => setDel(p)} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      <RadiusEditorDialog open={editor.open} profile={editor.profile} onClose={() => setEditor({ open: false, profile: null })} />
      <ConfirmDialog
        open={del !== null}
        onOpenChange={(o) => !o && setDel(null)}
        title={`Delete RADIUS profile "${del?.name ?? ""}"?`}
        description="Authentication flows referencing this profile will fall back to local users."
        loading={delMut.isPending}
        onConfirm={() => del && void delMut.mutateAsync(del.id)}
      />
    </Card>
  );
}

function RadiusRow(props: { profile: RadiusProfileDTO; onEdit: () => void; onDelete: () => void }) {
  const [test, setTest] = useState<{ ok: boolean; latencyMs: number; error?: string } | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);

  const testMut = useMutation({
    mutationFn: () => radiusApi.test(props.profile.id),
    onSuccess: (r) => setTest(r),
    onError: (e) => toastErr(e, "Test failed"),
  });

  // second click reveals; auto-hides after 15 s (M07 §7)
  const revealMut = useMutation({
    mutationFn: () => radiusApi.reveal(props.profile.id),
    onSuccess: (r) => {
      setRevealed(r.sharedSecret);
      window.setTimeout(() => setRevealed(null), 15_000);
    },
    onError: (e) => toastErr(e, "Reveal denied"),
  });

  return (
    <TableRow>
      <TableCell className="font-medium">{props.profile.name}</TableCell>
      <TableCell className="font-mono text-xs">
        {props.profile.serverIp}:{props.profile.authPort}
      </TableCell>
      <TableCell className="text-xs text-zinc-500">
        {props.profile.timeoutSec}s / {props.profile.retries}
      </TableCell>
      <TableCell>
        {revealed ? (
          <code className="rounded bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[11px] text-emerald-600 dark:text-emerald-400">{revealed}</code>
        ) : (
          <code className="font-mono text-[11px] text-zinc-500">{props.profile.sharedSecret}</code>
        )}
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" className="h-7 text-[11px]" onClick={() => void testMut.mutateAsync()} disabled={testMut.isPending}>
            {testMut.isPending ? "Testing…" : "Test"}
          </Button>
          {test && <TestResultPill ok={test.ok} label={test.ok ? `${test.latencyMs} ms` : "unreachable"} />}
        </div>
      </TableCell>
      <TableCell>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${props.profile.name}`}>
              <Icons.MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuItem onClick={props.onEdit}>
              <Icons.Pencil className="mr-2 h-3.5 w-3.5" /> Edit
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => (revealed ? setRevealed(null) : void revealMut.mutateAsync())} disabled={revealMut.isPending}>
              <Icons.Eye className="mr-2 h-3.5 w-3.5" />
              {revealed ? "Hide secret" : "Reveal secret"}
            </DropdownMenuItem>
            <DropdownMenuItem className="text-rose-600 focus:text-rose-600 dark:text-rose-400" onClick={props.onDelete}>
              <Icons.Trash2 className="mr-2 h-3.5 w-3.5" /> Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  );
}

function RadiusEditorDialog(props: { open: boolean; profile: RadiusProfileDTO | null; onClose: () => void }) {
  // Radix unmounts content when closed — the form remounts fresh per open.
  return (
    <Dialog open={props.open} onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <RadiusEditorForm profile={props.profile} onClose={props.onClose} />
      </DialogContent>
    </Dialog>
  );
}

function RadiusEditorForm(props: { profile: RadiusProfileDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.profile !== null;
  const [name, setName] = useState(() => props.profile?.name ?? "");
  const [serverIp, setServerIp] = useState(() => props.profile?.serverIp ?? "");
  const [authPort, setAuthPort] = useState(() => String(props.profile?.authPort ?? 1812));
  const [sharedSecret, setSharedSecret] = useState("");
  const [timeoutSec, setTimeoutSec] = useState(() => String(props.profile?.timeoutSec ?? 3));
  const [retries, setRetries] = useState(() => String(props.profile?.retries ?? 2));
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const save = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        name,
        serverIp,
        authPort: Number(authPort),
        timeoutSec: Number(timeoutSec),
        retries: Number(retries),
      };
      // omit the secret to keep the stored value (masked literal is ignored server-side)
      if (sharedSecret) body.sharedSecret = sharedSecret;
      return isEdit ? radiusApi.update(props.profile!.id, body) : radiusApi.create({ ...body, sharedSecret });
    },
    onSuccess: () => {
      toastOk(isEdit ? "Profile updated" : "Profile created", name);
      void queryClient.invalidateQueries({ queryKey: ["radius"] });
      props.onClose();
    },
    onError: (e) => {
      setErrs(fieldErrorsOf(e));
      toastErr(e, "Save failed");
    },
  });

  return (
    <>
      <DialogHeader>
        <DialogTitle>{isEdit ? `Edit ${props.profile!.name}` : "Add RADIUS Profile"}</DialogTitle>
        <DialogDescription>
          {isEdit ? "Leave the shared secret blank to keep the stored one." : "The secret is stored server-side and always masked in responses."}
        </DialogDescription>
      </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.currentTarget.value)} placeholder="CORP-RADIUS" className={cn(errs.name && "border-rose-500")} />
            {errs.name?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <div className="col-span-2">
              <FieldLabel>Server IP</FieldLabel>
              <Input value={serverIp} onChange={(e) => setServerIp(e.currentTarget.value)} placeholder="192.168.1.10" className={cn("font-mono text-xs", errs.serverIp && "border-rose-500")} />
              {errs.serverIp?.map((m) => (
                <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
              ))}
            </div>
            <div>
              <FieldLabel>Port</FieldLabel>
              <Input type="number" value={authPort} onChange={(e) => setAuthPort(e.currentTarget.value)} className={cn(errs.authPort && "border-rose-500")} />
            </div>
          </div>
          <div>
            <FieldLabel hint={isEdit ? "blank = keep current" : undefined}>Shared secret</FieldLabel>
            <Input
              type="password"
              value={sharedSecret}
              onChange={(e) => setSharedSecret(e.currentTarget.value)}
              placeholder={isEdit ? "Leave blank to keep" : "Shared secret"}
              className={cn("font-mono text-xs", errs.sharedSecret && "border-rose-500")}
            />
            {errs.sharedSecret?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div>
              <FieldLabel>Timeout (s)</FieldLabel>
              <Input type="number" value={timeoutSec} onChange={(e) => setTimeoutSec(e.currentTarget.value)} className={cn(errs.timeoutSec && "border-rose-500")} />
            </div>
            <div>
              <FieldLabel>Retries</FieldLabel>
              <Input type="number" value={retries} onChange={(e) => setRetries(e.currentTarget.value)} className={cn(errs.retries && "border-rose-500")} />
            </div>
          </div>
          <InfoNote>Test answers with seeded 5–40 ms latency; documentation-range IPs (192.0.2.x, 203.0.113.x) report unreachable.</InfoNote>
        </div>
      <DialogFooter>
        <Button variant="outline" onClick={props.onClose}>Cancel</Button>
        <Button onClick={() => void save.mutateAsync()} disabled={save.isPending || !name || !serverIp || (!isEdit && !sharedSecret)}>
          {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create profile"}
        </Button>
      </DialogFooter>
    </>
  );
}

// ── directory sources (LDAP/AD) ─────────────────────────────────────────────

export function DirectoryTab() {
  const queryClient = useQueryClient();
  const [editor, setEditor] = useState<{ open: boolean; source: DirectorySourceDTO | null }>({ open: false, source: null });
  const [del, setDel] = useState<DirectorySourceDTO | null>(null);

  const listQ = useQuery({ queryKey: ["directory", "list"], queryFn: directoryApi.list });

  const toggle = useMutation({
    mutationFn: (s: DirectorySourceDTO) => directoryApi.update(s.id, { enabled: !s.enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["directory"] }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const delMut = useMutation({
    mutationFn: (id: number) => directoryApi.delete(id),
    onSuccess: () => {
      toastOk("Directory source deleted");
      void queryClient.invalidateQueries({ queryKey: ["directory"] });
      setDel(null);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.DatabaseZap className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Directory Sources
          <span className="text-[11px] font-normal text-zinc-400">LDAP / AD connectors</span>
        </CardTitle>
        <Button size="sm" className="h-9" onClick={() => setEditor({ open: true, source: null })}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add Source
        </Button>
      </CardHeader>
      <CardContent className="px-0">
        {listQ.isLoading ? (
          <div className="px-6">
            <TableSkeleton rows={3} cols={6} />
          </div>
        ) : listQ.isError ? (
          <QueryError error={listQ.error} onRetry={() => void listQ.refetch()} />
        ) : (listQ.data?.length ?? 0) === 0 ? (
          <EmptyBlock
            icon={<Icons.DatabaseZap className="h-6 w-6" />}
            title="Connect your directory"
            description="Sync users and groups from LDAP/Active Directory for identity-based policies."
          />
        ) : (
          <div className="max-h-96 overflow-x-auto overflow-y-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead>Base DN</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Test</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {listQ.data!.map((s) => (
                  <DirectoryRow
                    key={s.id}
                    source={s}
                    onToggle={() => void toggle.mutateAsync(s)}
                    onEdit={() => setEditor({ open: true, source: s })}
                    onDelete={() => setDel(s)}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      <DirectoryEditorDialog open={editor.open} source={editor.source} onClose={() => setEditor({ open: false, source: null })} />
      <ConfirmDialog
        open={del !== null}
        onOpenChange={(o) => !o && setDel(null)}
        title={`Delete directory source "${del?.name ?? ""}"?`}
        description="Directory-backed authentication falls back to local users."
        loading={delMut.isPending}
        onConfirm={() => del && void delMut.mutateAsync(del.id)}
      />
    </Card>
  );
}

function DirectoryRow(props: { source: DirectorySourceDTO; onToggle: () => void; onEdit: () => void; onDelete: () => void }) {
  const [test, setTest] = useState<{ ok: boolean; latencyMs: number; userCount?: number; error?: string } | null>(null);

  const testMut = useMutation({
    mutationFn: () => directoryApi.test(props.source.id),
    onSuccess: (r) => setTest(r),
    onError: (e) => toastErr(e, "Test failed"),
  });

  return (
    <TableRow>
      <TableCell className="font-medium">{props.source.name}</TableCell>
      <TableCell>
        <DirectoryTypeChip type={props.source.type} />
      </TableCell>
      <TableCell className="font-mono text-xs">
        {props.source.serverIp}:{props.source.port}
      </TableCell>
      <TableCell className="max-w-52 truncate font-mono text-[11px] text-zinc-500" title={props.source.baseDn}>
        {props.source.baseDn}
      </TableCell>
      <TableCell>
        <Switch checked={props.source.enabled} onCheckedChange={props.onToggle} aria-label={`Toggle ${props.source.name}`} />
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" className="h-7 text-[11px]" onClick={() => void testMut.mutateAsync()} disabled={testMut.isPending}>
            {testMut.isPending ? "Testing…" : "Test"}
          </Button>
          {test && <TestResultPill ok={test.ok} label={test.ok ? `${test.latencyMs} ms${test.userCount ? ` · ${test.userCount} users` : ""}` : "refused"} />}
        </div>
      </TableCell>
      <TableCell>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${props.source.name}`}>
              <Icons.MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={props.onEdit}>
              <Icons.Pencil className="mr-2 h-3.5 w-3.5" /> Edit
            </DropdownMenuItem>
            <DropdownMenuItem className="text-rose-600 focus:text-rose-600 dark:text-rose-400" onClick={props.onDelete}>
              <Icons.Trash2 className="mr-2 h-3.5 w-3.5" /> Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  );
}

function DirectoryEditorDialog(props: { open: boolean; source: DirectorySourceDTO | null; onClose: () => void }) {
  // Radix unmounts content when closed — the form remounts fresh per open.
  return (
    <Dialog open={props.open} onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
        <DirectoryEditorForm source={props.source} onClose={props.onClose} />
      </DialogContent>
    </Dialog>
  );
}

function DirectoryEditorForm(props: { source: DirectorySourceDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.source !== null;
  const [name, setName] = useState(() => props.source?.name ?? "");
  const [type, setType] = useState<"ldap" | "ad">(() => (props.source?.type === "ad" ? "ad" : "ldap"));
  const [serverIp, setServerIp] = useState(() => props.source?.serverIp ?? "");
  const [port, setPort] = useState(() => String(props.source?.port ?? 389));
  const [baseDn, setBaseDn] = useState(() => props.source?.baseDn ?? "");
  const [bindDn, setBindDn] = useState(() => props.source?.bindDn ?? "");
  const [bindPassword, setBindPassword] = useState("");
  const [userFilter, setUserFilter] = useState(() => props.source?.userFilter ?? "");
  const [enabled, setEnabled] = useState(() => props.source?.enabled ?? true);
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const save = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { name, type, serverIp, port: Number(port), baseDn, bindDn, userFilter, enabled };
      if (bindPassword) body.bindPassword = bindPassword; // omit = keep stored
      return isEdit ? directoryApi.update(props.source!.id, body) : directoryApi.create({ ...body, bindPassword });
    },
    onSuccess: () => {
      toastOk(isEdit ? "Source updated" : "Source created", name);
      void queryClient.invalidateQueries({ queryKey: ["directory"] });
      props.onClose();
    },
    onError: (e) => {
      setErrs(fieldErrorsOf(e));
      toastErr(e, "Save failed");
    },
  });

  return (
    <>
      <DialogHeader>
        <DialogTitle>{isEdit ? `Edit ${props.source!.name}` : "Add Directory Source"}</DialogTitle>
        <DialogDescription>
          Bind credentials are write-only — they are never returned by the API and have no reveal endpoint.
        </DialogDescription>
      </DialogHeader>
        <div className="space-y-3">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div>
              <FieldLabel>Name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.currentTarget.value)} placeholder="CORP-AD" className={cn(errs.name && "border-rose-500")} />
              {errs.name?.map((m) => (
                <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
              ))}
            </div>
            <div>
              <FieldLabel>Type</FieldLabel>
              <RadioGroup value={type} onValueChange={(v) => setType(v as "ldap" | "ad")} className="flex gap-4 pt-1">
                <label className="flex cursor-pointer items-center gap-1.5 text-sm">
                  <RadioGroupItem value="ldap" /> LDAP
                </label>
                <label className="flex cursor-pointer items-center gap-1.5 text-sm">
                  <RadioGroupItem value="ad" /> Active Directory
                </label>
              </RadioGroup>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <div className="col-span-2">
              <FieldLabel>Server</FieldLabel>
              <Input value={serverIp} onChange={(e) => setServerIp(e.currentTarget.value)} placeholder="10.0.0.5" className={cn("font-mono text-xs", errs.serverIp && "border-rose-500")} />
              {errs.serverIp?.map((m) => (
                <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
              ))}
            </div>
            <div>
              <FieldLabel>Port</FieldLabel>
              <Input type="number" value={port} onChange={(e) => setPort(e.currentTarget.value)} className={cn(errs.port && "border-rose-500")} />
            </div>
          </div>
          <div>
            <FieldLabel>Base DN</FieldLabel>
            <Input value={baseDn} onChange={(e) => setBaseDn(e.currentTarget.value)} placeholder="dc=corp,dc=local" className={cn("font-mono text-xs", errs.baseDn && "border-rose-500")} />
            {errs.baseDn?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div>
            <FieldLabel hint="optional">Bind DN</FieldLabel>
            <Input value={bindDn} onChange={(e) => setBindDn(e.currentTarget.value)} placeholder="cn=svc-cryptsk,dc=corp,dc=local" className={cn("font-mono text-xs", errs.bindDn && "border-rose-500")} />
            {errs.bindDn?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div>
            <FieldLabel hint={isEdit ? "blank = keep current" : "optional"}>Bind password</FieldLabel>
            <Input
              type="password"
              value={bindPassword}
              onChange={(e) => setBindPassword(e.currentTarget.value)}
              placeholder={isEdit ? "Leave blank to keep" : "Bind password"}
              className={cn("font-mono text-xs", errs.bindPassword && "border-rose-500")}
            />
            {errs.bindPassword?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div>
            <FieldLabel hint="optional">User filter</FieldLabel>
            <Input value={userFilter} onChange={(e) => setUserFilter(e.currentTarget.value)} placeholder="(memberOf=cn=vpn,ou=groups,dc=corp,dc=local)" className={cn("font-mono text-xs", errs.userFilter && "border-rose-500")} />
            {errs.userFilter?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div className="flex items-center justify-between">
            <FieldLabel>Enabled</FieldLabel>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Source enabled" />
          </div>
        </div>
      <DialogFooter>
        <Button variant="outline" onClick={props.onClose}>Cancel</Button>
        <Button onClick={() => void save.mutateAsync()} disabled={save.isPending || !name || !serverIp || !baseDn}>
          {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create source"}
        </Button>
      </DialogFooter>
    </>
  );
}

// ── auth settings editor ────────────────────────────────────────────────────

export function AuthSettingsTab() {
  const q = useQuery({ queryKey: ["auth-settings"], queryFn: authSettingsApi.get });

  if (q.isLoading) {
    return (
      <Card>
        <CardContent className="space-y-3 pt-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-9 w-full animate-pulse rounded-md bg-zinc-100 dark:bg-zinc-800" />
          ))}
        </CardContent>
      </Card>
    );
  }
  if (q.isError) return <QueryError error={q.error} onRetry={() => void q.refetch()} />;
  if (!q.data) return null;
  return <AuthSettingsForm key={q.dataUpdatedAt} initial={q.data} />;
}

function AuthSettingsForm({ initial }: { initial: AuthSettings }) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<AuthSettings>(initial);
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const save = useMutation({
    mutationFn: () => authSettingsApi.put(form),
    onSuccess: () => {
      toastOk("Auth settings saved", "Applies to new/changed passwords and new logins.");
      void queryClient.invalidateQueries({ queryKey: ["auth-settings"] });
    },
    onError: (e) => {
      setErrs(fieldErrorsOf(e));
      toastErr(e, "Save failed");
    },
  });

  const num = (v: string) => (v === "" ? NaN : Number(v));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card className="gap-4">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.KeyRound className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            Password Policy
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <FieldLabel hint="8–64">Minimum length</FieldLabel>
              <Input
                type="number"
                value={form.password.minLength}
                onChange={(e) => setForm({ ...form, password: { ...form.password, minLength: num(e.currentTarget.value) } })}
                className={cn(errs["password.minLength"] && "border-rose-500")}
              />
            </div>
            <div>
              <FieldLabel hint="0 = never">Expiry (days)</FieldLabel>
              <Input
                type="number"
                value={form.password.expiryDays}
                onChange={(e) => setForm({ ...form, password: { ...form.password, expiryDays: num(e.currentTarget.value) } })}
                className={cn(errs["password.expiryDays"] && "border-rose-500")}
              />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Require complexity</p>
              <p className="text-[11px] text-zinc-400">Letters and digits must both be present</p>
            </div>
            <Switch
              checked={form.password.requireComplexity}
              onCheckedChange={(v) => setForm({ ...form, password: { ...form.password, requireComplexity: v } })}
              aria-label="Require password complexity"
            />
          </div>
          {errs["password.minLength"]?.concat(errs["password.expiryDays"] ?? []).map((m) => (
            <p key={m} className="text-[11px] text-rose-500">{m}</p>
          ))}
          <InfoNote>Policy applies to new or changed passwords; expiry is checked at login (simulated).</InfoNote>
        </CardContent>
      </Card>

      <Card className="gap-4">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.LockKeyhole className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            Lockout &amp; Sessions
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div>
              <FieldLabel hint="3–10">Max attempts</FieldLabel>
              <Input
                type="number"
                value={form.lockout.maxAttempts}
                onChange={(e) => setForm({ ...form, lockout: { ...form.lockout, maxAttempts: num(e.currentTarget.value) } })}
                className={cn(errs["lockout.maxAttempts"] && "border-rose-500")}
              />
            </div>
            <div>
              <FieldLabel hint="5–60">Window (min)</FieldLabel>
              <Input
                type="number"
                value={form.lockout.windowMin}
                onChange={(e) => setForm({ ...form, lockout: { ...form.lockout, windowMin: num(e.currentTarget.value) } })}
                className={cn(errs["lockout.windowMin"] && "border-rose-500")}
              />
            </div>
            <div>
              <FieldLabel hint="1–24">Session (h)</FieldLabel>
              <Input
                type="number"
                value={form.sessionLifetimeHours}
                onChange={(e) => setForm({ ...form, sessionLifetimeHours: num(e.currentTarget.value) })}
                className={cn(errs.sessionLifetimeHours && "border-rose-500")}
              />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <FieldLabel hint="1–16">Concurrent sessions / user</FieldLabel>
              <Input
                type="number"
                value={form.sessionLimits.maxConcurrentPerUser}
                onChange={(e) => setForm({ ...form, sessionLimits: { ...form.sessionLimits, maxConcurrentPerUser: num(e.currentTarget.value) } })}
                className={cn(errs["sessionLimits.maxConcurrentPerUser"] && "border-rose-500")}
              />
            </div>
            <div className="flex items-end justify-between gap-2 pb-1.5">
              <div>
                <p className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Require TOTP</p>
                <p className="text-[11px] text-zinc-400">All logins must present a code</p>
              </div>
              <Switch checked={form.totp.required} onCheckedChange={(v) => setForm({ ...form, totp: { required: v } })} aria-label="Require TOTP" />
            </div>
          </div>
          <InfoNote>
            Exceeding the concurrent cap expires the user&rsquo;s oldest session — visible live on #/identity/sessions.
          </InfoNote>
        </CardContent>
      </Card>

      <div className="lg:col-span-2">
        <Button onClick={() => void save.mutateAsync()} disabled={save.isPending}>
          {save.isPending ? "Saving…" : "Save auth settings"}
        </Button>
      </div>
    </div>
  );
}

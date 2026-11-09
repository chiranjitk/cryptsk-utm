"use client";

/**
 * Identity Users view (M07 §4) — hash #/identity/users.
 * Layout: users DataTable (primary) + User Groups card in a two-column xl
 * grid; secondary panels in tabs below — RADIUS Profiles | Directory Sources |
 * Auth Settings. Mutations broadcast config:updated {section:"identity"}
 * (invalidated by useIdentityConfigInvalidation). TOTP enrollment shows the
 * otpauth URI + secret exactly once. Secrets (sharedSecret/bindPassword) are
 * masked server-side; reveal is a second-click, auto-hiding action.
 */

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, MultiChips, toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import {
  fieldErrorsOf,
  fmtDateTime,
  groupsApi,
  usersApi,
  type TotpEnrollResult,
  type UserDTO,
  type UserGroupDTO,
} from "./identity-api";
import { InfoNote, RoleBadge, useIdentityConfigInvalidation } from "./identity-ui";
import { RadiusTab, DirectoryTab, AuthSettingsTab } from "./identity-panels";
import { ROLES } from "@/lib/auth/rbac";
import { cn } from "@/lib/utils";

// ── role descriptions (AUTH_AND_RBAC §4 via M07 §4 — help text) ─────────────

const ROLE_DESCRIPTIONS: Array<[string, string]> = [
  ["super_admin", "Everything, including HA, backup/restore, API keys, auth settings, user management"],
  ["tenant_admin", "Full configuration of the tenant's security/network stack; no appliance-level system keys"],
  ["security_admin", "Firewall, NAT, objects, IPS policies + events, VPN session operations, logs and threat response"],
  ["network_admin", "Interfaces, routing, WAN, DHCP, DNS, QoS, HA, VPN configuration"],
  ["soc_analyst", "Read security telemetry; live tail; suppress IPS events"],
  ["helpdesk", "Read identity sessions and VPN sessions; mark notifications read; no configuration or user changes"],
  ["auditor", "Read-only everywhere, including audit log"],
  ["api_service", "Machine-account marker role (API keys act through scopes, not this role's UI)"],
];

export function UsersView() {
  useIdentityConfigInvalidation();
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="min-w-0 xl:col-span-2">
          <UsersCard />
        </div>
        <GroupsCard />
      </div>

      <Tabs defaultValue="radius">
        <TabsList className="flex w-full flex-wrap justify-start gap-1 sm:w-auto">
          <TabsTrigger value="radius" className="text-xs sm:text-sm">RADIUS Profiles</TabsTrigger>
          <TabsTrigger value="directory" className="text-xs sm:text-sm">Directory Sources</TabsTrigger>
          <TabsTrigger value="auth" className="text-xs sm:text-sm">Auth Settings</TabsTrigger>
        </TabsList>
        <TabsContent value="radius" className="mt-3">
          <RadiusTab />
        </TabsContent>
        <TabsContent value="directory" className="mt-3">
          <DirectoryTab />
        </TabsContent>
        <TabsContent value="auth" className="mt-3">
          <AuthSettingsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── users table ─────────────────────────────────────────────────────────────

function UsersCard() {
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [editor, setEditor] = useState<{ open: boolean; user: UserDTO | null }>({ open: false, user: null });
  const [resetPw, setResetPw] = useState<UserDTO | null>(null);
  const [enrollment, setEnrollment] = useState<TotpEnrollResult | null>(null);
  const [deleteUser, setDeleteUser] = useState<UserDTO | null>(null);

  const usersQ = useQuery({
    queryKey: ["users", "list", q],
    queryFn: () => usersApi.list(q ? `q=${encodeURIComponent(q)}` : ""),
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["users"] });
    void queryClient.invalidateQueries({ queryKey: ["groups"] });
  };

  const del = useMutation({
    mutationFn: (id: number) => usersApi.delete(id),
    onSuccess: () => {
      toastOk("User deleted", "Group memberships removed; audit history preserved as former-username.");
      invalidate();
      setDeleteUser(null);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  const enroll = useMutation({
    mutationFn: async (user: UserDTO) => {
      if (user.totpEnrolled) {
        return usersApi.update(user.id, { totpEnroll: false });
      }
      return usersApi.update(user.id, { totpEnroll: true });
    },
    onSuccess: (updated) => {
      invalidate();
      if (updated.totpEnrollment) setEnrollment(updated.totpEnrollment);
      else toastOk("TOTP disenrolled", "The user can sign in with password only again.");
    },
    onError: (e) => toastErr(e, "TOTP change failed"),
  });

  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Users className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Users
          {usersQ.data ? (
            <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 px-1.5 text-[10px] text-zinc-600 dark:text-zinc-300">
              {usersQ.data.length}
            </Badge>
          ) : null}
        </CardTitle>
        <div className="flex w-full flex-wrap items-center justify-between gap-2 sm:w-auto sm:flex-nowrap">
          <Input
            value={q}
            onChange={(e) => setQ(e.currentTarget.value)}
            placeholder="Search users…"
            aria-label="Search users"
            className="h-9 w-36 text-xs sm:w-48"
          />
          <Button size="sm" className="h-9" onClick={() => setEditor({ open: true, user: null })}>
            <Icons.UserPlus className="mr-1 h-3.5 w-3.5" /> Add User
          </Button>
        </div>
      </CardHeader>
      <CardContent className="px-0">
        {usersQ.isLoading ? (
          <div className="px-6">
            <TableSkeleton rows={6} cols={6} />
          </div>
        ) : usersQ.isError ? (
          <QueryError error={usersQ.error} onRetry={() => void usersQ.refetch()} />
        ) : (usersQ.data?.length ?? 0) === 0 ? (
          <EmptyBlock
            icon={<Icons.Users className="h-6 w-6" />}
            title="No users match"
            description={q ? "Try a different search term." : "Create the first local user."}
          />
        ) : (
          <div className="max-h-96 overflow-x-auto overflow-y-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Groups</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last login</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {usersQ.data!.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>
                      <p className="flex items-center gap-1.5 font-medium">
                        {u.username}
                        {u.totpEnrolled && (
                          <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 px-1 py-0 text-[9px] text-emerald-600 dark:text-emerald-400">
                            <Icons.Smartphone className="mr-0.5 h-2.5 w-2.5" />TOTP
                          </Badge>
                        )}
                      </p>
                      <p className="text-[11px] text-zinc-400">{u.email ?? "—"}</p>
                    </TableCell>
                    <TableCell>
                      <RoleBadge role={u.role} />
                    </TableCell>
                    <TableCell>
                      {u.groups.length === 0 ? (
                        <span className="text-[11px] text-zinc-400">none</span>
                      ) : (
                        <span className="flex flex-wrap gap-1">
                          {u.groups.map((g) => (
                            <Badge key={g.id} variant="outline" className="border-zinc-500/30 bg-zinc-500/10 px-1.5 py-0 text-[10px] text-zinc-600 dark:text-zinc-300">
                              {g.name}
                            </Badge>
                          ))}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={cn(
                          "px-1.5 py-0 text-[10px]",
                          u.isActive
                            ? "border-transparent bg-emerald-600 text-white"
                            : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400",
                        )}
                      >
                        {u.isActive ? "enabled" : "disabled"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">{fmtDateTime(u.lastLoginAt)}</TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${u.username}`}>
                            <Icons.MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-48">
                          <DropdownMenuItem onClick={() => setEditor({ open: true, user: u })}>
                            <Icons.Pencil className="mr-2 h-3.5 w-3.5" /> Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => setResetPw(u)}>
                            <Icons.KeyRound className="mr-2 h-3.5 w-3.5" /> Reset password
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => void enroll.mutateAsync(u)} disabled={enroll.isPending}>
                            {u.totpEnrolled ? (
                              <>
                                <Icons.Smartphone className="mr-2 h-3.5 w-3.5" /> Disenroll TOTP
                              </>
                            ) : (
                              <>
                                <Icons.Smartphone className="mr-2 h-3.5 w-3.5" /> Enroll TOTP
                              </>
                            )}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-rose-600 focus:text-rose-600 dark:text-rose-400" onClick={() => setDeleteUser(u)}>
                            <Icons.Trash2 className="mr-2 h-3.5 w-3.5" /> Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      <UserEditorDialog
        open={editor.open}
        user={editor.user}
        onClose={() => setEditor({ open: false, user: null })}
        onEnrolled={(secret) => setEnrollment(secret)}
      />
      <ResetPasswordDialog user={resetPw} onClose={() => setResetPw(null)} />

      <Dialog open={enrollment !== null} onOpenChange={(o) => !o && setEnrollment(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Icons.Smartphone className="h-5 w-5 text-emerald-600" /> TOTP enrollment
            </DialogTitle>
            <DialogDescription>
              Scan the URI with your authenticator app or paste the secret. Shown <strong>only once</strong> — it is never displayed again.
            </DialogDescription>
          </DialogHeader>
          {enrollment && (
            <div className="space-y-3">
              <div>
                <FieldLabel>otpauth URI</FieldLabel>
                <div className="flex items-start gap-2">
                  <code className="max-h-20 flex-1 overflow-y-auto rounded-md border border-zinc-200 bg-zinc-50 p-2 font-mono text-[11px] break-all dark:border-zinc-800 dark:bg-zinc-900">
                    {enrollment.otpauthUri}
                  </code>
                  <Button variant="outline" size="icon" className="h-8 w-8 shrink-0" aria-label="Copy otpauth URI" onClick={() => void navigator.clipboard.writeText(enrollment.otpauthUri)}>
                    <Icons.Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
              <div>
                <FieldLabel hint="demo: verify codes at login with this secret">Secret (base32)</FieldLabel>
                <div className="flex items-center gap-2">
                  <code className="flex-1 rounded-md border border-zinc-200 bg-zinc-50 p-2 font-mono text-xs tracking-widest dark:border-zinc-800 dark:bg-zinc-900">
                    {enrollment.secret}
                  </code>
                  <Button variant="outline" size="icon" className="h-8 w-8 shrink-0" aria-label="Copy secret" onClick={() => void navigator.clipboard.writeText(enrollment.secret)}>
                    <Icons.Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
              <InfoNote>
                TOTP-enrolled users must present a 6-digit code at login. Tenant-wide enforcement lives in Auth Settings → &ldquo;Require TOTP&rdquo;.
              </InfoNote>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setEnrollment(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleteUser !== null}
        onOpenChange={(o) => !o && setDeleteUser(null)}
        title={`Delete user "${deleteUser?.username ?? ""}"?`}
        description="Group memberships are removed. Audit history is preserved under the former username. This cannot be undone."
        loading={del.isPending}
        onConfirm={() => deleteUser && void del.mutateAsync(deleteUser.id)}
      />
    </Card>
  );
}

// ── user editor dialog ──────────────────────────────────────────────────────

function UserEditorDialog(props: {
  open: boolean;
  user: UserDTO | null;
  onClose: () => void;
  onEnrolled: (t: TotpEnrollResult) => void;
}) {
  // Radix unmounts content when closed — the form remounts fresh per open.
  return (
    <Dialog open={props.open} onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
        <UserEditorForm user={props.user} onClose={props.onClose} onEnrolled={props.onEnrolled} />
      </DialogContent>
    </Dialog>
  );
}

function UserEditorForm(props: { user: UserDTO | null; onClose: () => void; onEnrolled: (t: TotpEnrollResult) => void }) {
  const isEdit = props.user !== null;
  const [username, setUsername] = useState(() => props.user?.username ?? "");
  const [email, setEmail] = useState(() => props.user?.email ?? "");
  const [role, setRole] = useState(() => props.user?.role ?? "helpdesk");
  const [isActive, setIsActive] = useState(() => props.user?.isActive ?? true);
  const [password, setPassword] = useState("");
  const [groupIds, setGroupIds] = useState<number[]>(() => props.user?.groups.map((g) => g.id) ?? []);
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const groupsQ = useQuery({ queryKey: ["groups", "list"], queryFn: groupsApi.list });

  const save = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { email, role, isActive, groupIds };
      if (!isEdit) {
        body.username = username;
        body.password = password;
      } else if (password) {
        body.password = password;
      }
      return isEdit ? usersApi.update(props.user!.id, body) : usersApi.create(body);
    },
    onSuccess: (created, _vars) => {
      if (!isEdit && (created as UserDTO & { totpEnrollment?: TotpEnrollResult }).totpEnrollment) {
        props.onEnrolled((created as UserDTO & { totpEnrollment?: TotpEnrollResult }).totpEnrollment!);
      }
      toastOk(isEdit ? "User updated" : "User created", isEdit ? props.user!.username : `Welcome, ${created.username}`);
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
        <DialogTitle>{isEdit ? `Edit ${props.user!.username}` : "Add User"}</DialogTitle>
        <DialogDescription>
          {isEdit ? "Leave the password blank to keep the current one." : "The password is policy-checked server-side and never echoed back."}
        </DialogDescription>
      </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel>Username</FieldLabel>
            <Input
              value={username}
              onChange={(e) => setUsername(e.currentTarget.value)}
              disabled={isEdit}
              placeholder="j.doe"
              className={cn("font-mono text-xs", errs.username && "border-rose-500")}
            />
            {errs.username?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div>
            <FieldLabel>Email</FieldLabel>
            <Input
              value={email}
              onChange={(e) => setEmail(e.currentTarget.value)}
              placeholder="name@company.com"
              className={cn(errs.email && "border-rose-500")}
            />
            {errs.email?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <FieldLabel>Role</FieldLabel>
              <Select value={role} onValueChange={setRole}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.filter((r) => r !== "api_service" || isEdit === false).map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end justify-between gap-2 pb-1">
              <FieldLabel>Active</FieldLabel>
              <Switch checked={isActive} onCheckedChange={setIsActive} aria-label="User enabled" />
            </div>
          </div>
          <div className="rounded-md border border-zinc-200 dark:border-zinc-800">
            <Table>
              <TableBody>
                {ROLE_DESCRIPTIONS.map(([r, d]) => (
                  <TableRow key={r} className={cn(r === role && "bg-zinc-500/10")}>
                    <TableCell className="w-32 py-1.5 align-top">
                      <code className="text-[11px] font-medium">{r}</code>
                    </TableCell>
                    <TableCell className="py-1.5 text-[11px] text-zinc-500">{d}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div>
            <FieldLabel hint="toggle to include/exclude">Groups</FieldLabel>
            <MultiChips
              options={(groupsQ.data ?? []).map((g) => ({ id: g.id, label: g.name }))}
              selected={groupIds}
              onToggle={(id) => setGroupIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]))}
              emptyLabel="no groups"
            />
          </div>
          <div>
            <FieldLabel hint={isEdit ? "blank = keep current" : "letters + digits, per auth policy"}>Password</FieldLabel>
            <div className="flex items-center gap-2">
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.currentTarget.value)}
                placeholder={isEdit ? "Leave blank to keep" : "Set an initial password"}
                className={cn("font-mono text-xs", errs.password && "border-rose-500")}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-9 shrink-0"
                onClick={() => {
                  const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
                  let out = "";
                  const buf = new Uint32Array(12);
                  crypto.getRandomValues(buf);
                  for (let i = 0; i < 12; i++) out += chars[buf[i]! % chars.length];
                  // guarantee a digit
                  if (!/\d/.test(out)) out = out.slice(0, -1) + "7";
                  setPassword(out);
                }}
              >
                <Icons.Wand2 className="mr-1 h-3.5 w-3.5" /> Generate
              </Button>
            </div>
            {errs.password?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
        </div>
      <DialogFooter>
        <Button variant="outline" onClick={props.onClose}>Cancel</Button>
        <Button onClick={() => void save.mutateAsync()} disabled={save.isPending || (!isEdit && (!username || !password))}>
          {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create user"}
        </Button>
      </DialogFooter>
    </>
  );
}

function ResetPasswordDialog(props: { user: UserDTO | null; onClose: () => void }) {
  // Radix unmounts content when closed — the form remounts fresh per open.
  return (
    <Dialog open={props.user !== null} onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        {props.user && <ResetPasswordForm user={props.user} onClose={props.onClose} />}
      </DialogContent>
    </Dialog>
  );
}

function ResetPasswordForm(props: { user: UserDTO; onClose: () => void }) {
  const [password, setPassword] = useState("");
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const reset = useMutation({
    mutationFn: () => usersApi.update(props.user.id, { password }),
    onSuccess: () => {
      toastOk("Password reset", `New password set for ${props.user.username}.`);
      props.onClose();
    },
    onError: (e) => {
      setErrs(fieldErrorsOf(e));
      toastErr(e, "Reset failed");
    },
  });

  return (
    <>
      <DialogHeader>
        <DialogTitle>Reset password — {props.user.username}</DialogTitle>
        <DialogDescription>The new password is policy-checked and never echoed back.</DialogDescription>
      </DialogHeader>
      <div>
        <FieldLabel hint="letters + digits, per auth policy">New password</FieldLabel>
        <Input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
          className={cn("font-mono text-xs", errs.password && "border-rose-500")}
        />
        {errs.password?.map((m) => (
          <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
        ))}
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={props.onClose}>Cancel</Button>
        <Button onClick={() => void reset.mutateAsync()} disabled={reset.isPending || !password}>
          {reset.isPending ? "Setting…" : "Set password"}
        </Button>
      </DialogFooter>
    </>
  );
}

// ── user groups card ────────────────────────────────────────────────────────

function GroupsCard() {
  const queryClient = useQueryClient();
  const [editor, setEditor] = useState<{ open: boolean; group: UserGroupDTO | null }>({ open: false, group: null });
  const [del, setDel] = useState<UserGroupDTO | null>(null);

  const groupsQ = useQuery({ queryKey: ["groups", "list"], queryFn: groupsApi.list });

  const delMut = useMutation({
    mutationFn: (id: number) => groupsApi.delete(id),
    onSuccess: () => {
      toastOk("Group deleted", "Memberships removed; users untouched.");
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setDel(null);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.UsersRound className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          User Groups
        </CardTitle>
        <Button size="sm" variant="outline" className="h-9" onClick={() => setEditor({ open: true, group: null })}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add Group
        </Button>
      </CardHeader>
      <CardContent>
        {groupsQ.isLoading ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded-md bg-zinc-100 dark:bg-zinc-800" />
            ))}
          </div>
        ) : groupsQ.isError ? (
          <QueryError error={groupsQ.error} onRetry={() => void groupsQ.refetch()} />
        ) : (groupsQ.data?.length ?? 0) === 0 ? (
          <EmptyBlock
            icon={<Icons.UsersRound className="h-6 w-6" />}
            title="Create your first group"
            description="Groups bundle users for firewall rules, VPN policies and QoS."
          />
        ) : (
          <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
            {groupsQ.data!.map((g) => (
              <div key={g.id} className="flex items-center justify-between gap-2 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{g.name}</p>
                  <p className="truncate text-[11px] text-zinc-400">{g.description || `${g.memberCount} member${g.memberCount === 1 ? "" : "s"}`}</p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Badge variant="outline" className="border-zinc-300 bg-zinc-50 px-1.5 py-0 text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
                    {g.memberCount} {g.memberCount === 1 ? "member" : "members"}
                  </Badge>
                  <Button variant="ghost" size="icon" className="h-7 w-7" aria-label={`Edit group ${g.name}`} onClick={() => setEditor({ open: true, group: g })}>
                    <Icons.Pencil className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="h-7 w-7 text-zinc-400 hover:text-rose-500" aria-label={`Delete group ${g.name}`} onClick={() => setDel(g)}>
                    <Icons.Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>

      <GroupEditorDialog open={editor.open} group={editor.group} onClose={() => setEditor({ open: false, group: null })} />
      <ConfirmDialog
        open={del !== null}
        onOpenChange={(o) => !o && setDel(null)}
        title={`Delete group "${del?.name ?? ""}"?`}
        description="Memberships are removed. Users themselves are untouched."
        loading={delMut.isPending}
        onConfirm={() => del && void delMut.mutateAsync(del.id)}
      />
    </Card>
  );
}

function GroupEditorDialog(props: { open: boolean; group: UserGroupDTO | null; onClose: () => void }) {
  // Radix unmounts content when closed — the form remounts fresh per open.
  return (
    <Dialog open={props.open} onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-md">
        <GroupEditorForm group={props.group} onClose={props.onClose} />
      </DialogContent>
    </Dialog>
  );
}

function GroupEditorForm(props: { group: UserGroupDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.group !== null;
  const [name, setName] = useState(() => props.group?.name ?? "");
  const [description, setDescription] = useState(() => props.group?.description ?? "");
  const [memberIds, setMemberIds] = useState<number[]>(() => props.group?.memberIds ?? []);
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const usersQ = useQuery({ queryKey: ["users", "list", ""], queryFn: () => usersApi.list("") });

  const save = useMutation({
    mutationFn: async () => {
      const body = { name, description: description || null, memberIds };
      return isEdit ? groupsApi.update(props.group!.id, body) : groupsApi.create(body);
    },
    onSuccess: () => {
      toastOk(isEdit ? "Group updated" : "Group created", name);
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      void queryClient.invalidateQueries({ queryKey: ["users"] });
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
        <DialogTitle>{isEdit ? `Edit ${props.group!.name}` : "Add Group"}</DialogTitle>
        <DialogDescription>Saving replaces the member set (replace-all semantics).</DialogDescription>
      </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.currentTarget.value)} placeholder="it-staff" className={cn(errs.name && "border-rose-500")} />
            {errs.name?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div>
            <FieldLabel hint="optional">Description</FieldLabel>
            <Input value={description} onChange={(e) => setDescription(e.currentTarget.value)} placeholder="What is this group for?" />
          </div>
          <div>
            <FieldLabel hint={`${memberIds.length} selected`}>Members</FieldLabel>
            <div className="max-h-48 space-y-1 overflow-y-auto rounded-md border border-zinc-200 p-2 dark:border-zinc-800">
              {(usersQ.data ?? []).map((u) => {
                const checked = memberIds.includes(u.id);
                return (
                  <label key={u.id} className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800/60">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => setMemberIds((prev) => (prev.includes(u.id) ? prev.filter((x) => x !== u.id) : [...prev, u.id]))}
                      className="h-3.5 w-3.5 accent-red-700"
                      aria-label={`Include ${u.username}`}
                    />
                    <span className="font-mono text-xs">{u.username}</span>
                    <span className="ml-auto text-[10px] text-zinc-400">{u.role}</span>
                  </label>
                );
              })}
              {errs.memberIds?.map((m) => (
                <p key={m} className="text-[11px] text-rose-500">{m}</p>
              ))}
            </div>
          </div>
        </div>
      <DialogFooter>
        <Button variant="outline" onClick={props.onClose}>Cancel</Button>
        <Button onClick={() => void save.mutateAsync()} disabled={save.isPending || !name}>
          {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create group"}
        </Button>
      </DialogFooter>
    </>
  );
}

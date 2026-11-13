"use client";

/**
 * #/pki/certificates — end-entity certificate management (M14 §2.12).
 * Toolbar with CA/type/status/search filters and an "Expiring ≤30d" chip that
 * switches the table into expiry-monitoring mode. "Issue certificate" walks
 * an ACTIVE CA and generates real X.509 material (node-forge) server-side.
 * Private-key download is admin-only (403 → "Forbidden — admin only" toast).
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
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import {
  ISSUED_FOR_LABELS,
  KEY_TYPE_LABELS,
  PkiApiError,
  fieldErrorsOf,
  pkiApi,
  qs,
  type CaDto,
  type CertDto,
  type IssuedFor,
  type PkiKeyType,
  type RevocationReason,
} from "./pki-api";
import { CertTypeBadge, ExpiryPill, IssuedForChip, PkiStatusBadge, SansChips } from "./pki-ui";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const REVOKE_REASONS: RevocationReason[] = ["unspecified", "keyCompromise", "caCompromise", "superseded", "ceaseOfOperation"];

// ── main view ───────────────────────────────────────────────────────────────

export function CertificatesView() {
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [caId, setCaId] = useState("");
  const [type, setType] = useState("");
  const [status, setStatus] = useState("");
  const [expiringOnly, setExpiringOnly] = useState(false);

  const casQuery = useQuery({ queryKey: ["pki", "cas"], queryFn: pkiApi.listCas });
  const cas = useMemo(() => casQuery.data ?? [], [casQuery.data]);
  const activeCas = useMemo(() => cas.filter((c) => c.status === "active"), [cas]);

  const params = qs({ q, caId, type, status: status === "expiring" ? "" : status });
  const certsQuery = useQuery({
    queryKey: ["pki", "certs", params],
    queryFn: () => pkiApi.listCerts(params),
  });
  const expiringQuery = useQuery({
    queryKey: ["pki", "expiring", 30],
    queryFn: () => pkiApi.listExpiring(30),
  });
  const expiringCount = expiringQuery.data?.length ?? 0;

  const certs = useMemo(() => {
    let rows = certsQuery.data ?? [];
    if (expiringOnly) {
      const ids = new Set((expiringQuery.data ?? []).map((c) => c.id));
      rows = rows.filter((c) => ids.has(c.id));
    }
    if (status === "expiring") {
      // client-side facet — computed from the expiry pill, not a server status
      rows = rows.filter((c) => c.status === "active" && c.daysUntilExpiry !== null && c.daysUntilExpiry <= 30);
    }
    return rows;
  }, [certsQuery.data, expiringOnly, expiringQuery.data, status]);

  const [issueOpen, setIssueOpen] = useState(false);
  const [revoking, setRevoking] = useState<CertDto | null>(null);
  const [deleting, setDeleting] = useState<CertDto | null>(null);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["pki", "certs"] });
    void queryClient.invalidateQueries({ queryKey: ["pki", "expiring"] });
    void queryClient.invalidateQueries({ queryKey: ["pki", "cas"] }); // issuedCount
  };

  const deleteMut = useMutation({
    mutationFn: (id: number) => pkiApi.deleteCert(id),
    onSuccess: () => {
      toastOk("Certificate deleted");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      setDeleting(null);
      toastErr(err, "Delete failed");
    },
  });

  const doExport = async (cert: CertDto, part: "cert" | "key" | "chain") => {
    try {
      const { filename } = await pkiApi.downloadCert(cert.id, part, `${cert.name}.${part === "key" ? "key" : part === "chain" ? "chain.pem" : "crt"}`);
      toastOk(`Exported ${filename}`);
    } catch (err) {
      if (err instanceof PkiApiError && err.code === "FORBIDDEN") toastErr(err, "Forbidden — admin only");
      else toastErr(err, "Download failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-zinc-500">
          End-entity certificates issued by the local authorities — SSL inspection, WAF, VPN and general TLS identities.
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setExpiringOnly((v) => !v)}
            aria-pressed={expiringOnly}
            className={cn(
              "inline-flex min-h-9 items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors",
              expiringOnly
                ? "border-rose-600/40 bg-rose-600/10 text-rose-600 dark:text-rose-400"
                : "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 hover:bg-zinc-500/20 dark:text-zinc-300",
            )}
          >
            <Icons.CalendarClock className="h-3.5 w-3.5" />
            Expiring ≤30d
            <Badge variant="outline" className="ml-1 border-transparent bg-white/60 px-1.5 text-[10px] dark:bg-zinc-900/60">
              {expiringCount}
            </Badge>
          </button>
          <Button size="sm" className="gap-1.5" onClick={() => setIssueOpen(true)} disabled={activeCas.length === 0}>
            <Icons.Plus className="h-4 w-4" /> Issue certificate
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 p-3">
          <div className="relative min-w-52 flex-1">
            <Icons.Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, CN or serial…" className="pl-8" aria-label="Search certificates" />
          </div>
          <Select value={caId} onValueChange={(v) => setCaId(v === "all" ? "" : v)}>
            <SelectTrigger className="w-44" aria-label="Filter by CA">
              <SelectValue placeholder="All CAs" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All CAs</SelectItem>
              {cas.map((c) => (
                <SelectItem key={c.id} value={String(c.id)}>
                  {c.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={type} onValueChange={(v) => setType(v === "all" ? "" : v)}>
            <SelectTrigger className="w-32" aria-label="Filter by type">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="server">Server</SelectItem>
              <SelectItem value="client">Client</SelectItem>
              <SelectItem value="device">Device</SelectItem>
              <SelectItem value="user">User</SelectItem>
            </SelectContent>
          </Select>
          <Select value={status} onValueChange={(v) => setStatus(v === "all" ? "" : v)}>
            <SelectTrigger className="w-32" aria-label="Filter by status">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="expiring">Expiring ≤30d</SelectItem>
              <SelectItem value="expired">Expired</SelectItem>
              <SelectItem value="revoked">Revoked</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {certsQuery.isError ? (
        <QueryError error={certsQuery.error} onRetry={() => void certsQuery.refetch()} />
      ) : certsQuery.isLoading ? (
        <Card>
          <CardContent className="p-0">
            <TableSkeleton rows={5} cols={8} />
          </CardContent>
        </Card>
      ) : certs.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.FileKey2 className="h-6 w-6" />}
              title={expiringOnly ? "Nothing expiring in the next 30 days" : "No certificates match"}
              description={
                expiringOnly
                  ? "Certificates appear here when their validity window closes in."
                  : activeCas.length === 0
                    ? "Create an active CA first — certificates are issued under it."
                    : "Issue a certificate under an active CA to get started."
              }
              action={
                !expiringOnly && activeCas.length > 0 ? (
                  <Button size="sm" className="gap-1.5" onClick={() => setIssueOpen(true)}>
                    <Icons.Plus className="h-4 w-4" /> Issue certificate
                  </Button>
                ) : undefined
              }
            />
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="max-h-96 overflow-y-auto">
              <Table>
                <TableHeader className="sticky top-0 bg-background">
                  <TableRow>
                    <TableHead>Certificate</TableHead>
                    <TableHead>SANs</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Issued for</TableHead>
                    <TableHead>Key</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {certs.map((cert) => (
                    <TableRow key={cert.id} className={cn(cert.status !== "active" && "opacity-70")}>
                      <TableCell>
                        <p className="font-medium">{cert.name}</p>
                        <p className="font-mono text-[11px] text-zinc-400">{cert.commonName}</p>
                      </TableCell>
                      <TableCell>
                        <SansChips sans={cert.sans} />
                      </TableCell>
                      <TableCell>
                        <CertTypeBadge type={cert.type} />
                      </TableCell>
                      <TableCell>
                        <IssuedForChip issuedFor={cert.issuedFor} />
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs">{KEY_TYPE_LABELS[cert.keyType] ?? cert.keyType}</span>
                      </TableCell>
                      <TableCell>
                        <ExpiryPill notAfter={cert.notAfter} daysUntilExpiry={cert.daysUntilExpiry} status={cert.status} />
                      </TableCell>
                      <TableCell>
                        <PkiStatusBadge status={cert.status} />
                        {cert.revocationReason ? (
                          <p className="mt-0.5 text-[10px] text-zinc-400">{cert.revocationReason}</p>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${cert.name}`}>
                              <Icons.MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => void doExport(cert, "cert")}>
                              <Icons.FileDown className="mr-2 h-4 w-4" /> Download cert
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => void doExport(cert, "key")}>
                              <Icons.KeyRound className="mr-2 h-4 w-4" /> Download key
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => void doExport(cert, "chain")}>
                              <Icons.Link2 className="mr-2 h-4 w-4" /> Download chain
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => setRevoking(cert)} disabled={cert.status === "revoked"}>
                              <Icons.Ban className="mr-2 h-4 w-4 text-rose-500" /> Revoke
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setDeleting(cert)} disabled={cert.status === "active"}>
                              <Icons.Trash2 className="mr-2 h-4 w-4 text-rose-500" /> Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      <IssueCertDialog open={issueOpen} onOpenChange={setIssueOpen} activeCas={activeCas} onDone={invalidate} />

      <RevokeCertDialog cert={revoking} onOpenChange={(open) => !open && setRevoking(null)} onDone={invalidate} />

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete certificate "${deleting?.name ?? ""}"?`}
        description="Only revoked or expired certificates can be deleted. This removes the record and its key material."
        confirmLabel="Delete certificate"
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

// ── issue dialog ────────────────────────────────────────────────────────────

interface IssueForm {
  caId: string;
  name: string;
  commonName: string;
  sans: string[];
  sanDraft: string;
  type: CertDto["type"];
  issuedFor: IssuedFor;
  keyType: PkiKeyType;
  validityDays: number;
}

function IssueCertDialog(props: { open: boolean; onOpenChange: (open: boolean) => void; activeCas: CaDto[]; onDone: () => void }) {
  const [form, setForm] = useState<IssueForm>({
    caId: "",
    name: "",
    commonName: "",
    sans: [],
    sanDraft: "",
    type: "server",
    issuedFor: "general",
    keyType: "rsa2048",
    validityDays: 365,
  });
  const [errors, setErrors] = useState<Record<string, string[]>>({});
  const set = <K extends keyof IssueForm>(k: K, v: IssueForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  const addSan = () => {
    const raw = form.sanDraft.trim();
    if (!raw) return;
    const value = /^(DNS|IP):/i.test(raw) ? raw : `DNS:${raw}`; // prefixes auto-applied
    if (!form.sans.includes(value)) set("sans", [...form.sans, value]);
    set("sanDraft", "");
  };

  const mut = useMutation({
    mutationFn: () =>
      pkiApi.issueCert({
        caId: Number(form.caId),
        name: form.name,
        commonName: form.commonName,
        sans: form.sans,
        type: form.type,
        issuedFor: form.issuedFor,
        keyType: form.keyType,
        validityDays: form.validityDays,
      }),
    onSuccess: (cert) => {
      toastOk(`Certificate "${cert.name}" issued`, `Serial ${cert.serial} — signed by ${cert.caName ?? "CA"}.`);
      setForm((f) => ({ ...f, caId: "", name: "", commonName: "", sans: [], sanDraft: "" }));
      setErrors({});
      props.onOpenChange(false);
      props.onDone();
    },
    onError: (err) => {
      setErrors(fieldErrorsOf(err));
      toastErr(err, "Issue failed");
    },
  });

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Issue certificate</DialogTitle>
          <DialogDescription>Real key pair + X.509 signing under the selected active CA.</DialogDescription>
        </DialogHeader>

        <div className="grid gap-3">
          <div>
            <FieldLabel hint="active only">Issuing CA</FieldLabel>
            <Select value={form.caId} onValueChange={(v) => set("caId", v)}>
              <SelectTrigger aria-label="Issuing CA">
                <SelectValue placeholder={props.activeCas.length ? "Select CA" : "No active CAs"} />
              </SelectTrigger>
              <SelectContent>
                {props.activeCas.map((c) => (
                  <SelectItem key={c.id} value={String(c.id)}>
                    {c.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.caId && <p className="mt-1 text-xs text-rose-600">{errors.caId.join(", ")}</p>}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Name</FieldLabel>
              <Input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="waf-vhost-demo" aria-label="Certificate name" />
              {errors.name && <p className="mt-1 text-xs text-rose-600">{errors.name.join(", ")}</p>}
            </div>
            <div>
              <FieldLabel>Common name (CN)</FieldLabel>
              <Input value={form.commonName} onChange={(e) => set("commonName", e.target.value)} placeholder="app.corp.example" aria-label="Common name" />
              {errors.commonName && <p className="mt-1 text-xs text-rose-600">{errors.commonName.join(", ")}</p>}
            </div>
          </div>

          <div>
            <FieldLabel hint="DNS:/IP: prefixes auto-applied">Subject alternative names</FieldLabel>
            <div className="flex gap-2">
              <Input
                value={form.sanDraft}
                onChange={(e) => set("sanDraft", e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addSan();
                  }
                }}
                placeholder="*.cryptsk.local or 10.0.0.5"
                aria-label="Add SAN"
              />
              <Button type="button" variant="outline" size="sm" className="min-h-9 shrink-0 gap-1" onClick={addSan}>
                <Icons.Plus className="h-3.5 w-3.5" /> Add
              </Button>
            </div>
            {form.sans.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {form.sans.map((s) => (
                  <Badge key={s} variant="outline" className="gap-1 border-zinc-500/30 bg-zinc-500/10 font-mono text-[10px] font-normal text-zinc-600 dark:text-zinc-300">
                    {s}
                    <button
                      type="button"
                      aria-label={`Remove ${s}`}
                      className="rounded-sm p-0.5 hover:bg-zinc-500/20"
                      onClick={() => set("sans", form.sans.filter((x) => x !== s))}
                    >
                      <Icons.X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
            {errors.sans && <p className="mt-1 text-xs text-rose-600">{errors.sans.join(", ")}</p>}
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <FieldLabel>Type</FieldLabel>
              <Select value={form.type} onValueChange={(v) => set("type", v as CertDto["type"])}>
                <SelectTrigger aria-label="Certificate type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="server">Server</SelectItem>
                  <SelectItem value="client">Client</SelectItem>
                  <SelectItem value="device">Device</SelectItem>
                  <SelectItem value="user">User</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Issued for</FieldLabel>
              <Select value={form.issuedFor} onValueChange={(v) => set("issuedFor", v as IssuedFor)}>
                <SelectTrigger aria-label="Issued for">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(ISSUED_FOR_LABELS) as IssuedFor[]).map((k) => (
                    <SelectItem key={k} value={k}>
                      {ISSUED_FOR_LABELS[k]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Key type</FieldLabel>
              <Select value={form.keyType} onValueChange={(v) => set("keyType", v as PkiKeyType)}>
                <SelectTrigger aria-label="Key type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="rsa2048">RSA 2048</SelectItem>
                  <SelectItem value="rsa4096">RSA 4096</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <div className="mb-1.5 flex items-baseline justify-between gap-2">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Validity</span>
              <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{form.validityDays} days</span>
            </div>
            <Slider
              value={[form.validityDays]}
              min={90}
              max={3980}
              step={5}
              onValueChange={(v) => set("validityDays", v[0] ?? form.validityDays)}
              aria-label="Validity days"
            />
            <div className="mt-1 flex justify-between text-[10px] text-zinc-400">
              <span>90d</span>
              <span>3980d (internal ceiling)</span>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)} disabled={mut.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => mut.mutate()}
            disabled={mut.isPending || !form.caId || !form.name || !form.commonName}
            className="gap-1.5 bg-zinc-700 text-white hover:bg-zinc-800"
          >
            {mut.isPending ? <Icons.Loader2 className="h-4 w-4 animate-spin" /> : <Icons.FileKey2 className="h-4 w-4" />}
            {mut.isPending ? "Signing…" : "Issue certificate"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── revoke dialog (reason select) ───────────────────────────────────────────

function RevokeCertDialog(props: { cert: CertDto | null; onOpenChange: (open: boolean) => void; onDone: () => void }) {
  const [reason, setReason] = useState<RevocationReason>("unspecified");

  const mut = useMutation({
    mutationFn: () => pkiApi.revokeCert(props.cert!.id, reason),
    onSuccess: () => {
      toastOk("Certificate revoked", "It now appears on the CA's CRL.");
      props.onOpenChange(false);
      props.onDone();
    },
    onError: (err) => {
      props.onOpenChange(false);
      toastErr(err, "Revoke failed");
    },
  });

  return (
    <AlertDialog open={props.cert !== null} onOpenChange={props.onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke "{props.cert?.name ?? ""}"?</AlertDialogTitle>
          <AlertDialogDescription>
            The certificate stops being trusted by TLS inspection, WAF and VPN consumers relying on the CA&apos;s CRL.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div>
          <Label htmlFor="revoke-reason" className="mb-1.5 block text-xs font-medium text-zinc-700 dark:text-zinc-300">
            Revocation reason
          </Label>
          <Select value={reason} onValueChange={(v) => setReason(v as RevocationReason)}>
            <SelectTrigger id="revoke-reason" aria-label="Revocation reason">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {REVOKE_REASONS.map((r) => (
                <SelectItem key={r} value={r}>
                  {r}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={mut.isPending}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            className="bg-rose-600 text-white hover:bg-rose-700 focus-visible:ring-rose-600"
            disabled={mut.isPending}
            onClick={(e) => {
              e.preventDefault();
              mut.mutate();
            }}
          >
            {mut.isPending ? "Revoking…" : "Revoke certificate"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

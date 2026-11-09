"use client";

/**
 * #/pki/authorities — Certificate Authority management (M14 §2.12).
 * CA cards with type/status badges, validity window + days-until pill, issued
 * count and export actions (cert/key/chain + CRL). Private-key export goes
 * through the admin-only endpoint; a 403 surfaces as "Forbidden — admin
 * only". Create dialog generates REAL X.509 material via the API (node-forge).
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
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import {
  KEY_TYPE_LABELS,
  PkiApiError,
  fmtDate,
  fieldErrorsOf,
  pkiApi,
  type CaDto,
} from "./pki-api";
import { CaTypeBadge, ExpiryPill, PkiStatusBadge } from "./pki-ui";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const CAS_KEY = ["pki", "cas"] as const;

// ── form state ──────────────────────────────────────────────────────────────

interface CaForm {
  name: string;
  type: "root" | "subordinate";
  commonName: string;
  org: string;
  keyType: "rsa2048" | "rsa4096";
  validityDays: number;
  parentCaId: string;
  crlUrl: string;
  ocspUrl: string;
  autoRenew: boolean;
}

const EMPTY_FORM: CaForm = {
  name: "",
  type: "root",
  commonName: "",
  org: "",
  keyType: "rsa2048",
  validityDays: 1825,
  parentCaId: "",
  crlUrl: "",
  ocspUrl: "",
  autoRenew: false,
};

// ── main view ───────────────────────────────────────────────────────────────

export function AuthoritiesView() {
  const queryClient = useQueryClient();
  const casQuery = useQuery({ queryKey: CAS_KEY, queryFn: pkiApi.listCas });
  const cas = useMemo(() => casQuery.data ?? [], [casQuery.data]);

  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<CaDto | null>(null);
  const [revoking, setRevoking] = useState<CaDto | null>(null);
  const [deleting, setDeleting] = useState<CaDto | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: CAS_KEY });

  const deleteMut = useMutation({
    mutationFn: (id: number) => pkiApi.deleteCa(id),
    onSuccess: () => {
      toastOk("CA deleted");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      setDeleting(null);
      toastErr(err, "Delete failed");
    },
  });

  const revokeMut = useMutation({
    mutationFn: (id: number) => pkiApi.revokeCa(id),
    onSuccess: () => {
      toastOk("CA revoked", "Issued certificates are unaffected — revoke them individually.");
      setRevoking(null);
      invalidate();
    },
    onError: (err) => {
      setRevoking(null);
      toastErr(err, "Revoke failed");
    },
  });

  /** Export with graceful 403 (key part is admin-only). */
  const doExport = async (ca: CaDto, part: "cert" | "key" | "chain") => {
    try {
      const { filename } = await pkiApi.exportCa(ca.id, part, `${ca.name}.${part === "key" ? "key" : part === "chain" ? "chain.pem" : "crt"}`);
      toastOk(`Exported ${filename}`);
    } catch (err) {
      if (err instanceof PkiApiError && err.code === "FORBIDDEN") toastErr(err, "Forbidden — admin only");
      else toastErr(err, "Export failed");
    }
  };

  const doDownloadCrl = async (ca: CaDto) => {
    try {
      const { filename } = await pkiApi.downloadCrl(ca.id, `${ca.name}.crl`);
      toastOk(`Exported ${filename}`);
    } catch (err) {
      toastErr(err, "CRL download failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-zinc-500">
          Real X.509 authorities (node-forge) — roots and subordinates with genuine RSA key pairs, CRLs and exports.
        </p>
        <Button size="sm" className="gap-1.5" onClick={() => setCreateOpen(true)}>
          <Icons.Plus className="h-4 w-4" /> Create CA
        </Button>
      </div>

      {casQuery.isError ? (
        <QueryError error={casQuery.error} onRetry={() => void casQuery.refetch()} />
      ) : casQuery.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <TableSkeleton rows={3} cols={2} />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : cas.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Landmark className="h-6 w-6" />}
              title="No certificate authorities yet"
              description="Create a root CA first, then issue subordinate CAs and end-entity certificates under it."
              action={
                <Button size="sm" className="gap-1.5" onClick={() => setCreateOpen(true)}>
                  <Icons.Plus className="h-4 w-4" /> Create CA
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {cas.map((ca) => (
            <CaCard
              key={ca.id}
              ca={ca}
              onEdit={() => setEditing(ca)}
              onRevoke={() => setRevoking(ca)}
              onDelete={() => setDeleting(ca)}
              onExport={doExport}
              onCrl={doDownloadCrl}
            />
          ))}
        </div>
      )}

      <CreateCaDialog open={createOpen} onOpenChange={setCreateOpen} cas={cas} onDone={invalidate} />
      <EditCaDialog ca={editing} onOpenChange={(open) => !open && setEditing(null)} onDone={invalidate} />

      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={`Revoke CA "${revoking?.name ?? ""}"?`}
        description="The authority stops signing new certificates. Its issued certificates stay valid until individually revoked or expired."
        confirmLabel="Revoke CA"
        loading={revokeMut.isPending}
        onConfirm={() => revoking && revokeMut.mutate(revoking.id)}
      />

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete CA "${deleting?.name ?? ""}"?`}
        description="This permanently removes the authority record and its key material. Only possible while no certificates were issued by it."
        confirmLabel="Delete CA"
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

// ── card ────────────────────────────────────────────────────────────────────

function CaCard(props: {
  ca: CaDto;
  onEdit: () => void;
  onRevoke: () => void;
  onDelete: () => void;
  onExport: (ca: CaDto, part: "cert" | "key" | "chain") => void;
  onCrl: (ca: CaDto) => void;
}) {
  const { ca } = props;
  return (
    <Card className={cn("flex flex-col", ca.status !== "active" && "opacity-75")}>
      <CardContent className="flex flex-1 flex-col gap-3 p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate font-medium">{ca.name}</p>
            <p className="truncate text-xs text-zinc-500">
              CN: <span className="font-mono">{ca.commonName}</span>
              {ca.org ? ` · ${ca.org}` : ""}
            </p>
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" aria-label={`Actions for ${ca.name}`}>
                <Icons.MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => props.onCrl(ca)}>
                <Icons.FileWarning className="mr-2 h-4 w-4" /> Download CRL
              </DropdownMenuItem>
              <DropdownMenuItem onClick={props.onEdit}>
                <Icons.Pencil className="mr-2 h-4 w-4" /> Edit
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={props.onRevoke} disabled={ca.status === "revoked"}>
                <Icons.Ban className="mr-2 h-4 w-4 text-rose-500" /> Revoke CA
              </DropdownMenuItem>
              <DropdownMenuItem onClick={props.onDelete} disabled={ca.issuedCount > 0}>
                <Icons.Trash2 className="mr-2 h-4 w-4 text-rose-500" /> Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <CaTypeBadge type={ca.type} />
          <PkiStatusBadge status={ca.status} />
          <Badge variant="outline" className="border-zinc-300 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
            {KEY_TYPE_LABELS[ca.keyType] ?? ca.keyType}
          </Badge>
        </div>

        <div className="flex items-end justify-between gap-2">
          <div className="text-xs text-zinc-500">
            <p>
              Valid {fmtDate(ca.notBefore)} → {fmtDate(ca.notAfter)}
            </p>
            <p className="mt-0.5">
              Issued <span className="font-medium text-zinc-700 dark:text-zinc-300">{ca.issuedCount}</span> certificate
              {ca.issuedCount === 1 ? "" : "s"}
              {ca.parentName ? ` · signed by ${ca.parentName}` : ""}
            </p>
            <p className="mt-0.5 max-w-52 truncate font-mono text-[10px] text-zinc-400" title={`Serial ${ca.serial}`}>
              SN {ca.serial || "—"}
            </p>
          </div>
          <ExpiryPill notAfter={ca.notAfter} daysUntilExpiry={ca.daysUntilExpiry} status={ca.status} />
        </div>

        <div className="mt-auto flex flex-wrap gap-1.5 border-t border-zinc-200 pt-3 dark:border-zinc-800">
          <Button size="sm" variant="outline" className="h-8 gap-1" onClick={() => props.onExport(ca, "cert")}>
            <Icons.FileDown className="h-3.5 w-3.5" /> Cert
          </Button>
          <Button size="sm" variant="outline" className="h-8 gap-1" onClick={() => props.onExport(ca, "key")}>
            <Icons.KeyRound className="h-3.5 w-3.5" /> Key
          </Button>
          <Button size="sm" variant="outline" className="h-8 gap-1" onClick={() => props.onExport(ca, "chain")}>
            <Icons.Link2 className="h-3.5 w-3.5" /> Chain
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── create dialog ───────────────────────────────────────────────────────────

function CreateCaDialog(props: { open: boolean; onOpenChange: (open: boolean) => void; cas: CaDto[]; onDone: () => void }) {
  const [form, setForm] = useState<CaForm>(EMPTY_FORM);
  const [errors, setErrors] = useState<Record<string, string[]>>({});
  const set = <K extends keyof CaForm>(k: K, v: CaForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  const mut = useMutation({
    mutationFn: () =>
      pkiApi.createCa({
        name: form.name,
        type: form.type,
        commonName: form.commonName,
        org: form.org || undefined,
        keyType: form.keyType,
        validityDays: form.validityDays,
        parentCaId: form.type === "subordinate" ? Number(form.parentCaId) : undefined,
        crlUrl: form.crlUrl || undefined,
        ocspUrl: form.ocspUrl || undefined,
        autoRenew: form.autoRenew,
      }),
    onSuccess: (ca) => {
      toastOk(`CA "${ca.name}" created`, "Real RSA key pair and X.509 certificate generated.");
      setForm(EMPTY_FORM);
      setErrors({});
      props.onOpenChange(false);
      props.onDone();
    },
    onError: (err) => {
      setErrors(fieldErrorsOf(err));
      toastErr(err, "Create CA failed");
    },
  });

  const activeParents = props.cas.filter((c) => c.status === "active");

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Create certificate authority</DialogTitle>
          <DialogDescription>Generates a genuine RSA key pair and signs an X.509 CA certificate.</DialogDescription>
        </DialogHeader>

        <div className="grid gap-3">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Cryptsk Root CA" aria-label="CA name" />
            {errors.name && <p className="mt-1 text-xs text-rose-600">{errors.name.join(", ")}</p>}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Type</FieldLabel>
              <Select value={form.type} onValueChange={(v) => set("type", v as CaForm["type"])}>
                <SelectTrigger aria-label="CA type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="root">Root (self-signed)</SelectItem>
                  <SelectItem value="subordinate">Subordinate (signed by parent)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Key type</FieldLabel>
              <Select value={form.keyType} onValueChange={(v) => set("keyType", v as CaForm["keyType"])}>
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

          {form.type === "subordinate" && (
            <div>
              <FieldLabel hint="only active CAs can sign">Parent CA</FieldLabel>
              <Select value={form.parentCaId} onValueChange={(v) => set("parentCaId", v)}>
                <SelectTrigger aria-label="Parent CA">
                  <SelectValue placeholder={activeParents.length ? "Select parent CA" : "No active CAs"} />
                </SelectTrigger>
                <SelectContent>
                  {activeParents.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {errors.parentCaId && <p className="mt-1 text-xs text-rose-600">{errors.parentCaId.join(", ")}</p>}
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Common name (CN)</FieldLabel>
              <Input value={form.commonName} onChange={(e) => set("commonName", e.target.value)} placeholder="pki.cryptsk.local" aria-label="Common name" />
              {errors.commonName && <p className="mt-1 text-xs text-rose-600">{errors.commonName.join(", ")}</p>}
            </div>
            <div>
              <FieldLabel hint="optional">Organization</FieldLabel>
              <Input value={form.org} onChange={(e) => set("org", e.target.value)} placeholder="Cryptsk" aria-label="Organization" />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel hint="30–7300 days">Validity (days)</FieldLabel>
              <Input
                type="number"
                min={30}
                max={7300}
                value={form.validityDays}
                onChange={(e) => set("validityDays", Number(e.target.value))}
                aria-label="Validity days"
              />
              {errors.validityDays && <p className="mt-1 text-xs text-rose-600">{errors.validityDays.join(", ")}</p>}
            </div>
            <div>
              <FieldLabel hint="optional">CRL URL</FieldLabel>
              <Input value={form.crlUrl} onChange={(e) => set("crlUrl", e.target.value)} placeholder="http://pki.cryptsk.local/crl" aria-label="CRL URL" />
              {errors.crlUrl && <p className="mt-1 text-xs text-rose-600">{errors.crlUrl.join(", ")}</p>}
            </div>
          </div>

          <div>
            <FieldLabel hint="optional">OCSP URL</FieldLabel>
            <Input value={form.ocspUrl} onChange={(e) => set("ocspUrl", e.target.value)} placeholder="http://ocsp.cryptsk.local" aria-label="OCSP URL" />
          </div>

          <div className="flex items-center justify-between rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <div>
              <Label htmlFor="ca-autorenew" className="text-sm">
                Auto-renew
              </Label>
              <p className="text-[11px] text-zinc-400">Renew before expiry (sandbox flag)</p>
            </div>
            <Switch id="ca-autorenew" checked={form.autoRenew} onCheckedChange={(v) => set("autoRenew", v)} />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)} disabled={mut.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => mut.mutate()}
            disabled={mut.isPending || !form.name || !form.commonName || (form.type === "subordinate" && !form.parentCaId)}
            className="gap-1.5 bg-red-700 text-white hover:bg-red-800"
          >
            {mut.isPending ? (
              <Icons.Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Icons.KeyRound className="h-4 w-4" />
            )}
            {mut.isPending ? "Generating key pair…" : "Create CA"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── edit dialog (name / CRL / OCSP / auto-renew) ────────────────────────────

function EditCaDialog(props: { ca: CaDto | null; onOpenChange: (open: boolean) => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [crlUrl, setCrlUrl] = useState("");
  const [ocspUrl, setOcspUrl] = useState("");
  const [autoRenew, setAutoRenew] = useState(false);
  const [hydrated, setHydrated] = useState<number | null>(null);

  // hydrate fields when a different CA opens the dialog
  if (props.ca && hydrated !== props.ca.id) {
    setName(props.ca.name);
    setCrlUrl(props.ca.crlUrl ?? "");
    setOcspUrl(props.ca.ocspUrl ?? "");
    setAutoRenew(props.ca.autoRenew);
    setHydrated(props.ca.id);
  }
  if (!props.ca && hydrated !== null) setHydrated(null);

  const mut = useMutation({
    mutationFn: () =>
      pkiApi.updateCa(props.ca!.id, {
        name,
        crlUrl: crlUrl || null,
        ocspUrl: ocspUrl || null,
        autoRenew,
      }),
    onSuccess: () => {
      toastOk("CA updated");
      props.onOpenChange(false);
      props.onDone();
    },
    onError: (err) => toastErr(err, "Update failed"),
  });

  return (
    <Dialog open={props.ca !== null} onOpenChange={props.onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit CA</DialogTitle>
          <DialogDescription>Certificate identity is immutable — only metadata can change.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} aria-label="CA name" />
          </div>
          <div>
            <FieldLabel hint="optional">CRL URL</FieldLabel>
            <Input value={crlUrl} onChange={(e) => setCrlUrl(e.target.value)} aria-label="CRL URL" />
          </div>
          <div>
            <FieldLabel hint="optional">OCSP URL</FieldLabel>
            <Input value={ocspUrl} onChange={(e) => setOcspUrl(e.target.value)} aria-label="OCSP URL" />
          </div>
          <div className="flex items-center justify-between rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <Label htmlFor="ca-edit-autorenew" className="text-sm">
              Auto-renew
            </Label>
            <Switch id="ca-edit-autorenew" checked={autoRenew} onCheckedChange={setAutoRenew} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)} disabled={mut.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => mut.mutate()}
            disabled={mut.isPending || !name}
            className="bg-red-700 text-white hover:bg-red-800"
          >
            Save changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

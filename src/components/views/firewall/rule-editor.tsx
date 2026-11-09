"use client";

/**
 * RuleEditor — create/edit/duplicate firewall rules (M03 §4). Sections:
 * General / Match / Action / Protections / Attachments. Validate runs
 * POST /firewall-rules/validate and renders shadow/conflict warnings inline;
 * blocking errors (shadowed_by, conflicts_with) disable Save unless
 * "Save anyway" is clicked (warning text is prepended to the rule comment).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  api,
  parseMacList,
  type AddressObject,
  type ConflictRow,
  type FwAction,
  type FwRule,
  type FwRuleBody,
  type LoggingLevel,
  type NamedWithMembers,
  type ScheduleObject,
  type ServiceObject,
  type Zone,
} from "./fw-api";
import {
  ActionBadge,
  EditorSection,
  FieldLabel,
  MultiChips,
  ObjectPicker,
  PopoverMulti,
  toastErr,
  toastOk,
} from "./fw-ui";

interface RuleForm {
  name: string;
  description: string;
  tags: string[];
  comment: string;
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  applicationIds: string[];
  userIds: number[];
  srcMacsRaw: string;
  scheduleId: number | null;
  action: FwAction;
  logging: LoggingLevel;
  connLimit: string;
  rateLimit: string;
  synProtection: boolean;
  synThreshold: string;
}

function formFromRule(r: FwRule | null): RuleForm {
  if (!r) {
    return {
      name: "",
      description: "",
      tags: [],
      comment: "",
      srcZoneIds: [],
      dstZoneIds: [],
      srcAddrIds: [],
      dstAddrIds: [],
      serviceIds: [],
      applicationIds: [],
      userIds: [],
      srcMacsRaw: "",
      scheduleId: null,
      action: "allow",
      logging: "none",
      connLimit: "",
      rateLimit: "",
      synProtection: false,
      synThreshold: "",
    };
  }
  return {
    name: r.name,
    description: r.description ?? "",
    tags: [...r.tags],
    comment: r.comment ?? "",
    srcZoneIds: [...r.srcZoneIds],
    dstZoneIds: [...r.dstZoneIds],
    srcAddrIds: [...r.srcAddrIds],
    dstAddrIds: [...r.dstAddrIds],
    serviceIds: [...r.serviceIds],
    applicationIds: [...r.applicationIds],
    userIds: [...r.userIds],
    srcMacsRaw: r.srcMacs.join(", "),
    scheduleId: r.scheduleId,
    action: r.action,
    logging: r.logging,
    connLimit: r.connLimit == null ? "" : String(r.connLimit),
    rateLimit: r.rateLimit == null ? "" : String(r.rateLimit),
    synProtection: r.synProtection,
    synThreshold: r.synThreshold == null ? "" : String(r.synThreshold),
  };
}

function numOrNull(v: string): number | null {
  const t = v.trim();
  if (!t) return null;
  const n = Number(t);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
}

function buildBody(f: RuleForm): FwRuleBody {
  return {
    name: f.name.trim(),
    description: f.description.trim() || null,
    enabled: true,
    srcZoneIds: f.srcZoneIds,
    dstZoneIds: f.dstZoneIds,
    srcAddrIds: f.srcAddrIds,
    dstAddrIds: f.dstAddrIds,
    serviceIds: f.serviceIds,
    applicationIds: f.applicationIds,
    userIds: f.userIds,
    srcMacs: parseMacList(f.srcMacsRaw).valid,
    scheduleId: f.scheduleId,
    action: f.action,
    logging: f.logging,
    connLimit: numOrNull(f.connLimit),
    rateLimit: numOrNull(f.rateLimit),
    synProtection: f.synProtection,
    synThreshold: f.synProtection ? numOrNull(f.synThreshold) : null,
    tags: f.tags,
    comment: f.comment.trim() || null,
  };
}

const REASON_LABEL: Record<ConflictRow["reason"], string> = {
  shadowed_by: "Shadowed by",
  conflicts_with: "Conflicts with",
  redundant: "Redundant with",
};

export function RuleEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: FwRule | null;
  duplicateOf: FwRule | null;
  /** create-mode draft handed over from other modules (e.g. M04 IPS events) */
  prefill?: FwRule | null;
  zones: Zone[];
  addresses: AddressObject[];
  addressGroups: NamedWithMembers[];
  services: ServiceObject[];
  serviceGroups: NamedWithMembers[];
  schedules: ScheduleObject[];
  tagSuggestions: string[];
  onSaved: () => void;
}) {
  const { open, editing, duplicateOf } = props;
  const base = editing ?? duplicateOf ?? props.prefill ?? null;
  const [form, setForm] = useState<RuleForm>(() => {
    const f = formFromRule(base);
    if (!editing && duplicateOf) f.name = `${duplicateOf.name}-copy`;
    return f;
  });
  const [tagDraft, setTagDraft] = useState("");
  const [conflicts, setConflicts] = useState<ConflictRow[] | null>(null);
  const [override, setOverride] = useState(false);
  const [macError, setMacError] = useState<string | null>(null);

  const set = <K extends keyof RuleForm>(key: K, value: RuleForm[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const zoneOptions = useMemo(() => props.zones.map((z) => ({ id: z.id, label: z.name })), [props.zones]);
  const scheduleById = useMemo(() => new Map(props.schedules.map((s) => [s.id, s])), [props.schedules]);

  const addrPickerObjects = useMemo(
    () => props.addresses.map((a) => ({ id: a.id, name: a.name, sub: a.value })),
    [props.addresses],
  );
  const addrPickerGroups = useMemo(
    () => props.addressGroups.map((g) => ({ id: g.id, name: g.name, memberCount: g.memberIds.length })),
    [props.addressGroups],
  );
  const svcPickerObjects = useMemo(
    () =>
      props.services.map((s) => ({
        id: s.id,
        name: s.name,
        sub: s.protocol === "icmp" ? "icmp" : `${s.protocol}${s.dstPort ? `/${s.dstPort}` : ""}`,
      })),
    [props.services],
  );
  const svcPickerGroups = useMemo(
    () => props.serviceGroups.map((g) => ({ id: g.id, name: g.name, memberCount: g.memberIds.length })),
    [props.serviceGroups],
  );

  const appsQuery = useQuery({
    queryKey: ["firewall", "meta", "apps"],
    queryFn: api.listApps,
    enabled: open,
    staleTime: 5 * 60_000,
  });
  const usersQuery = useQuery({
    queryKey: ["firewall", "meta", "users"],
    queryFn: api.listUsers,
    enabled: open,
    staleTime: 5 * 60_000,
  });

  const appOptions = useMemo(
    () => (appsQuery.data?.apps ?? []).map((a) => ({ id: a, label: a })),
    [appsQuery.data],
  );
  const userOptions = useMemo(
    () => (usersQuery.data?.data ?? []).map((u) => ({ id: String(u.id), label: u.username, sub: u.role })),
    [usersQuery.data],
  );

  const macs = parseMacList(form.srcMacsRaw);

  const validateMut = useMutation({
    mutationFn: () => api.validateRule(buildBody(form), editing?.id),
    onSuccess: (res) => {
      setConflicts(res.conflicts);
      if (res.ok) toastOk("No conflicts", "Rule does not shadow or collide with earlier rules");
    },
    onError: (err) => toastErr(err, "Validation failed"),
  });

  const blocking = (conflicts ?? []).some((c) => c.reason === "shadowed_by" || c.reason === "conflicts_with");

  const saveMut = useMutation({
    mutationFn: async () => {
      const body = buildBody(form);
      if (editing) return api.updateRule(editing.id, body);
      return api.createRule(body);
    },
    onSuccess: (_data, _vars) => {
      toastOk(editing ? "Rule updated" : "Rule created", `${form.name.trim()} saved`);
      props.onSaved();
      props.onOpenChange(false);
    },
    onError: (err) => toastErr(err, editing ? "Update failed" : "Create failed"),
  });

  const saveAnyway = () => {
    const blockingRows = (conflicts ?? []).filter((c) => c.reason !== "redundant");
    const warning = `saved despite validation warning: ${blockingRows
      .map((c) => `${c.reason} by ${c.withRuleName}`)
      .join("; ")}`;
    setForm((prev) => ({
      ...prev,
      comment: prev.comment.trim() ? `${warning} — ${prev.comment.trim()}` : warning,
    }));
    setOverride(true);
  };

  const submit = () => {
    if (blocking && !override) return;
    if (macs.invalid.length > 0) {
      setMacError(`Invalid MAC addresses: ${macs.invalid.join(", ")}`);
      return;
    }
    saveMut.mutate();
  };

  const addTag = (raw: string) => {
    const t = raw.trim().replace(/,+$/, "");
    if (!t) return;
    if (!form.tags.includes(t) && t.length <= 32) set("tags", [...form.tags, t]);
    setTagDraft("");
  };

  return (
    <Dialog open={open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] w-[calc(100vw-1rem)] max-w-3xl overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit rule — ${editing.name}` : duplicateOf ? `Duplicate rule — ${duplicateOf.name}-copy` : props.prefill ? `Add rule — prefilled (${props.prefill.name})` : "Add firewall rule"}</DialogTitle>
          <DialogDescription>
            Rules are evaluated top-down, first match wins. Empty match dimensions are wildcards.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <EditorSection title="General">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="rule-name" className="text-xs font-medium">
                  Name
                </Label>
                <Input
                  id="rule-name"
                  value={form.name}
                  onChange={(e) => set("name", e.target.value)}
                  placeholder="allow-lan-to-wan"
                  className="mt-1.5"
                />
              </div>
              <div>
                <Label htmlFor="rule-desc" className="text-xs font-medium">
                  Description
                </Label>
                <Input
                  id="rule-desc"
                  value={form.description}
                  onChange={(e) => set("description", e.target.value)}
                  placeholder="What does this rule allow?"
                  className="mt-1.5"
                />
              </div>
            </div>
            <div>
              <FieldLabel hint="Enter or comma to add">Tags</FieldLabel>
              <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-zinc-200 p-2 dark:border-zinc-800">
                {form.tags.map((t) => (
                  <Badge key={t} variant="outline" className="gap-1 border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300">
                    {t}
                    <button type="button" aria-label={`Remove tag ${t}`} onClick={() => set("tags", form.tags.filter((x) => x !== t))}>
                      <Icons.X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
                <input
                  value={tagDraft}
                  onChange={(e) => setTagDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === ",") {
                      e.preventDefault();
                      addTag(tagDraft);
                    }
                  }}
                  onBlur={() => addTag(tagDraft)}
                  placeholder="add tag…"
                  className="min-w-24 flex-1 bg-transparent text-sm outline-none placeholder:text-zinc-400"
                />
              </div>
              {props.tagSuggestions.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {props.tagSuggestions
                    .filter((t) => !form.tags.includes(t))
                    .map((t) => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => addTag(t)}
                        className="rounded-full border border-dashed border-zinc-300 px-2 py-0.5 text-[11px] text-zinc-500 hover:border-zinc-500/40 hover:text-zinc-600 dark:border-zinc-700 dark:hover:text-zinc-300"
                      >
                        + {t}
                      </button>
                    ))}
                </div>
              )}
            </div>
            <div>
              <Label htmlFor="rule-comment" className="text-xs font-medium">
                Comment
              </Label>
              <Textarea
                id="rule-comment"
                value={form.comment}
                onChange={(e) => set("comment", e.target.value)}
                rows={2}
                className="mt-1.5"
                placeholder="Operational notes…"
              />
            </div>
          </EditorSection>

          <EditorSection title="Match">
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <FieldLabel hint="empty = any">Source zones</FieldLabel>
                <MultiChips options={zoneOptions} selected={form.srcZoneIds} onToggle={(id) => set("srcZoneIds", form.srcZoneIds.includes(id) ? form.srcZoneIds.filter((x) => x !== id) : [...form.srcZoneIds, id])} />
              </div>
              <div>
                <FieldLabel hint="empty = any">Destination zones</FieldLabel>
                <MultiChips options={zoneOptions} selected={form.dstZoneIds} onToggle={(id) => set("dstZoneIds", form.dstZoneIds.includes(id) ? form.dstZoneIds.filter((x) => x !== id) : [...form.dstZoneIds, id])} />
              </div>
              <div>
                <FieldLabel>Source addresses / groups</FieldLabel>
                <ObjectPicker
                  kind="address"
                  objects={addrPickerObjects}
                  groups={addrPickerGroups}
                  value={form.srcAddrIds}
                  onChange={(v) => set("srcAddrIds", v)}
                  triggerLabel="Pick source"
                />
              </div>
              <div>
                <FieldLabel>Destination addresses / groups</FieldLabel>
                <ObjectPicker
                  kind="address"
                  objects={addrPickerObjects}
                  groups={addrPickerGroups}
                  value={form.dstAddrIds}
                  onChange={(v) => set("dstAddrIds", v)}
                  triggerLabel="Pick destination"
                />
              </div>
              <div>
                <FieldLabel>Services / service groups</FieldLabel>
                <ObjectPicker
                  kind="service"
                  objects={svcPickerObjects}
                  groups={svcPickerGroups}
                  value={form.serviceIds}
                  onChange={(v) => set("serviceIds", v)}
                  triggerLabel="Pick services"
                />
              </div>
              <div>
                <FieldLabel hint="nDPI labels">Applications</FieldLabel>
                <PopoverMulti
                  options={appOptions}
                  selected={form.applicationIds}
                  onChange={(v) => set("applicationIds", v)}
                  placeholder="Search apps…"
                  triggerLabel="Pick applications"
                  icon={<Icons.AppWindow className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />}
                />
              </div>
              <div>
                <FieldLabel>Users</FieldLabel>
                <PopoverMulti
                  options={userOptions}
                  selected={form.userIds.map(String)}
                  onChange={(v) => set("userIds", v.map(Number))}
                  placeholder="Search users…"
                  triggerLabel="Pick users"
                  icon={<Icons.UserRound className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />}
                />
              </div>
              <div>
                <FieldLabel hint="aa:bb:cc:dd:ee:01, comma separated">Source MACs</FieldLabel>
                <Input
                  value={form.srcMacsRaw}
                  onChange={(e) => {
                    set("srcMacsRaw", e.target.value);
                    setMacError(null);
                  }}
                  placeholder="aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02"
                  className={cn("font-mono text-xs", macs.invalid.length > 0 && "border-rose-500 focus-visible:ring-rose-500")}
                />
                {macs.invalid.length > 0 && (
                  <p className="mt-1 text-[11px] text-rose-600 dark:text-rose-400">Invalid MACs: {macs.invalid.join(", ")}</p>
                )}
              </div>
              <div>
                <FieldLabel>Schedule</FieldLabel>
                <Select
                  value={form.scheduleId == null ? "always" : String(form.scheduleId)}
                  onValueChange={(v) => set("scheduleId", v === "always" ? null : Number(v))}
                >
                  <SelectTrigger className="mt-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="always">Always</SelectItem>
                    {props.schedules.map((s) => (
                      <SelectItem key={s.id} value={String(s.id)}>
                        {s.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {form.scheduleId != null && scheduleById.get(form.scheduleId) ? (
                  <p className="mt-1 text-[11px] text-zinc-400">{describeSchedule(scheduleById.get(form.scheduleId)!)}</p>
                ) : null}
              </div>
            </div>
          </EditorSection>

          <EditorSection title="Action">
            <RadioGroup
              value={form.action}
              onValueChange={(v) => set("action", v as FwAction)}
              className="grid grid-cols-2 gap-2 sm:grid-cols-4"
            >
              {(["allow", "deny", "drop", "reject"] as FwAction[]).map((a) => (
                <Label
                  key={a}
                  className={cn(
                    "flex cursor-pointer items-center justify-center gap-2 rounded-lg border p-2.5 text-sm",
                    form.action === a && "border-zinc-500/50 bg-zinc-500/5",
                  )}
                >
                  <RadioGroupItem value={a} className="sr-only" />
                  <ActionBadge action={a} />
                </Label>
              ))}
            </RadioGroup>
            <div>
              <FieldLabel>Logging</FieldLabel>
              <RadioGroup value={form.logging} onValueChange={(v) => set("logging", v as LoggingLevel)} className="flex gap-4">
                {(["none", "summary", "detail"] as LoggingLevel[]).map((l) => (
                  <Label key={l} className="flex cursor-pointer items-center gap-2 text-sm capitalize">
                    <RadioGroupItem value={l} /> {l}
                  </Label>
                ))}
              </RadioGroup>
            </div>
          </EditorSection>

          <EditorSection title="Protections">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel hint="conns per source">Connection limit</FieldLabel>
                <Input
                  type="number"
                  min={1}
                  value={form.connLimit}
                  onChange={(e) => set("connLimit", e.target.value)}
                  placeholder="e.g. 500"
                />
              </div>
              <div>
                <FieldLabel hint="new conns/s per source">Rate limit</FieldLabel>
                <Input
                  type="number"
                  min={1}
                  value={form.rateLimit}
                  onChange={(e) => set("rateLimit", e.target.value)}
                  placeholder="e.g. 100"
                />
              </div>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              <div>
                <p className="text-sm font-medium">SYN flood protection</p>
                <p className="text-[11px] text-zinc-500">SYN cookies / drops above threshold on this rule&apos;s scope</p>
              </div>
              <Switch checked={form.synProtection} onCheckedChange={(v) => set("synProtection", v)} />
            </div>
            {form.synProtection && (
              <div>
                <FieldLabel hint="SYN packets/s">SYN threshold</FieldLabel>
                <Input
                  type="number"
                  min={1}
                  value={form.synThreshold}
                  onChange={(e) => set("synThreshold", e.target.value)}
                  placeholder="e.g. 1000"
                />
              </div>
            )}
          </EditorSection>

          <EditorSection title="Attachments">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel>IPS policy</FieldLabel>
                <Select disabled value="none">
                  <SelectTrigger>
                    <SelectValue placeholder="Available in M04" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Available in M04</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <FieldLabel>QoS policy</FieldLabel>
                <Select disabled value="none">
                  <SelectTrigger>
                    <SelectValue placeholder="Available in M08" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Available in M08</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </EditorSection>

          {/* validation panel */}
          {conflicts !== null && (
            <div
              className={cn(
                "space-y-2 rounded-lg border p-3",
                conflicts.length === 0
                  ? "border-zinc-500/30 bg-zinc-500/5"
                  : blocking
                    ? "border-rose-500/40 bg-rose-500/5"
                    : "border-amber-500/40 bg-amber-500/5",
              )}
            >
              <p className="flex items-center gap-1.5 text-xs font-semibold">
                <Icons.ShieldQuestion className="h-3.5 w-3.5" />
                {conflicts.length === 0
                  ? "No conflicts — rule is clean"
                  : blocking
                    ? `${conflicts.length} blocking issue(s) — save requires “Save anyway”`
                    : `${conflicts.length} warning(s)`}
              </p>
              {conflicts.map((c, i) => (
                <div
                  key={i}
                  className={cn(
                    "flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded-md border px-2.5 py-1.5 text-xs",
                    c.reason === "redundant"
                      ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
                      : "border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-400",
                  )}
                >
                  <span className="font-medium">{REASON_LABEL[c.reason]}</span>
                  <span className="font-mono">{c.withRuleName}</span>
                  <span className="text-zinc-400">
                    ({c.reason === "redundant" ? "this rule is unreachable / duplicate" : "scope overlaps with a different action"})
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <Separator />
        <DialogFooter className="flex-col gap-2 sm:flex-row sm:items-center">
          <div className="flex gap-2 sm:mr-auto">
            <Button type="button" variant="outline" onClick={() => validateMut.mutate()} disabled={validateMut.isPending || saveMut.isPending}>
              <Icons.ShieldQuestion className="mr-1.5 h-4 w-4" />
              {validateMut.isPending ? "Validating…" : "Validate"}
            </Button>
          </div>
          {blocking && !override && (
            <Button type="button" variant="secondary" onClick={saveAnyway}>
              Save anyway
            </Button>
          )}
          <Button type="button" variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            type="button"
            onClick={submit}
            disabled={saveMut.isPending || validateMut.isPending || !form.name.trim() || (blocking && !override) || macs.invalid.length > 0}
            className="bg-zinc-700 text-white hover:bg-zinc-800"
          >
            {saveMut.isPending ? "Saving…" : editing ? "Save changes" : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function describeSchedule(s: ScheduleObject): string {
  if (s.type === "always") return "Always active";
  if (s.type === "recurring" && s.recurrence) {
    const days = s.recurrence.days.map((d) => ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][d - 1] ?? String(d)).join(", ");
    return `Recurring ${days} ${s.recurrence.start}–${s.recurrence.end} (${s.timezone})`;
  }
  if (s.type === "onetime") return `One-time window (${s.timezone})`;
  return s.type;
}

"use client";

/**
 * SD-WAN typed client (M20, spec 2.5) — mirrors the url-filter-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO types declared here (server routes live under
 * /api/v1/sdwan/*, service DTOs are structurally identical).
 */

// ── DTOs (mirror app/api/v1/sdwan/service.ts) ───────────────────────────────

export type SlaAction = "switch" | "warn";
export type Topology = "hub_spoke" | "full_mesh";
export type Encryption = "wireguard" | "ipsec";
export type SiteRole = "hub" | "spoke";
export type WanInterface = "wan0" | "wan1" | "wan2";
export type PathLabel = "mpls" | "broadband" | "lte";
export type PathState = "up" | "degraded" | "down";
export type PreferredPath = "latency" | "jitter" | "loss" | "fixed";

export interface SlaProfileDTO {
  id: number;
  name: string;
  latencyMsMax: number;
  jitterMsMax: number;
  lossPctMax: number;
  actionOnBreach: SlaAction;
  policyCount: number;
  createdAt: string;
}

export interface OverlayDTO {
  id: number;
  name: string;
  topology: Topology;
  encryption: Encryption;
  enabled: boolean;
  siteCount: number;
  policyCount: number;
  createdAt: string;
}

export interface SiteDTO {
  id: number;
  overlayId: number;
  overlayName: string;
  name: string;
  role: SiteRole;
  publicIp: string;
  wgPubKey: string | null;
  region: string | null;
  enabled: boolean;
  pathCount: number;
  createdAt: string;
}

export interface PathDTO {
  id: number;
  siteId: number;
  siteName: string;
  wanInterface: WanInterface;
  label: PathLabel;
  latencyMs: number;
  jitterMs: number;
  lossPct: number;
  state: PathState;
  lastProbeAt: string;
}

export interface PolicyDTO {
  id: number;
  name: string;
  overlayId: number;
  matchApp: string | null;
  matchDscp: string | null;
  matchDestCidr: string | null;
  preferredPath: PreferredPath;
  fixedWanInterface: WanInterface | null;
  slaProfileId: number | null;
  slaProfileName: string | null;
  enabled: boolean;
  createdAt: string;
}

export interface SdwanStatsDTO {
  overlays: number;
  sites: number;
  pathsByState: { up: number; degraded: number; down: number };
  avgLatencyMs: number;
  worstPath: { siteName: string; wanInterface: WanInterface; latencyMs: number } | null;
}

export interface ProbeSummaryDTO {
  probed: number;
  up: number;
  degraded: number;
  down: number;
}

/** Fallback SLA thresholds — keep in sync with FALLBACK_SLA in the service. */
export const FALLBACK_SLA = { latencyMsMax: 150, jitterMsMax: 30, lossPctMax: 1.0 } as const;

// ── constants + loose format regexes (mirror lib/validators/sdwan.ts) ───────

export const TOPOLOGIES: Topology[] = ["hub_spoke", "full_mesh"];
export const ENCRYPTIONS: Encryption[] = ["wireguard", "ipsec"];
export const SITE_ROLES: SiteRole[] = ["hub", "spoke"];
export const WAN_INTERFACES: WanInterface[] = ["wan0", "wan1", "wan2"];
export const PATH_LABELS: PathLabel[] = ["mpls", "broadband", "lte"];
export const PATH_STATES: PathState[] = ["up", "degraded", "down"];
export const PREFERRED_PATHS: PreferredPath[] = ["latency", "jitter", "loss", "fixed"];
export const SLA_ACTIONS: SlaAction[] = ["switch", "warn"];
/** Editor suggestions — the server accepts any CS0–CS6 / EF / AFxy label. */
export const DSCP_PRESETS: string[] = ["CS0", "CS2", "CS3", "CS4", "CS6", "EF", "AF31", "AF41"];

export const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export const IPV4_CIDR_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;
export const WG_PUBKEY_RE = /^[A-Za-z0-9+/=]{40,}$/;
export const DSCP_RE = /^(CS[0-6]|EF|AF[1-4][1-3]?)$/i;

// ── envelope plumbing (url-filter-api pattern) ──────────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class SdwanApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "SdwanApiError";
    this.code = code;
    this.details = details;
  }
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new SdwanApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SdwanApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from a SdwanApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof SdwanApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoint object ─────────────────────────────────────────────────────────

export const sdwanApi = {
  // SLA profiles
  listSlaProfiles: () => fetchJson<SlaProfileDTO[]>("/api/v1/sdwan/sla-profiles"),
  createSlaProfile: (body: Record<string, unknown>) =>
    fetchJson<SlaProfileDTO>("/api/v1/sdwan/sla-profiles", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateSlaProfile: (id: number, body: Record<string, unknown>) =>
    fetchJson<SlaProfileDTO>(`/api/v1/sdwan/sla-profiles/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteSlaProfile: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sdwan/sla-profiles/${id}`, { method: "DELETE" }),

  // overlays
  listOverlays: () => fetchJson<OverlayDTO[]>("/api/v1/sdwan/overlays"),
  createOverlay: (body: Record<string, unknown>) =>
    fetchJson<OverlayDTO>("/api/v1/sdwan/overlays", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateOverlay: (id: number, body: Record<string, unknown>) =>
    fetchJson<OverlayDTO>(`/api/v1/sdwan/overlays/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteOverlay: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sdwan/overlays/${id}`, { method: "DELETE" }),

  // sites
  listSites: (overlayId?: number) =>
    fetchJson<SiteDTO[]>(`/api/v1/sdwan/sites${overlayId !== undefined ? `?overlayId=${overlayId}` : ""}`),
  createSite: (body: Record<string, unknown>) =>
    fetchJson<SiteDTO>("/api/v1/sdwan/sites", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateSite: (id: number, body: Record<string, unknown>) =>
    fetchJson<SiteDTO>(`/api/v1/sdwan/sites/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteSite: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sdwan/sites/${id}`, { method: "DELETE" }),

  // paths
  listPaths: (siteId?: number) =>
    fetchJson<PathDTO[]>(`/api/v1/sdwan/paths${siteId !== undefined ? `?siteId=${siteId}` : ""}`),
  createPath: (siteId: number, body: Record<string, unknown>) =>
    fetchJson<PathDTO>(`/api/v1/sdwan/sites/${siteId}/paths`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePath: (id: number, body: Record<string, unknown>) =>
    fetchJson<PathDTO>(`/api/v1/sdwan/paths/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePath: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sdwan/paths/${id}`, { method: "DELETE" }),
  probe: (overlayId?: number) =>
    fetchJson<ProbeSummaryDTO>("/api/v1/sdwan/paths/probe", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(overlayId !== undefined ? { overlayId } : {}),
    }),

  // policies
  listPolicies: () => fetchJson<PolicyDTO[]>("/api/v1/sdwan/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    fetchJson<PolicyDTO>("/api/v1/sdwan/policies", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updatePolicy: (id: number, body: Record<string, unknown>) =>
    fetchJson<PolicyDTO>(`/api/v1/sdwan/policies/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deletePolicy: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sdwan/policies/${id}`, { method: "DELETE" }),

  // stats
  getStats: () => fetchJson<SdwanStatsDTO>("/api/v1/sdwan/stats"),
};

// ── formatting helpers ──────────────────────────────────────────────────────

/** Relative time for the last-probe column (url-filter-api pattern). */
export function fmtRelative(value: string | null): string {
  if (!value) return "never";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return value;
  const diff = Date.now() - ts;
  if (diff < 0) return "just now";
  const sec = Math.floor(diff / 1000);
  if (sec < 45) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

/** "hub_spoke" → "hub & spoke" for badge labels. */
export function topologyLabel(t: Topology): string {
  return t === "hub_spoke" ? "hub & spoke" : "full mesh";
}

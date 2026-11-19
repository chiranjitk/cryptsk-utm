"use client";

/**
 * SASE typed client (spec §4.2) — mirrors the incidents-api contract:
 * module-local envelope unwrapping that preserves zod `details`, DTO types
 * declared here (server routes live under /api/v1/sase/*, service DTOs are
 * structurally identical). Mesh configs are PLAN-ONLY previews — key
 * material arrives redacted ([REDACTED-SEE-SECRET-STORE]) and nothing is
 * ever applied to the host OS.
 */

// ── DTOs (mirror lib/sase/service.ts) ───────────────────────────────────────

export type SaseCloud = "onprem" | "aws" | "azure" | "gcp";
export type SaseRole = "edge" | "gateway";
export type SaseStatus = "planned" | "active" | "down";
export type SaseTunnelState = "planned" | "active" | "down";

export interface SaseNodeDTO {
  id: number;
  name: string;
  cloud: SaseCloud;
  region: string;
  role: SaseRole;
  tunnelEndpoint: string;
  publicSubnets: string[];
  status: SaseStatus;
  createdAt: string;
}

export interface SaseTunnelDTO {
  id: number;
  name: string;
  fromNodeId: number;
  toNodeId: number;
  fromNodeName: string;
  toNodeName: string;
  state: SaseTunnelState;
  pskRef: string;
  allowedSubnets: string[];
  createdAt: string;
}

export interface SaseMeshErrorDTO {
  code: string;
  message: string;
  tunnelId: number | null;
  nodeId: number | null;
}

export interface SaseNodeConfigDTO {
  nodeId: number;
  nodeName: string;
  filename: string;
  content: string;
}

export interface SaseMeshPlanDTO {
  valid: boolean;
  errors: SaseMeshErrorDTO[];
  configs: SaseNodeConfigDTO[];
}

export interface SaseRoutingEntryDTO {
  userEmail: string;
  region: string;
  updatedAt: string;
  resolvedNode: SaseNodeDTO | null;
}

export interface SaseResolveResultDTO {
  userEmail: string;
  region: string | null;
  node: SaseNodeDTO | null;
}

// ── display constants ───────────────────────────────────────────────────────

export const SASE_CLOUDS: SaseCloud[] = ["onprem", "aws", "azure", "gcp"];
export const SASE_ROLES: SaseRole[] = ["edge", "gateway"];
export const SASE_STATUSES: SaseStatus[] = ["planned", "active", "down"];
export const SASE_TUNNEL_STATES: SaseTunnelState[] = ["planned", "active", "down"];

/** Loose host[:port] check mirroring the server validator (renderer is strict). */
export const SASE_ENDPOINT_RE = /^\S+?(:\d{1,5})?$/;
export const SASE_IPV4_CIDR_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;
export const SASE_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Comma-separated input → trimmed CIDR list ("" → []); null when invalid. */
export function parseCidrInput(raw: string): string[] | null {
  const parts = raw
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  return parts.every((p) => SASE_IPV4_CIDR_RE.test(p)) ? parts : null;
}

// ── fetch plumbing (same shape as incidents-api.ts) ─────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class SaseApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "SaseApiError";
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
    throw new SaseApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SaseApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

export interface CreateNodeBody {
  name: string;
  cloud?: SaseCloud;
  region?: string;
  role?: SaseRole;
  tunnelEndpoint?: string;
  publicSubnets?: string[];
  status?: SaseStatus;
}

export interface UpdateNodeBody {
  name?: string;
  cloud?: SaseCloud;
  region?: string;
  role?: SaseRole;
  tunnelEndpoint?: string;
  publicSubnets?: string[];
  status?: SaseStatus;
}

export interface CreateTunnelBody {
  name: string;
  fromNodeId: number;
  toNodeId: number;
  state?: SaseTunnelState;
  pskRef?: string;
  allowedSubnets?: string[];
}

export interface UpdateTunnelBody {
  name?: string;
  fromNodeId?: number;
  toNodeId?: number;
  state?: SaseTunnelState;
  pskRef?: string;
  allowedSubnets?: string[];
}

export interface UpsertRoutingBody {
  userEmail: string;
  region: string;
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const saseApi = {
  listNodes: () => fetchJson<SaseNodeDTO[]>("/api/v1/sase/nodes"),
  createNode: (body: CreateNodeBody) =>
    fetchJson<SaseNodeDTO>("/api/v1/sase/nodes", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  updateNode: (id: number, body: UpdateNodeBody) =>
    fetchJson<SaseNodeDTO>(`/api/v1/sase/nodes/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deleteNode: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sase/nodes/${id}`, { method: "DELETE" }),

  listTunnels: () => fetchJson<SaseTunnelDTO[]>("/api/v1/sase/tunnels"),
  createTunnel: (body: CreateTunnelBody) =>
    fetchJson<SaseTunnelDTO>("/api/v1/sase/tunnels", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  updateTunnel: (id: number, body: UpdateTunnelBody) =>
    fetchJson<SaseTunnelDTO>(`/api/v1/sase/tunnels/${id}`, {
      method: "PATCH",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  deleteTunnel: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/sase/tunnels/${id}`, { method: "DELETE" }),

  renderMesh: () => fetchJson<SaseMeshPlanDTO>("/api/v1/sase/mesh"),

  listRouting: () => fetchJson<SaseRoutingEntryDTO[]>("/api/v1/sase/routing"),
  upsertRouting: (body: UpsertRoutingBody) =>
    fetchJson<SaseRoutingEntryDTO>("/api/v1/sase/routing", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  resolveRouting: (userEmail: string) =>
    fetchJson<SaseResolveResultDTO>("/api/v1/sase/routing/resolve", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ userEmail }),
    }),
};

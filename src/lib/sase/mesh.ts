/**
 * sase/mesh — PURE SASE → WireGuard (wg-quick) edge-to-cloud mesh renderer
 * (spec §4.2). Translates the console model (sase_nodes + sase_tunnels) into
 * one wg-quick config per node:
 *   utm-sase-<slug>.conf
 *
 * Pure module: no db, no exec, no filesystem — fully unit-tested. The DB
 * loading + identity-aware routing stub live in sase/service.ts, the API
 * surface in /api/v1/sase/mesh (GET = preview only).
 *
 * Design contract (mirrors the sdwan/os.ts plan-render conventions):
 *
 *  • PLAN-ONLY — this is a PREVIEW. Nothing here touches the host OS; cloud
 *    VM deployment is out of scope (§4.2 note). Every file header says so.
 *  • REDACTED KEYS — real key material NEVER appears in plans. PrivateKey,
 *    PublicKey and PresharedKey render the exact placeholder
 *    `[REDACTED-SEE-SECRET-STORE]`. Key material materializes out-of-band
 *    from the secret store at deploy time — never fabricated here.
 *  • PSK BY REFERENCE — the tunnel's pskRef (a secret-store pointer) renders
 *    only as a comment next to the redacted PresharedKey line; the reference
 *    is metadata, not secret content.
 *  • MESH SYMMETRY — every tunnel emits a [Peer] block on BOTH endpoints:
 *    the config of node A describes node B (Endpoint = B's tunnelEndpoint,
 *    AllowedIPs = the traffic routed toward B) and vice versa, so the total
 *    [Peer] count across all configs is always 2 × tunnels.
 *  • ALLOWEDIPs — the tunnel's allowedSubnets win; when empty the remote
 *    node's publicSubnets are used; when both are empty the peer is skipped
 *    with a loud error (wg-quick requires AllowedIPs — never guessed).
 *  • ENDPOINT HONESTY — a node without tunnelEndpoint (missing-endpoint) or
 *    without a numeric :port (endpoint-without-port) cannot be a peer; the
 *    affected [Peer] block is skipped, not guessed. The node's own
 *    [Interface] ListenPort falls back to the WireGuard default 51820.
 *  • ADDRESS — [Interface] Address takes the node's FIRST publicSubnets
 *    entry, annotated with a /32 host-bit suggestion comment (SASE v1: the
 *    registry stores routed subnets; the wg interface itself should carry a
 *    host address). No subnets → missing-address error, line omitted.
 *  • VALIDATION — self-tunnels, dangling node refs and duplicate tunnel
 *    names are collected as errors (valid=false); the affected tunnel's peer
 *    blocks are skipped, everything else keeps rendering.
 *  • Deterministic: same input → byte-identical configs (sorted by id).
 */

// ── constants ───────────────────────────────────────────────────────────────

/** Managed file prefix — every mesh config the console owns. */
export const SASE_FILE_PREFIX = "utm-sase-";

/** wg-quick config dir convention (preview paths only — nothing is written). */
export const SASE_WG_DIR = process.env.CONSOLE_WG_DIR || "/etc/wireguard";

/** WireGuard default listen port when the node endpoint carries none. */
export const SASE_DEFAULT_PORT = 51820;

/**
 * Plan-only key placeholder — PrivateKey/PublicKey/PresharedKey ALL render
 * this exact literal; real key material lives in the secret store.
 */
export const SASE_KEY_PLACEHOLDER = "[REDACTED-SEE-SECRET-STORE]";

/** /32 host-bit hint appended to the [Interface] Address line. */
export const SASE_HOST_HINT =
  "# hint: the wg interface itself should carry a /32 host address — this subnet is the routed public space";

// ── input shapes (db → deterministic DTOs, service-owned) ───────────────────

export interface SaseNodeShape {
  id: number;
  name: string;
  cloud: string;
  region: string;
  role: string;
  /** public host:port for WireGuard — empty while the node is unplanned */
  tunnelEndpoint: string;
  /** routed public subnets, e.g. ["10.10.0.0/16"] */
  publicSubnets: string[];
  status: string;
}

export interface SaseTunnelShape {
  id: number;
  name: string;
  fromNodeId: number;
  toNodeId: number;
  state: string;
  /** secret-store REFERENCE (e.g. "vault:wg/edge-to-aws") — never a PSK */
  pskRef: string;
  /** traffic allowed through this tunnel; falls back to remote publicSubnets */
  allowedSubnets: string[];
}

// ── output shapes ───────────────────────────────────────────────────────────

export type SaseMeshErrorCode =
  | "missing-endpoint"
  | "endpoint-without-port"
  | "self-tunnel"
  | "dangling-node-ref"
  | "duplicate-tunnel-name"
  | "no-allowed-subnets"
  | "missing-address";

export interface SaseMeshError {
  code: SaseMeshErrorCode;
  message: string;
  /** tunnel the error belongs to (null for node-scoped errors) */
  tunnelId: number | null;
  /** node the error belongs to (null for tunnel-scoped errors) */
  nodeId: number | null;
}

export interface SaseNodeConfig {
  nodeId: number;
  nodeName: string;
  /** `utm-sase-<slug>.conf` — wg-quick file name (preview path only) */
  filename: string;
  /** complete wg-quick file content (plan rendering — keys redacted) */
  content: string;
}

export interface SaseMeshPlan {
  /** true when errors is empty — a valid plan is deployable out-of-band */
  valid: boolean;
  errors: SaseMeshError[];
  configs: SaseNodeConfig[];
}

// ── deterministic helpers ───────────────────────────────────────────────────

/** "Edge NYC" + 7 → "edge-nyc-7" (kebab name + id — the mission slug rule). */
export function saseSlug(name: string, id: number): string {
  const kebab = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || "node";
  return `${kebab}-${id}`;
}

/** `utm-sase-<slug>.conf` — the wg-quick file name for a node. */
export function saseFilename(name: string, id: number): string {
  return `${SASE_FILE_PREFIX}${saseSlug(name, id)}.conf`;
}

/** Preview path under the wg config dir — NOTHING is ever written there. */
export function sasePreviewPath(name: string, id: number): string {
  return `${SASE_WG_DIR}/${saseFilename(name, id)}`;
}

/**
 * Numeric :port suffix of a tunnel endpoint, or null when absent/invalid.
 * Valid range 1..65535 — "edge.example.com" → null, "…:0"/"…:99999" → null.
 */
export function endpointPort(endpoint: string): number | null {
  const m = /:(\d{1,5})$/.exec(endpoint.trim());
  if (!m) return null;
  const port = Number(m[1]);
  return port >= 1 && port <= 65535 ? port : null;
}

/** Endpoint is non-empty AND carries a valid numeric port. */
export function endpointHasPort(endpoint: string): boolean {
  const trimmed = endpoint.trim();
  return trimmed.length > 0 && endpointPort(trimmed) !== null;
}

// ── identity-aware routing stub (§4.2 user → nearest node) ──────────────────

/**
 * Pick the node a user should anchor to:
 *   1. among ACTIVE nodes in the same region (case-insensitive), prefer the
 *      gateway role (lowest id on ties),
 *   2. else the first active node anywhere (lowest id),
 *   3. else null — no usable node exists.
 * planned/down nodes are never routable, so they never win — not even in the
 * user's own region.
 */
export function pickNearestNode(nodes: SaseNodeShape[], userRegion: string): SaseNodeShape | null {
  const region = userRegion.trim().toLowerCase();
  const active = [...nodes].filter((n) => n.status === "active").sort((a, b) => a.id - b.id);
  if (!region) return active[0] ?? null;
  const inRegion = active.filter((n) => n.region.trim().toLowerCase() === region);
  const gateway = inRegion.find((n) => n.role === "gateway");
  return gateway ?? inRegion[0] ?? active[0] ?? null;
}

// ── renderer ────────────────────────────────────────────────────────────────

function meshError(
  code: SaseMeshErrorCode,
  message: string,
  tunnelId: number | null,
  nodeId: number | null,
): SaseMeshError {
  return { code, message, tunnelId, nodeId };
}

/** AllowedIPs for the peer toward `remote` on `tunnel` — null when undecidable. */
function allowedIpsFor(tunnel: SaseTunnelShape, remote: SaseNodeShape): string[] | null {
  if (tunnel.allowedSubnets.length > 0) return tunnel.allowedSubnets;
  if (remote.publicSubnets.length > 0) return remote.publicSubnets;
  return null;
}

function peerBlock(tunnel: SaseTunnelShape, remote: SaseNodeShape): string[] {
  const lines: string[] = [
    "",
    "[Peer]",
    `# tunnel '${tunnel.name}' (id ${tunnel.id}, state ${tunnel.state}) — remote node '${remote.name}' (id ${remote.id}, cloud ${remote.cloud}, region ${remote.region})`,
    `PublicKey = ${SASE_KEY_PLACEHOLDER}`,
  ];
  if (tunnel.pskRef.trim()) {
    lines.push(
      `# PSK reference: ${tunnel.pskRef.trim()} (secret store — value never rendered)`,
      `PresharedKey = ${SASE_KEY_PLACEHOLDER}`,
    );
  }
  lines.push(`AllowedIPs = ${allowedIpsFor(tunnel, remote)!.join(", ")}`);
  lines.push(`Endpoint = ${remote.tunnelEndpoint.trim()}`);
  return lines;
}

/**
 * Render one wg-quick config per node (sorted by id). Deterministic and pure:
 * same input → byte-identical content. Peer blocks are emitted per tunnel on
 * BOTH endpoints; structurally broken tunnels (self/dangling/duplicate-name)
 * collect errors and skip their affected peers without aborting the plan.
 */
export function renderMeshConfig(nodes: SaseNodeShape[], tunnels: SaseTunnelShape[]): SaseMeshPlan {
  const errors: SaseMeshError[] = [];
  const sortedNodes = [...nodes].sort((a, b) => a.id - b.id);
  const sortedTunnels = [...tunnels].sort((a, b) => a.id - b.id);
  const byId = new Map(sortedNodes.map((n) => [n.id, n]));

  // duplicate tunnel names — flagged once per offending tunnel (the DB also
  // enforces (tenantId, name) unique, but the pure renderer must catch raw
  // shapes too)
  const nameSeen = new Map<string, number>();
  for (const t of sortedTunnels) {
    const owner = nameSeen.get(t.name);
    if (owner !== undefined) {
      errors.push(
        meshError(
          "duplicate-tunnel-name",
          `tunnel '${t.name}' (id ${t.id}) duplicates the name of tunnel id ${owner}`,
          t.id,
          null,
        ),
      );
    } else {
      nameSeen.set(t.name, t.id);
    }
  }

  // structural tunnel errors — self-loops and dangling refs skip the tunnel's
  // peer rendering entirely (both directions), everything else continues
  const renderable = new Set<number>();
  for (const t of sortedTunnels) {
    if (t.fromNodeId === t.toNodeId) {
      errors.push(
        meshError(
          "self-tunnel",
          `tunnel '${t.name}' (id ${t.id}) connects node ${t.fromNodeId} to itself — peer blocks skipped`,
          t.id,
          t.fromNodeId,
        ),
      );
      continue;
    }
    if (!byId.has(t.fromNodeId) || !byId.has(t.toNodeId)) {
      const missing = !byId.has(t.fromNodeId) ? t.fromNodeId : t.toNodeId;
      errors.push(
        meshError(
          "dangling-node-ref",
          `tunnel '${t.name}' (id ${t.id}) references missing node id ${missing} — peer blocks skipped`,
          t.id,
          null,
        ),
      );
      continue;
    }
    renderable.add(t.id);
  }

  // peers per node — tunnel id order, both directions per renderable tunnel
  const peers = new Map<number, string[][]>();
  for (const t of sortedTunnels) {
    if (!renderable.has(t.id)) continue;
    const from = byId.get(t.fromNodeId)!;
    const to = byId.get(t.toNodeId)!;
    for (const [local, remote] of [
      [from, to],
      [to, from],
    ] as const) {
      // remote endpoint honesty — a peer without a dialable endpoint is
      // skipped, never guessed
      const endpoint = remote.tunnelEndpoint.trim();
      if (!endpoint) {
        errors.push(
          meshError(
            "missing-endpoint",
            `tunnel '${t.name}' (id ${t.id}): node '${remote.name}' (id ${remote.id}) has no tunnel endpoint — [Peer] block skipped on '${local.name}'`,
            t.id,
            remote.id,
          ),
        );
        continue;
      }
      if (endpointPort(endpoint) === null) {
        errors.push(
          meshError(
            "endpoint-without-port",
            `tunnel '${t.name}' (id ${t.id}): node '${remote.name}' (id ${remote.id}) endpoint '${endpoint}' carries no numeric :port — [Peer] block skipped on '${local.name}'`,
            t.id,
            remote.id,
          ),
        );
        continue;
      }
      if (allowedIpsFor(t, remote) === null) {
        errors.push(
          meshError(
            "no-allowed-subnets",
            `tunnel '${t.name}' (id ${t.id}): neither the tunnel allowedSubnets nor node '${remote.name}' (id ${remote.id}) publicSubnets define any CIDR — [Peer] block skipped on '${local.name}'`,
            t.id,
            remote.id,
          ),
        );
        continue;
      }
      const list = peers.get(local.id) ?? [];
      list.push(peerBlock(t, remote));
      peers.set(local.id, list);
    }
  }

  // one config per node — [Interface] + collected [Peer] blocks
  const configs: SaseNodeConfig[] = sortedNodes.map((node) => {
    const lines: string[] = [
      `# === UTM CONSOLE MANAGED (generated, do not edit) — GUI: SASE (spec §4.2) ===`,
      `# PLAN-ONLY preview: keys are redacted (${SASE_KEY_PLACEHOLDER}); nothing is`,
      `# applied to the host OS — cloud VM deployment happens out-of-band.`,
      `# node '${node.name}' (id ${node.id}, cloud ${node.cloud}, region ${node.region}, role ${node.role}, status ${node.status})`,
      ``,
      `[Interface]`,
      `ListenPort = ${endpointPort(node.tunnelEndpoint) ?? SASE_DEFAULT_PORT}`,
      `PrivateKey = ${SASE_KEY_PLACEHOLDER}`,
    ];
    if (node.publicSubnets.length > 0) {
      lines.push(`Address = ${node.publicSubnets[0]} ${SASE_HOST_HINT}`);
    } else {
      errors.push(
        meshError(
          "missing-address",
          `node '${node.name}' (id ${node.id}) has no publicSubnets — [Interface] Address line omitted`,
          null,
          node.id,
        ),
      );
    }
    for (const block of peers.get(node.id) ?? []) {
      lines.push(...block);
    }
    if ((peers.get(node.id) ?? []).length === 0) {
      lines.push(``, `# no renderable peers yet — add tunnels to complete the mesh`);
    }
    return {
      nodeId: node.id,
      nodeName: node.name,
      filename: saseFilename(node.name, node.id),
      content: lines.join("\n") + "\n",
    };
  });

  return { valid: errors.length === 0, errors, configs };
}

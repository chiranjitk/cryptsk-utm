/**
 * SASE Basics tests (spec §4.2) — two layers:
 *
 *  • PURE renderer tests over lib/sase/mesh.ts (the sdwan-os.test.ts style):
 *    mesh symmetry (every tunnel renders a [Peer] block on BOTH endpoints →
 *    total peers = 2 × tunnels), wg-quick structure (ListenPort from the
 *    endpoint, Address = first public subnet with the /32 hint), REDACTED
 *    key placeholders (PrivateKey/PublicKey/PresharedKey — never fabricated
 *    key material), PSK-by-reference comments, the error collection contract
 *    (missing endpoint, endpoint without port, self-tunnel, dangling node
 *    ref, duplicate tunnel names, no-allowed-subnets, missing address) and
 *    the identity-aware routing stub pickNearestNode (same-region gateway
 *    preference + active fallbacks).
 *
 *  • DB-backed service tests over the per-run copy of the pushed dev schema
 *    (the incidents.test.ts harness): node/tunnel CRUD paths with the mesh
 *    integrity guards (duplicate name, duplicate direction, self-tunnel,
 *    dangling node, referenced-node delete), renderForTenant happy path and
 *    the identity routing map (upsert/list/resolve through the system
 *    settings helpers). The sase modules are imported AFTER the DATABASE_URL
 *    override — static imports would resolve the Prisma datasource too early.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  SASE_DEFAULT_PORT,
  SASE_KEY_PLACEHOLDER,
  endpointHasPort,
  endpointPort,
  renderMeshConfig,
  pickNearestNode,
  saseFilename,
  saseSlug,
  type SaseNodeShape,
  type SaseTunnelShape,
} from "@/lib/sase/mesh";

// ── DB harness (copy of the pushed dev schema — dev DB never written) ───────

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "sase-mesh-"));
const DB_PATH = path.join(TMP_DIR, "sase-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const service = await import("@/lib/sase/service");

beforeAll(async () => {
  // the copied dev schema has no tenant rows — sase rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "sase-test" } });
});

beforeEach(async () => {
  await db.saseTunnel.deleteMany({});
  await db.saseNode.deleteMany({});
  await db.systemSetting.deleteMany({ where: { category: "sase" } });
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── pure fixtures ───────────────────────────────────────────────────────────

const nodeA: SaseNodeShape = {
  id: 1,
  name: "Edge NYC",
  cloud: "onprem",
  region: "us-east-1",
  role: "edge",
  tunnelEndpoint: "nyc.example.com:51820",
  publicSubnets: ["10.10.0.0/16"],
  status: "active",
};

const nodeB: SaseNodeShape = {
  id: 2,
  name: "AWS Gateway",
  cloud: "aws",
  region: "eu-west-1",
  role: "gateway",
  tunnelEndpoint: "aws.example.com:51821",
  publicSubnets: ["10.20.0.0/16"],
  status: "active",
};

const nodeC: SaseNodeShape = {
  id: 3,
  name: "GCP Edge",
  cloud: "gcp",
  region: "eu-west-1",
  role: "edge",
  tunnelEndpoint: "gcp.example.com:51822",
  publicSubnets: ["10.30.0.0/16"],
  status: "active",
};

const tunnel = (over: Partial<SaseTunnelShape> & Pick<SaseTunnelShape, "id" | "name" | "fromNodeId" | "toNodeId">): SaseTunnelShape => ({
  state: "planned",
  pskRef: "",
  allowedSubnets: [],
  ...over,
});

const tAB = tunnel({ id: 1, name: "edge-to-aws", fromNodeId: 1, toNodeId: 2, pskRef: "vault:wg/edge-to-aws", allowedSubnets: ["10.10.0.0/16", "192.168.0.0/16"] });

function countPeers(content: string): number {
  return content.split("\n").filter((l) => l.trim() === "[Peer]").length;
}

// ── renderer: structure + mesh symmetry ─────────────────────────────────────

describe("renderMeshConfig — structure", () => {
  it("renders one config per node, a [Peer] block on BOTH endpoints and parsed listen ports", () => {
    const plan = renderMeshConfig([nodeA, nodeB], [tAB]);
    expect(plan.valid).toBe(true);
    expect(plan.errors).toEqual([]);
    expect(plan.configs.map((c) => c.filename)).toEqual([
      "utm-sase-edge-nyc-1.conf",
      "utm-sase-aws-gateway-2.conf",
    ]);

    const confA = plan.configs[0].content;
    const confB = plan.configs[1].content;
    expect(countPeers(confA)).toBe(1);
    expect(countPeers(confB)).toBe(1);

    // A's peer describes B: B's endpoint + the tunnel's allowed subnets
    expect(confA).toContain("ListenPort = 51820");
    expect(confA).toContain("Endpoint = aws.example.com:51821");
    expect(confA).toContain("AllowedIPs = 10.10.0.0/16, 192.168.0.0/16");
    // B's peer describes A: A's endpoint
    expect(confB).toContain("ListenPort = 51821");
    expect(confB).toContain("Endpoint = nyc.example.com:51820");
    // interface address = first public subnet + the /32 host-bit hint
    expect(confA).toContain("Address = 10.10.0.0/16");
    expect(confA).toContain("/32");
    // plan-only header honesty
    expect(confA).toContain("PLAN-ONLY preview");
    expect(confA).toContain("[Interface]");
  });

  it("falls back to the WireGuard default port when the endpoint carries none", () => {
    expect(endpointPort(nodeA.tunnelEndpoint)).toBe(51820);
    expect(endpointPort("aws.example.com")).toBeNull();
    expect(endpointPort("aws.example.com:99999")).toBeNull();
    expect(endpointHasPort("aws.example.com")).toBe(false);
    const lone: SaseNodeShape = { ...nodeA, id: 9, tunnelEndpoint: "lone.example.com" };
    const plan = renderMeshConfig([lone], []);
    expect(plan.configs[0].content).toContain(`ListenPort = ${SASE_DEFAULT_PORT}`);
  });

  it("keeps the total peer count at 2 × tunnels across a multi-node mesh", () => {
    const tBC = tunnel({ id: 2, name: "aws-to-gcp", fromNodeId: 2, toNodeId: 3 });
    const plan = renderMeshConfig([nodeA, nodeB, nodeC], [tAB, tBC]);
    expect(plan.valid).toBe(true);
    expect(plan.configs).toHaveLength(3);
    const totalPeers = plan.configs.reduce((sum, c) => sum + countPeers(c.content), 0);
    expect(totalPeers).toBe(4); // 2 tunnels × both endpoints
    expect(plan.configs.find((c) => c.nodeId === 2)?.content).toContain("AllowedIPs = 10.30.0.0/16"); // fallback: remote publicSubnets
  });

  it("is deterministic — same input, byte-identical configs", () => {
    const tBC = tunnel({ id: 2, name: "aws-to-gcp", fromNodeId: 2, toNodeId: 3 });
    const one = renderMeshConfig([nodeA, nodeB, nodeC], [tAB, tBC]);
    const two = renderMeshConfig([nodeC, nodeA, nodeB], [tBC, tAB]);
    expect(one.configs.map((c) => c.content)).toEqual(two.configs.map((c) => c.content));
  });

  it("names files with the utm-sase-<slug>.conf convention", () => {
    expect(saseSlug("Edge NYC", 1)).toBe("edge-nyc-1");
    expect(saseFilename("AWS Gateway", 2)).toBe("utm-sase-aws-gateway-2.conf");
  });
});

// ── renderer: redacted keys (security rule) ─────────────────────────────────

describe("renderMeshConfig — redacted keys", () => {
  it("renders the exact placeholder for PrivateKey/PublicKey/PresharedKey and never fabricates material", () => {
    const plan = renderMeshConfig([nodeA, nodeB], [tAB]);
    for (const c of plan.configs) {
      expect(c.content).toContain(`PrivateKey = ${SASE_KEY_PLACEHOLDER}`);
      expect(c.content).toContain(`PublicKey = ${SASE_KEY_PLACEHOLDER}`);
      expect(c.content).toContain(`PresharedKey = ${SASE_KEY_PLACEHOLDER}`);
      // no 44-char base64 key material anywhere in the plan
      expect(/[A-Za-z0-9+/]{43}=/.test(c.content)).toBe(false);
      // the pskRef renders as a comment reference only
      expect(c.content).toContain("# PSK reference: vault:wg/edge-to-aws");
    }
  });

  it("omits the PresharedKey line entirely when the tunnel has no pskRef", () => {
    const bare = tunnel({ id: 1, name: "no-psk", fromNodeId: 1, toNodeId: 2 });
    const plan = renderMeshConfig([nodeA, nodeB], [bare]);
    expect(plan.valid).toBe(true);
    expect(plan.configs[0].content).not.toContain("PresharedKey");
    expect(plan.configs[1].content).not.toContain("PresharedKey");
  });
});

// ── renderer: error collection ──────────────────────────────────────────────

describe("renderMeshConfig — error collection", () => {
  it("flags a missing endpoint and renders the reachable direction only", () => {
    const bOffline: SaseNodeShape = { ...nodeB, tunnelEndpoint: "" };
    const plan = renderMeshConfig([nodeA, bOffline], [tAB]);
    expect(plan.valid).toBe(false);
    expect(plan.errors.map((e) => e.code)).toContain("missing-endpoint");
    expect(plan.errors[0].tunnelId).toBe(1);
    expect(plan.errors[0].nodeId).toBe(2);
    // A cannot dial B (no endpoint) — B's config still renders its peer toward A
    const confA = plan.configs.find((c) => c.nodeId === 1)!;
    const confB = plan.configs.find((c) => c.nodeId === 2)!;
    expect(countPeers(confA.content)).toBe(0);
    expect(countPeers(confB.content)).toBe(1);
    expect(confA.content).toContain("no renderable peers yet");
  });

  it("flags an endpoint without a numeric :port", () => {
    const bNoPort: SaseNodeShape = { ...nodeB, tunnelEndpoint: "aws.example.com" };
    const plan = renderMeshConfig([nodeA, bNoPort], [tAB]);
    expect(plan.valid).toBe(false);
    const err = plan.errors.find((e) => e.code === "endpoint-without-port");
    expect(err).toBeTruthy();
    expect(err?.message).toContain("aws.example.com");
  });

  it("flags self-tunnels and dangling node refs, skipping the affected peers", () => {
    const selfLoop = tunnel({ id: 1, name: "self-loop", fromNodeId: 1, toNodeId: 1 });
    const dangling = tunnel({ id: 2, name: "ghost-link", fromNodeId: 1, toNodeId: 99 });
    const plan = renderMeshConfig([nodeA, nodeB], [selfLoop, dangling]);
    expect(plan.valid).toBe(false);
    expect(plan.errors.map((e) => e.code)).toEqual(
      expect.arrayContaining(["self-tunnel", "dangling-node-ref"]),
    );
    for (const c of plan.configs) expect(countPeers(c.content)).toBe(0);
  });

  it("flags duplicate tunnel names once per offender", () => {
    const dup = tunnel({ id: 2, name: "edge-to-aws", fromNodeId: 2, toNodeId: 1 });
    const plan = renderMeshConfig([nodeA, nodeB], [tAB, dup]);
    const dupErrors = plan.errors.filter((e) => e.code === "duplicate-tunnel-name");
    expect(dupErrors).toHaveLength(1);
    expect(dupErrors[0].tunnelId).toBe(2);
    // both tunnels are structurally sound — peers still render both ways
    const totalPeers = plan.configs.reduce((sum, c) => sum + countPeers(c.content), 0);
    expect(totalPeers).toBe(4);
  });

  it("flags peers with no decidable AllowedIPs and nodes without an Address", () => {
    const noSubnets: SaseNodeShape = { ...nodeB, publicSubnets: [] };
    const bareTunnel = tunnel({ id: 1, name: "bare", fromNodeId: 1, toNodeId: 2 });
    const plan = renderMeshConfig([nodeA, noSubnets], [bareTunnel]);
    expect(plan.errors.map((e) => e.code)).toContain("no-allowed-subnets");
    const addrErrors = plan.errors.filter((e) => e.code === "missing-address");
    expect(addrErrors).toHaveLength(1);
    expect(addrErrors[0].nodeId).toBe(2);
    const confB = plan.configs.find((c) => c.nodeId === 2)!;
    expect(confB.content).not.toContain("Address =");
  });
});

// ── identity-aware routing stub (pure) ──────────────────────────────────────

describe("pickNearestNode", () => {
  const edgeUs: SaseNodeShape = { ...nodeA }; // id 1 · edge · us-east-1 · active
  const gwUs: SaseNodeShape = { ...nodeB, id: 2, region: "us-east-1" }; // gateway · us-east-1
  const gwEu: SaseNodeShape = { ...nodeC, id: 3, role: "gateway" }; // gateway · eu-west-1

  it("prefers the gateway role within the user's region", () => {
    expect(pickNearestNode([edgeUs, gwUs, gwEu], "us-east-1")?.id).toBe(2);
  });

  it("falls back to a same-region edge node when no gateway exists there", () => {
    expect(pickNearestNode([edgeUs, gwEu], "us-east-1")?.id).toBe(1);
  });

  it("falls back to the first active node anywhere when the region has none", () => {
    expect(pickNearestNode([gwEu], "us-east-1")?.id).toBe(3);
  });

  it("never anchors to planned/down nodes — even in the user's own region", () => {
    const plannedUs: SaseNodeShape = { ...edgeUs, status: "planned" };
    const downUs: SaseNodeShape = { ...gwUs, status: "down" };
    expect(pickNearestNode([plannedUs, downUs, gwEu], "us-east-1")?.id).toBe(3);
  });

  it("returns null when nothing is active and matches region-insensitively", () => {
    expect(pickNearestNode([edgeUs, gwEu], "us-east-1")).not.toBeNull();
    expect(pickNearestNode([{ ...edgeUs, status: "down" }], "us-east-1")).toBeNull();
    expect(pickNearestNode([{ ...edgeUs, region: "US-EAST-1" }], "us-east-1")?.id).toBe(1);
    expect(pickNearestNode([], "us-east-1")).toBeNull();
  });
});

// ── DB-backed service paths ─────────────────────────────────────────────────

async function seedNode(over: {
  name: string;
  cloud?: string;
  region?: string;
  role?: string;
  tunnelEndpoint?: string;
  publicSubnets?: string[];
  status?: string;
}) {
  return service.createNode(1, {
    name: over.name,
    cloud: (over.cloud ?? "onprem") as "onprem" | "aws" | "azure" | "gcp",
    region: over.region ?? "us-east-1",
    role: (over.role ?? "edge") as "edge" | "gateway",
    tunnelEndpoint: over.tunnelEndpoint ?? "",
    publicSubnets: over.publicSubnets ?? [],
    status: (over.status ?? "planned") as "planned" | "active" | "down",
  });
}

describe("SASE service — node CRUD", () => {
  it("creates, lists, updates and reads nodes with parsed subnet JSON", async () => {
    const created = await seedNode({
      name: "edge-nyc",
      cloud: "aws",
      region: "us-east-1",
      role: "gateway",
      tunnelEndpoint: "nyc.example.com:51820",
      publicSubnets: ["10.10.0.0/16", "10.11.0.0/16"],
      status: "active",
    });
    expect(created.id).toBeGreaterThan(0);
    expect(created.publicSubnets).toEqual(["10.10.0.0/16", "10.11.0.0/16"]);
    expect(created.cloud).toBe("aws");
    expect(created.status).toBe("active");

    const updated = await service.updateNode(1, created.id, { status: "down", region: "us-west-2" });
    expect(updated.status).toBe("down");
    expect(updated.region).toBe("us-west-2");
    expect(updated.publicSubnets).toEqual(["10.10.0.0/16", "10.11.0.0/16"]); // untouched

    const listed = await service.listNodes(1);
    expect(listed.map((n) => n.name)).toEqual(["edge-nyc"]);

    const single = await service.getNode(1, created.id);
    expect(single.tunnelEndpoint).toBe("nyc.example.com:51820");
  });

  it("rejects duplicate node names per tenant", async () => {
    await seedNode({ name: "edge-nyc" });
    await expect(seedNode({ name: "edge-nyc" })).rejects.toThrow(/already exists/);
  });

  it("refuses to delete a node still referenced by a tunnel", async () => {
    const a = await seedNode({ name: "edge-nyc", tunnelEndpoint: "nyc.example.com:51820", status: "active" });
    const b = await seedNode({ name: "aws-gw", tunnelEndpoint: "aws.example.com:51820", status: "active" });
    await service.createTunnel(1, { name: "edge-to-aws", fromNodeId: a.id, toNodeId: b.id });

    await expect(service.deleteNode(1, a.id)).rejects.toThrow(/referenced by tunnel/);
    await service.deleteTunnel(1, (await service.listTunnels(1))[0].id);
    await expect(service.deleteNode(1, a.id)).resolves.toEqual({ ok: true });
  });
});

describe("SASE service — tunnel guards", () => {
  it("rejects self-tunnels, dangling node refs and duplicate same-direction pairs", async () => {
    const a = await seedNode({ name: "edge-nyc", tunnelEndpoint: "nyc.example.com:51820", status: "active" });
    const b = await seedNode({ name: "aws-gw", tunnelEndpoint: "aws.example.com:51820", status: "active" });

    await expect(
      service.createTunnel(1, { name: "self", fromNodeId: a.id, toNodeId: a.id }),
    ).rejects.toThrow(/itself/);
    await expect(
      service.createTunnel(1, { name: "ghost", fromNodeId: 9999, toNodeId: b.id }),
    ).rejects.toThrow(/fromNodeId 9999 does not reference an existing SASE node/);
    await expect(
      service.createTunnel(1, { name: "ghost-to", fromNodeId: a.id, toNodeId: 9999 }),
    ).rejects.toThrow(/toNodeId 9999 does not reference an existing SASE node/);

    const first = await service.createTunnel(1, {
      name: "edge-to-aws",
      fromNodeId: a.id,
      toNodeId: b.id,
      pskRef: "vault:wg/edge-to-aws",
    });
    await expect(
      service.createTunnel(1, { name: "edge-to-aws-2", fromNodeId: a.id, toNodeId: b.id }),
    ).rejects.toThrow(/already exists/);

    // the reverse direction is a distinct mesh link — allowed
    const reverse = await service.createTunnel(1, { name: "aws-to-edge", fromNodeId: b.id, toNodeId: a.id });
    expect(reverse.fromNodeName).toBe("aws-gw");
    expect(reverse.toNodeName).toBe("edge-nyc");

    const listed = await service.listTunnels(1);
    expect(listed.map((t) => t.name).sort()).toEqual(["aws-to-edge", "edge-to-aws"]);
    expect(listed.find((t) => t.name === "edge-to-aws")?.pskRef).toBe("vault:wg/edge-to-aws");
    void first;
  });

  it("re-runs the pair guards on PATCH (self-loop and duplicate direction)", async () => {
    const a = await seedNode({ name: "edge-nyc", tunnelEndpoint: "nyc.example.com:51820", status: "active" });
    const b = await seedNode({ name: "aws-gw", tunnelEndpoint: "aws.example.com:51820", status: "active" });
    const c = await seedNode({ name: "gcp-edge", tunnelEndpoint: "gcp.example.com:51820", status: "active" });
    const t1 = await service.createTunnel(1, { name: "edge-to-aws", fromNodeId: a.id, toNodeId: b.id });
    await service.createTunnel(1, { name: "aws-to-gcp", fromNodeId: b.id, toNodeId: c.id });

    await expect(
      service.updateTunnel(1, t1.id, { toNodeId: a.id }),
    ).rejects.toThrow(/itself/);
    await expect(
      service.updateTunnel(1, t1.id, { fromNodeId: b.id, toNodeId: c.id }),
    ).rejects.toThrow(/already exists/);
    const swapped = await service.updateTunnel(1, t1.id, { toNodeId: c.id, state: "active" });
    expect(swapped.fromNodeName).toBe("edge-nyc");
    expect(swapped.toNodeName).toBe("gcp-edge");
    expect(swapped.state).toBe("active");
  });
});

describe("renderForTenant — DB happy path", () => {
  it("renders the whole registry into a valid plan with redacted keys", async () => {
    const a = await seedNode({
      name: "Edge NYC",
      tunnelEndpoint: "nyc.example.com:51820",
      publicSubnets: ["10.10.0.0/16"],
      status: "active",
    });
    const b = await seedNode({
      name: "AWS Gateway",
      region: "eu-west-1",
      role: "gateway",
      tunnelEndpoint: "aws.example.com:51821",
      publicSubnets: ["10.20.0.0/16"],
      status: "active",
    });
    const c = await seedNode({
      name: "GCP Edge",
      cloud: "gcp",
      region: "eu-west-1",
      tunnelEndpoint: "gcp.example.com:51822",
      publicSubnets: ["10.30.0.0/16"],
      status: "active",
    });
    await service.createTunnel(1, {
      name: "edge-to-aws",
      fromNodeId: a.id,
      toNodeId: b.id,
      allowedSubnets: ["10.10.0.0/16"],
    });
    await service.createTunnel(1, { name: "aws-to-gcp", fromNodeId: b.id, toNodeId: c.id });

    const plan = await service.renderForTenant(1);
    expect(plan.valid).toBe(true);
    expect(plan.errors).toEqual([]);
    expect(plan.configs.map((cfg) => cfg.nodeName).sort()).toEqual(["AWS Gateway", "Edge NYC", "GCP Edge"]);
    const totalPeers = plan.configs.reduce((sum, cfg) => sum + countPeers(cfg.content), 0);
    expect(totalPeers).toBe(4); // 2 tunnels × both endpoints
    for (const cfg of plan.configs) {
      expect(cfg.filename).toMatch(/^utm-sase-[a-z0-9-]+\.conf$/);
      expect(cfg.content).toContain(`PrivateKey = ${SASE_KEY_PLACEHOLDER}`);
      expect(/[A-Za-z0-9+/]{43}=/.test(cfg.content)).toBe(false);
    }
  });

  it("surfaces registry mistakes as plan errors (dangling ref survives the DB layer)", async () => {
    const a = await seedNode({ name: "edge-nyc", tunnelEndpoint: "nyc.example.com:51820" });
    // raw row with a dangling ref — the renderer must catch what the CRUD
    // layer would have refused (defense in depth for raw shapes)
    await db.saseTunnel.create({
      data: { tenantId: 1, name: "ghost-link", fromNodeId: a.id, toNodeId: 4242 },
    });
    const plan = await service.renderForTenant(1);
    expect(plan.valid).toBe(false);
    expect(plan.errors.map((e) => e.code)).toContain("dangling-node-ref");
  });
});

describe("SASE service — identity-aware routing map", () => {
  it("upserts user→region mappings through the system settings store", async () => {
    const alice = await identityUpsert("Alice@Corp.example", "eu-west-1");
    expect(alice.userEmail).toBe("alice@corp.example"); // normalized
    await identityUpsert("bob@corp.example", "us-east-1");
    await identityUpsert("alice@corp.example", "us-east-1"); // overwrite

    const entries = await service.identityRoutingList(1);
    expect(entries.map((e) => e.userEmail)).toEqual(["alice@corp.example", "bob@corp.example"]); // sorted
    expect(entries.find((e) => e.userEmail === "alice@corp.example")?.region).toBe("us-east-1");
    expect(entries.every((e) => e.updatedAt.length > 0)).toBe(true);
  });

  it("resolves users to the nearest node: same-region gateway first, else first active", async () => {
    const edgeUs = await seedNode({ name: "edge-nyc", region: "us-east-1", tunnelEndpoint: "nyc:51820", status: "active" });
    const gwUs = await seedNode({ name: "gw-us", region: "us-east-1", role: "gateway", tunnelEndpoint: "gw-us:51820", status: "active" });
    const gwEu = await seedNode({ name: "gw-eu", region: "eu-west-1", role: "gateway", tunnelEndpoint: "gw-eu:51820", status: "active" });
    void edgeUs;
    void gwEu;

    await identityUpsert("alice@corp.example", "us-east-1");
    await identityUpsert("bob@corp.example", "eu-west-1");
    await identityUpsert("carol@corp.example", "ap-south-1"); // no node there

    const alice = await service.resolveNode(1, { userEmail: "ALICE@corp.example" });
    expect(alice.region).toBe("us-east-1");
    expect(alice.node?.name).toBe("gw-us"); // gateway preferred over the edge

    const bob = await service.resolveNode(1, { userEmail: "bob@corp.example" });
    expect(bob.node?.name).toBe("gw-eu");

    const carol = await service.resolveNode(1, { userEmail: "carol@corp.example" });
    expect(carol.node?.name).toBe("edge-nyc"); // first active anywhere (lowest id)

    const dave = await service.resolveNode(1, { userEmail: "dave@corp.example" });
    expect(dave.region).toBeNull();
    expect(dave.node).toBeNull();

    // the list enriches every entry with the same resolution
    const entries = await service.identityRoutingList(1);
    expect(entries.find((e) => e.userEmail === "alice@corp.example")?.resolvedNode?.id).toBe(gwUs.id);
  });

  it("resolves to null when the mapped region only has planned/down nodes", async () => {
    const planned = await seedNode({ name: "edge-ap", region: "ap-south-1", status: "planned" });
    void planned;
    await identityUpsert("erin@corp.example", "ap-south-1");
    const erin = await service.resolveNode(1, { userEmail: "erin@corp.example" });
    expect(erin.region).toBe("ap-south-1");
    expect(erin.node).toBeNull();
  });

  it("keeps the map in ONE SystemSetting row (category sase, key identity_routing)", async () => {
    await identityUpsert("alice@corp.example", "us-east-1");
    await identityUpsert("bob@corp.example", "eu-west-1");
    const rows = await db.systemSetting.findMany({ where: { tenantId: 1, category: "sase" } });
    expect(rows).toHaveLength(1);
    expect(rows[0].key).toBe("identity_routing");
    const map = JSON.parse(rows[0].value) as Record<string, { region: string }>;
    expect(Object.keys(map).sort()).toEqual(["alice@corp.example", "bob@corp.example"]);
  });
});

async function identityUpsert(userEmail: string, region: string) {
  return service.identityRoutingUpsert(1, { userEmail, region });
}

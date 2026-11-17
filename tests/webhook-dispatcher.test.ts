/**
 * Webhook dispatcher tests (T1-e) — vitest with mocked global fetch and a
 * mocked @/lib/db (in-memory webhook/delivery rows). Harness style mirrors
 * tests/app-control-os.test.ts (mock only what the unit under test touches).
 * Covers: HMAC signature correctness, retry-then-success, timeout recording,
 * disabled-webhook skip, event filtering, delivery-row fields, the forced
 * `webhook.test` delivery, the ledger read, and the trigger bridges.
 */

import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createHmac } from "node:crypto";

// ── fake db state (vi.hoisted so the vi.mock factory can see it) ────────────

type FakeWebhook = {
  id: number;
  tenantId: number;
  name: string;
  url: string;
  events: string;
  secret: string | null;
  enabled: boolean;
  failureCount: number;
  lastDeliveryAt?: Date | null;
  lastStatus?: string | null;
};

type FakeDelivery = {
  id: number;
  tenantId: number;
  webhookId: number;
  event: string;
  payload: string;
  ok: boolean;
  statusCode: number | null;
  durationMs: number | null;
  attempts: number;
  error: string | null;
  signature: string | null;
  createdAt: Date;
};

const h = vi.hoisted(() => ({
  webhooks: [] as FakeWebhook[],
  deliveries: [] as FakeDelivery[],
  nextId: 0,
}));

vi.mock("@/lib/db", () => ({
  db: {
    webhook: {
      findMany: async (args?: { where?: { enabled?: boolean; tenantId?: number } }) =>
        h.webhooks.filter(
          (w) =>
            (args?.where?.enabled === undefined || w.enabled === args.where.enabled) &&
            (args?.where?.tenantId === undefined || w.tenantId === args.where.tenantId),
        ),
      findFirst: async (args: { where: { id: number; tenantId: number } }) =>
        h.webhooks.find((w) => w.id === args.where.id && w.tenantId === args.where.tenantId) ?? null,
      update: async (args: { where: { id: number }; data: Partial<FakeWebhook> }) => {
        const row = h.webhooks.find((w) => w.id === args.where.id);
        if (!row) throw new Error(`webhook ${args.where.id} not found`);
        Object.assign(row, args.data);
        return row;
      },
    },
    webhookDelivery: {
      create: async (args: { data: Omit<FakeDelivery, "id" | "createdAt"> }) => {
        const row: FakeDelivery = { id: ++h.nextId, createdAt: new Date(), ...args.data };
        h.deliveries.push(row);
        return row;
      },
      findMany: async (args?: {
        where?: { tenantId?: number; webhookId?: number };
        orderBy?: { createdAt: string };
        take?: number;
      }) => {
        const rows = h.deliveries
          .filter(
            (d) =>
              (args?.where?.tenantId === undefined || d.tenantId === args.where.tenantId) &&
              (args?.where?.webhookId === undefined || d.webhookId === args.where.webhookId),
          )
          .sort((a, b) => b.id - a.id); // createdAt desc (ids are monotonic)
        return typeof args?.take === "number" ? rows.slice(0, args.take) : rows;
      },
    },
  },
}));

// ── imports under test (after the db mock is registered) ────────────────────

import {
  buildEventBody,
  deliverEvent,
  deliverWebhookTest,
  eventMatches,
  listRecentDeliveries,
  signBody,
} from "@/lib/webhooks/dispatcher";
import { auditTrigger, registerWebhookTriggers } from "@/lib/webhooks/triggers";
import { emitEvent } from "@/lib/engine/events";

// ── fixtures ────────────────────────────────────────────────────────────────

const fetchMock = vi.fn<typeof fetch>();
vi.stubGlobal("fetch", fetchMock);
afterAll(() => vi.unstubAllGlobals());

function httpResponse(status: number): Response {
  return { ok: status >= 200 && status < 300, status } as unknown as Response;
}

let seq = 100;
function seedWebhook(over: Partial<FakeWebhook> = {}): FakeWebhook {
  seq += 1;
  const row: FakeWebhook = {
    id: seq,
    tenantId: 1,
    name: `wh-${seq}`,
    url: "https://hooks.example.test/cryptsk",
    events: JSON.stringify(["alerts.new"]),
    secret: null,
    enabled: true,
    failureCount: 0,
    lastDeliveryAt: null,
    lastStatus: null,
    ...over,
  };
  h.webhooks.push(row);
  return row;
}

const SECRET = "whsec-0123456789abcdef";
const FAST = { backoffMs: [5, 5] as [number, number] };

beforeEach(() => {
  h.webhooks.length = 0;
  h.deliveries.length = 0;
  h.nextId = 0;
  fetchMock.mockReset();
});

// ── pure helpers ────────────────────────────────────────────────────────────

describe("pure helpers", () => {
  it("signBody produces sha256=<HMAC-SHA256 hex of the raw body>", () => {
    const body = buildEventBody("alerts.new", 1, { id: 1 });
    expect(signBody(SECRET, body)).toBe(
      "sha256=" + createHmac("sha256", SECRET).update(body).digest("hex"),
    );
  });

  it("buildEventBody shapes {event, tenantId, ts, data}", () => {
    const parsed = JSON.parse(buildEventBody("wan.status", 3, { iface: "wan1" })) as {
      event: string;
      tenantId: number;
      ts: string;
      data: { iface: string };
    };
    expect(parsed.event).toBe("wan.status");
    expect(parsed.tenantId).toBe(3);
    expect(new Date(parsed.ts).getTime()).not.toBeNaN();
    expect(parsed.data).toEqual({ iface: "wan1" });
  });

  it("eventMatches honors explicit events and the * wildcard", () => {
    expect(eventMatches(["alerts.new"], "alerts.new")).toBe(true);
    expect(eventMatches(["alerts.new"], "wan.status")).toBe(false);
    expect(eventMatches(["*"], "anything.at.all")).toBe(true);
  });
});

// ── deliverEvent — wire contract ────────────────────────────────────────────

describe("deliverEvent — signed POST wire contract", () => {
  it("POSTs {event, tenantId, ts, data} with the locked header set and a correct HMAC", async () => {
    seedWebhook({ secret: SECRET });
    fetchMock.mockResolvedValue(httpResponse(200));

    await deliverEvent("alerts.new", { id: 3, title: "cpu" }, { tenantId: 1 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://hooks.example.test/cryptsk");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["X-Cryptsk-Event"]).toBe("alerts.new");

    const body = init.body as string;
    const parsed = JSON.parse(body) as { event: string; tenantId: number; ts: string; data: unknown };
    expect(parsed.event).toBe("alerts.new");
    expect(parsed.tenantId).toBe(1); // the webhook's tenant
    expect(new Date(parsed.ts).getTime()).not.toBeNaN();
    expect(parsed.data).toEqual({ id: 3, title: "cpu" });

    // signature correctness — recompute the HMAC over the RAW body
    const expected = "sha256=" + createHmac("sha256", SECRET).update(body).digest("hex");
    expect(headers["X-Cryptsk-Signature"]).toBe(expected);
  });

  it("omits the signature header (and ledger signature) when no secret is stored", async () => {
    seedWebhook({ secret: null, events: JSON.stringify(["*"]) });
    fetchMock.mockResolvedValue(httpResponse(204));

    await deliverEvent("wan.status", { iface: "wan1", state: "down" }, { tenantId: 1 });

    const headers = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1]
      .headers as Record<string, string>;
    expect(headers["X-Cryptsk-Signature"]).toBeUndefined();
    expect(h.deliveries[0].signature).toBeNull();
  });
});

// ── retries, timeouts, permanence ───────────────────────────────────────────

describe("deliverEvent — retry / timeout semantics", () => {
  it("retries a transient 500 and succeeds on attempt 2", async () => {
    const wh = seedWebhook({ secret: SECRET, events: JSON.stringify(["config.updated"]) });
    fetchMock.mockResolvedValueOnce(httpResponse(500)).mockResolvedValueOnce(httpResponse(200));

    await deliverEvent("config.updated", { section: "firewall" }, { tenantId: 1, ...FAST });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(h.deliveries).toHaveLength(1); // ONE row per final outcome
    const row = h.deliveries[0];
    expect(row.attempts).toBe(2);
    expect(row.ok).toBe(true);
    expect(row.statusCode).toBe(200);
    expect(row.error).toBeNull();
    expect(wh.failureCount).toBe(0);
    expect(wh.lastStatus).toBe("200");
  });

  it("records a timeout error after exhausting all 3 attempts", async () => {
    const wh = seedWebhook({ secret: null, events: JSON.stringify(["*"]) });
    // hang until the dispatcher's AbortController fires (real abort semantics)
    fetchMock.mockImplementation((_url: string | URL | Request, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const err = new Error("This operation was aborted");
          err.name = "AbortError";
          reject(err);
        });
      });
    });

    await deliverEvent("wan.status", { iface: "wan1" }, { tenantId: 1, timeoutMs: 30, ...FAST });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    const row = h.deliveries[0];
    expect(row.ok).toBe(false);
    expect(row.statusCode).toBeNull();
    expect(row.attempts).toBe(3);
    expect(row.error).toContain("timeout");
    expect(row.durationMs).toBeTypeOf("number");
    // registration marked with the timeout status + failure count bumped
    expect(wh.lastStatus).toBe("timeout");
    expect(wh.failureCount).toBe(1);
  });

  it("treats permanent 4xx as final — exactly one attempt", async () => {
    seedWebhook({ secret: SECRET });
    fetchMock.mockResolvedValue(httpResponse(410));

    await deliverEvent("alerts.new", {}, { tenantId: 1, ...FAST });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const row = h.deliveries[0];
    expect(row.attempts).toBe(1);
    expect(row.ok).toBe(false);
    expect(row.statusCode).toBe(410);
    expect(row.error).toBe("HTTP 410");
    expect(row.signature).not.toBeNull();
  });

  it("never throws — network failure resolves (fire-and-forget contract)", async () => {
    seedWebhook({ secret: SECRET });
    fetchMock.mockRejectedValue(new TypeError("fetch failed"));

    await expect(
      deliverEvent("alerts.new", {}, { tenantId: 1, ...FAST }),
    ).resolves.toBeUndefined();

    const row = h.deliveries[0];
    expect(row.ok).toBe(false);
    expect(row.error).toContain("fetch failed");
  });
});

// ── filtering + tenant isolation ────────────────────────────────────────────

describe("deliverEvent — subscription + tenant filtering", () => {
  it("skips disabled webhooks silently (no fetch, no ledger row)", async () => {
    seedWebhook({ enabled: false, secret: SECRET });
    await deliverEvent("alerts.new", {}, { tenantId: 1 });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(h.deliveries).toHaveLength(0);
  });

  it("filters events against the explicit subscription list", async () => {
    seedWebhook({ events: JSON.stringify(["wan.status"]), secret: SECRET });
    await deliverEvent("alerts.new", {}, { tenantId: 1 });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(h.deliveries).toHaveLength(0);
  });

  it("delivers to * wildcard subscriptions", async () => {
    seedWebhook({ events: JSON.stringify(["*"]), secret: SECRET });
    fetchMock.mockResolvedValue(httpResponse(200));
    await deliverEvent("sessions.update", { kind: "vpn", diff: [] }, { tenantId: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(h.deliveries[0].event).toBe("sessions.update");
  });

  it("keeps tenant-scoped events isolated (tenant 2 webhook never sees tenant 1 events)", async () => {
    seedWebhook({ tenantId: 2, events: JSON.stringify(["*"]), secret: SECRET });
    fetchMock.mockResolvedValue(httpResponse(200));
    await deliverEvent("audit.firewall_rule", { action: "rule.create" }, { tenantId: 1 });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(h.deliveries).toHaveLength(0);
  });
});

// ── delivery row fields ─────────────────────────────────────────────────────

describe("deliverEvent — WebhookDelivery ledger fields", () => {
  it("records one row per final outcome with all ledger fields", async () => {
    const wh = seedWebhook({ secret: SECRET });
    fetchMock.mockResolvedValue(httpResponse(200));

    await deliverEvent("alerts.new", { id: 1, severity: "critical" }, { tenantId: 1 });

    expect(h.deliveries).toHaveLength(1);
    const row = h.deliveries[0];
    expect(row.id).toBeGreaterThan(0);
    expect(row.webhookId).toBe(wh.id);
    expect(row.tenantId).toBe(1);
    expect(row.event).toBe("alerts.new");
    // payload column = the JSON body actually POSTed
    expect(JSON.parse(row.payload)).toMatchObject({ event: "alerts.new", tenantId: 1 });
    expect(row.ok).toBe(true);
    expect(row.statusCode).toBe(200);
    expect(row.attempts).toBe(1);
    expect(row.error).toBeNull();
    expect(row.durationMs).toBeTypeOf("number");
    expect(row.createdAt).toBeInstanceOf(Date);
    // signature column = first 16 hex chars of the HMAC
    const expectedPrefix = createHmac("sha256", SECRET).update(row.payload).digest("hex").slice(0, 16);
    expect(row.signature).toBe(expectedPrefix);
  });

  it("truncates oversized errors to 300 chars", async () => {
    seedWebhook({ secret: SECRET });
    fetchMock.mockRejectedValue(new Error("x".repeat(500)));
    await deliverEvent("alerts.new", {}, { tenantId: 1, ...FAST });
    expect(h.deliveries[0].error).toHaveLength(300);
  });
});

// ── Send test (POST /api/v1/webhooks/{id}/test) + ledger read ───────────────

describe("deliverWebhookTest + listRecentDeliveries", () => {
  it("performs a forced signed webhook.test delivery and returns the real outcome", async () => {
    const wh = seedWebhook({ id: 42, secret: SECRET, events: JSON.stringify(["alerts.new"]) });
    fetchMock.mockResolvedValue(httpResponse(200));

    const res = await deliverWebhookTest(1, 42);

    expect(fetchMock).toHaveBeenCalledTimes(1); // forced past the events filter
    expect(res.ok).toBe(true);
    expect(res.statusCode).toBe(200);
    expect(res.attempts).toBe(1);
    expect(res.error).toBeNull();
    expect(res.deliveryId).toBe(h.deliveries[0].id);
    expect(res.durationMs).toBeTypeOf("number");
    expect(res.signaturePrefix).toBe(
      createHmac("sha256", SECRET).update(h.deliveries[0].payload).digest("hex").slice(0, 16),
    );
    const posted = JSON.parse(h.deliveries[0].payload) as {
      event: string;
      tenantId: number;
      data: { name: string; note: string };
    };
    expect(posted.event).toBe("webhook.test");
    expect(posted.tenantId).toBe(wh.tenantId);
    expect(posted.data.name).toBe(wh.name);
    expect(posted.data.note).toContain("Test delivery");
    expect(wh.lastStatus).toBe("200");
  });

  it("returns the failed attempt outcome without throwing", async () => {
    seedWebhook({ id: 43, secret: SECRET });
    fetchMock.mockResolvedValue(httpResponse(503)).mockResolvedValue(httpResponse(503)).mockResolvedValue(httpResponse(503));

    const res = await deliverWebhookTest(1, 43, FAST);

    expect(res.ok).toBe(false);
    expect(res.attempts).toBe(3); // 503 is transient → all 3 attempts
    expect(res.statusCode).toBe(503);
    expect(res.error).toBe("HTTP 503");
  });

  it("404s unknown or foreign-tenant webhooks", async () => {
    seedWebhook({ id: 44, tenantId: 2 });
    await expect(deliverWebhookTest(1, 9999)).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(deliverWebhookTest(1, 44)).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("listRecentDeliveries returns newest-first rows bounded by take", async () => {
    h.deliveries.push(
      ...([1, 2, 3].map((n) => ({
        id: n,
        tenantId: 1,
        webhookId: 7,
        event: "alerts.new",
        payload: "{}",
        ok: n !== 2,
        statusCode: n !== 2 ? 200 : 500,
        durationMs: 10 * n,
        attempts: 1,
        error: n === 2 ? "HTTP 500" : null,
        signature: null,
        createdAt: new Date(Date.parse("2026-01-0" + n + "T00:00:00Z")),
      })) as FakeDelivery[]),
    );

    const rows = await listRecentDeliveries(1, 7, 2);
    expect(rows.map((r) => r.id)).toEqual([3, 2]); // newest first
    expect(rows[0].createdAt).toBe("2026-01-03T00:00:00.000Z");
    expect(rows[1].ok).toBe(false);
    expect(rows[1].error).toBe("HTTP 500");
    // tenant scoping applies to the ledger too
    expect(await listRecentDeliveries(2, 7, 50)).toEqual([]);
  });
});

// ── trigger bridges (audit pipeline + engine event bus) ─────────────────────

describe("triggers — registerWebhookTriggers / auditTrigger", () => {
  it("bridges alerts:new engine events to alerts.new webhook deliveries", async () => {
    seedWebhook({ events: JSON.stringify(["alerts.new"]), secret: SECRET });
    fetchMock.mockResolvedValue(httpResponse(200));

    registerWebhookTriggers();
    emitEvent({
      type: "alerts:new",
      payload: {
        notification: {
          id: 9,
          type: "system",
          severity: "warning",
          title: "CPU high",
          message: null,
          sourceModule: "system",
          createdAt: new Date().toISOString(),
          isRead: false,
        },
      },
    });

    await vi.waitFor(() => expect(h.deliveries).toHaveLength(1));
    const body = JSON.parse(h.deliveries[0].payload) as {
      event: string;
      data: { id: number; title: string };
    };
    expect(h.deliveries[0].event).toBe("alerts.new");
    expect(body.data.id).toBe(9);
    expect(body.data.title).toBe("CPU high");
  });

  it("auditTrigger fans out audit.<objectType> events, tenant-scoped", async () => {
    seedWebhook({ events: JSON.stringify(["*"]), secret: SECRET }); // tenant 1
    seedWebhook({ tenantId: 2, events: JSON.stringify(["*"]), secret: SECRET }); // other tenant
    fetchMock.mockResolvedValue(httpResponse(200));

    auditTrigger(1, { action: "rule.create", objectType: "firewall_rule", objectId: 5 });

    await vi.waitFor(() => expect(h.deliveries).toHaveLength(1));
    const body = JSON.parse(h.deliveries[0].payload) as {
      event: string;
      tenantId: number;
      data: Record<string, unknown>;
    };
    expect(body.event).toBe("audit.firewall_rule");
    expect(body.tenantId).toBe(1);
    expect(body.data).toEqual({
      action: "rule.create",
      objectType: "firewall_rule",
      objectId: 5,
      objectName: null,
      result: "success",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1); // tenant-2 webhook excluded
  });
});

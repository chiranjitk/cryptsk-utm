/**
 * GET  /api/v1/interfaces — list with live rx/tx + link state (M02 §3/§4 tab 1)
 * POST /api/v1/interfaces — create logical iface (vlan|bridge|bond|gre|ipip|loopback)
 */

import { route } from "@/lib/api/handler";
import { ifaceCreateSchema, netListQuery } from "@/lib/validators/network";
import { createIface, loadShapedIfaces } from "@/lib/network/iface-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  let rows = await loadShapedIfaces(auth.tenantId);

  // additive field filters (M02 §3 — standard field-filter convention)
  if (query.type) rows = rows.filter((i) => i.type === query.type);
  if (query.role) rows = rows.filter((i) => i.role === query.role);
  if (query.enabled) rows = rows.filter((i) => i.enabled === (query.enabled === "true"));
  const q = (query.q ?? "").trim().toLowerCase();
  if (q) rows = rows.filter((i) => i.name.toLowerCase().includes(q));

  const total = rows.length;
  const page = rows.slice((query.page - 1) * query.limit, query.page * query.limit);
  return {
    data: page,
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "network", bodySchema: ifaceCreateSchema, section: "interfaces" },
  async ({ auth, body }) => {
    const created = await createIface(auth.tenantId, body);
    const shaped = (await loadShapedIfaces(auth.tenantId)).find((i) => i.id === created.id) ?? null;
    return {
      data: shaped,
      audit: { action: "iface.create", objectType: "interface", objectId: created.id, objectName: created.name },
    };
  },
);

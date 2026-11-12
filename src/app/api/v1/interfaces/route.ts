/**
 * GET  /api/v1/interfaces — list with live rx/tx + link state (M02 §3/§4 tab 1)
 * POST /api/v1/interfaces — create logical iface (vlan|bridge|bond|gre|ipip|loopback)
 *
 * GET rows additionally carry (vendor-parity, P0 spec):
 *   live — real kernel facts from /sys/class/net for this interface (null when
 *          absent on the host), so the operator sees config and live state in
 *          ONE table (FortiGate Status/Speed, PAN-OS Status columns)
 *   refs — FortiGate "Ref." column: { count, items[] } of referencing objects
 *          (static routes, WAN policies, DHCP subnets, zones, master memberships)
 */

import { route } from "@/lib/api/handler";
import { netListQuery, ifaceCreateSchema } from "@/lib/validators/network";
import { collectAllRefs, createIface, loadShapedIfaces } from "@/lib/network/iface-service";
import { readInterfaces } from "@/lib/host/proc";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  const [shaped, osIfaces, refsMap] = await Promise.all([
    loadShapedIfaces(auth.tenantId),
    readInterfaces(),
    collectAllRefs(auth.tenantId),
  ]);
  const liveByName = new Map(osIfaces.map((i) => [i.name, i]));

  let rows = shaped.map((i) => {
    const os = liveByName.get(i.name) ?? null;
    return {
      ...i,
      live: os
        ? {
            operState: os.operState,
            carrier: os.carrier,
            mtu: os.mtu,
            ipv4: os.ipv4,
            mac: os.mac,
            isDefaultRoute: os.isDefaultRoute,
          }
        : null,
      refs: refsMap.get(i.name) ?? { count: 0, items: [] },
    };
  });

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
      os: created.os,
      audit: { action: "iface.create", objectType: "interface", objectId: created.id, objectName: created.name },
    };
  },
);

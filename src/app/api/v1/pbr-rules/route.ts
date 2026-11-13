/**
 * GET  /api/v1/pbr-rules — policy-based routing rules, ordered by position
 *      (M02 §4 tab 2). Each row carries an honest kernelState
 *      (in-kernel | missing | config-only | disabled | null) computed from
 *      the compiled match plan + live `ip rule`, plus the resolved match
 *      summary (src/dst CIDRs + service selectors) for UI transparency.
 *      Plans compile as-if-confirmed with the egress next-hop resolved from
 *      the interface's live default route (same prepare path as the apply
 *      route — the Kernel column never lies about installability).
 * POST /api/v1/pbr-rules — create; every address/service id must exist in
 *      the mixed object∪group sets, outgoingIface must resolve, position
 *      defaults to max+1 and an explicitly occupied slot is rejected with
 *      409 (dense 1..N kernel table mapping).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { netListQuery, pbrBodySchema, type PbrBody } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapePbrRule } from "@/lib/network/shapes";
import { loadAddressIdSet, loadServiceIdSet } from "@/lib/firewall/refs";
import {
  compileServiceSelectors,
  pbrKernelState,
  preparePbrRules,
  readKernelPbrRules,
  type PbrKernelState,
  type PreparedPbrRule,
} from "@/lib/network/pbr-os";

export const dynamic = "force-dynamic";

/** Mixed object∪group id validation (M02 §3) — same semantics as firewall refs. */
async function assertPbrRefs(tenantId: number, body: PbrBody): Promise<void> {
  const [addrIds, svcIds] = await Promise.all([loadAddressIdSet(tenantId), loadServiceIdSet(tenantId)]);
  for (const id of [...body.srcAddrIds, ...body.dstAddrIds]) {
    if (!addrIds.has(id)) throw ApiError.validation(`Unknown address id ${id}`);
  }
  for (const id of body.serviceIds) {
    if (!svcIds.has(id)) throw ApiError.validation(`Unknown service id ${id}`);
  }
  if (body.outgoingIface) await assertIfacesExist(tenantId, [body.outgoingIface]);
}

/** Resolved match summary for one prepared rule (UI transparency + kernel badge). */
function matchesSummary(p: PreparedPbrRule) {
  const compiled = compileServiceSelectors(p.svc);
  return {
    src: p.src.map((s) => s.cidr).filter((c): c is string => c !== null),
    dst: p.dst.map((d) => d.cidr).filter((c): c is string => c !== null),
    services: compiled.selectors.map((s) =>
      [s.ipproto, s.sport ? `sport ${s.sport}` : "", s.dport ? `dport ${s.dport}` : ""].filter(Boolean).join(" "),
    ),
    srcUnresolved: p.src.filter((s) => s.cidr === null).length,
    dstUnresolved: p.dst.filter((d) => d.cidr === null).length,
  };
}

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth }) => {
  const rows = await db.pbrRule.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: { position: "asc" },
  });
  const kernel = await readKernelPbrRules().catch(() => null);
  const shapedRows = rows.map((row) => shapePbrRule(row));
  const prepared = await preparePbrRules(
    shapedRows.map((s) => ({
      id: s.id,
      name: s.name,
      position: s.position,
      enabled: s.enabled,
      srcAddrIds: s.srcAddrIds,
      dstAddrIds: s.dstAddrIds,
      serviceIds: s.serviceIds,
      outgoingIface: s.outgoingIface,
      gateway: s.gateway,
    })),
    auth.tenantId,
  );
  const data: Array<{
    id: number;
    name: string;
    position: number;
    enabled: boolean;
    srcAddrIds: number[];
    dstAddrIds: number[];
    serviceIds: number[];
    outgoingIface: string | null;
    gateway: string | null;
    description: string | null;
    createdAt: Date | null;
    kernelState: PbrKernelState | null;
    matchAll: boolean;
    matches: {
      src: string[];
      dst: string[];
      services: string[];
      srcUnresolved: number;
      dstUnresolved: number;
    };
  }> = [];
  for (const shaped of shapedRows) {
    const p = prepared.find((x) => x.view.id === shaped.id);
    data.push({
      ...shaped,
      description: shaped.description ?? null,
      createdAt: shaped.createdAt ?? null,
      kernelState: p ? pbrKernelState(p.view, kernel, { configOnly: p.confirmedPlan.configOnly }) : null,
      matchAll: p?.matchAll ?? false,
      matches: p
        ? matchesSummary(p)
        : { src: [], dst: [], services: [], srcUnresolved: 0, dstUnresolved: 0 },
    });
  }
  return { data };
});

export const POST = route(
  { area: "network", bodySchema: pbrBodySchema, section: "routing" },
  async ({ auth, body }) => {
    await assertPbrRefs(auth.tenantId, body);

    // position appends at max+1 unless an explicit slot is provided (M03 pattern)
    const max = await db.pbrRule.aggregate({ where: { tenantId: auth.tenantId }, _max: { position: true } });
    const position = body.position ?? (max._max.position ?? 0) + 1;

    // kernel tables map 1:1 to positions — an occupied slot would collide
    if (body.position != null) {
      const occupant = await db.pbrRule.findFirst({ where: { tenantId: auth.tenantId, position } });
      if (occupant) {
        throw ApiError.conflict(
          `Position ${position} is occupied by '${occupant.name}' — use Move to swap, or let the position auto-append`,
        );
      }
    }

    const created = await db.pbrRule.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        position,
        enabled: body.enabled,
        srcAddrIds: JSON.stringify(body.srcAddrIds),
        dstAddrIds: JSON.stringify(body.dstAddrIds),
        serviceIds: JSON.stringify(body.serviceIds),
        outgoingIface: body.outgoingIface ?? null,
        gateway: body.gateway ?? null,
        description: body.description ?? null,
      },
    });
    return {
      data: shapePbrRule(created),
      audit: { action: "pbr.create", objectType: "pbr_rule", objectId: created.id, objectName: created.name },
    };
  },
);

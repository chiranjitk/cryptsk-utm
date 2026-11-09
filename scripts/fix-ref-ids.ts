/**
 * fix-ref-ids.ts — eliminate object/group id collisions in mixed logical refs.
 *
 * srcAddrIds/srcAddrIds/serviceIds JSON arrays mix address_objects+address_groups
 * and service_objects+service_groups ids. When the two tables' autoincrement ids
 * overlap, the client-side label resolver shows the wrong chip (e.g. group
 * "corp-servers" instead of object "lan-subnet").
 *
 * Fix: recreate the starter groups with explicit high ids (101,102) — clear of
 * the object id range — and patch the seeded firewall rule JSON that referenced
 * the old group ids.
 */
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const T = 1;

async function main() {
  // capture object ids BEFORE deleting groups (memberIds reference them)
  const addrObjs = await prisma.addressObject.findMany({ where: { tenantId: T } });
  const svcObjs = await prisma.serviceObject.findMany({ where: { tenantId: T } });
  const byName = (rows: { id: number; name: string }[], n: string) => rows.find((r) => r.name === n);

  const oldAddrGroups = await prisma.addressGroup.findMany({ where: { tenantId: T, id: { lt: 100 } } });
  const oldSvcGroups = await prisma.serviceGroup.findMany({ where: { tenantId: T, id: { lt: 100 } } });

  // remember members by group name
  const addrMembers = new Map(oldAddrGroups.map((g) => [g.name, JSON.parse(g.memberIds) as number[]]));
  const svcMembers = new Map(oldSvcGroups.map((g) => [g.name, JSON.parse(g.memberIds) as number[]]));

  // recreate with explicit high ids, then delete the low-id originals
  for (const g of oldAddrGroups) {
    await prisma.addressGroup.upsert({
      where: { tenantId_name: { tenantId: T, name: g.name } },
      create: { id: g.id + 100, tenantId: T, name: g.name, memberIds: g.memberIds, description: g.description },
      update: { memberIds: g.memberIds, description: g.description },
    });
    await prisma.addressGroup.delete({ where: { id: g.id } });
    console.log(`addr-group ${g.name}: id ${g.id} -> ${g.id + 100}`);
  }
  for (const g of oldSvcGroups) {
    await prisma.serviceGroup.upsert({
      where: { tenantId_name: { tenantId: T, name: g.name } },
      create: { id: g.id + 100, tenantId: T, name: g.name, memberIds: g.memberIds, description: g.description },
      update: { memberIds: g.memberIds, description: g.description },
    });
    await prisma.serviceGroup.delete({ where: { id: g.id } });
    console.log(`svc-group ${g.name}: id ${g.id} -> ${g.id + 100}`);
  }

  // patch firewall rules whose serviceIds referenced the old GROUP ids
  const rules = await prisma.firewallRule.findMany({ where: { tenantId: T } });
  const oldSvcGroupIds = new Set(oldSvcGroups.map((g) => g.id));
  const oldAddrGroupIds = new Set(oldAddrGroups.map((g) => g.id));
  const svcObjIds = new Set(svcObjs.map((o) => o.id));
  const addrObjIds = new Set(addrObjs.map((o) => o.id));

  for (const r of rules) {
    const svcIds = JSON.parse(r.serviceIds) as number[];
    const srcIds = JSON.parse(r.srcAddrIds) as number[];
    const dstIds = JSON.parse(r.dstAddrIds) as number[];
    const remap = (arr: number[], oldGroupIds: Set<number>, objIds: Set<number>, delta: number) =>
      arr.map((id) => (oldGroupIds.has(id) && !objIds.has(id) ? id + delta : id));
    // group ids shift +100; object ids that collide are object refs and stay
    const newSvc = remap(svcIds, oldSvcGroupIds, svcObjIds, 100);
    const newSrc = remap(srcIds, oldAddrGroupIds, addrObjIds, 100);
    const newDst = remap(dstIds, oldAddrGroupIds, addrObjIds, 100);
    if (JSON.stringify(newSvc) !== r.serviceIds || JSON.stringify(newSrc) !== r.srcAddrIds || JSON.stringify(newDst) !== r.dstAddrIds) {
      await prisma.firewallRule.update({
        where: { id: r.id },
        data: { serviceIds: JSON.stringify(newSvc), srcAddrIds: JSON.stringify(newSrc), dstAddrIds: JSON.stringify(newDst) },
      });
      console.log(`fw-rule ${r.name}: patched refs`);
    }
  }
  console.log("done");
}

main().catch((e) => { console.error(e); process.exit(1); }).finally(() => prisma.$disconnect());

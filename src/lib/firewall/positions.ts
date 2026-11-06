/**
 * Dense position management for firewall + NAT rules (M03 §5):
 * position is dense 1..N, top of the table = evaluated first.
 * Prisma tx args are structurally typed here to keep the helpers reusable.
 */

interface RuleTx {
  firewallRule: {
    findMany(args: { where: { tenantId: number }; orderBy: { position: "asc" }; select: { id: true } }): Promise<Array<{ id: number }>>;
    update(args: { where: { id: number }; data: { position: number } }): Promise<unknown>;
  };
  natRule: {
    findMany(args: { where: { tenantId: number }; orderBy: { position: "asc" }; select: { id: true } }): Promise<Array<{ id: number }>>;
    update(args: { where: { id: number }; data: { position: number } }): Promise<unknown>;
  };
}

export async function renumberFirewallRules(tx: RuleTx, tenantId: number, orderedIds?: number[]): Promise<void> {
  if (orderedIds) {
    let p = 1;
    for (const id of orderedIds) {
      await tx.firewallRule.update({ where: { id }, data: { position: p++ } });
    }
    return;
  }
  const rules = await tx.firewallRule.findMany({ where: { tenantId }, orderBy: { position: "asc" }, select: { id: true } });
  let i = 1;
  for (const r of rules) {
    await tx.firewallRule.update({ where: { id: r.id }, data: { position: i++ } });
  }
}

export async function renumberNatRules(tx: RuleTx, tenantId: number, orderedIds?: number[]): Promise<void> {
  if (orderedIds) {
    let p = 1;
    for (const id of orderedIds) {
      await tx.natRule.update({ where: { id }, data: { position: p++ } });
    }
    return;
  }
  const rules = await tx.natRule.findMany({ where: { tenantId }, orderBy: { position: "asc" }, select: { id: true } });
  let i = 1;
  for (const r of rules) {
    await tx.natRule.update({ where: { id: r.id }, data: { position: i++ } });
  }
}

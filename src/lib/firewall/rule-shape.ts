/**
 * Firewall/NAT rule response shapers — JSON columns become real arrays.
 */

export function shapeFirewallRule(r: {
  id: number;
  tenantId: number;
  name: string;
  description: string | null;
  enabled: boolean;
  position: number;
  srcZoneIds: string;
  dstZoneIds: string;
  srcAddrIds: string;
  dstAddrIds: string;
  serviceIds: string;
  applicationIds: string;
  userIds: string;
  srcMacs: string;
  scheduleId: number | null;
  action: string;
  logging: string;
  connLimit: number | null;
  rateLimit: number | null;
  synProtection: boolean;
  synThreshold: number | null;
  ipsPolicyId: number | null;
  qosPolicyId: number | null;
  tags: string;
  comment: string | null;
  hitCount: number;
  lastHitAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  const arr = (raw: string): number[] => {
    try {
      const v = JSON.parse(raw);
      return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : [];
    } catch {
      return [];
    }
  };
  const strArr = (raw: string): string[] => {
    try {
      const v = JSON.parse(raw);
      return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
    } catch {
      return [];
    }
  };
  return {
    id: r.id,
    tenantId: r.tenantId,
    name: r.name,
    description: r.description,
    enabled: r.enabled,
    position: r.position,
    srcZoneIds: arr(r.srcZoneIds),
    dstZoneIds: arr(r.dstZoneIds),
    srcAddrIds: arr(r.srcAddrIds),
    dstAddrIds: arr(r.dstAddrIds),
    serviceIds: arr(r.serviceIds),
    applicationIds: strArr(r.applicationIds),
    userIds: arr(r.userIds),
    srcMacs: strArr(r.srcMacs),
    scheduleId: r.scheduleId,
    action: r.action,
    logging: r.logging,
    connLimit: r.connLimit,
    rateLimit: r.rateLimit,
    synProtection: r.synProtection,
    synThreshold: r.synThreshold,
    ipsPolicyId: r.ipsPolicyId,
    qosPolicyId: r.qosPolicyId,
    tags: strArr(r.tags),
    comment: r.comment,
    hitCount: r.hitCount,
    lastHitAt: r.lastHitAt,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
  };
}

export function shapeNatRule(r: {
  id: number;
  tenantId: number;
  name: string | null;
  position: number;
  type: string;
  enabled: boolean;
  srcAddrIds: string;
  dstAddrIds: string;
  serviceIds: string;
  outgoingIface: string | null;
  translatedSrc: string | null;
  translatedSrcPool: string;
  overload: boolean;
  translatedDst: string | null;
  translatedPort: number | null;
  translatedPortRange: string | null;
  logging: string;
  comment: string | null;
  hitCount: number;
  createdAt: Date;
}) {
  const arr = (raw: string): number[] => {
    try {
      const v = JSON.parse(raw);
      return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : [];
    } catch {
      return [];
    }
  };
  return {
    id: r.id,
    tenantId: r.tenantId,
    name: r.name,
    position: r.position,
    type: r.type,
    enabled: r.enabled,
    srcAddrIds: arr(r.srcAddrIds),
    dstAddrIds: arr(r.dstAddrIds),
    serviceIds: arr(r.serviceIds),
    outgoingIface: r.outgoingIface,
    translatedSrc: r.translatedSrc,
    translatedSrcPool: arr(r.translatedSrcPool),
    overload: r.overload,
    translatedDst: r.translatedDst,
    translatedPort: r.translatedPort,
    translatedPortRange: r.translatedPortRange,
    logging: r.logging,
    comment: r.comment,
    hitCount: r.hitCount,
    createdAt: r.createdAt,
  };
}

/**
 * Response shapers for M03 objects — JSON columns are parsed once here so the
 * API always speaks real arrays (API_STANDARDS §3).
 */

export function shapeAddressObject(a: {
  id: number;
  name: string;
  type: string;
  value: string;
  description: string | null;
  createdAt: Date;
}) {
  return { id: a.id, name: a.name, type: a.type, value: a.value, description: a.description, createdAt: a.createdAt };
}

export function shapeNamedWithMembers(g: { id: number; name: string; memberIds: string; description: string | null }) {
  let memberIds: number[] = [];
  try {
    const v = JSON.parse(g.memberIds);
    if (Array.isArray(v)) memberIds = v.filter((x): x is number => typeof x === "number");
  } catch {
    memberIds = [];
  }
  return { id: g.id, name: g.name, memberIds, description: g.description };
}

export function shapeServiceObject(s: {
  id: number;
  name: string;
  protocol: string;
  srcPort: string | null;
  dstPort: string | null;
  icmpType: number | null;
  icmpCode: number | null;
  description: string | null;
}) {
  return {
    id: s.id,
    name: s.name,
    protocol: s.protocol,
    srcPort: s.srcPort,
    dstPort: s.dstPort,
    icmpType: s.icmpType,
    icmpCode: s.icmpCode,
    description: s.description,
  };
}

export function shapeScheduleObject(s: {
  id: number;
  name: string;
  type: string;
  recurrence: string | null;
  startsAt: Date | null;
  endsAt: Date | null;
  timezone: string;
}) {
  let recurrence: { days: number[]; start: string; end: string } | null = null;
  if (s.recurrence) {
    try {
      const v = JSON.parse(s.recurrence);
      if (v && Array.isArray(v.days)) recurrence = { days: v.days, start: v.start, end: v.end };
    } catch {
      recurrence = null;
    }
  }
  return {
    id: s.id,
    name: s.name,
    type: s.type,
    recurrence,
    startsAt: s.startsAt,
    endsAt: s.endsAt,
    timezone: s.timezone,
  };
}

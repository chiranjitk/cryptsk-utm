/**
 * Rule loader — converts DB rows into the pure EvalRule/CandidateRule shapes
 * used by rule-match.ts (validate endpoint + firewall-log generator).
 * Groups are expanded at load time (mixed object+group id semantics).
 */

import { db } from "@/lib/db";
import { parseIds } from "./refs";
import {
  parseAddrMatcher,
  parsePortList,
  type AddrMatcher,
  type EvalRule,
  type ScheduleSpec,
  type ServiceMatcher,
  type CandidateRule,
} from "./rule-match";

interface LoadedData {
  rules: EvalRule[];
}

export interface ExpansionContext {
  expandAddr(ids: number[]): AddrMatcher[];
  expandSvc(ids: number[]): ServiceMatcher[];
  toSchedule(id: number | null): ScheduleSpec | null;
  userNames(ids: number[]): string[];
}

export async function loadExpansionContext(tenantId: number): Promise<ExpansionContext> {
  const [addrObjs, addrGroups, svcObjs, svcGroups, schedules, users] = await Promise.all([
    db.addressObject.findMany({ where: { tenantId } }),
    db.addressGroup.findMany({ where: { tenantId } }),
    db.serviceObject.findMany({ where: { tenantId } }),
    db.serviceGroup.findMany({ where: { tenantId } }),
    db.scheduleObject.findMany({ where: { tenantId } }),
    db.user.findMany({ where: { tenantId }, select: { id: true, username: true } }),
  ]);

  const addrById = new Map(addrObjs.map((a) => [a.id, a]));
  const addrGroupById = new Map(addrGroups.map((g) => [g.id, g]));
  const svcById = new Map(svcObjs.map((s) => [s.id, s]));
  const svcGroupById = new Map(svcGroups.map((g) => [g.id, g]));
  const scheduleById = new Map(schedules.map((s) => [s.id, s]));
  const userNameById = new Map(users.map((u) => [u.id, u.username]));

  return {
    expandAddr(ids: number[]): AddrMatcher[] {
      const out: AddrMatcher[] = [];
      for (const id of ids) {
        const obj = addrById.get(id);
        if (obj) {
          out.push(parseAddrMatcher(obj.type, obj.value));
          continue;
        }
        const grp = addrGroupById.get(id);
        if (grp) {
          for (const mid of parseIds(grp.memberIds)) {
            const m = addrById.get(mid);
            if (m) out.push(parseAddrMatcher(m.type, m.value));
          }
        }
      }
      return out;
    },
    expandSvc(ids: number[]): ServiceMatcher[] {
      const out: ServiceMatcher[] = [];
      for (const id of ids) {
        const obj = svcById.get(id);
        if (obj) {
          out.push({
            protocol: obj.protocol as ServiceMatcher["protocol"],
            srcPorts: parsePortList(obj.srcPort),
            dstPorts: parsePortList(obj.dstPort),
          });
          continue;
        }
        const grp = svcGroupById.get(id);
        if (grp) {
          for (const mid of parseIds(grp.memberIds)) {
            const m = svcById.get(mid);
            if (m)
              out.push({
                protocol: m.protocol as ServiceMatcher["protocol"],
                srcPorts: parsePortList(m.srcPort),
                dstPorts: parsePortList(m.dstPort),
              });
          }
        }
      }
      return out;
    },
    toSchedule(id: number | null): ScheduleSpec | null {
      if (id == null) return null;
      const s = scheduleById.get(id);
      if (!s) return null;
      let rec: { days?: number[]; start?: string; end?: string } = {};
      if (s.recurrence) {
        try {
          rec = JSON.parse(s.recurrence);
        } catch {
          rec = {};
        }
      }
      return {
        type: s.type as ScheduleSpec["type"],
        days: rec.days ?? [],
        start: rec.start ?? "00:00",
        end: rec.end ?? "23:59",
        startsAt: s.startsAt ? s.startsAt.getTime() : null,
        endsAt: s.endsAt ? s.endsAt.getTime() : null,
        timezone: s.timezone || "UTC",
      };
    },
    userNames(ids: number[]): string[] {
      return ids
        .map((id) => userNameById.get(id))
        .filter((n): n is string => Boolean(n));
    },
  };
}

export async function loadEvalRules(tenantId: number, onlyEnabled = false): Promise<LoadedData> {
  const [rules, ctx] = await Promise.all([
    db.firewallRule.findMany({
      where: { tenantId, ...(onlyEnabled ? { enabled: true } : {}) },
      orderBy: { position: "asc" },
    }),
    loadExpansionContext(tenantId),
  ]);

  const evalRules: EvalRule[] = rules.map((r) => ({
    id: r.id,
    name: r.name,
    action: r.action,
    enabled: r.enabled,
    position: r.position,
    srcZoneIds: parseIds(r.srcZoneIds),
    dstZoneIds: parseIds(r.dstZoneIds),
    srcAddrs: ctx.expandAddr(parseIds(r.srcAddrIds)),
    dstAddrs: ctx.expandAddr(parseIds(r.dstAddrIds)),
    services: ctx.expandSvc(parseIds(r.serviceIds)),
    applicationIds: safeStrArr(r.applicationIds),
    userNames: ctx.userNames(parseIds(r.userIds)),
    srcMacs: safeStrArr(r.srcMacs),
    schedule: ctx.toSchedule(r.scheduleId),
  }));

  return { rules: evalRules };
}

export function safeStrArr(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

export function evalRuleToCandidate(r: EvalRule): CandidateRule {
  return {
    name: r.name,
    action: r.action,
    srcZoneIds: r.srcZoneIds,
    dstZoneIds: r.dstZoneIds,
    srcAddrs: r.srcAddrs,
    dstAddrs: r.dstAddrs,
    services: r.services,
    applicationIds: r.applicationIds,
    userNames: r.userNames,
    schedule: r.schedule,
  };
}

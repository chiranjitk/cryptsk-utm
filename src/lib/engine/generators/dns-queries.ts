/**
 * DNS query-log generator (M06 §5.1/§5.4) — derived view only (no Prisma).
 * Domain mix per SIMULATION_LAYER §6: ~85% normal, ~10% ads, ~5% malware/phishing.
 * Policy evaluation (first match wins, policies ordered by id asc):
 *   1. customAllow (exact or subdomain) → allowed, stop
 *   2. customBlock → blocked with that policy's action, category "custom"
 *   3. category ∈ blockCategories → blocked with that policy's action
 *   4. else allowed
 * Latency flavor: forwardZones domains carry the zone server's (fast, local)
 * latency; everything else uses the default forwarder flavor (M06 §5.4).
 */

import type { TrafficProfile } from "../profiles";

export interface DnsPolicyEntry {
  id: number;
  name: string;
  action: "sinkhole" | "nxdomain";
  sinkholeIp: string;
  blockCategories: string[];
  customBlock: string[];
  customAllow: string[];
}

export interface DnsPolicyRuntime {
  resolver: {
    forwarders: string[];
    forwardZones: Array<{ domain: string; server: string; port?: number }>;
  };
  policies: DnsPolicyEntry[];
}

export interface DnsQueryLogEntry {
  seq: number;
  ts: string;
  clientIp: string;
  domain: string;
  qtype: string;
  action: "allowed" | "sinkhole" | "nxdomain";
  blocked: boolean;
  category: string | null;
  latencyMs: number;
}

// ── domain pools ────────────────────────────────────────────────────────────

const NORMAL_DOMAINS = [
  "www.google.com", "api.github.com", "cdn.jsdelivr.net", "mail.corp.local", "intranet.corp.local",
  "portal.corp.local", "www.wikipedia.org", "updates.debian.org", "registry.npmjs.org",
  "s3.amazonaws.com", "teams.microsoft.com", "zoom.us", "slack.com", "docs.python.org",
  "time.cloudflare.com", "ocsp.digicert.com", "printer.corp.local", "nas.corp.local",
];
const ADS_DOMAINS = [
  "ads.example-banners.net", "tracker.example.net", "metrics.example-analytics.com",
  "popads.example-cdn.net", "doubleclick.example.net", "banner.example-ads.io",
  "telemetry.example-tracker.net", "pixel.example-social.com",
];
const BAD_DOMAINS = [
  "payload.example-malware.ru", "c2.example-botnet.tk", "phish.example-login.ml",
  "stealer.example-phishing.cf", "dropper.example-malware.su", "fake-bank.example-phishing.ga",
];
const QTYPES = ["A", "A", "A", "A", "A", "A", "A", "A", "AAAA", "AAAA", "CNAME", "MX", "TXT"];

function domainMatches(domain: string, entry: string): boolean {
  return domain === entry || domain.endsWith(`.${entry}`);
}

export class DnsQueryGenerator {
  private runtime: DnsPolicyRuntime | null = null;
  private seq = 0;

  constructor(
    private readonly rand: () => number,
    private profile: TrafficProfile,
  ) {}

  setProfile(p: TrafficProfile): void {
    this.profile = p;
  }

  setRuntime(rt: DnsPolicyRuntime | null): void {
    this.runtime = rt;
  }

  /** 1–3 rows per tick, scaled mildly by profile.dnsShare. */
  generate(): DnsQueryLogEntry[] {
    const rt = this.runtime;
    const base = 1 + Math.floor(this.rand() * 3) + (this.profile.dnsShare > 0.1 ? 1 : 0);
    const rows: DnsQueryLogEntry[] = [];
    for (let i = 0; i < base; i++) rows.push(this.one(rt));
    return rows;
  }

  private one(rt: DnsPolicyRuntime | null): DnsQueryLogEntry {
    const roll = this.rand();
    let domain: string;
    let category: string | null = null; // pre-known category from the pool mix
    if (roll < 0.1) {
      domain = ADS_DOMAINS[Math.floor(this.rand() * ADS_DOMAINS.length)]!;
      category = "ads";
    } else if (roll < 0.15) {
      domain = BAD_DOMAINS[Math.floor(this.rand() * BAD_DOMAINS.length)]!;
      category = this.rand() < 0.5 ? "malware" : "phishing";
    } else {
      domain = NORMAL_DOMAINS[Math.floor(this.rand() * NORMAL_DOMAINS.length)]!;
    }

    // Policy evaluation — first match wins (M06 §5.1).
    let action: "allowed" | "sinkhole" | "nxdomain" = "allowed";
    let blocked = false;
    let matchedCategory: string | null = null;
    if (rt) {
      let allowed = false;
      let decided = false;
      for (const p of rt.policies) {
        if (p.customAllow.some((a) => domainMatches(domain, a))) {
          allowed = true;
          decided = true;
          break;
        }
        const customHit = p.customBlock.some((b) => domainMatches(domain, b));
        if (customHit || (category !== null && p.blockCategories.includes(category))) {
          action = p.action;
          blocked = true;
          matchedCategory = customHit ? "custom" : category;
          decided = true;
          break;
        }
      }
      if (!decided) allowed = true;
      action = allowed ? "allowed" : action;
    }

    // Latency flavor: forward-zone server (fast/local) vs default forwarders.
    const zone = rt?.resolver.forwardZones.find((z) => domainMatches(domain, z.domain));
    const latencyMs =
      blocked && action === "nxdomain"
        ? 1 + Math.floor(this.rand() * 4)
        : zone
          ? 2 + Math.floor(this.rand() * 7)
          : 15 + Math.floor(this.rand() * 50);

    const octet = () => 100 + Math.floor(this.rand() * 100);
    const clientIp = `192.168.10.${octet()}`;

    this.seq += 1;
    return {
      seq: this.seq,
      ts: new Date().toISOString(),
      clientIp,
      domain,
      qtype: QTYPES[Math.floor(this.rand() * QTYPES.length)]!,
      action: blocked ? action : "allowed",
      blocked,
      category: blocked ? matchedCategory : category,
      latencyMs,
    };
  }
}

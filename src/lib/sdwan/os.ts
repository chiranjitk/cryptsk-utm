/**
 * sdwan/os — PURE SD-WAN → WireGuard (wg-quick) overlay renderer (spec 2.5).
 *
 * Translates the GUI SD-WAN model (overlays, sites) into one wg-quick config
 * per enabled WireGuard overlay for the LOCAL appliance:
 *   /etc/wireguard/utm-sdwan-<overlaySlug>.conf
 *
 * Pure module: no db, no exec — fully unit-tested. Execution lives in
 * os-service.ts, the API surface in /api/v1/sdwan/os.
 *
 * Design contract (mirrors app-control/os.ts + vpn/os.ts semantics):
 *
 *  • PLAN-ONLY KEYS — real private key material NEVER appears in plans. The
 *    [Interface] PrivateKey line carries the placeholder
 *    `[REDACTED-SEE-SECRET-STORE]`; real keys materialize server-side at
 *    apply time from an env/secret source (CONSOLE_SDWAN_WG_PRIVATE_KEY or
 *    CONSOLE_SDWAN_KEY_DIR/<iface>.key). When no source exists the written
 *    file carries `[GENERATED-ON-APPLY]` and a loud warning — wg-quick up
 *    will fail until a key is provisioned (honest, never fabricated).
 *  • Peer PublicKey: the site's recorded wgPubKey is PUBLIC material and is
 *    rendered verbatim; sites without one get `[GENERATED-ON-APPLY]` (the
 *    remote site's key cannot be invented locally) + a warning.
 *  • DERIVED ADDRESSING v1 — the schema has no subnet columns, so overlay
 *    tunnel addressing is derived deterministically from ids:
 *      overlay /16  = 10.<octet(overlayId)>.0.0/16
 *      site    /24  = 10.<octet(overlayId)>.<octet(siteId)>.0/24
 *    octet(x) = ((x - 1) % 254) + 1. Collisions are DETECTED and surfaced as
 *    loud warnings — never silently hidden.
 *  • LISTEN PORTS derived: 51820 + (overlayId - 1). A collision risk with the
 *    VPN module defaults (51820/51821) is warned, not hidden.
 *  • IFNAMSIZ honesty — interface names longer than 15 chars cannot be
 *    brought up by wg-quick; the renderer keeps the mission file naming
 *    (`utm-sdwan-<slug>.conf`) and emits a loud warning instead of mangling.
 *  • LOCAL ANCHOR — the file describes THIS appliance: the overlay's hub
 *    (lowest id, else first enabled site) is the local [Interface]; every
 *    other enabled site renders as one [Peer]. No hub → warning.
 *  • IPsec overlays are SKIPPED (wg-quick renders WireGuard only) with a
 *    warning — never silently pretended.
 *  • Deterministic: same input → byte-identical files + identical sha256
 *    confHash per file and a combined hash (order-independent).
 *  • Warnings are part of the plan (probe-simulated, traffic-affecting…).
 */

import { createHash } from "crypto";

// ── constants ───────────────────────────────────────────────────────────────

/** Managed interface + file prefix — every OS object the console owns. */
export const SDWAN_IFACE_PREFIX = "utm-sdwan-";
/** wg-quick config dir (same env override as the VPN module). */
export const SDWAN_WG_DIR = process.env.CONSOLE_WG_DIR || "/etc/wireguard";
/** Derived listen-port base (VPN module defaults occupy 51820/51821). */
export const SDWAN_PORT_BASE = 51820;
/** IFNAMSIZ — kernel interface name limit. */
export const IFNAMSIZ = 15;

export const PRIVATE_KEY_PLACEHOLDER = "[REDACTED-SEE-SECRET-STORE]";
export const GENERATED_ON_APPLY = "[GENERATED-ON-APPLY]";

/** Keepalive default when the tenant setting is absent (wg common practice). */
export const SDWAN_KEEPALIVE_DEFAULT = 25;

const UTMSN = "[a-z0-9-]+"; // slug charset for the anchored whitelist

// ── input shapes (db → deterministic DTOs, service-owned) ───────────────────

export interface SdwanSiteShape {
  id: number;
  name: string;
  role: "hub" | "spoke";
  publicIp: string;
  /** remote WireGuard public key (PUBLIC material — safe to render) */
  wgPubKey: string | null;
  enabled: boolean;
}

export interface SdwanOverlayShape {
  id: number;
  name: string;
  topology: "hub_spoke" | "full_mesh";
  encryption: "wireguard" | "ipsec";
  enabled: boolean;
  sites: SdwanSiteShape[];
}

// ── output shapes ───────────────────────────────────────────────────────────

export interface SdwanGenWarning {
  scope: "plan" | "overlay" | "site";
  overlayId: number | null;
  siteId: number | null;
  /** overlay name (scope overlay/plan) or site name (scope site) */
  name: string;
  code: string;
  message: string;
}

export interface SdwanPeerRender {
  siteId: number;
  siteName: string;
  role: string;
  publicKey: string;
  allowedIps: string[];
  endpoint: string;
}

export interface SdwanOverlayFile {
  overlayId: number;
  overlayName: string;
  topology: string;
  /** interface name = file stem = `utm-sdwan-<slug>` */
  iface: string;
  slug: string;
  /** absolute path under /etc/wireguard */
  fileName: string;
  /** complete wg-quick file content (plan rendering — keys redacted) */
  conf: string;
  /** sha256 of conf (deterministic) */
  confHash: string;
  listenPort: number;
  localSite: { id: number; name: string; role: string } | null;
  /** local tunnel address from the derived addressing scheme */
  address: string | null;
  overlaySubnet: string;
  peers: SdwanPeerRender[];
  warnings: SdwanGenWarning[];
}

export interface SdwanPlan {
  generatedAt: string;
  files: SdwanOverlayFile[];
  /** sha256 over the per-file hashes (sorted by iface) — order-independent */
  combinedHash: string;
  counts: { overlays: number; rendered: number; skipped: number; peers: number };
  skippedOverlays: Array<{ id: number; name: string; reason: string }>;
  warnings: SdwanGenWarning[];
}

// ── deterministic derivation helpers ────────────────────────────────────────

/** "HQ Mesh" + 7 → "hq-mesh-7" (kebab name + id — the mission slug rule). */
export function sdwanSlug(name: string, id: number): string {
  const kebab = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || "overlay";
  return `${kebab}-${id}`;
}

/** `utm-sdwan-<slug>` — interface AND file stem (kept intact, IFNAMSIZ warned). */
export function sdwanIface(name: string, id: number): string {
  return `${SDWAN_IFACE_PREFIX}${sdwanSlug(name, id)}`;
}

/** Derived listen port: 51820 + (overlayId - 1). */
export function sdwanListenPort(overlayId: number): number {
  return SDWAN_PORT_BASE + (overlayId - 1);
}

/** 1..254 host octet from an integer id (deterministic). */
export function octetOf(id: number): number {
  return ((Math.max(1, Math.floor(id)) - 1) % 254) + 1;
}

/** Overlay tunnel network: 10.<octet>.0.0/16. */
export function deriveOverlaySubnet(overlayId: number): string {
  return `10.${octetOf(overlayId)}.0.0/16`;
}

/** Site tunnel network: 10.<octet(overlayId)>.<octet(siteId)>.0/24. */
export function deriveSiteNet(overlayId: number, siteId: number): string {
  return `10.${octetOf(overlayId)}.${octetOf(siteId)}.0/24`;
}

/** Site tunnel address (first usable host of the site /24). */
export function deriveSiteAddress(overlayId: number, siteId: number): string {
  return deriveSiteNet(overlayId, siteId).replace(/\.0\/24$/, ".1/24");
}

/** A recorded wgPubKey looks like real base64 WireGuard key material. */
export function wgPubKeyLooksReal(v: string | null): boolean {
  return !!v && /^[A-Za-z0-9+/]{43}=$/.test(v);
}

function sha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

// ── renderer ────────────────────────────────────────────────────────────────

function planWarning(
  scope: SdwanGenWarning["scope"],
  overlayId: number | null,
  siteId: number | null,
  name: string,
  code: string,
  message: string,
): SdwanGenWarning {
  return { scope, overlayId, siteId, name, code, message };
}

/**
 * Generate the per-overlay wg-quick files for all ENABLED WireGuard overlays.
 * Deterministic: same input + generatedAt → byte-identical output.
 * Disabled overlays/sites are excluded; ipsec overlays are skipped loudly.
 */
export function generateSdwanWgConfigs(input: {
  overlays: SdwanOverlayShape[];
  keepaliveSec?: number;
  generatedAt?: Date;
}): SdwanPlan {
  const warnings: SdwanGenWarning[] = [];
  const files: SdwanOverlayFile[] = [];
  const skippedOverlays: Array<{ id: number; name: string; reason: string }> = [];

  // plan-level honesty (mission-mandated warnings)
  warnings.push(
    planWarning(
      "plan",
      null,
      null,
      "sdwan",
      "probe-simulated",
      "path probes are simulated (deterministic walk) until the path engine wires real probes — SLA path states are not live measurements",
    ),
  );
  warnings.push(
    planWarning(
      "plan",
      null,
      null,
      "sdwan",
      "traffic-affecting",
      "overlay up/down affects tunnel traffic — apply writes config files only; bringing interfaces up requires an explicit bringUp confirmation",
    ),
  );

  // keepalive validation — invalid settings are surfaced, never guessed
  let keepalive: number | null = null;
  if (input.keepaliveSec !== undefined) {
    const v = Number(input.keepaliveSec);
    if (Number.isInteger(v) && v > 0 && v <= 600) keepalive = v;
    else if (v !== 0) {
      warnings.push(
        planWarning(
          "plan",
          null,
          null,
          "sdwan",
          "keepalive-invalid",
          `PersistentKeepalive setting ${input.keepaliveSec} is not an integer in 1..600 — line omitted from the rendered files`,
        ),
      );
    }
  }

  const overlays = [...input.overlays].filter((o) => o.enabled).sort((a, b) => a.id - b.id);

  // derived-octet collision detection (overlay second octet)
  const overlayOctets = new Map<number, number[]>();
  for (const o of overlays) {
    const oct = octetOf(o.id);
    const list = overlayOctets.get(oct) ?? [];
    list.push(o.id);
    overlayOctets.set(oct, list);
  }
  for (const [oct, ids] of overlayOctets) {
    if (ids.length > 1) {
      warnings.push(
        planWarning(
          "plan",
          null,
          null,
          "sdwan",
          "tunnel-address-collision",
          `overlays ${ids.join(", ")} all derive tunnel octet ${oct} (10.${oct}.0.0/16) — derived addressing collides; assign real subnets before production use`,
        ),
      );
    }
  }

  let peersTotal = 0;

  for (const overlay of overlays) {
    if (overlay.encryption !== "wireguard") {
      skippedOverlays.push({
        id: overlay.id,
        name: overlay.name,
        reason: `encryption=${overlay.encryption} — wg-quick renders WireGuard overlays only (v1)`,
      });
      warnings.push(
        planWarning(
          "overlay",
          overlay.id,
          null,
          overlay.name,
          "ipsec-not-rendered",
          `overlay '${overlay.name}' uses ${overlay.encryption} — skipped by the WireGuard renderer (v1)`,
        ),
      );
      continue;
    }

    const slug = sdwanSlug(overlay.name, overlay.id);
    const iface = `${SDWAN_IFACE_PREFIX}${slug}`;
    const listenPort = sdwanListenPort(overlay.id);
    const fileWarnings: SdwanGenWarning[] = [];

    if (iface.length > IFNAMSIZ) {
      fileWarnings.push(
        planWarning(
          "overlay",
          overlay.id,
          null,
          overlay.name,
          "iface-name-too-long",
          `interface '${iface}' exceeds IFNAMSIZ (${iface.length} > ${IFNAMSIZ}) — wg-quick up will refuse it; shorten the overlay name`,
        ),
      );
    }
    if (listenPort === SDWAN_PORT_BASE || listenPort === SDWAN_PORT_BASE + 1) {
      fileWarnings.push(
        planWarning(
          "overlay",
          overlay.id,
          null,
          overlay.name,
          "listen-port-collision-risk",
          `derived ListenPort ${listenPort} is a common VPN-module default — verify no utm-* VPN tunnel already binds it`,
        ),
      );
    }

    const enabledSites = [...overlay.sites].filter((s) => s.enabled).sort((a, b) => a.id - b.id);
    if (enabledSites.length === 0) {
      skippedOverlays.push({
        id: overlay.id,
        name: overlay.name,
        reason: "no enabled sites — nothing to render",
      });
      warnings.push(
        planWarning(
          "overlay",
          overlay.id,
          null,
          overlay.name,
          "no-sites",
          `overlay '${overlay.name}' has no enabled sites — file skipped`,
        ),
      );
      continue;
    }

    const hub = enabledSites.find((s) => s.role === "hub");
    const local = hub ?? enabledSites[0];
    if (!hub) {
      fileWarnings.push(
        planWarning(
          "overlay",
          overlay.id,
          null,
          overlay.name,
          "no-hub",
          `overlay '${overlay.name}' has no hub site — anchoring to first enabled site '${local.name}'; verify the topology`,
        ),
      );
    }

    // site-octet collision detection within the overlay
    const siteOctets = new Map<number, number[]>();
    for (const s of enabledSites) {
      const oct = octetOf(s.id);
      const list = siteOctets.get(oct) ?? [];
      list.push(s.id);
      siteOctets.set(oct, list);
    }
    for (const [oct, ids] of siteOctets) {
      if (ids.length > 1) {
        fileWarnings.push(
          planWarning(
            "overlay",
            overlay.id,
            null,
            overlay.name,
            "tunnel-address-collision",
            `sites ${ids.join(", ")} of overlay '${overlay.name}' derive the same tunnel /24 (10.${octetOf(overlay.id)}.${oct}.0/24) — verify before bringing up`,
          ),
        );
      }
    }

    const peers: SdwanPeerRender[] = [];
    for (const site of enabledSites) {
      if (site.id === local.id) continue;
      const publicKey = wgPubKeyLooksReal(site.wgPubKey) ? (site.wgPubKey as string) : GENERATED_ON_APPLY;
      if (!wgPubKeyLooksReal(site.wgPubKey)) {
        fileWarnings.push(
          planWarning(
            "site",
            overlay.id,
            site.id,
            site.name,
            "generated-on-apply",
            `site '${site.name}' has no WireGuard public key recorded — peer renders ${GENERATED_ON_APPLY}; wg-quick up will fail until the site records its key`,
          ),
        );
      }
      peers.push({
        siteId: site.id,
        siteName: site.name,
        role: site.role,
        publicKey,
        allowedIps: [deriveSiteNet(overlay.id, site.id)],
        endpoint: `${site.publicIp}:${listenPort}`,
      });
    }
    peersTotal += peers.length;

    const address = deriveSiteAddress(overlay.id, local.id);

    const lines: string[] = [
      `# === UTM CONSOLE MANAGED (generated, do not edit) — GUI: Routing → SD-WAN ===`,
      `# overlay '${overlay.name}' (id ${overlay.id}, topology ${overlay.topology}, encryption wireguard)`,
      `# local anchor site: ${local.name} (id ${local.id}, role ${local.role})`,
      `# addressing v1 is DERIVED from ids (10.${octetOf(overlay.id)}.0.0/16) — see plan warnings`,
      ``,
      `[Interface]`,
      `ListenPort = ${listenPort}`,
      `PrivateKey = ${PRIVATE_KEY_PLACEHOLDER}`,
      `Address = ${address}`,
    ];
    for (const p of peers) {
      lines.push(``, `[Peer]`, `# site ${p.siteName} (id ${p.siteId}, role ${p.role})`);
      lines.push(`PublicKey = ${p.publicKey}`);
      lines.push(`AllowedIPs = ${p.allowedIps.join(", ")}`);
      lines.push(`Endpoint = ${p.endpoint}`);
      if (keepalive !== null) lines.push(`PersistentKeepalive = ${keepalive}`);
    }
    const conf = lines.join("\n") + "\n";

    files.push({
      overlayId: overlay.id,
      overlayName: overlay.name,
      topology: overlay.topology,
      iface,
      slug,
      fileName: `${SDWAN_WG_DIR}/${iface}.conf`,
      conf,
      confHash: sha256(conf),
      listenPort,
      localSite: { id: local.id, name: local.name, role: local.role },
      address,
      overlaySubnet: deriveOverlaySubnet(overlay.id),
      peers,
      warnings: fileWarnings,
    });
  }

  const combinedHash = sha256(
    [...files]
      .sort((a, b) => (a.iface < b.iface ? -1 : a.iface > b.iface ? 1 : 0))
      .map((f) => `${f.iface}:${f.confHash}`)
      .join("\n"),
  );

  return {
    generatedAt: (input.generatedAt ?? new Date()).toISOString(),
    files,
    combinedHash,
    counts: {
      overlays: overlays.length,
      rendered: files.length,
      skipped: skippedOverlays.length,
      peers: peersTotal,
    },
    skippedOverlays,
    warnings,
  };
}

// ── `wg show` parser (pure) ─────────────────────────────────────────────────

export interface WgShowIface {
  iface: string;
  listenPort: number | null;
  /** peer count currently configured on the live interface */
  peers: number;
  publicKey: string | null;
}

/**
 * Parse the human `wg show` output:
 *   interface: utm-sdwan-x
 *     public key: ...
 *     listening port: 51820
 *   peer: <base64>
 *     endpoint: ...
 */
export function parseWgShow(stdout: string): WgShowIface[] {
  const ifaces: WgShowIface[] = [];
  let current: WgShowIface | null = null;
  for (const raw of stdout.split("\n")) {
    const line = raw.trim();
    const im = /^interface:\s+(\S+)$/.exec(line);
    if (im) {
      current = { iface: im[1], listenPort: null, peers: 0, publicKey: null };
      ifaces.push(current);
      continue;
    }
    if (!current) continue;
    const pm = /^listening port:\s+(\d+)$/.exec(line);
    if (pm) {
      current.listenPort = Number(pm[1]);
      continue;
    }
    const km = /^public key:\s+(\S+)$/.exec(line);
    if (km) {
      current.publicKey = km[1];
      continue;
    }
    if (/^peer:\s+\S+$/.test(line)) {
      current.peers += 1;
    }
  }
  return ifaces;
}

/** Only the console-managed SD-WAN interfaces from a wg-show parse. */
export function sdwanIfacesFromWgShow(ifaces: WgShowIface[]): WgShowIface[] {
  return ifaces.filter((i) => i.iface.startsWith(SDWAN_IFACE_PREFIX));
}

// ── exec whitelist (anchored, mirror of appctl/vpn guards) ──────────────────

const WG_QUICK_RE = new RegExp(`^wg-quick (strip|up|down) ${SDWAN_IFACE_PREFIX}${UTMSN}$`);
const WG_READ_RE = /^wg (show|show all dump|--version)$/;
const ARM_RE = /^nohup \/bin\/sh "[^"]+" >\/dev\/null 2>&1 &$/;

/**
 * Command whitelist — the os-service aborts ANY step failing this guard.
 * wg-quick is restricted to the utm-sdwan-* namespace (strip = read-only
 * parser, up/down touch ONLY managed interfaces); wg is read/version only;
 * the rollback timer is the exact detached nohup form.
 */
export function sdwanStepGuarded(cmd: string): boolean {
  const c = cmd.trim();
  if (!c) return false;
  if (WG_QUICK_RE.test(c)) return true;
  if (WG_READ_RE.test(c)) return true;
  if (ARM_RE.test(c) && /\/rollback-[\w.-]+\.sh"/.test(c)) return true;
  return false;
}

// ── apply step-guard (confirm semantics — firewall confirm flow) ────────────

export type SdwanApplyMode = "confirm" | "execute" | "step-guard";

/**
 * Confirm step-guard for apply/up/down (firewall confirm-flow semantics):
 *   • ts present                → "confirm" (confirm an armed apply window)
 *   • confirmSec absent         → "step-guard" — NOTHING executes; the caller
 *                                 receives {confirmed:false, ts} and must
 *                                 re-issue with an explicit confirmSec window
 *   • confirmSec present        → "execute"
 */
export function sdwanApplyMode(body: { ts?: string; confirmSec?: number }): SdwanApplyMode {
  if (body.ts) return "confirm";
  if (body.confirmSec === undefined) return "step-guard";
  return "execute";
}

/** Fresh apply timestamp (state/backup naming) — ts-shaped, filesystem safe. */
export function sdwanApplyTs(now?: Date): string {
  return (now ?? new Date()).toISOString().replace(/[:.]/g, "-");
}

// ── rollback script (pure) ──────────────────────────────────────────────────

export interface SdwanRollbackScriptInput {
  ts: string;
  confirmSec: number;
  confirmFile: string;
  backupDir: string;
  stateFile: string;
  scriptFile: string;
  /** absolute config dir the files live in (/etc/wireguard) */
  wgDir: string;
  /** file stems that existed before the apply (restored from backup) */
  updated: string[];
  /** file stems created by the apply (removed on rollback) */
  created: string[];
}

/**
 * Detached commit-confirm rollback timer for the SD-WAN config files
 * (survives console restarts). Restores the snapshot taken BEFORE the apply;
 * running tunnels are intentionally NOT torn down (files-only rollback).
 */
export function buildSdwanRollbackScript(input: SdwanRollbackScriptInput): string {
  const lines: string[] = [
    "#!/bin/sh",
    `# utm-sdwan commit-confirm rollback armed ${input.ts}`,
    `# restores the pre-apply snapshot of the managed overlay config files;`,
    `# running tunnels are NOT torn down automatically — down them explicitly`,
    `sleep ${input.confirmSec}`,
    `if [ -f ${JSON.stringify(input.confirmFile)} ]; then exit 0; fi`,
  ];
  for (const stem of input.updated) {
    lines.push(
      `cp -f ${JSON.stringify(`${input.backupDir}/${stem}.conf`)} ${JSON.stringify(`${input.wgDir}/${stem}.conf`)}`,
    );
  }
  for (const stem of input.created) {
    lines.push(`rm -f ${JSON.stringify(`${input.wgDir}/${stem}.conf`)}`);
  }
  lines.push(`rm -f ${JSON.stringify(input.scriptFile)}`);
  // clear the pending window if it still belongs to THIS apply (a newer
  // apply supersedes it and owns the file — never touch that one)
  lines.push(
    `if grep -qF ${JSON.stringify(`"ts": "${input.ts}"`)} ${JSON.stringify(input.stateFile)} 2>/dev/null; then rm -f ${JSON.stringify(input.stateFile)}; fi`,
  );
  return lines.join("\n");
}

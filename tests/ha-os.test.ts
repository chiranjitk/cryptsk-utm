/**
 * HA OS integration — unit tests for the pure core of lib/ha/os.ts
 * (keepalived.conf renderer / parser / drift / guarded plan) and the HA
 * validator extensions. Filesystem and process boundaries are NOT exercised
 * here (prod E2E covers those with `keepalived -t` and systemd on the
 * appliance); everything below is deterministic.
 */

import { describe, it, expect } from "vitest";
import {
  renderKeepalivedConf,
  parseKeepalivedConf,
  computeHaDrift,
  buildHaApplyPlan,
  hardRefusal,
  haStepGuarded,
  isHaBackupPath,
  parseVrrpStateFromJournal,
  haConfHash,
  HA_INSTANCE_NAME,
  KEEPALIVED_CONF,
  KEEPALIVED_STAGE,
  HA_STATE_DIR,
  type HaKeepalivedInput,
  type HaOsFacts,
} from "@/lib/ha/os";
import { haConfigSchema } from "@/lib/validators/system";

// ── fixtures ────────────────────────────────────────────────────────────────

const cfg = (over: Partial<HaKeepalivedInput> = {}): HaKeepalivedInput => ({
  enabled: true,
  role: "active",
  priority: 150,
  virtualIp: "10.99.99.253/32",
  ifaceName: "ens34",
  peerIp: "10.99.99.254",
  trackedInterfaces: ["ens34"],
  failAfterSec: 10,
  holdDownSec: 60,
  vrid: 51,
  advertIntSec: 1,
  authPass: "utmha51",
  preempt: true,
  ...over,
});

const facts = (over: Partial<HaOsFacts> = {}): HaOsFacts => ({
  available: true,
  serviceState: "active",
  confText: null,
  confHash: null,
  osConfHash: null,
  conntrackdState: "active",
  vrrpState: "master",
  vipPresent: true,
  localIfaceIp: "10.99.99.252",
  ...over,
});

/** The REAL production conf observed on the appliance (VI_TEST bootstrap). */
const PROD_CONF = `! Minimal production config — health-only VRRP instance on the test interface.
! No VIP is routed anywhere; HA peers get provisioned via the console later.
global_defs {
        router_id UTM-PRIMARY
        enable_script_security
}

vrrp_instance VI_TEST {
        state BACKUP
        interface ens34
        virtual_router_id 51
        priority 100
        advert_int 1
        authentication {
                auth_type PASS
                auth_pass utmha51
        }
        virtual_ipaddress {
                10.99.99.253/32 dev ens34
        }
}
`;

// ── renderer ────────────────────────────────────────────────────────────────

describe("renderKeepalivedConf", () => {
  it("renders a full MASTER instance with unicast, auth, preempt_delay and track", () => {
    const conf = renderKeepalivedConf(cfg(), { routerId: "UTM-PRIMARY", localIfaceIp: "10.99.99.252" });
    expect(conf).toContain(`vrrp_instance ${HA_INSTANCE_NAME} {`);
    expect(conf).toContain("state MASTER");
    expect(conf).toContain("interface ens34");
    expect(conf).toContain("virtual_router_id 51");
    expect(conf).toContain("priority 150");
    expect(conf).toContain("advert_int 1");
    expect(conf).toContain("auth_type PASS");
    expect(conf).toContain("auth_pass utmha51");
    expect(conf).toContain("unicast_src_ip 10.99.99.252");
    expect(conf).toContain("unicast_peer {");
    expect(conf).toContain("\t\t10.99.99.254");
    expect(conf).toContain("preempt_delay 60");
    expect(conf).not.toContain("nopreempt");
    expect(conf).toContain("\t\t10.99.99.253/32 dev ens34");
    expect(conf).toContain("track_interface {");
    expect(conf).toContain("\t\tens34");
  });

  it("renders a BACKUP standby with nopreempt when preempt=false", () => {
    const conf = renderKeepalivedConf(cfg({ role: "standby", preempt: false }), { routerId: "r2" });
    expect(conf).toContain("state BACKUP");
    expect(conf).toContain("nopreempt");
    expect(conf).not.toContain("preempt_delay");
  });

  it("omits unicast when the local iface IP is unknown (multicast fallback)", () => {
    const conf = renderKeepalivedConf(cfg(), { routerId: "r", localIfaceIp: null });
    expect(conf).not.toContain("unicast_src_ip");
    expect(conf).not.toContain("unicast_peer");
  });

  it("disabled config renders global_defs only — no vrrp_instance", () => {
    const conf = renderKeepalivedConf(cfg({ enabled: false }), { routerId: "r" });
    expect(conf).toContain("global_defs {");
    expect(conf).not.toContain("vrrp_instance VI_CONSOLE");
    expect(conf).not.toContain("state MASTER");
    expect(conf).toContain("HA disabled in console");
  });

  it("no auth block when authPass is null", () => {
    const conf = renderKeepalivedConf(cfg({ authPass: null }), { routerId: "r" });
    expect(conf).not.toContain("authentication {");
  });

  it("holdDownSec=0 with preempt=true renders no preempt_delay", () => {
    const conf = renderKeepalivedConf(cfg({ holdDownSec: 0 }), { routerId: "r" });
    expect(conf).not.toContain("preempt_delay");
  });

  it("sanitizes the router_id (non hostname-safe chars dropped)", () => {
    const conf = renderKeepalivedConf(cfg(), { routerId: "ut m@primary!!" });
    expect(conf).toContain("router_id utmprimary");
  });

  it("is deterministic — identical inputs produce byte-identical conf (hash-stable)", () => {
    const a = renderKeepalivedConf(cfg(), { routerId: "R" });
    const b = renderKeepalivedConf(cfg(), { routerId: "R" });
    expect(a).toBe(b);
    expect(haConfHash(a)).toBe(haConfHash(b));
  });
});

// ── parser ──────────────────────────────────────────────────────────────────

describe("parseKeepalivedConf", () => {
  it("parses the real production VI_TEST bootstrap conf", () => {
    const parsed = parseKeepalivedConf(PROD_CONF);
    expect(parsed).toHaveLength(1);
    const inst = parsed[0];
    expect(inst.name).toBe("VI_TEST");
    expect(inst.iface).toBe("ens34");
    expect(inst.vrid).toBe(51);
    expect(inst.priority).toBe(100);
    expect(inst.state).toBe("BACKUP");
    expect(inst.vips).toEqual(["10.99.99.253/32"]);
    expect(inst.trackInterfaces).toEqual([]);
  });

  it("parses the console-rendered instance with nested vip+track blocks", () => {
    const conf = renderKeepalivedConf(cfg(), { routerId: "R", localIfaceIp: "10.99.99.252" });
    const parsed = parseKeepalivedConf(conf);
    expect(parsed).toHaveLength(1);
    const inst = parsed[0];
    expect(inst.name).toBe(HA_INSTANCE_NAME);
    expect(inst.iface).toBe("ens34");
    expect(inst.vrid).toBe(51);
    expect(inst.priority).toBe(150);
    expect(inst.state).toBe("MASTER");
    expect(inst.vips).toEqual(["10.99.99.253/32"]);
    expect(inst.trackInterfaces).toEqual(["ens34"]);
  });

  it("parses multiple instances", () => {
    const two = `${PROD_CONF}\nvrrp_instance VI_SECOND {\n\tstate MASTER\n\tinterface ens35\n\tvirtual_router_id 52\n\tpriority 200\n\tvirtual_ipaddress {\n\t\t192.168.50.1/24\n\t}\n\ttrack_interface {\n\t\tems34\n\t\tens35\n\t}\n}\n`;
    const parsed = parseKeepalivedConf(two);
    expect(parsed.map((p) => p.name)).toEqual(["VI_TEST", "VI_SECOND"]);
    expect(parsed[1].vips).toEqual(["192.168.50.1/24"]);
    expect(parsed[1].trackInterfaces).toEqual(["ems34", "ens35"]);
  });

  it("ignores comments and global_defs", () => {
    const parsed = parseKeepalivedConf(PROD_CONF);
    expect(parsed.some((p) => p.name.includes("global"))).toBe(false);
  });
});

// ── drift ───────────────────────────────────────────────────────────────────

describe("computeHaDrift", () => {
  it("reports in-sync when managed, instance matches, service active and VIP present", () => {
    const confText = renderKeepalivedConf(cfg(), { routerId: "R", localIfaceIp: "10.99.99.252" });
    const f = facts({
      confText,
      confHash: haConfHash(confText),
      osConfHash: haConfHash(confText),
    });
    const d = computeHaDrift(cfg(), f);
    expect(d.inSync).toBe(true);
    expect(d.managedByConsole).toBe(true);
    expect(d.reasons).toEqual([]);
  });

  it("flags unmanaged conf (hash mismatch with last applied)", () => {
    const f = facts({ confText: PROD_CONF, confHash: haConfHash(PROD_CONF), osConfHash: null });
    const d = computeHaDrift(cfg(), f);
    expect(d.managedByConsole).toBe(false);
    expect(d.reasons.some((r) => r.includes("not console-managed"))).toBe(true);
  });

  it("flags missing VI_CONSOLE instance when the OS conf only has VI_TEST", () => {
    const f = facts({ confText: PROD_CONF, confHash: haConfHash(PROD_CONF), osConfHash: haConfHash(PROD_CONF) });
    const d = computeHaDrift(cfg(), f);
    expect(d.inSync).toBe(false);
    expect(d.reasons.some((r) => r.includes(`no ${HA_INSTANCE_NAME} instance`))).toBe(true);
  });

  it("flags instance field mismatches (priority, VRID, iface, missing VIP, missing track)", () => {
    const driftedConf = `vrrp_instance ${HA_INSTANCE_NAME} {
        state BACKUP
        interface ens35
        virtual_router_id 60
        priority 90
        advert_int 1
        virtual_ipaddress {
                192.168.1.1/24 dev ens35
        }
}
`;
    const f = facts({ confText: driftedConf, confHash: haConfHash(driftedConf), osConfHash: haConfHash(driftedConf) });
    const d = computeHaDrift(cfg(), f);
    expect(d.reasons.some((r) => r.includes("iface ens35"))).toBe(true);
    expect(d.reasons.some((r) => r.includes("VRID 60"))).toBe(true);
    expect(d.reasons.some((r) => r.includes("priority 90"))).toBe(true);
    expect(d.reasons.some((r) => r.includes("VIP 10.99.99.253 not present"))).toBe(true);
    expect(d.reasons.some((r) => r.includes("tracked interface ens34 missing"))).toBe(true);
  });

  it("flags keepalived service not active", () => {
    const confText = renderKeepalivedConf(cfg(), { routerId: "R" });
    const f = facts({ confText, confHash: haConfHash(confText), osConfHash: haConfHash(confText), serviceState: "failed" });
    const d = computeHaDrift(cfg(), f);
    expect(d.reasons.some((r) => r.includes("keepalived service is failed"))).toBe(true);
  });

  it("flags VIP not assigned (VRRP not master / iface down)", () => {
    const confText = renderKeepalivedConf(cfg(), { routerId: "R" });
    const f = facts({ confText, confHash: haConfHash(confText), osConfHash: haConfHash(confText), vipPresent: false });
    const d = computeHaDrift(cfg(), f);
    expect(d.reasons.some((r) => r.includes("not assigned to ens34"))).toBe(true);
  });

  it("disabled config: only management reasons count (operator instances allowed)", () => {
    const f = facts({ confText: PROD_CONF, confHash: haConfHash(PROD_CONF), osConfHash: null });
    const d = computeHaDrift(cfg({ enabled: false }), f);
    // VI_TEST stays a legitimate operator conf — no VI_CONSOLE complaint
    expect(d.reasons.every((r) => r.includes("not console-managed"))).toBe(true);
    expect(d.reasons.some((r) => r.includes("no VI_CONSOLE"))).toBe(false);
  });

  it("missing keepalived binary → drift with availability reason", () => {
    const d = computeHaDrift(cfg(), facts({ available: false, confText: PROD_CONF, confHash: haConfHash(PROD_CONF) }));
    expect(d.inSync).toBe(false);
    expect(d.reasons[0]).toContain("keepalived binary not available");
  });
});

// ── red lines: hard refusal + command whitelist ─────────────────────────────

describe("hardRefusal (red lines)", () => {
  it("refuses the WAN uplink ens32 as the VRRP interface", () => {
    const r = hardRefusal(cfg({ ifaceName: "ens32" }));
    expect(r).toContain("protected WAN uplink");
    expect(r).toContain("ens32");
  });

  it("refuses the WAN uplink as a tracked interface", () => {
    const r = hardRefusal(cfg({ trackedInterfaces: ["ens34", "ens32"] }));
    expect(r).toContain("tracked interface 'ens32'");
  });

  it("refuses enabled-but-no-VIP (nothing to apply)", () => {
    const r = hardRefusal(cfg({ virtualIp: null }));
    expect(r).toContain("no virtual IP");
  });

  it("passes a legitimate ens34 config", () => {
    expect(hardRefusal(cfg())).toBeNull();
  });
});

describe("haStepGuarded (command whitelist)", () => {
  it("allows the exact plan commands", () => {
    expect(haStepGuarded(`mkdir -p ${HA_STATE_DIR}`)).toBe(true);
    expect(haStepGuarded(`cp ${KEEPALIVED_CONF} ${HA_STATE_DIR}/keepalived.conf.backup-20261116T000000-000000Z`)).toBe(true);
    expect(haStepGuarded(`install -m 0644 /dev/null ${KEEPALIVED_STAGE}`)).toBe(true);
    expect(haStepGuarded(`write-file ${KEEPALIVED_STAGE}`)).toBe(true);
    expect(haStepGuarded(`keepalived -t -f ${KEEPALIVED_STAGE}`)).toBe(true);
    expect(haStepGuarded(`keepalived -t -f /tmp/console-ha-validate.conf`)).toBe(true);
    expect(haStepGuarded(`install -m 0644 ${KEEPALIVED_STAGE} ${KEEPALIVED_CONF}`)).toBe(true);
    expect(haStepGuarded("systemctl restart keepalived")).toBe(true);
    expect(haStepGuarded("systemctl is-active keepalived")).toBe(true);
    expect(haStepGuarded(`rm -f ${KEEPALIVED_STAGE}`)).toBe(true);
  });

  it("rejects arbitrary / injected commands", () => {
    expect(haStepGuarded("rm -rf /")).toBe(false);
    expect(haStepGuarded("systemctl restart sshd")).toBe(false);
    expect(haStepGuarded(`cp ${KEEPALIVED_CONF} /etc/shadow`)).toBe(false);
    expect(haStepGuarded(`install -m 0644 /tmp/evil ${KEEPALIVED_CONF}`)).toBe(false);
    expect(haStepGuarded("keepalived -t -f /etc/keepalived/keepalived.conf")).toBe(false);
    expect(haStepGuarded("")).toBe(false);
    expect(haStepGuarded("bash -c 'echo hi'")).toBe(false);
  });
});

describe("buildHaApplyPlan", () => {
  it("builds a fully guarded validate-first plan in the right order", () => {
    const plan = buildHaApplyPlan(cfg(), { routerId: "R", localIfaceIp: "10.99.99.252" }, "exec", "20261116T000000-000000Z");
    expect(plan.guarded).toBe(true);
    expect(plan.refused).toBeNull();
    const names = plan.steps.map((s) => s.step);
    expect(names[0]).toBe("state dir");
    expect(names.indexOf("backup live conf")).toBeLessThan(names.indexOf("stage conf"));
    expect(names.indexOf("validate stage")).toBeLessThan(names.indexOf("install conf"));
    expect(names.indexOf("install conf")).toBeLessThan(names.indexOf("restart"));
    expect(names[names.length - 1]).toBe("cleanup stage");
    expect(plan.backupFile.startsWith(`${HA_STATE_DIR}/keepalived.conf.backup-`)).toBe(true);
    expect(plan.confText).toBe(renderKeepalivedConf(cfg(), { routerId: "R", localIfaceIp: "10.99.99.252" }));
    expect(plan.confHash).toBe(haConfHash(plan.confText));
  });

  it("carries the hard refusal without building around it", () => {
    const plan = buildHaApplyPlan(cfg({ ifaceName: "ens32" }), { routerId: "R" }, "exec", "t");
    expect(plan.refused).toContain("protected WAN uplink");
  });

  it("mode 'plan' is preview-only metadata", () => {
    const plan = buildHaApplyPlan(cfg(), { routerId: "R" }, "plan", "t");
    expect(plan.mode).toBe("plan");
  });
});

describe("isHaBackupPath", () => {
  it("accepts console-owned backups", () => {
    expect(isHaBackupPath(`${HA_STATE_DIR}/keepalived.conf.backup-20261116T05-00-00-000Z`)).toBe(true);
  });
  it("rejects paths outside the state dir or with wrong names", () => {
    expect(isHaBackupPath("/etc/keepalived/keepalived.conf")).toBe(false);
    expect(isHaBackupPath(`${HA_STATE_DIR}/evil.sh`)).toBe(false);
    expect(isHaBackupPath(`${HA_STATE_DIR}/../keepalived.conf.backup-x`)).toBe(false);
    expect(isHaBackupPath("")).toBe(false);
  });
});

// ── journal-derived VRRP state ──────────────────────────────────────────────

describe("parseVrrpStateFromJournal", () => {
  it("derives master / backup / fault from keepalived journal lines", () => {
    expect(parseVrrpStateFromJournal("(VI_CONSOLE): Entering MASTER STATE")).toBe("master");
    expect(parseVrrpStateFromJournal("(VI_TEST) Entering BACKUP STATE")).toBe("backup");
    expect(parseVrrpStateFromJournal("(VI_TEST) entering FAULT state (interface ens34 down)")).toBe("fault");
  });

  it("the LAST transition wins (chronological journal)", () => {
    const j = [
      "Nov 13 09:35:17 Keepalived_vrrp[901]: (VI_TEST) Entering MASTER STATE",
      "Nov 13 09:37:32 Keepalived_vrrp[901]: (VI_TEST) Entering BACKUP STATE",
      "Nov 13 09:37:34 Keepalived_vrrp[901]: (VI_TEST) Entering FAULT STATE",
    ].join("\n");
    expect(parseVrrpStateFromJournal(j)).toBe("fault");
  });

  it("returns null for empty / irrelevant journals", () => {
    expect(parseVrrpStateFromJournal("")).toBeNull();
    expect(parseVrrpStateFromJournal("systemd[1]: Started keepalived.service.")).toBeNull();
  });
});

// ── validator extensions ────────────────────────────────────────────────────

describe("haConfigSchema (keepalived-native fields)", () => {
  const base = {
    enabled: false,
    role: "standby",
    priority: 100,
    ifaceName: "ens34",
    trackedInterfaces: [],
    failAfterSec: 10,
    holdDownSec: 60,
  };

  it("applies keepalived defaults (vrid 51, advert 1 s, preempt on)", () => {
    const p = haConfigSchema.parse(base);
    expect(p.vrid).toBe(51);
    expect(p.advertIntSec).toBe(1);
    expect(p.preempt).toBe(true);
    expect(p.authPass ?? null).toBeNull();
  });

  it("rejects VRID out of 1-255", () => {
    expect(() => haConfigSchema.parse({ ...base, vrid: 0 })).toThrow();
    expect(() => haConfigSchema.parse({ ...base, vrid: 256 })).toThrow();
    expect(haConfigSchema.parse({ ...base, vrid: 255 }).vrid).toBe(255);
  });

  it("rejects advert interval out of 1-255", () => {
    expect(() => haConfigSchema.parse({ ...base, advertIntSec: 0 })).toThrow();
    expect(haConfigSchema.parse({ ...base, advertIntSec: 10 }).advertIntSec).toBe(10);
  });

  it("enforces the VRRPv2 8-char auth_pass limit (4-8 alnum)", () => {
    expect(haConfigSchema.parse({ ...base, authPass: "utmha51" }).authPass).toBe("utmha51");
    expect(() => haConfigSchema.parse({ ...base, authPass: "abc" })).toThrow();
    expect(() => haConfigSchema.parse({ ...base, authPass: "123456789" })).toThrow();
    expect(() => haConfigSchema.parse({ ...base, authPass: "utm ha5" })).toThrow();
  });

  it("enabled HA requires role, peer IP AND virtual IP", () => {
    expect(() => haConfigSchema.parse({ ...base, enabled: true, role: "active" })).toThrow(/peer IP/);
    expect(() =>
      haConfigSchema.parse({ ...base, enabled: true, role: "active", peerIp: "10.99.99.254" }),
    ).toThrow(/virtual IP/);
    const ok = haConfigSchema.parse({
      ...base,
      enabled: true,
      role: "active",
      peerIp: "10.99.99.254",
      virtualIp: "10.99.99.253/32",
    });
    expect(ok.enabled).toBe(true);
  });

  it("keep the hold-down ≥ fail-after rule", () => {
    expect(() => haConfigSchema.parse({ ...base, failAfterSec: 10, holdDownSec: 5 })).toThrow();
    expect(haConfigSchema.parse({ ...base, failAfterSec: 10, holdDownSec: 10 }).holdDownSec).toBe(10);
  });
});

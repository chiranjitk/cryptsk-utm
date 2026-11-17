/**
 * Embedded OUI fingerprint map (Phase 3 §3.6) — curated fingerprinting
 * subset of IEEE-assigned prefixes covering the device classes an enterprise
 * edge actually sees: consumer cameras, smart TVs, printers, phones,
 * networking gear, NAS, speakers and smart-home radios. Only prefixes we are
 * confident about are listed — a wrong vendor label is worse than no label —
 * so real-world coverage is deliberately partial (full IEEE OUI CSV import is
 * future work). Vendor blocks that span several product lines (e.g. Samsung
 * TVs vs phones) carry no deviceTypeHint; hostname/DHCP signals refine them.
 */

export type DeviceType = "printer" | "phone" | "camera" | "workstation" | "mobile" | "iot" | "unknown";

export interface OuiEntry {
  vendor: string;
  /** Best-effort class hint; "unknown" = vendor-only entry (no type claim). */
  deviceTypeHint: DeviceType;
  osHint?: string;
}

const CAMERA_FW = "camera firmware";
const PRINTER_FW = "embedded print server";
const PHONE_FW = "IP phone firmware";

/** Keys are lowercase 6-hex OUI prefixes ("4477cc"). */
const OUI_MAP: Readonly<Record<string, OuiEntry>> = {
  // ── consumer cameras ───────────────────────────────────────────────────────
  "4447cc": { vendor: "Hikvision", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "4cbd8f": { vendor: "Hikvision", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "4419b6": { vendor: "Hikvision", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "c056e3": { vendor: "Hikvision", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "e0508b": { vendor: "Dahua Technology", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "3cef8c": { vendor: "Dahua Technology", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "a0bd1d": { vendor: "Dahua Technology", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "00408c": { vendor: "Axis Communications", deviceTypeHint: "camera", osHint: CAMERA_FW },
  "accc8e": { vendor: "Axis Communications", deviceTypeHint: "camera", osHint: CAMERA_FW },

  // ── printers ───────────────────────────────────────────────────────────────
  "001f29": { vendor: "Hewlett-Packard", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "001e0b": { vendor: "Hewlett-Packard", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "002665": { vendor: "Hewlett-Packard", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "3c4a92": { vendor: "Hewlett-Packard", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "b4b52f": { vendor: "Hewlett-Packard", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "008077": { vendor: "Brother Industries", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "001ba9": { vendor: "Brother Industries", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "000085": { vendor: "Canon", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "001e8f": { vendor: "Canon", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "000048": { vendor: "Seiko Epson", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "0026ab": { vendor: "Seiko Epson", deviceTypeHint: "printer", osHint: PRINTER_FW },
  "000001": { vendor: "Xerox", deviceTypeHint: "printer", osHint: PRINTER_FW },

  // ── phones / tablets ───────────────────────────────────────────────────────
  "000393": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "000a27": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "000a95": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "001124": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "0016cb": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "0017f2": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "0019e3": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "001e52": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "0021e9": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "002312": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "0023df": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "002500": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "0025bc": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "002608": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "f01898": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "f81edf": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "14109f": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "24a074": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "d89695": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "acbc32": { vendor: "Apple", deviceTypeHint: "mobile", osHint: "iOS/macOS" },
  "00e0fc": { vendor: "Huawei", deviceTypeHint: "mobile", osHint: "Android/HarmonyOS" },
  "001882": { vendor: "Huawei", deviceTypeHint: "mobile", osHint: "Android/HarmonyOS" },
  "001e10": { vendor: "Huawei", deviceTypeHint: "mobile", osHint: "Android/HarmonyOS" },
  "00259e": { vendor: "Huawei", deviceTypeHint: "mobile", osHint: "Android/HarmonyOS" },
  "04f938": { vendor: "Huawei", deviceTypeHint: "mobile", osHint: "Android/HarmonyOS" },
  "a47174": { vendor: "Huawei", deviceTypeHint: "mobile", osHint: "Android/HarmonyOS" },
  "e8cd2d": { vendor: "Huawei", deviceTypeHint: "mobile", osHint: "Android/HarmonyOS" },
  "640980": { vendor: "Xiaomi", deviceTypeHint: "mobile", osHint: "Android (MIUI)" },
  "7802f8": { vendor: "Xiaomi", deviceTypeHint: "mobile", osHint: "Android (MIUI)" },
  "f8a45f": { vendor: "Xiaomi", deviceTypeHint: "mobile", osHint: "Android (MIUI)" },
  "f0b429": { vendor: "Xiaomi", deviceTypeHint: "mobile", osHint: "Android (MIUI)" },
  // Samsung blocks span phones AND TVs — phone-era blocks hint mobile, the
  // older blocks stay vendor-only (the hostname "tv" signal decides).
  "001632": { vendor: "Samsung Electronics", deviceTypeHint: "mobile", osHint: "Android/Tizen" },
  "001b98": { vendor: "Samsung Electronics", deviceTypeHint: "mobile", osHint: "Android/Tizen" },
  "001d25": { vendor: "Samsung Electronics", deviceTypeHint: "mobile", osHint: "Android/Tizen" },
  "002119": { vendor: "Samsung Electronics", deviceTypeHint: "mobile", osHint: "Android/Tizen" },
  "002490": { vendor: "Samsung Electronics", deviceTypeHint: "mobile", osHint: "Android/Tizen" },
  "002637": { vendor: "Samsung Electronics", deviceTypeHint: "mobile", osHint: "Android/Tizen" },
  "dc7144": { vendor: "Samsung Electronics", deviceTypeHint: "mobile", osHint: "Android/Tizen" },
  "0007ab": { vendor: "Samsung Electronics", deviceTypeHint: "unknown" },
  "00e064": { vendor: "Samsung Electronics", deviceTypeHint: "unknown" },
  "001c62": { vendor: "LG Electronics", deviceTypeHint: "mobile", osHint: "Android/webOS" },
  "0026e2": { vendor: "LG Electronics", deviceTypeHint: "mobile", osHint: "Android/webOS" },
  "f82fa8": { vendor: "LG Electronics", deviceTypeHint: "mobile", osHint: "Android/webOS" },
  "001a11": { vendor: "Google", deviceTypeHint: "mobile", osHint: "Android" },
  "546009": { vendor: "Google", deviceTypeHint: "mobile", osHint: "Android" },
  "f4f5d8": { vendor: "Google", deviceTypeHint: "mobile", osHint: "Android" },

  // ── desk phones / VoIP handsets ────────────────────────────────────────────
  "001565": { vendor: "Yealink", deviceTypeHint: "phone", osHint: PHONE_FW },
  "805e4c": { vendor: "Yealink", deviceTypeHint: "phone", osHint: PHONE_FW },
  "0004f2": { vendor: "Polycom", deviceTypeHint: "phone", osHint: PHONE_FW },
  "000b82": { vendor: "Grandstream Networks", deviceTypeHint: "phone", osHint: PHONE_FW },

  // ── networking gear ────────────────────────────────────────────────────────
  "245ebe": { vendor: "Ubiquiti Networks", deviceTypeHint: "iot", osHint: "UniFi/AirOS" },
  "24a43c": { vendor: "Ubiquiti Networks", deviceTypeHint: "iot", osHint: "UniFi/AirOS" },
  "44d9e7": { vendor: "Ubiquiti Networks", deviceTypeHint: "iot", osHint: "UniFi/AirOS" },
  "68d79a": { vendor: "Ubiquiti Networks", deviceTypeHint: "iot", osHint: "UniFi/AirOS" },
  "788a20": { vendor: "Ubiquiti Networks", deviceTypeHint: "iot", osHint: "UniFi/AirOS" },
  "f09fc2": { vendor: "Ubiquiti Networks", deviceTypeHint: "iot", osHint: "UniFi/AirOS" },
  "50c7bf": { vendor: "TP-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "a42bb0": { vendor: "TP-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "14cc20": { vendor: "TP-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "6032b1": { vendor: "TP-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "74da38": { vendor: "TP-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "f4f26d": { vendor: "TP-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "001b0d": { vendor: "Cisco Systems", deviceTypeHint: "iot", osHint: "Cisco IOS" },
  "001da1": { vendor: "Cisco Systems", deviceTypeHint: "iot", osHint: "Cisco IOS" },
  "002255": { vendor: "Cisco Systems", deviceTypeHint: "iot", osHint: "Cisco IOS" },
  "002304": { vendor: "Cisco Systems", deviceTypeHint: "iot", osHint: "Cisco IOS" },
  "002545": { vendor: "Cisco Systems", deviceTypeHint: "iot", osHint: "Cisco IOS" },
  "000c42": { vendor: "MikroTik", deviceTypeHint: "iot", osHint: "RouterOS" },
  "488f5a": { vendor: "MikroTik", deviceTypeHint: "iot", osHint: "RouterOS" },
  "64d154": { vendor: "MikroTik", deviceTypeHint: "iot", osHint: "RouterOS" },
  "d4ca6d": { vendor: "MikroTik", deviceTypeHint: "iot", osHint: "RouterOS" },
  "00095b": { vendor: "Netgear", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "001b2f": { vendor: "Netgear", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "001f33": { vendor: "Netgear", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "b03956": { vendor: "Netgear", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "00055d": { vendor: "D-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "00179a": { vendor: "D-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "00265a": { vendor: "D-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "1c7ee5": { vendor: "D-Link", deviceTypeHint: "iot", osHint: "embedded Linux" },
  "000b86": { vendor: "Aruba Networks", deviceTypeHint: "iot", osHint: "ArubaOS" },

  // ── NAS ────────────────────────────────────────────────────────────────────
  "001132": { vendor: "Synology", deviceTypeHint: "iot", osHint: "DSM (embedded Linux)" },
  "00089b": { vendor: "QNAP (ICP Electronics)", deviceTypeHint: "iot", osHint: "QTS (embedded Linux)" },

  // ── speakers / smart home ──────────────────────────────────────────────────
  "000e58": { vendor: "Sonos", deviceTypeHint: "iot", osHint: "Sonos OS" },
  "542a1b": { vendor: "Sonos", deviceTypeHint: "iot", osHint: "Sonos OS" },
  "b8e937": { vendor: "Sonos", deviceTypeHint: "iot", osHint: "Sonos OS" },
  "5ccf7f": { vendor: "Espressif Systems", deviceTypeHint: "iot", osHint: "ESP firmware" },
  "240ac4": { vendor: "Espressif Systems", deviceTypeHint: "iot", osHint: "ESP firmware" },
  "246f28": { vendor: "Espressif Systems", deviceTypeHint: "iot", osHint: "ESP firmware" },
  "30aea4": { vendor: "Espressif Systems", deviceTypeHint: "iot", osHint: "ESP firmware" },
  "840d8e": { vendor: "Espressif Systems", deviceTypeHint: "iot", osHint: "ESP firmware" },
  "a020a6": { vendor: "Shelly (Allterco)", deviceTypeHint: "iot", osHint: "Shelly firmware" },
  "508f4c": { vendor: "Tuya", deviceTypeHint: "iot", osHint: "Tuya firmware" },
  "001788": { vendor: "Signify (Philips Hue)", deviceTypeHint: "iot", osHint: "Hue bridge" },
  "ecbd27": { vendor: "Signify (Philips Hue)", deviceTypeHint: "iot", osHint: "Hue bridge" },
  "b827eb": { vendor: "Raspberry Pi Trading", deviceTypeHint: "iot", osHint: "Raspberry Pi OS" },
  "dca632": { vendor: "Raspberry Pi Trading", deviceTypeHint: "iot", osHint: "Raspberry Pi OS" },
  "e45f01": { vendor: "Raspberry Pi Trading", deviceTypeHint: "iot", osHint: "Raspberry Pi OS" },

  // ── workstations / virtual machines ────────────────────────────────────────
  "001b21": { vendor: "Intel Corporate", deviceTypeHint: "workstation" },
  "001de0": { vendor: "Intel Corporate", deviceTypeHint: "workstation" },
  "002710": { vendor: "Intel Corporate", deviceTypeHint: "workstation" },
  "847b57": { vendor: "Intel Corporate", deviceTypeHint: "workstation" },
  "a0a8cd": { vendor: "Intel Corporate", deviceTypeHint: "workstation" },
  "001422": { vendor: "Dell", deviceTypeHint: "workstation", osHint: "Windows" },
  "002170": { vendor: "Dell", deviceTypeHint: "workstation", osHint: "Windows" },
  "f01faf": { vendor: "Dell", deviceTypeHint: "workstation", osHint: "Windows" },
  "d4bed9": { vendor: "Dell", deviceTypeHint: "workstation", osHint: "Windows" },
  "00e04c": { vendor: "Realtek", deviceTypeHint: "workstation" },
  "000d3a": { vendor: "Microsoft", deviceTypeHint: "workstation", osHint: "Windows/Azure" },
  "000c29": { vendor: "VMware", deviceTypeHint: "workstation", osHint: "VMware VM" },
  "005056": { vendor: "VMware", deviceTypeHint: "workstation", osHint: "VMware VM" },
  "001c14": { vendor: "VMware", deviceTypeHint: "workstation", osHint: "VMware VM" },
  "080027": { vendor: "Oracle VirtualBox", deviceTypeHint: "workstation", osHint: "VirtualBox VM" },
  "00155d": { vendor: "Microsoft Hyper-V", deviceTypeHint: "workstation", osHint: "Hyper-V VM" },
  "525400": { vendor: "QEMU/KVM", deviceTypeHint: "workstation", osHint: "KVM/QEMU VM" },
  "00163e": { vendor: "Xensource", deviceTypeHint: "workstation", osHint: "Xen VM" },
};

/**
 * Normalize the MAC notations the profiler meets in the wild —
 * "aa-bb-cc-dd-ee-ff" (dashes), "aabbccddeeff" (bare) and "AA:BB:CC:DD:EE:FF"
 * (colons) — into uppercase colon form. A 6-hex OUI prefix ("aabbcc" /
 * "aa-bb-cc" / "AA:BB:CC") is also accepted and yields "AA:BB:CC". Anything
 * else (wrong length, non-hex) → null.
 */
export function normalizeMac(mac: string): string | null {
  const hex = mac.trim().toLowerCase().replace(/[:-]/g, "");
  if (!/^[0-9a-f]{6}$/.test(hex) && !/^[0-9a-f]{12}$/.test(hex)) return null;
  return (hex.match(/.{2}/g) ?? []).join(":").toUpperCase();
}

/**
 * OUI lookup by exact 6-hex prefix. Accepts every notation normalizeMac does
 * (a full MAC works too — the prefix is cut off); unknown prefixes and
 * malformed input return null instead of guessing.
 */
export function lookupOui(mac: string): OuiEntry | null {
  const hex = mac.trim().toLowerCase().replace(/[:-]/g, "");
  if (!/^[0-9a-f]{6}$/.test(hex) && !/^[0-9a-f]{12}$/.test(hex)) return null;
  return OUI_MAP[hex.slice(0, 6)] ?? null;
}

/** Size of the curated subset (observability / tests). */
export function ouiMapSize(): number {
  return Object.keys(OUI_MAP).length;
}

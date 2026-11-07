/**
 * SIMULATED IA_PD prefix-delegation lease (M21 §2.7) — computed on the fly,
 * no persistence: the prefix is derived deterministically from tenant + WAN
 * interface (FNV-1a), the lifetimes mirror a typical 24h/12h ISP lease.
 */

import { route } from "@/lib/api/handler";
import { getPrefixDelegation } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ipv6" }, async ({ auth }) => {
  return { data: await getPrefixDelegation(auth.tenantId) };
});

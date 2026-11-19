/**
 * /api/v1/sites/firmware — central firmware catalog (Phase 4 §4.1). GET lists
 * the per-channel releases; POST adds a release whose sha256 must be exactly
 * 64 hex characters (checksum used to verify the image on the remote site).
 */

import { route } from "@/lib/api/handler";
import { firmwareCreateSchema } from "@/lib/validators/sites";
import { addFirmware, listFirmware } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sites" }, async ({ auth }) => {
  return { data: await listFirmware(auth.tenantId) };
});

export const POST = route(
  { area: "sites", bodySchema: firmwareCreateSchema },
  async ({ auth, body }) => {
    const created = await addFirmware(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "firmware.create",
        objectType: "firmware_release",
        objectId: created.id,
        objectName: `${created.channel}@${created.version}`,
        after: created,
      },
    };
  },
);

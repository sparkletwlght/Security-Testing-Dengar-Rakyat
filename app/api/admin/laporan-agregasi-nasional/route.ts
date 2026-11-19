import { NextResponse } from "next/server";
import { countStatusNasional } from "@/features/laporan/laporan.queries";
import { getCurrentUser } from "@/features/auth/session.service";
import { serverError } from "@/lib/http";
import { logDataEvent, logSystemEvent } from "@/features/audit/audit.service";

export async function GET(req: Request) {
  try {
    const user = await getCurrentUser();
    if (!user) {
      await logSystemEvent({ event_type: "permission_denied", request: req, http_status: 401, metadata: { reason: "unauthenticated", action: "national_report_aggregation" } });
      return NextResponse.json({ error: "Belum login" }, { status: 401 });
    }
    if ((user.role || "").toLowerCase() !== "pusat") {
      await logSystemEvent({
        event_type: "permission_denied", user_id: user.id, user_email: user.email,
        user_role: user.role, request: req, http_status: 403,
        metadata: { reason: "insufficient_role", action: "national_report_aggregation" },
      });
      return NextResponse.json({ error: "Akses khusus Pemerintah Pusat" }, { status: 403 });
    }
    const result = await countStatusNasional();
    await logDataEvent({
      event_type: "laporan_read", user_id: user.id, user_email: user.email,
      user_role: user.role, target_type: "report_aggregation", target_id: "national",
      request: req, metadata: { scope: "national" },
    });
    return NextResponse.json(result);
  } catch (err) {
    return serverError(err);
  }
}

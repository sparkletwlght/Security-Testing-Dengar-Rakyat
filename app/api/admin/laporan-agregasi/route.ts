import { NextResponse } from "next/server";
import { countStatusByKotaKab } from "@/features/laporan/laporan.queries";
import { getCurrentUser } from "@/features/auth/session.service";
import { serverError } from "@/lib/http";
import { logDataEvent, logSystemEvent } from "@/features/audit/audit.service";

export async function GET(req: Request) {
  try {
    const user = await getCurrentUser();
    if (!user) {
      await logSystemEvent({ event_type: "permission_denied", request: req, http_status: 401, metadata: { reason: "unauthenticated", action: "regional_report_aggregation" } });
      return NextResponse.json({ error: "Belum login" }, { status: 401 });
    }

    const role = (user.role || "").toLowerCase();
    if (!["pusat", "admin_pemda", "pemda"].includes(role)) {
      await logSystemEvent({
        event_type: "permission_denied", user_id: user.id, user_email: user.email,
        user_role: user.role, request: req, http_status: 403,
        metadata: { reason: "insufficient_role", action: "regional_report_aggregation" },
      });
      return NextResponse.json(
        { error: "Akses ditolak: Hanya Pemda dan Pusat yang dapat mengakses data agregasi" },
        { status: 403 }
      );
    }

    const { searchParams } = new URL(req.url);
    const kotaKabIdParam = searchParams.get("kotaKabId") ?? "";
    if (!kotaKabIdParam) {
      return NextResponse.json({ error: "kotaKabId wajib diisi" }, { status: 400 });
    }

    const kotaKabId = Number(kotaKabIdParam);
    if (!Number.isSafeInteger(kotaKabId) || kotaKabId <= 0) {
      return NextResponse.json({ error: "kotaKabId harus berupa angka valid" }, { status: 400 });
    }

    // IDOR Protection: Admin Pemda hanya boleh mengakses wilayah hukumnya sendiri
    if ((role === "admin_pemda" || role === "pemda") && user.wilayah_id !== kotaKabId) {
      await logSystemEvent({
        event_type: "permission_denied", user_id: user.id, user_email: user.email,
        user_role: user.role, request: req, http_status: 403,
        metadata: { reason: "out_of_scope_region", action: "regional_report_aggregation" },
      });
      return NextResponse.json(
        { error: "Akses terlarang: Anda tidak memiliki wewenang melihat data agregasi kota/kabupaten lain (IDOR Protected)" },
        { status: 403 }
      );
    }

    const result = await countStatusByKotaKab(kotaKabId);
    await logDataEvent({
      event_type: "laporan_read", user_id: user.id, user_email: user.email,
      user_role: user.role, target_type: "report_aggregation", target_id: String(kotaKabId),
      request: req, metadata: { scope: "region" },
    });
    return NextResponse.json(result);
  } catch (err) {
    return serverError(err);
  }
}

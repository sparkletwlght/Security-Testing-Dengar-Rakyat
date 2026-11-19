/**
 * Profile Update API
 * PUT - Update user profile (nama, alamat)
 */

import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { getCurrentUser } from "@/features/auth/session.service";
import { SESSION_COOKIE_NAME } from "@/lib/cookies";
import { query } from "@/lib/db";
import { encrypt } from "@/lib/crypto";
import { validateCsrfToken } from "@/lib/csrf";
import { logDataEvent, logSystemEvent } from "@/features/audit/audit.service";

export async function PUT(req: Request) {
  try {
    // Auth check
    const cookieStore = await cookies();
    const sessionId = cookieStore.get(SESSION_COOKIE_NAME)?.value;
    const user = await getCurrentUser(sessionId);

    if (!user) {
      await logSystemEvent({
        event_type: "permission_denied", request: req, http_status: 401,
        metadata: { reason: "unauthenticated", action: "profile_update" },
      });
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!sessionId || !validateCsrfToken(req.headers.get("x-csrf-token") || "", sessionId).valid) {
      await logSystemEvent({
        event_type: "csrf_violation", user_id: user.id, user_email: user.email,
        user_role: user.role, request: req, http_status: 403,
        metadata: { reason: "invalid_csrf_token", action: "profile_update" },
      });
      return NextResponse.json({ error: "CSRF token tidak valid" }, { status: 403 });
    }

    const body = await req.json();
    const nama = body?.nama;
    const alamat = body?.alamat;

    if (typeof nama !== "string" || nama.trim().length < 3 || nama.trim().length > 120 || (alamat != null && (typeof alamat !== "string" || alamat.length > 1000))) {
      await logSystemEvent({
        event_type: "validation_failure", user_id: user.id, user_email: user.email,
        user_role: user.role, request: req, http_status: 400,
        metadata: { reason: "validation_failed", action: "profile_update" },
      });
      return NextResponse.json(
        { error: "Nama harus minimal 3 karakter" },
        { status: 400 }
      );
    }

    // Encrypt alamat if provided
    const alamatEnc = typeof alamat === "string" && alamat.trim() ? encrypt(alamat.trim()) : null;

    // Update user
    await query(
      `UPDATE users 
       SET nama = ?, alamat_enc = COALESCE(?, alamat_enc)
       WHERE id = ?`,
      [nama.trim(), alamatEnc, user.id]
    );

    await logDataEvent({
      event_type: "profile_update", user_id: user.id, user_email: user.email,
      user_role: user.role, target_type: "user_profile", target_id: String(user.id),
      request: req, metadata: { changed_fields: typeof alamat === "string" ? ["nama", "alamat"] : ["nama"] },
    });

    return NextResponse.json({
      message: "Profil berhasil diperbarui",
      user: { nama: nama.trim() },
    });
  } catch (error) {
    console.error("[profile/update] Error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * Reset Password API Route - Iterasi 2 H4 Hardened
 * - Token validation (hash + expiry + single-use)
 * - Password policy enforcement
 * - Invalidate all sessions after reset
 */

import { NextResponse } from "next/server";
import { resetPassword } from "@/features/auth/password.service";
import { logAuthEvent } from "@/features/audit/audit.service";
import { getRequestContext } from "@/lib/request-context";

export async function POST(req: Request) {
  const requestContext = getRequestContext(req);
  try {
    const body = await req.json();
    const token = typeof body?.token === "string" ? body.token : "";
    const newPassword = typeof body?.newPassword === "string" ? body.newPassword : "";

    if (!token || !newPassword) {
      await logAuthEvent({
        event_type: "password_reset_complete", status: "failure",
        error_message: "Password reset payload incomplete", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: 400,
        metadata: { reason: "validation_failed" },
      });
      return NextResponse.json(
        { error: "Token dan password wajib diisi" },
        { status: 400 }
      );
    }

    const result = await resetPassword(token, newPassword);

    if (!result.ok) {
      await logAuthEvent({
        event_type: "password_reset_complete", status: "failure",
        error_message: "Password reset did not complete", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: result.status,
        metadata: { reason: result.status === 400 ? "invalid_token_or_password" : "reset_failed" },
      });
      return NextResponse.json(
        { error: result.error },
        { status: result.status }
      );
    }

    await logAuthEvent({
      event_type: "password_reset_complete", user_id: result.userId, status: "success",
      ...requestContext, request_path: new URL(req.url).pathname, http_status: 200,
      metadata: { reason: "password_reset_completed" },
    });

    return NextResponse.json({
      message: result.message || "Password berhasil direset",
    });
  } catch (err) {
    console.error("Reset password API error:", err);
    await logAuthEvent({
      event_type: "password_reset_complete", status: "failure",
      error_message: "Password reset processing failed", ...requestContext,
      request_path: new URL(req.url).pathname, http_status: 500,
      metadata: { reason: "server_error" },
    });
    return NextResponse.json(
      { error: "Terjadi kesalahan saat reset password" },
      { status: 500 }
    );
  }
}

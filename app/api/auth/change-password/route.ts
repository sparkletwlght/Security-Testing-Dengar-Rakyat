import { NextResponse } from "next/server";
import { getCurrentUser } from "@/features/auth/session.service";
import { changePassword } from "@/features/auth/password.service";
import { serverError } from "@/lib/http";
import { cookies } from "next/headers";
import { validateCsrfToken } from "@/lib/csrf";
import { getSessionCookieOptions, SESSION_COOKIE_NAME } from "@/lib/cookies";
import { logAuthEvent, logSystemEvent } from "@/features/audit/audit.service";
import { getRequestContext } from "@/lib/request-context";

export async function POST(req: Request) {
  const requestContext = getRequestContext(req);
  try {
    const user = await getCurrentUser();
    if (!user) {
      await logAuthEvent({
        event_type: "password_change", status: "failure", error_message: "Unauthenticated password change attempt",
        ...requestContext, request_path: new URL(req.url).pathname, http_status: 401,
        metadata: { reason: "unauthenticated" },
      });
      return NextResponse.json({ error: "Belum login" }, { status: 401 });
    }
    const sessionId = (await cookies()).get(SESSION_COOKIE_NAME)?.value;
    if (!sessionId || !validateCsrfToken(req.headers.get("x-csrf-token") || "", sessionId).valid) {
      await logSystemEvent({
        event_type: "csrf_violation", user_id: user.id, user_email: user.email,
        user_role: user.role, request: req, http_status: 403,
        metadata: { reason: "invalid_csrf_token", action: "password_change" },
      });
      return NextResponse.json({ error: "CSRF token tidak valid" }, { status: 403 });
    }
    const body = await req.json();
    const currentPassword = body?.currentPassword || body?.passwordLama;
    const newPassword = body?.newPassword || body?.passwordBaru || body?.password;
    if (typeof currentPassword !== "string" || typeof newPassword !== "string") {
      await logAuthEvent({
        event_type: "password_change", user_id: user.id, user_email: user.email, user_role: user.role,
        status: "failure", error_message: "Password change payload invalid", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: 400,
        metadata: { reason: "validation_failed" },
      });
      return NextResponse.json({ error: "Password lama dan baru wajib diisi" }, { status: 400 });
    }

    const result = await changePassword(user.id, currentPassword, newPassword, user.email.split("@")[0]);
    if (!result.ok) {
      await logAuthEvent({
        event_type: "password_change", user_id: user.id, user_email: user.email, user_role: user.role,
        status: "failure", error_message: "Password change rejected", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: result.status,
        metadata: { reason: result.status === 401 ? "current_password_invalid" : "password_policy_or_update_failed" },
      });
      return NextResponse.json({ error: result.error }, { status: result.status });
    }
    await logAuthEvent({
      event_type: "password_change", user_id: user.id, user_email: user.email, user_role: user.role,
      status: "success", ...requestContext, request_path: new URL(req.url).pathname, http_status: 200,
      metadata: { reason: "password_changed_sessions_rotated" },
    });
    const response = NextResponse.json({ message: result.message });
    if (result.sessionId) response.cookies.set(SESSION_COOKIE_NAME, result.sessionId, getSessionCookieOptions());
    return response;
  } catch (err) {
    await logAuthEvent({
      event_type: "password_change", status: "failure", error_message: "Password change processing failed",
      ...requestContext, request_path: new URL(req.url).pathname, http_status: 500,
      metadata: { reason: "server_error" },
    });
    return serverError(err);
  }
}

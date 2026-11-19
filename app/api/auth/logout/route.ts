/**
 * Logout API Route - Iterasi 2 H3 + P1 Complete
 * - Delete session from database (server-side invalidation)
 * - Clear cookie with secure options
 * - Audit log logout event
 */

import { NextResponse } from "next/server";
import { cookies, headers } from "next/headers";
import { destroySession, getSessionWithUser } from "@/features/auth/session.service";
import { SESSION_COOKIE_NAME, getClearCookieOptions } from "@/lib/cookies";
import { logAuthEvent, logSystemEvent } from "@/features/audit/audit.service";
import { handleApiError } from "@/lib/error-handler";
import { validateCsrfToken } from "@/lib/csrf";
import { getRequestContext } from "@/lib/request-context";

export async function POST(req: Request) {
  const requestContext = getRequestContext(req);
  try {
    const cookieStore = await cookies();
    const headersList = await headers();
    const sessionId = cookieStore.get(SESSION_COOKIE_NAME)?.value;

    if (!sessionId) {
      await logAuthEvent({
        event_type: "logout", status: "failure", error_message: "Logout requested without an active session",
        ...requestContext, request_path: new URL(req.url).pathname, http_status: 400,
        metadata: { reason: "no_active_session" },
      });
      return NextResponse.json(
        { error: "No active session" },
        { status: 400 }
      );
    }
    if (!validateCsrfToken(headersList.get("x-csrf-token") || "", sessionId).valid) {
      await logSystemEvent({
        event_type: "csrf_violation", request: req, http_status: 403,
        metadata: { reason: "invalid_csrf_token", action: "logout" },
      });
      return NextResponse.json({ error: "CSRF token tidak valid" }, { status: 403 });
    }

    // Get session info for audit log (before deletion)
    const session = await getSessionWithUser(sessionId);

    // Delete session from database (server-side invalidation)
    await destroySession(sessionId);

    // Audit log (AFTER successful deletion)
    if (session) {
      await logAuthEvent({
        event_type: "logout",
        user_id: session.user_id,
        user_email: session.email,
        user_role: session.role,
        ...requestContext,
        request_path: new URL(req.url).pathname,
        http_status: 200,
        status: "success",
      });
    }

    // Clear cookie (client-side)
    cookieStore.set(SESSION_COOKIE_NAME, "", getClearCookieOptions());

    return NextResponse.json({ message: "Logout berhasil" });
  } catch (error) {
    return handleApiError(error, "Logout");
  }
}

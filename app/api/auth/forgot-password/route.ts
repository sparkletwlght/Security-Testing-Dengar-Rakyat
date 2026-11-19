/**
 * Forgot Password API Route - Iterasi 2 H4 Hardened
 * - Rate limiting (3 attempts/hour)
 * - Generic responses (no email disclosure)
 * - Token hashing
 */

import { NextResponse } from "next/server";
import { requestPasswordReset } from "@/features/auth/password.service";
import { logAuthEvent } from "@/features/audit/audit.service";
import { getRequestContext } from "@/lib/request-context";

export async function POST(req: Request) {
  const requestContext = getRequestContext(req);
  try {
    const { email } = await req.json();

    if (!email) {
      await logAuthEvent({
        event_type: "password_reset_request", status: "failure",
        error_message: "Password reset request missing email", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: 400,
        metadata: { reason: "validation_failed" },
      });
      return NextResponse.json(
        { error: "Email wajib diisi" },
        { status: 400 }
      );
    }

    const result = await requestPasswordReset(email);

    // Always return 200 with generic message (don't reveal if email exists)
    if (!result.ok && result.status === 429) {
      // Only exception: rate limit (user needs to know)
      await logAuthEvent({
        event_type: "password_reset_request", user_email: typeof email === "string" ? email.trim().toLowerCase() : undefined,
        status: "failure", error_message: "Password reset rate limit exceeded", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: 429,
        metadata: { reason: "rate_limit" },
      });
      return NextResponse.json(
        { error: result.error },
        { status: 429 }
      );
    }

    // Keep the audit result generic too: it must not reveal whether the email exists.
    await logAuthEvent({
      event_type: "password_reset_request", user_email: typeof email === "string" ? email.trim().toLowerCase() : undefined,
      status: "success", ...requestContext, request_path: new URL(req.url).pathname, http_status: 200,
      metadata: { reason: "request_accepted" },
    });

    return NextResponse.json({
      message: result.message || "Jika email terdaftar dan layanan email tersedia, instruksi reset akan dikirim.",
    });
  } catch (err) {
    console.error("Forgot password API error:", err);
    await logAuthEvent({
      event_type: "password_reset_request", status: "failure",
      error_message: "Password reset request processing failed", ...requestContext,
      request_path: new URL(req.url).pathname, http_status: 200,
      metadata: { reason: "processing_error" },
    });
    // Generic error (don't leak details)
    return NextResponse.json(
      { message: "Jika email terdaftar dan layanan email tersedia, instruksi reset akan dikirim." },
      { status: 200 }
    );
  }
}

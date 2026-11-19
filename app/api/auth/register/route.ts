/**
 * Register API Route - Iterasi 2 H2 + H5 Hardened
 * - Input validation & sanitization
 * - Error handling with sanitized messages
 * - Rate limiting (via register.service)
 */

import { NextResponse } from "next/server";
import { registerUser } from "@/features/auth/register.service";
import { handleApiError } from "@/lib/error-handler";
import { sanitizeEmail, sanitizeString } from "@/lib/sanitizers";
import {
  validateEmail,
  validateNik,
  validateLength,
  validateWilayahId,
} from "@/lib/validators";
import { checkRateLimit, RateLimits } from "@/lib/rate-limiter";
import { getClientIP, getRequestContext } from "@/lib/request-context";
import { logAuthEvent } from "@/features/audit/audit.service";
import crypto from "node:crypto";
import { sendRegistrationOtp } from "@/features/auth/email-verification.service";

export async function POST(req: Request) {
  const requestContext = getRequestContext(req);
  try {
    const body = await req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      await logAuthEvent({
        event_type: "register", status: "failure", error_message: "Invalid registration payload",
        ...requestContext, request_path: new URL(req.url).pathname, http_status: 400,
        metadata: { reason: "malformed_input" },
      });
      return NextResponse.json({ error: "Data registrasi tidak valid" }, { status: 400 });
    }

    // Sanitize inputs
    const sanitized = {
      nik: typeof body.nik === "string" ? body.nik.trim() : "",
      nama: sanitizeString(body.nama),
      email: sanitizeEmail(body.email),
      alamat: sanitizeString(body.alamat),
      wilayah_id: body.wilayah_id,
      password: typeof body.password === "string" ? body.password : "", // Don't sanitize password (needs original)
      // Public self-registration can only create a warga account.
      role: "warga" as const,
    };

    // Validate inputs
    const errors: string[] = [];

    const nikValidation = validateNik(sanitized.nik);
    if (!nikValidation.valid) errors.push(nikValidation.error!);

    const namaValidation = validateLength(sanitized.nama, 2, 100, "Nama");
    if (!namaValidation.valid) errors.push(namaValidation.error!);

    const emailValidation = validateEmail(sanitized.email);
    if (!emailValidation.valid) errors.push(emailValidation.error!);

    const alamatValidation = validateLength(sanitized.alamat, 5, 255, "Alamat");
    if (!alamatValidation.valid) errors.push(alamatValidation.error!);

    const wilayahValidation = validateWilayahId(sanitized.wilayah_id);
    if (!wilayahValidation.valid) errors.push(wilayahValidation.error!);

    if (errors.length > 0) {
      await logAuthEvent({
        event_type: "register", user_email: sanitized.email, status: "failure",
        error_message: "Registration validation failed", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: 400,
        metadata: { reason: "validation_failed", field_count: errors.length },
      });
      return NextResponse.json(
        {
          error: "Validasi gagal",
          details: errors,
        },
        { status: 400 }
      );
    }

    // Bound expensive Argon2 registration work per email and trusted client IP.
    try {
      const emailKey = crypto.createHash("sha256").update(sanitized.email).digest("hex");
      const ip = getClientIP(req);
      const emailLimit = checkRateLimit(`register:email:${emailKey}`, RateLimits.REGISTER.maxAttempts, RateLimits.REGISTER.windowMs);
      const ipLimit = ip !== "unknown"
        ? checkRateLimit(`register:ip:${ip}`, RateLimits.REGISTER.maxAttempts, RateLimits.REGISTER.windowMs)
        : { allowed: true };
      if (!emailLimit.allowed || !ipLimit.allowed) {
        await logAuthEvent({
          event_type: "register", user_email: sanitized.email, status: "failure",
          error_message: "Registration rate limit exceeded", ...requestContext,
          request_path: new URL(req.url).pathname, http_status: 429,
          metadata: { reason: "rate_limit" },
        });
        return NextResponse.json({ error: "Terlalu banyak percobaan registrasi. Coba lagi nanti." }, { status: 429 });
      }
    } catch {
      await logAuthEvent({
        event_type: "register", user_email: sanitized.email, status: "failure",
        error_message: "Registration rate limiter unavailable", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: 503,
        metadata: { reason: "rate_limiter_unavailable" },
      });
      return NextResponse.json({ error: "Layanan registrasi sementara tidak tersedia" }, { status: 503 });
    }

    const otp = typeof body.otp === "string" ? body.otp.trim() : "";
    if (!otp) {
      try {
        const sent = await sendRegistrationOtp(sanitized.email, sanitized.nama);
        if (!sent.ok) return NextResponse.json({ error: sent.error }, { status: 400 });
      } catch (emailError) {
        console.error("Registration OTP email could not be sent:", emailError);
        return NextResponse.json({ error: "Kode OTP gagal dikirim. Periksa konfigurasi email lalu coba lagi." }, { status: 503 });
      }
      return NextResponse.json({ otpRequired: true, message: "Kode OTP sudah dikirim ke email kamu." });
    }

    // Create the account only after the email OTP has been verified.
    const result = await registerUser(sanitized, otp);

    if (!result.ok) {
      await logAuthEvent({
        event_type: "register", user_email: sanitized.email, status: "failure",
        error_message: "Registration rejected", ...requestContext,
        request_path: new URL(req.url).pathname, http_status: result.status,
        metadata: { reason: "registration_rejected" },
      });
      return NextResponse.json(
        { error: result.error },
        { status: result.status }
      );
    }

    await logAuthEvent({
      event_type: "register", user_id: result.user.id, user_email: result.user.email,
      user_role: result.user.role, status: "success", ...requestContext,
      request_path: new URL(req.url).pathname, http_status: 201,
    });

    return NextResponse.json(
      {
        message: "Registrasi berhasil",
        user: result.user,
      },
      { status: 201 }
    );
  } catch (err) {
    await logAuthEvent({
      event_type: "register", status: "failure", error_message: "Registration processing failed",
      ...requestContext, request_path: new URL(req.url).pathname, http_status: 500,
      metadata: { reason: "server_error" },
    });
    return handleApiError(err, "Register");
  }
}

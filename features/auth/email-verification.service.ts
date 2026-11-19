import crypto from "node:crypto";
import { query } from "@/lib/db";
import { findUserByEmail } from "./auth.queries";
import { isEmailConfigured, sendRegistrationOtp as deliverRegistrationOtp } from "@/lib/email";

const OTP_LIFETIME_MS = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

function hashOtp(email: string, otp: string): string {
  const secret = process.env.EMAIL_OTP_SECRET || process.env.HMAC_KEY;
  if (!secret) throw new Error("EMAIL_OTP_SECRET or HMAC_KEY is required");
  return crypto.createHmac("sha256", secret).update(`${email}:${otp}`).digest("hex");
}

export async function sendRegistrationOtp(email: string, name: string) {
  if (!isEmailConfigured()) {
    return { ok: false as const, error: "Pengiriman email belum dikonfigurasi." };
  }

  const existing = await findUserByEmail(email);
  if (existing.length) return { ok: false as const, error: "Email sudah terdaftar." };

  const otp = crypto.randomInt(100000, 1000000).toString();
  const otpHash = hashOtp(email, otp);
  const expiresAt = new Date(Date.now() + OTP_LIFETIME_MS);
  await query(
    `INSERT INTO email_verifications (email, otp_hash, expires_at, attempts)
     VALUES (?, ?, ?, 0)
     ON DUPLICATE KEY UPDATE otp_hash = VALUES(otp_hash), expires_at = VALUES(expires_at), attempts = 0`,
    [email, otpHash, expiresAt]
  );

  try {
    await deliverRegistrationOtp(email, name, otp);
  } catch (error) {
    await query("DELETE FROM email_verifications WHERE email = ? AND otp_hash = ?", [email, otpHash]);
    throw error;
  }

  return { ok: true as const };
}

export async function verifyRegistrationOtp(email: string, otp: string): Promise<boolean> {
  if (!/^\d{6}$/.test(otp)) return false;
  const result = await query(
    "SELECT otp_hash, expires_at, attempts FROM email_verifications WHERE email = ? LIMIT 1",
    [email]
  );
  const challenge = result.rows[0] as { otp_hash: string; expires_at: Date | string; attempts: number } | undefined;
  if (!challenge || Number(challenge.attempts) >= OTP_MAX_ATTEMPTS || new Date(challenge.expires_at).getTime() <= Date.now()) return false;

  const provided = Buffer.from(hashOtp(email, otp), "hex");
  const stored = Buffer.from(challenge.otp_hash, "hex");
  const matches = provided.length === stored.length && crypto.timingSafeEqual(provided, stored);
  if (!matches) {
    await query(
      "UPDATE email_verifications SET attempts = attempts + 1 WHERE email = ? AND attempts < ?",
      [email, OTP_MAX_ATTEMPTS]
    );
    return false;
  }
  return true;
}

export async function consumeRegistrationOtp(email: string): Promise<void> {
  await query("DELETE FROM email_verifications WHERE email = ?", [email]);
}

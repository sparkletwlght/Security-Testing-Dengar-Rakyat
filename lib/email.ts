const RESEND_ENDPOINT = "https://api.resend.com/emails";

function escapeHtml(value: string): string {
  return value.replace(/[&<>\"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
  })[character]!);
}

export function isEmailConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY && process.env.EMAIL_FROM);
}

async function sendEmail(to: string, subject: string, html: string, text: string): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM;
  if (!apiKey || !from) throw new Error("Resend email is not configured");
  const response = await fetch(RESEND_ENDPOINT, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject, html, text }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`Email provider returned HTTP ${response.status}`);
}

export async function sendSecurityAlertEmail(to: string, subject: string, text: string): Promise<void> {
  const safeText = escapeHtml(text).replace(/\n/g, "<br>");
  await sendEmail(to, subject, `<p>${safeText}</p>`, text);
}

export async function sendRegistrationOtp(to: string, name: string, code: string): Promise<void> {
  const safeName = escapeHtml(name || "pengguna");
  await sendEmail(
    to,
    "Kode verifikasi email Dengar Rakyat",
    `<p>Halo ${safeName},</p><p>Kode OTP untuk memverifikasi email Dengar Rakyat:</p><p style="font-size:28px;font-weight:bold;letter-spacing:6px">${code}</p><p>Kode berlaku selama 10 menit dan hanya dapat digunakan sekali. Jika kamu tidak mendaftar, abaikan email ini.</p>`,
    `Halo ${name || "pengguna"},\n\nKode OTP verifikasi email Dengar Rakyat: ${code}\nKode berlaku 10 menit dan hanya dapat digunakan sekali. Jika kamu tidak mendaftar, abaikan email ini.`
  );
}

export async function sendPasswordResetEmail(to: string, name: string, resetUrl: URL): Promise<void> {
  const safeName = escapeHtml(name || "pengguna");
  const safeUrl = escapeHtml(resetUrl.toString());
  await sendEmail(
    to,
    "Tautan reset password Dengar Rakyat",
    `<p>Halo ${safeName},</p><p>Kami menerima permintaan untuk mengatur ulang password akun Dengar Rakyat.</p><p><a href="${safeUrl}">Atur ulang password</a></p><p>Tautan berlaku selama 15 menit dan hanya dapat digunakan sekali. Jika kamu tidak meminta reset password, abaikan email ini.</p>`,
    `Halo ${name || "pengguna"},\n\nAtur ulang password Dengar Rakyat melalui tautan berikut (berlaku 15 menit dan sekali pakai):\n${resetUrl}\n\nJika kamu tidak meminta reset password, abaikan email ini.`
  );
}

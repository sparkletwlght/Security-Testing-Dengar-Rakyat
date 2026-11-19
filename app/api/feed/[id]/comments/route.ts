import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { query } from "@/lib/db";
import { validateSession } from "@/features/auth/session.service";
import { SESSION_COOKIE_NAME } from "@/lib/cookies";
import { validateCsrfToken } from "@/lib/csrf";
import { checkRateLimit } from "@/lib/rate-limiter";
import { logDataEvent, logSystemEvent } from "@/features/audit/audit.service";

type RouteContext = { params: Promise<{ id: string }> };
async function auth() {
  const sid = (await cookies()).get(SESSION_COOKIE_NAME)?.value;
  if (!sid) return null;
  const session = await validateSession(sid);
  return session.valid && session.user?.role === "warga" ? { sid, user: session.user } : null;
}

export async function GET(_req: Request, context: RouteContext) {
  const current = await auth();
  if (!current) {
    await logSystemEvent({ event_type: "permission_denied", request: _req, http_status: 401, metadata: { reason: "unauthorized_comment_read" } });
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const id = Number((await context.params).id);
  if (!Number.isSafeInteger(id) || id <= 0) return NextResponse.json({ error: "ID tidak valid" }, { status: 400 });
  const exists = await query("SELECT id FROM laporan WHERE id=? AND is_public=1", [id]);
  if (!exists.rows.length) return NextResponse.json({ error: "Postingan tidak ditemukan" }, { status: 404 });
  const rows = await query("SELECT c.id,c.isi,c.created_at FROM laporan_komentar c WHERE c.laporan_id=? ORDER BY c.created_at ASC,c.id ASC LIMIT 100", [id]);
  await logDataEvent({
    event_type: "laporan_read", user_id: current.user.id, user_email: current.user.email,
    user_role: current.user.role, target_type: "laporan_comments", target_id: String(id),
    request: _req, metadata: { result_count: rows.rows.length },
  });
  return NextResponse.json(rows.rows.map((row) => ({ ...row, author: "Warga" })));
}

export async function POST(req: Request, context: RouteContext) {
  const current = await auth();
  if (!current) {
    await logSystemEvent({ event_type: "permission_denied", request: req, http_status: 401, metadata: { reason: "unauthorized_comment_create" } });
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const csrf = validateCsrfToken(req.headers.get("x-csrf-token") || "", current.sid);
  if (!csrf.valid) {
    await logSystemEvent({
      event_type: "csrf_violation", user_id: current.user.id, user_email: current.user.email,
      user_role: current.user.role, request: req, http_status: 403,
      metadata: { reason: "invalid_csrf_token", action: "comment_create" },
    });
    return NextResponse.json({ error: "Sesi keamanan kedaluwarsa. Muat ulang halaman." }, { status: 403 });
  }
  const id = Number((await context.params).id);
  if (!Number.isSafeInteger(id) || id <= 0) return NextResponse.json({ error: "ID tidak valid" }, { status: 400 });
  let body: { isi?: unknown };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Isi komentar tidak valid" }, { status: 400 }); }
  const isi = typeof body?.isi === "string" ? body.isi.trim() : "";
  if (!isi || isi.length > 1000) return NextResponse.json({ error: "Komentar wajib diisi (maksimal 1000 karakter)" }, { status: 400 });
  if (!checkRateLimit(`feed:comment:${current.user.id}`, 20, 60 * 60 * 1000).allowed) {
    await logSystemEvent({
      event_type: "rate_limit_exceeded", user_id: current.user.id, user_email: current.user.email,
      user_role: current.user.role, request: req, http_status: 429,
      metadata: { reason: "comment_rate_limit" },
    });
    return NextResponse.json({ error: "Terlalu banyak komentar. Coba lagi nanti." }, { status: 429 });
  }
  const exists = await query("SELECT id FROM laporan WHERE id=? AND is_public=1", [id]);
  if (!exists.rows.length) return NextResponse.json({ error: "Postingan tidak ditemukan" }, { status: 404 });
  await query("INSERT INTO laporan_komentar(laporan_id,user_id,isi) VALUES(?,?,?)", [id,current.user.id,isi]);
  await logDataEvent({
    event_type: "comment_create", user_id: current.user.id, user_email: current.user.email,
    user_role: current.user.role, target_type: "laporan_comment", target_id: String(id),
    request: req, http_status: 201,
  });
  return NextResponse.json({ message: "Komentar terkirim" }, { status: 201 });
}

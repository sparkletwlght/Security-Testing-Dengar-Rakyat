import { NextResponse } from "next/server";

export function serverError(err: unknown) {
  console.error("[HTTP] Unhandled server error:", err);
  return NextResponse.json(
    { error: "Terjadi kesalahan server", code: "INTERNAL_ERROR" },
    { status: 500 }
  );
}

"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import AuthCard from "@/components/ui/AuthCard";
import FormField from "@/components/ui/FormField";
import Button from "@/components/ui/Button";
import Alert from "@/components/ui/Alert";
import { postJson } from "@/lib/api-client";

export default function LoginForm({ registered }: { registered?: boolean }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [warning, setWarning] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setWarning("");
    setLoading(true);
    const { ok, data } = await postJson("/api/auth/login", { email, password });
    setLoading(false);
    if (typeof data.warning === "string") setWarning(data.warning);
    if (!ok) {
      setError(data.error ?? "Terjadi kesalahan");
      return;
    }
    // A full navigation makes the browser send the newly-set HttpOnly cookie
    // on the first protected page request.
    window.location.assign("/dashboard");
  }

  return (
    <AuthCard title="Masuk" subtitle="Dengar Rakyat! — Lapor, dilacak, ditindaklanjuti">
      <form onSubmit={handleSubmit} className="space-y-4">
        {registered && <Alert type="success">Registrasi berhasil, silakan masuk.</Alert>}
        {error && <Alert type="error">{error}</Alert>}
        {warning && <Alert type="warning">{warning}</Alert>}

        <FormField id="email" label="Email" type="text" value={email} onChange={(e) => setEmail(e.target.value)} />
        <FormField id="password" label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />

        <Button type="submit" disabled={loading}>
          {loading ? "Memproses..." : "Masuk"}
        </Button>
      </form>

      <div className="flex justify-between text-sm">
        <Link href="/forgot-password" className="text-blue-600">
          Lupa password?
        </Link>
        <Link href="/register" className="text-blue-600">
          Daftar akun
        </Link>
      </div>
    </AuthCard>
  );
}

"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, Cloud, Mail } from "lucide-react";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to request a password reset.");
      setMessage(data.message || "If the account exists, a password reset link will be sent.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  return <main className="flex min-h-screen items-center justify-center bg-[#f5f7fb] px-4 py-12">
    <section className="w-full max-w-md rounded-3xl border border-slate-200 bg-white p-8 shadow-xl shadow-slate-900/5 sm:p-10">
      <div className="mb-8 flex items-center gap-3"><span className="grid h-11 w-11 place-items-center rounded-2xl bg-blue-700 text-white"><Cloud size={22}/></span><span className="text-lg font-semibold text-slate-950">Nexora <span className="text-blue-700">Control</span></span></div>
      <p className="text-sm font-medium text-blue-700">Account recovery</p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">Forgot your password?</h1>
      <p className="mt-2 text-sm leading-6 text-slate-500">Enter the email address associated with your Nexora account. If it exists, we’ll send a secure reset link.</p>
      <form onSubmit={submit} className="mt-7 space-y-4">
        <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-600">Email address</span><span className="relative block"><Mail className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required type="email" maxLength={254} autoComplete="email" className="w-full rounded-xl border border-slate-200 bg-white py-3 pl-11 pr-4 text-sm text-slate-900 outline-none placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10" placeholder="you@company.com" value={email} onChange={event=>setEmail(event.target.value)}/></span></label>
        {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700">{error}</p>}
        {message && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-800">{message}</p>}
        <button disabled={busy} className="w-full rounded-xl bg-blue-700 py-3.5 text-sm font-semibold text-white transition hover:bg-blue-800 disabled:opacity-60">{busy ? "Sending…" : "Send reset link"}</button>
      </form>
      <Link href="/login" className="mt-7 inline-flex items-center gap-2 text-sm font-medium text-slate-600 hover:text-slate-950"><ArrowLeft size={16}/> Back to sign in</Link>
    </section>
  </main>;
}

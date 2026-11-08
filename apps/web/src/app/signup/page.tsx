"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, Building2, Cloud, Eye, EyeOff, LockKeyhole, Mail, UserRound, ShieldCheck } from "lucide-react";

export default function SignupPage() {
  const router = useRouter();
  const [form, setForm] = useState({ name: "", organizationName: "", email: "", password: "", confirmPassword: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function update(field: keyof typeof form, value: string) {
    setForm(current => ({ ...current, [field]: value }));
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (form.password !== form.confirmPassword) {
      setError("The passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: form.name, organizationName: form.organizationName, email: form.email, password: form.password }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to create your account.");
      router.replace("/customer");
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  const inputClass = "w-full rounded-xl border border-slate-200 bg-white py-3 pl-11 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10";

  return <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#f4f6fb] px-4 py-10">
    <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-blue-200/40 blur-3xl"/>
    <div className="pointer-events-none absolute -bottom-40 -right-20 h-96 w-96 rounded-full bg-indigo-200/40 blur-3xl"/>
    <section className="relative grid w-full max-w-5xl overflow-hidden rounded-[28px] border border-slate-200 bg-white shadow-2xl shadow-slate-900/5 lg:grid-cols-[1.02fr_0.98fr]">
      <aside className="hidden flex-col justify-between bg-[#101a2d] p-10 text-white lg:flex">
        <div>
          <Link href="/login" className="flex items-center gap-3"><span className="grid h-11 w-11 place-items-center rounded-2xl bg-blue-600"><Cloud size={23}/></span><span className="text-lg font-semibold tracking-tight">Nexora <span className="text-blue-300">Control</span></span></Link>
          <div className="mt-24"><p className="text-xs font-semibold uppercase tracking-[0.22em] text-blue-300">Start with Nexora</p><h1 className="mt-4 text-4xl font-semibold leading-tight tracking-tight">Your hosting workspace starts here.</h1><p className="mt-5 max-w-sm text-sm leading-6 text-slate-400">Create one account to access the websites, domains and services assigned to you by your hosting provider.</p></div>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400"><ShieldCheck size={15} className="text-emerald-400"/> Private customer workspace</div>
      </aside>
      <div className="p-7 sm:p-10 lg:p-12">
        <div className="mb-8 flex items-center gap-3 lg:hidden"><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Cloud size={21}/></span><span className="font-semibold text-slate-950">Nexora <span className="text-blue-700">Control</span></span></div>
        <p className="text-sm font-semibold text-blue-700">Customer registration</p>
        <h2 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Create your account</h2>
        <p className="mt-2 text-sm leading-6 text-slate-500">Register your login details. Your hosting provider can then assign a hosting account and plan.</p>
        <form onSubmit={submit} className="mt-7 space-y-4">
          <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Full name</span><span className="relative block"><UserRound className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required maxLength={100} autoComplete="name" className={inputClass} placeholder="Your full name" value={form.name} onChange={event=>update("name",event.target.value)}/></span></label>
          <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Company or account name</span><span className="relative block"><Building2 className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required maxLength={120} autoComplete="organization" className={inputClass} placeholder="Company or account name" value={form.organizationName} onChange={event=>update("organizationName",event.target.value)}/></span></label>
          <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Email address</span><span className="relative block"><Mail className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required type="email" maxLength={254} autoComplete="email" className={inputClass} placeholder="you@company.com" value={form.email} onChange={event=>update("email",event.target.value)}/></span></label>
          <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Password</span><span className="relative block"><LockKeyhole className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required minLength={12} maxLength={128} type={showPassword ? "text" : "password"} autoComplete="new-password" className={inputClass + " pr-12"} placeholder="At least 12 characters" value={form.password} onChange={event=>update("password",event.target.value)}/><button type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={()=>setShowPassword(value=>!value)} className="absolute right-3.5 top-3 text-slate-400 hover:text-slate-700">{showPassword ? <EyeOff size={18}/> : <Eye size={18}/>}</button></span></label>
          <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Confirm password</span><input required minLength={12} maxLength={128} type="password" autoComplete="new-password" className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10" placeholder="Enter your password again" value={form.confirmPassword} onChange={event=>update("confirmPassword",event.target.value)}/></label>
          {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700">{error}</p>}
          <button disabled={busy} className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue-700 py-3.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60">{busy ? "Creating account…" : "Create customer account"}{!busy && <ArrowRight size={17}/>}</button>
        </form>
        <div className="mt-6 border-t border-slate-100 pt-5 text-center"><p className="text-sm text-slate-500">Already have an account? <Link href="/login" className="font-semibold text-blue-700 hover:text-blue-800">Sign in</Link></p></div>
        <p className="mt-5 text-center text-[11px] leading-5 text-slate-400">Registration does not grant access to server administration or unassigned hosting resources.</p>
      </div>
    </section>
  </main>;
}

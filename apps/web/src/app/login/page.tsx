"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Cloud, Eye, EyeOff, LockKeyhole, Mail, Building2, UserRound } from "lucide-react";

type Mode = "login" | "register";
type WorkspaceChoice = { id: string; name: string; slug: string; role: string };

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [workspaces, setWorkspaces] = useState<WorkspaceChoice[]>([]);
  const [organizationId, setOrganizationId] = useState("");
  const [form, setForm] = useState({ email: "", password: "", name: "", organizationName: "" });

  function update(field: keyof typeof form, value: string) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch(`/api/auth/${mode}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(mode === "login"
          ? { email: form.email, password: form.password, ...(organizationId ? { organizationId } : {}) }
          : { email: form.email, password: form.password, name: form.name, organizationName: form.organizationName }),
      });
      const data = await response.json();
      if (!response.ok && data.requiresOrganization && Array.isArray(data.organizations)) {
        setWorkspaces(data.organizations);
        setOrganizationId(data.organizations[0]?.id || "");
        setMessage(data.message || "Choose a workspace to continue.");
        return;
      }
      if (!response.ok) throw new Error(data.message || "Authentication failed");
      setWorkspaces([]);
      // New registrations enter the customer portal. Existing users with an
      // active hosting-account assignment also return to the customer portal;
      // workspace administrators retain the WHM landing page.
      const destination = mode === "register" || data.customerAccess || data.role === "MEMBER"
        ? "/customer"
        : "/";
      router.replace(destination);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  const inputClass = "w-full rounded-xl border border-slate-200 bg-white py-3 pl-11 pr-4 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10";

  return <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#f5f7fb] px-4 py-12">
    <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-blue-200/40 blur-3xl"/>
    <div className="pointer-events-none absolute -bottom-40 -right-20 h-96 w-96 rounded-full bg-indigo-200/40 blur-3xl"/>
    <section className="relative grid w-full max-w-5xl overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-2xl shadow-slate-900/5 lg:grid-cols-[1fr_1.05fr]">
      <div className="hidden flex-col justify-between bg-slate-950 p-10 text-white lg:flex">
        <div><div className="flex items-center gap-3"><span className="grid h-11 w-11 place-items-center rounded-2xl bg-blue-600"><Cloud size={23}/></span><span className="text-lg font-semibold tracking-tight">Nexora <span className="text-blue-300">Control</span></span></div>
          <div className="mt-24"><p className="text-xs font-semibold uppercase tracking-[0.24em] text-blue-300">Infrastructure control plane</p><h1 className="mt-4 text-4xl font-semibold leading-tight tracking-tight">Your servers.<br/>Your platform.<br/><span className="text-blue-300">One control plane.</span></h1><p className="mt-5 max-w-sm text-sm leading-6 text-slate-400">Manage hosting infrastructure, customer workspaces and server operations from a single secure console.</p></div>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500"><LockKeyhole size={14}/> Protected workspace access</div>
      </div>
      <div className="p-7 sm:p-10 lg:p-12">
        <div className="mb-9 flex items-center gap-3 lg:hidden"><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Cloud size={21}/></span><span className="font-semibold">Nexora <span className="text-blue-700">Control</span></span></div>
        <p className="text-sm font-medium text-blue-700">Welcome to Nexora</p>
        <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">{mode === "login" ? "Sign in to Nexora Control" : "Create your customer account"}</h2>
        <p className="mt-2 text-sm text-slate-500">{mode === "login" ? "Enter your account details to continue." : "Register your Nexora login. Your hosting provider can assign your account access."}</p>
        <div className="mt-7 grid grid-cols-2 rounded-xl bg-slate-100 p-1 text-sm">
          <button type="button" onClick={() => { setMode("login"); setError(""); setMessage(""); setWorkspaces([]); setOrganizationId(""); }} className={`rounded-lg py-2.5 font-medium transition ${mode === "login" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500"}`}>Sign in</button>
          <button type="button" onClick={() => { setMode("register"); setError(""); setMessage(""); setWorkspaces([]); setOrganizationId(""); }} className={`rounded-lg py-2.5 font-medium transition ${mode === "register" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500"}`}>Create account</button>
        </div>
        <form onSubmit={submit} className="mt-6 space-y-4">
          {mode === "register" && <>
            <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-600">Your name</span><span className="relative block"><UserRound className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required maxLength={100} autoComplete="name" className={inputClass} placeholder="Full name" value={form.name} onChange={(e) => update("name", e.target.value)}/></span></label>
            <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-600">Company or account name</span><span className="relative block"><Building2 className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required maxLength={120} className={inputClass} placeholder="Company or account name" value={form.organizationName} onChange={(e) => update("organizationName", e.target.value)}/></span></label>
          </>}
          <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-600">Email address</span><span className="relative block"><Mail className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required type="email" maxLength={254} autoComplete="email" className={inputClass} placeholder="you@company.com" value={form.email} onChange={(e) => update("email", e.target.value)}/></span></label>
          <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-600">Password</span><span className="relative block"><LockKeyhole className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required minLength={12} maxLength={128} type={showPassword ? "text" : "password"} autoComplete={mode === "login" ? "current-password" : "new-password"} className={inputClass + " pr-12"} placeholder="At least 12 characters" value={form.password} onChange={(e) => update("password", e.target.value)}/><button type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-3 text-slate-400 hover:text-slate-700">{showPassword ? <EyeOff size={18}/> : <Eye size={18}/>}</button></span></label>
          {mode === "login" && workspaces.length > 0 && <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-600">Workspace</span><select required value={organizationId} onChange={e => setOrganizationId(e.target.value)} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10">{workspaces.map(workspace => <option key={workspace.id} value={workspace.id}>{workspace.name} · {workspace.role}</option>)}</select></label>}
          {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700">{error}</p>}
          {message && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-800">{message}</p>}
          <button disabled={busy} className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue-700 py-3.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60">{busy ? "Please wait…" : mode === "login" ? "Sign in securely" : "Create customer account"}{!busy && <ArrowRight size={17}/>}</button>
        </form>
        <p className="mt-6 text-center text-xs leading-5 text-slate-400">By continuing, you agree to use this infrastructure platform responsibly. Keep your credentials private.</p>
      </div>
    </section>
  </main>;
}

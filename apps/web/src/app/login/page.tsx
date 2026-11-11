"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, Cloud, Eye, EyeOff, LockKeyhole, Mail, ShieldCheck, Smartphone } from "lucide-react";

type WorkspaceChoice = { id: string; name: string; slug: string; role: string };
type MfaChallenge = { challengeId: string; expiresAt: string };

export default function LoginPage() {
  const router = useRouter();
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [workspaces, setWorkspaces] = useState<WorkspaceChoice[]>([]);
  const [organizationId, setOrganizationId] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // MFA challenge state: when the API returns mfaRequired=true, the password
  // form is replaced by the 6-digit code form. The challengeId is what the
  // dashboard submits back to /api/auth/login/mfa — it is the only handle
  // that authorizes MFA completion, and it is single-use + 10-minute expiry
  // + 5-attempt cap (enforced by the API).
  const [mfaChallenge, setMfaChallenge] = useState<MfaChallenge | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password, ...(organizationId ? { organizationId } : {}) }),
      });
      const data = await response.json();
      if (!response.ok && data.requiresOrganization && Array.isArray(data.organizations)) {
        setWorkspaces(data.organizations);
        setOrganizationId(data.organizations[0]?.id || "");
        setMessage(data.message || "Choose the workspace you want to open.");
        return;
      }
      // MFA challenge: the API verified the password but the user has an
      // active TOTP factor, so it returned a challengeId instead of a
      // session. Switch to the MFA code form. No cookie was set by the
      // proxy because the response had no accessToken.
      if (response.ok && data.mfaRequired && typeof data.challengeId === "string") {
        setMfaChallenge({ challengeId: data.challengeId, expiresAt: data.expiresAt });
        setMessage(data.message || "Enter the 6-digit code from your authenticator app.");
        setMfaCode("");
        return;
      }
      if (!response.ok) throw new Error(data.message || "Unable to sign in.");
      const selectedPlanId = new URLSearchParams(window.location.search).get("planId");
      const destination = data.platformRole ? "/" : selectedPlanId ? `/store?planId=${encodeURIComponent(selectedPlanId)}` : "/customer";
      router.replace(destination);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  async function submitMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!mfaChallenge) return;
    const code = mfaCode.trim();
    if (!/^\d{6}$/.test(code)) {
      setError("Enter the 6-digit code from your authenticator app.");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch("/api/auth/login/mfa", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ challengeId: mfaChallenge.challengeId, code }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to verify the code.");
      // Successful MFA: the proxy set the session cookie from data.accessToken.
      // Clear the challenge state so a re-login attempt starts fresh.
      setMfaChallenge(null);
      setMfaCode("");
      setPassword("");
      const selectedPlanId = new URLSearchParams(window.location.search).get("planId");
      const destination = data.platformRole ? "/" : selectedPlanId ? `/store?planId=${encodeURIComponent(selectedPlanId)}` : "/customer";
      router.replace(destination);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to verify the code.");
    } finally {
      setBusy(false);
    }
  }

  function cancelMfa() {
    setMfaChallenge(null);
    setMfaCode("");
    setError("");
    setMessage("");
  }

  const inputClass = "w-full rounded-xl border border-slate-200 bg-white py-3 pl-11 pr-12 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10";
  const mfaInputClass = "w-full rounded-xl border border-slate-200 bg-white py-3 pl-12 pr-4 text-center text-lg tracking-[0.4em] font-medium text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10";

  return <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#f4f6fb] px-4 py-10">
    <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-blue-200/40 blur-3xl"/>
    <div className="pointer-events-none absolute -bottom-40 -right-20 h-96 w-96 rounded-full bg-indigo-200/40 blur-3xl"/>
    <section className="relative grid w-full max-w-5xl overflow-hidden rounded-[28px] border border-slate-200 bg-white shadow-2xl shadow-slate-900/5 lg:grid-cols-[1.02fr_0.98fr]">
      <aside className="hidden flex-col justify-between bg-[#101a2d] p-10 text-white lg:flex">
        <div>
          <Link href="/" className="flex items-center gap-3"><span className="grid h-11 w-11 place-items-center rounded-2xl bg-blue-600"><Cloud size={23}/></span><span className="text-lg font-semibold tracking-tight">Nexora <span className="text-blue-300">Control</span></span></Link>
          <div className="mt-24"><p className="text-xs font-semibold uppercase tracking-[0.22em] text-blue-300">Hosting control panel</p><h1 className="mt-4 text-4xl font-semibold leading-tight tracking-tight">Everything your hosting needs.<br/><span className="text-blue-300">One secure place.</span></h1><p className="mt-5 max-w-sm text-sm leading-6 text-slate-400">Manage websites, domains, databases and hosting services through your Nexora customer workspace.</p></div>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400"><ShieldCheck size={15} className="text-emerald-400"/> Secure account access</div>
      </aside>
      <div className="p-7 sm:p-10 lg:p-12">
        <div className="mb-8 flex items-center gap-3 lg:hidden"><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Cloud size={21}/></span><span className="font-semibold text-slate-950">Nexora <span className="text-blue-700">Control</span></span></div>
        {mfaChallenge ? (
          <>
            <p className="text-sm font-semibold text-blue-700">Verification code</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Enter your MFA code</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">Your password was accepted. Complete sign-in with the 6-digit code from your authenticator app.</p>
            <form onSubmit={submitMfa} className="mt-8 space-y-5">
              <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Authenticator code</span><span className="relative block"><Smartphone className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={mfaCode} onChange={event => setMfaCode(event.target.value.replace(/\D/g, ""))} className={mfaInputClass} placeholder="••••••" autoFocus/></span></label>
              {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700">{error}</p>}
              {message && <p role="status" className="rounded-xl border border-blue-200 bg-blue-50 px-3 py-2.5 text-sm text-blue-800">{message}</p>}
              <div className="flex flex-wrap gap-2">
                <button disabled={busy} className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-blue-700 py-3.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60">{busy ? "Verifying…" : "Verify and sign in"}{!busy && <ArrowRight size={17}/>}</button>
                <button type="button" onClick={cancelMfa} className="rounded-xl border border-slate-200 px-4 py-3.5 text-sm font-semibold text-slate-600 hover:bg-slate-50">Back</button>
              </div>
            </form>
            <p className="mt-7 text-center text-[11px] leading-5 text-slate-400">Your authenticator code refreshes every 30 seconds. After 5 wrong attempts you will need to sign in again to receive a new challenge.</p>
          </>
        ) : (
          <>
            <p className="text-sm font-semibold text-blue-700">Welcome back</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Sign in to your account</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">Use your Nexora account credentials to continue to your workspace.</p>
            <form onSubmit={submit} className="mt-8 space-y-5">
              <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Email address</span><span className="relative block"><Mail className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required type="email" maxLength={254} autoComplete="email" className={inputClass} placeholder="you@company.com" value={email} onChange={event=>setEmail(event.target.value)}/></span></label>
              <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Password</span><span className="relative block"><LockKeyhole className="absolute left-3.5 top-3.5 text-slate-400" size={17}/><input required maxLength={128} type={showPassword ? "text" : "password"} autoComplete="current-password" className={inputClass} placeholder="Enter your password" value={password} onChange={event=>setPassword(event.target.value)}/><button type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={()=>setShowPassword(value=>!value)} className="absolute right-3.5 top-3 text-slate-400 hover:text-slate-700">{showPassword ? <EyeOff size={18}/> : <Eye size={18}/>}</button></span></label>
              <div className="flex justify-end"><Link href="/forgot-password" className="text-sm font-semibold text-blue-700 hover:text-blue-800">Forgot password?</Link></div>
              {workspaces.length > 0 && <label className="block"><span className="mb-2 block text-xs font-semibold text-slate-700">Choose workspace</span><select required value={organizationId} onChange={event=>setOrganizationId(event.target.value)} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10">{workspaces.map(workspace=><option key={workspace.id} value={workspace.id}>{workspace.name} · {workspace.role}</option>)}</select></label>}
              {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700">{error}</p>}
              {message && <p role="status" className="rounded-xl border border-blue-200 bg-blue-50 px-3 py-2.5 text-sm text-blue-800">{message}</p>}
              <button disabled={busy} className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue-700 py-3.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60">{busy ? "Signing in…" : "Sign in securely"}{!busy && <ArrowRight size={17}/>}</button>
            </form>
            <div className="mt-7 border-t border-slate-100 pt-6 text-center"><p className="text-sm text-slate-500">New to Nexora? <Link href={new URLSearchParams(typeof window !== "undefined" ? window.location.search : "").get("planId") ? `/signup?planId=${encodeURIComponent(new URLSearchParams(window.location.search).get("planId")!)}` : "/signup"} className="font-semibold text-blue-700 hover:text-blue-800">Create an account</Link></p></div>
            <p className="mt-7 text-center text-[11px] leading-5 text-slate-400">Your account only sees hosting resources assigned to it by the platform administrator.</p>
          </>
        )}
      </div>
    </section>
  </main>;
}

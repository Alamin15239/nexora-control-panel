"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { CheckCircle2, KeyRound, Loader2, PowerOff, ShieldCheck, Smartphone } from "lucide-react";

type EnrollmentResponse = {
  otpauthUri?: string;
  otpauth?: string;
  secret?: string;
  message?: string;
};

type MfaStatus = {
  enrolled: boolean;
};

export default function MfaEnrollment() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [enrollment, setEnrollment] = useState<EnrollmentResponse | null>(null);
  const [enrollBusy, setEnrollBusy] = useState(false);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [disableBusy, setDisableBusy] = useState(false);
  const [verifyCode, setVerifyCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const loadStatus = useCallback(async () => {
    setLoadingStatus(true); setError("");
    try {
      const response = await fetch("/api/control/auth/me", { cache: "no-store" });
      const data = await response.json();
      if (response.ok) {
        setStatus({ enrolled: Boolean(data.mfaEnrolled ?? data.mfaEnabled ?? false) });
      } else {
        setStatus({ enrolled: false });
      }
    } catch {
      setStatus({ enrolled: false });
    } finally { setLoadingStatus(false); }
  }, []);

  useEffect(() => { void loadStatus(); }, [loadStatus]);

  async function enroll() {
    setEnrollBusy(true); setError(""); setNotice(""); setEnrollment(null);
    try {
      const response = await fetch("/api/control/auth/mfa/enroll", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({}) });
      const data: EnrollmentResponse = await response.json();
      if (!response.ok) throw new Error((data as unknown as { message?: string }).message || "Unable to start MFA enrollment.");
      setEnrollment(data);
      setNotice(data.message || "Scan the QR code or enter the secret into your authenticator app.");
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to start MFA enrollment."); }
    finally { setEnrollBusy(false); }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!/^\d{6}$/.test(verifyCode.trim())) { setError("Enter the 6-digit code from your authenticator app."); return; }
    setVerifyBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/auth/mfa/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: verifyCode.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to verify the MFA code.");
      setNotice(data.message || "MFA verified. Multi-factor authentication is now active for your account.");
      setEnrollment(null);
      setVerifyCode("");
      setStatus({ enrolled: true });
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to verify the MFA code."); }
    finally { setVerifyBusy(false); }
  }

  async function disable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!/^\d{6}$/.test(disableCode.trim())) { setError("Enter your current 6-digit MFA code to disable."); return; }
    setDisableBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/auth/mfa/disable", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: disableCode.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to disable MFA.");
      setNotice(data.message || "MFA disabled. Your account is now protected by password only.");
      setDisableCode("");
      setStatus({ enrolled: false });
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to disable MFA."); }
    finally { setDisableBusy(false); }
  }

  const otpauthUri = enrollment?.otpauthUri || enrollment?.otpauth || "";
  const secret = enrollment?.secret || "";

  return <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
    <div className="flex items-start gap-3 border-b border-slate-100 px-5 py-4">
      <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><ShieldCheck size={20}/></span>
      <div className="min-w-0">
        <h2 className="font-semibold">Multi-factor authentication</h2>
        <p className="mt-1 text-xs text-slate-500">Add a time-based one-time password (TOTP) authenticator to protect your workspace sign-in.</p>
      </div>
      {!loadingStatus && status && (
        <span className={"ml-auto rounded-full px-2.5 py-1 text-xs font-medium " + (status.enrolled ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-800")}>
          {status.enrolled ? "Enabled" : "Not configured"}
        </span>
      )}
    </div>

    <div className="space-y-5 px-5 py-5">
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-800">{notice}</p>}

      {loadingStatus ? (
        <div className="flex items-center gap-2 text-sm text-slate-500"><Loader2 size={16} className="animate-spin"/> Checking MFA status…</div>
      ) : status?.enrolled ? (
        <form onSubmit={disable} className="space-y-3">
          <div className="flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50/60 px-3 py-2.5 text-sm text-emerald-800"><CheckCircle2 size={16} className="mt-0.5"/><span>MFA is active on your account. Enter your current 6-digit code to disable it.</span></div>
          <label className="block"><span className="mb-1.5 block text-xs font-semibold text-slate-700">Current MFA code</span>
            <input type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={disableCode} onChange={event => setDisableCode(event.target.value.replace(/\D/g, ""))} placeholder="123456" className="w-48 rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10"/>
          </label>
          <button type="submit" disabled={disableBusy} className="inline-flex items-center gap-2 rounded-xl border border-red-200 px-4 py-2.5 text-sm font-semibold text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"><PowerOff size={16}/>{disableBusy ? "Disabling…" : "Disable MFA"}</button>
        </form>
      ) : enrollment ? (
        <div className="space-y-4">
          <div className="rounded-xl border border-blue-100 bg-gradient-to-br from-blue-50/80 to-indigo-50/50 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-blue-800"><Smartphone size={16}/> Add to your authenticator app</div>
            <p className="mt-2 text-xs leading-5 text-slate-600">Scan the otpauth URI below with Google Authenticator, 1Password, Authy, or any TOTP app. Then enter the 6-digit code the app shows.</p>
            {otpauthUri && <p className="mt-3 break-all rounded-lg bg-white px-3 py-2 font-mono text-[11px] text-slate-700">{otpauthUri}</p>}
            {secret && <div className="mt-2"><span className="text-[11px] font-semibold text-slate-500">Secret (manual entry):</span><p className="mt-1 break-all rounded-lg bg-white px-3 py-2 font-mono text-[11px] tracking-wide text-slate-700">{secret}</p></div>}
          </div>
          <form onSubmit={verify} className="space-y-3">
            <label className="block"><span className="mb-1.5 block text-xs font-semibold text-slate-700">Verification code</span>
              <input type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={verifyCode} onChange={event => setVerifyCode(event.target.value.replace(/\D/g, ""))} placeholder="123456" className="w-48 rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10"/>
            </label>
            <div className="flex flex-wrap gap-2">
              <button type="submit" disabled={verifyBusy} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"><KeyRound size={16}/>{verifyBusy ? "Verifying…" : "Verify and enable"}</button>
              <button type="button" onClick={() => { setEnrollment(null); setVerifyCode(""); }} className="rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-600 hover:bg-slate-50">Cancel</button>
            </div>
          </form>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm leading-6 text-slate-600">MFA is not yet configured for your account. Enroll a TOTP authenticator to require a one-time code at every sign-in.</p>
          <button onClick={() => void enroll()} disabled={enrollBusy} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"><ShieldCheck size={16}/>{enrollBusy ? "Starting enrollment…" : "Start MFA enrollment"}</button>
        </div>
      )}
    </div>
  </section>;
}

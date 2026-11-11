"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Globe, Monitor, RefreshCw, Trash2 } from "lucide-react";

type Session = {
  id: string;
  userAgent: string | null;
  ipAddress: string | null;
  issuedAt: string;
  expiresAt: string | null;
  isCurrent?: boolean;
  browser?: string | null;
};

type SessionsResponse = {
  sessions?: Session[];
  items?: Session[];
};

function describeBrowser(userAgent: string | null): string {
  if (!userAgent) return "Unknown device";
  if (/edg/i.test(userAgent)) return "Microsoft Edge";
  if (/opr\//i.test(userAgent) || /opera/i.test(userAgent)) return "Opera";
  if (/chrome/i.test(userAgent)) return "Chrome";
  if (/firefox/i.test(userAgent)) return "Firefox";
  if (/safari/i.test(userAgent)) return "Safari";
  return "Web browser";
}

function describePlatform(userAgent: string | null): string {
  if (!userAgent) return "";
  if (/iphone|ipad|ios/i.test(userAgent)) return "iOS";
  if (/android/i.test(userAgent)) return "Android";
  if (/mac os/i.test(userAgent)) return "macOS";
  if (/windows/i.test(userAgent)) return "Windows";
  if (/linux/i.test(userAgent)) return "Linux";
  return "";
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const response = await fetch("/api/control/sessions", { cache: "no-store" });
      const data: SessionsResponse = await response.json();
      if (!response.ok) throw new Error((data as unknown as { message?: string }).message || "Unable to load active sessions.");
      setSessions(data.sessions ?? data.items ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load active sessions."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function revoke(session: Session) {
    if (!window.confirm("Revoke this session? The device will need to sign in again.")) return;
    setBusyId(session.id); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to revoke session.");
      setNotice(data.message || "Session revoked.");
      setSessions(current => current.filter(item => item.id !== session.id));
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to revoke session."); }
    finally { setBusyId(""); }
  }

  const activeCount = sessions.filter(s => !s.expiresAt || new Date(s.expiresAt).getTime() > Date.now()).length;

  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85"><div className="mx-auto flex max-w-[1200px] items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3">
        <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
        <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Monitor size={20}/></span>
        <div><p className="font-semibold">Active sessions</p><p className="text-xs text-slate-500">Nexora Control / Access &amp; security</p></div>
      </div>
      <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1200px] space-y-6 px-6 py-8">
      <div>
        <p className="text-sm font-medium text-blue-700">Workspace sessions</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">Active sessions</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">Review every device signed into this workspace. Revoke a session to immediately sign out that device. Your current session is highlighted.</p>
      </div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
          <div><h2 className="font-semibold">Signed-in devices</h2><p className="mt-1 text-xs text-slate-500">Sessions include browser, IP address, and validity window.</p></div>
          <span className="rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-600">{activeCount} active</span>
        </div>
        {loading ? <div className="p-10 text-center text-sm text-slate-500">Loading sessions…</div> : sessions.length === 0 ? <div className="p-12 text-center"><Globe size={30} className="mx-auto text-slate-300"/><p className="mt-3 text-sm text-slate-500">No active sessions found.</p></div> : (
          <div className="divide-y divide-slate-100">
            {sessions.map(session => {
              const browser = session.browser || describeBrowser(session.userAgent);
              const platform = describePlatform(session.userAgent);
              const expired = session.expiresAt ? new Date(session.expiresAt).getTime() <= Date.now() : false;
              return <div key={session.id} className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold text-slate-800">{browser}{platform && <span className="text-slate-500"> · {platform}</span>}</p>
                    {session.isCurrent && <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700">Current</span>}
                    {expired && !session.isCurrent && <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-500">Expired</span>}
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-slate-500">{session.ipAddress || "IP not recorded"}</p>
                  <p className="mt-1 text-[11px] text-slate-400">Issued {formatDate(session.issuedAt)} · Expires {formatDate(session.expiresAt)}</p>
                </div>
                <button disabled={session.isCurrent || busyId === session.id} onClick={() => void revoke(session)} className="inline-flex items-center gap-2 rounded-lg border border-red-200 px-3 py-2 text-xs font-semibold text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50"><Trash2 size={14}/>{busyId === session.id ? "Revoking…" : "Revoke"}</button>
              </div>;
            })}
          </div>
        )}
      </section>
      <p className="text-xs leading-5 text-slate-400">Revoking a session invalidates the cookie tied to that device. Your current session cannot be revoked from here — sign out instead to end it.</p>
    </section>
  </main>;
}

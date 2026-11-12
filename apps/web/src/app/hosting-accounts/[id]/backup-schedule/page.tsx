"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, HardDrive, RefreshCw, Save } from "lucide-react";

type BackupSchedule = {
  frequency: string;
  retentionCount: number;
};

const FREQUENCIES = [
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
  { value: "disabled", label: "Disabled" },
];

const defaultSchedule: BackupSchedule = { frequency: "disabled", retentionCount: 7 };

export default function HostingAccountBackupSchedulePage() {
  const params = useParams<{ id: string }>();
  const accountId = params?.id ?? "";
  const [schedule, setSchedule] = useState<BackupSchedule>(defaultSchedule);
  const [original, setOriginal] = useState<BackupSchedule>(defaultSchedule);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    if (!accountId) return;
    setLoading(true); setError("");
    try {
      const response = await fetch(`/api/control/hosting-accounts/${encodeURIComponent(accountId)}/backup-schedule`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load backup schedule.");
      const next: BackupSchedule = {
        frequency: data.frequency || defaultSchedule.frequency,
        retentionCount: Number(data.retentionCount ?? defaultSchedule.retentionCount),
      };
      setSchedule(next);
      setOriginal(next);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load backup schedule."); }
    finally { setLoading(false); }
  }, [accountId]);

  useEffect(() => { void load(); }, [load]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/hosting-accounts/${encodeURIComponent(accountId)}/backup-schedule`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(schedule),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to save backup schedule.");
      setNotice(data.message || "Backup schedule updated for this hosting account.");
      setOriginal(schedule);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to save backup schedule."); }
    finally { setSaving(false); }
  }

  const dirty = JSON.stringify(schedule) !== JSON.stringify(original);

  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85"><div className="mx-auto flex max-w-[1200px] items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3">
        <Link href="/hosting-accounts" aria-label="Back to hosting accounts" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
        <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><HardDrive size={20}/></span>
        <div><p className="font-semibold">Backup schedule</p><p className="text-xs text-slate-500">Nexora Control / Hosting accounts</p></div>
      </div>
      <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1200px] space-y-6 px-6 py-8">
      <div>
        <p className="text-sm font-medium text-blue-700">Hosting account backups</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">Backup schedule</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">Define how often this hosting account is backed up and how many restore points are retained. Backups run on the connected hosting node and are stored in the configured object storage destination.</p>
      </div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      {loading ? <div className="rounded-2xl border border-slate-200 bg-white p-10 text-center text-sm text-slate-500 shadow-sm">Loading backup schedule…</div> : (
        <form onSubmit={save} className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Schedule policy</h2><p className="mt-1 text-xs text-slate-500">Applies to the account&apos;s files and databases.</p></div>
          <div className="grid gap-5 px-5 py-6 md:grid-cols-2">
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-700">Frequency</span>
              <select value={schedule.frequency} onChange={event => setSchedule(s => ({ ...s, frequency: event.target.value }))} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10">
                {FREQUENCIES.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
              </select>
              <span className="mt-1 block text-[11px] text-slate-400">Daily, weekly, monthly, or disabled.</span>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-700">Retention count</span>
              <input type="number" min={1} max={52} step={1} value={schedule.retentionCount} onChange={event => setSchedule(s => ({ ...s, retentionCount: Number(event.target.value) || 1 }))} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10"/>
              <span className="mt-1 block text-[11px] text-slate-400">Range 1–52 restore points retained.</span>
            </label>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 bg-slate-50/50 px-5 py-4">
            <span className="text-xs text-slate-500">{dirty ? "You have unsaved changes." : "All changes saved."}</span>
            <button type="submit" disabled={saving || !dirty} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"><Save size={16}/>{saving ? "Saving…" : "Save schedule"}</button>
          </div>
        </form>
      )}
      <p className="text-xs leading-5 text-slate-400">When frequency is disabled, no scheduled backups run for this account. Manual backups from the Backups dashboard remain available.</p>
    </section>
  </main>;
}

"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, ArrowLeft, CheckCircle2, DatabaseBackup, HardDrive, RefreshCw, RotateCcw, Trash2 } from "lucide-react";

type HostingAccount = { id: string; username: string; status: string; primary_domain: string | null };
type Backup = {
  id: string;
  status: string;
  archiveName: string | null;
  sizeBytes: number | null;
  sha256: string | null;
  databaseNames: string[];
  errorMessage: string | null;
  createdAt: string;
  completedAt: string | null;
  stagedAt: string | null;
};

function formatBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return "—";
  if (value < 1024) return value + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
  return size.toFixed(1) + " " + units[index];
}

function statusClass(status: string): string {
  if (status === "AVAILABLE" || status === "RESTORE_STAGED") return "bg-emerald-50 text-emerald-700";
  if (status === "FAILED") return "bg-red-50 text-red-700";
  if (status === "DELETING" || status === "RESTORING" || status === "RUNNING") return "bg-blue-50 text-blue-700";
  return "bg-slate-100 text-slate-600";
}

export default function BackupsDashboard() {
  const [accounts, setAccounts] = useState<HostingAccount[]>([]);
  const [accountId, setAccountId] = useState("");
  const [backups, setBackups] = useState<Backup[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const loadBackups = useCallback(async (selectedId: string) => {
    if (!selectedId) { setBackups([]); return; }
    const response = await fetch("/api/control/hosting-accounts/" + encodeURIComponent(selectedId) + "/backups", { cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Unable to load backups.");
    setBackups(data.backups ?? []);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/control/hosting-accounts", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load hosting accounts.");
      const activeAccounts = (data.accounts ?? []).filter((account: HostingAccount) => account.status === "ACTIVE");
      setAccounts(activeAccounts);
      const selectedId = activeAccounts.some((account: HostingAccount) => account.id === accountId) ? accountId : (activeAccounts[0]?.id ?? "");
      setAccountId(selectedId);
      await loadBackups(selectedId);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load backup data.");
    } finally {
      setLoading(false);
    }
  }, [accountId, loadBackups]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!accountId) return;
    const timer = window.setInterval(() => {
      void loadBackups(accountId).catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [accountId, loadBackups]);

  async function createBackup() {
    if (!accountId) return;
    setBusy("create"); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/hosting-accounts/" + encodeURIComponent(accountId) + "/backups", {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to queue backup.");
      setNotice("Backup request queued. The connected Linux agent will create the archive.");
      await loadBackups(accountId);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to queue backup.");
    } finally { setBusy(""); }
  }

  async function restoreBackup(backup: Backup) {
    if (!window.confirm("Stage this backup for recovery? This will NOT overwrite the live website or database. Files and SQL dumps will be extracted to a protected staging directory.")) return;
    setBusy(backup.id); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/backups/" + encodeURIComponent(backup.id) + "/restore", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to queue restore staging.");
      setNotice(data.message || "Restore staging queued.");
      await loadBackups(accountId);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to stage backup restore.");
    } finally { setBusy(""); }
  }

  async function deleteBackup(backup: Backup) {
    if (!window.confirm("Permanently delete this backup archive? This cannot be undone.")) return;
    setBusy(backup.id); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/backups/" + encodeURIComponent(backup.id), { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to queue backup deletion.");
      setNotice(data.message || "Backup deletion queued.");
      await loadBackups(accountId);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to delete backup.");
    } finally { setBusy(""); }
  }

  const available = backups.filter((backup) => backup.status === "AVAILABLE").length;
  const pending = backups.filter((backup) => ["QUEUED", "RUNNING", "RESTORING", "DELETING"].includes(backup.status)).length;

  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[1500px] items-center justify-between px-6 py-4">
        <div className="flex items-center gap-3">
          <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><HardDrive size={20}/></span>
          <div><p className="font-semibold">Backups</p><p className="text-xs text-slate-500">Nexora Control / Recovery</p></div>
        </div>
        <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={15}/> Refresh</button>
      </div>
    </header>
    <section className="mx-auto max-w-[1500px] space-y-6 px-6 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div><p className="text-sm font-medium text-blue-700">Customer hosting</p><h1 className="mt-1 text-3xl font-semibold tracking-tight text-slate-950">Account backups</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">Create compressed archives of a hosting account's public_html and its active account-owned databases. Archives are stored outside customer web roots with root-only permissions.</p></div>
        <button onClick={() => void createBackup()} disabled={!accountId || busy !== "" || loading} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-50"><DatabaseBackup size={17}/>{busy === "create" ? "Queueing…" : "Create backup"}</button>
      </div>

      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4">
        <div className="flex gap-3"><AlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-700"/><div><p className="text-sm font-semibold text-amber-900">Restore is staging-only</p><p className="mt-1 text-sm leading-5 text-amber-800">Restore extracts website files and SQL dumps into a protected staging directory. It does not replace live files or import databases. Review and perform any live recovery separately after verification.</p></div></div>
      </div>

      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}

      <div className="rounded-2xl border border-slate-200 bg-white p-5">
        <label className="block max-w-xl text-xs font-medium text-slate-600">Hosting account
          <select value={accountId} onChange={(event) => { setAccountId(event.target.value); void loadBackups(event.target.value).catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load backups.")); }} disabled={loading || accounts.length === 0} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-blue-500">
            {accounts.length === 0 && <option value="">No active hosting accounts</option>}
            {accounts.map((account) => <option key={account.id} value={account.id}>{account.username}{account.primary_domain ? " · " + account.primary_domain : ""}</option>)}
          </select>
        </label>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Total backups</p><p className="mt-2 text-3xl font-semibold">{backups.length}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Available</p><p className="mt-2 text-3xl font-semibold">{available}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">In progress</p><p className="mt-2 text-3xl font-semibold">{pending}</p></div>
      </div>

      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Backup inventory</h2><p className="mt-1 text-xs text-slate-500">Status refreshes automatically every five seconds while this page is open.</p></div>
        {loading ? <p className="p-6 text-sm text-slate-500">Loading backup inventory…</p> : backups.length === 0 ? <div className="p-8 text-center"><HardDrive size={28} className="mx-auto text-slate-300"/><p className="mt-3 text-sm font-medium text-slate-700">No backups yet</p><p className="mt-1 text-xs text-slate-500">Choose an active hosting account and create its first backup.</p></div> : <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-medium">Created</th><th className="px-5 py-3 font-medium">Archive</th><th className="px-5 py-3 font-medium">Size</th><th className="px-5 py-3 font-medium">Databases</th><th className="px-5 py-3 font-medium">Status</th><th className="px-5 py-3 text-right font-medium">Actions</th></tr></thead>
            <tbody className="divide-y divide-slate-100">{backups.map((backup) => <tr key={backup.id}>
              <td className="px-5 py-4 text-slate-600">{new Date(backup.createdAt).toLocaleString()}</td>
              <td className="px-5 py-4"><p className="font-medium text-slate-800">{backup.archiveName || backup.id.slice(0, 8)}</p><p className="mt-1 font-mono text-[10px] text-slate-400">{backup.id}</p></td>
              <td className="px-5 py-4 tabular-nums text-slate-600">{formatBytes(backup.sizeBytes)}</td>
              <td className="px-5 py-4 text-slate-600">{backup.databaseNames.length ? backup.databaseNames.join(", ") : "None"}</td>
              <td className="px-5 py-4"><span className={"rounded-full px-2.5 py-1 text-xs font-medium " + statusClass(backup.status)}>{backup.status.replaceAll("_", " ")}</span>{backup.errorMessage && <p className="mt-1 max-w-xs text-xs text-red-600">{backup.errorMessage}</p>}{backup.stagedAt && <p className="mt-1 text-xs text-slate-500">Staged {new Date(backup.stagedAt).toLocaleString()}</p>}</td>
              <td className="px-5 py-4"><div className="flex justify-end gap-2">
                <button onClick={() => void restoreBackup(backup)} disabled={busy !== "" || backup.status !== "AVAILABLE"} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"><RotateCcw size={14}/> Stage restore</button>
                <button onClick={() => void deleteBackup(backup)} disabled={busy !== "" || backup.status !== "AVAILABLE"} className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 px-3 py-2 text-xs font-medium text-red-700 hover:bg-red-50 disabled:opacity-40"><Trash2 size={14}/> Delete</button>
              </div></td>
            </tr>)}</tbody>
          </table>
        </div>}
      </section>
      <div className="flex items-start gap-2 text-xs leading-5 text-slate-500"><CheckCircle2 size={15} className="mt-0.5 shrink-0"/>Backups include the account's active managed databases and website document root. Files outside public_html, email data, and external object-storage replication are not included in this initial implementation.</div>
    </section>
  </main>;
}

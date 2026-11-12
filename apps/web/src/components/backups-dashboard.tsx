"use client";

import { useCallback, useEffect, useState } from "react";
import { DatabaseBackup, HardDrive, RefreshCw, RotateCcw, Trash2 } from "lucide-react";
import {
  EmptyState, InlineAlert, PageHeader, SectionCard, StatCard, StatusBadge,
  statusTone, TableFrame, Th,
} from "@/components/ui";

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
  const selectedAccount = accounts.find(account => account.id === accountId) ?? null;

  return (
    <main className="mx-auto max-w-[1400px] px-5 py-8 lg:px-9">
      <PageHeader
        eyebrow="Hosting services · Recovery"
        title="Backups"
        description="Create compressed archives of a hosting account's public_html and its active account-owned databases. Archives are stored outside customer web roots with root-only permissions."
        actions={
          <>
            <label className="text-xs font-semibold text-slate-500">
              <span className="sr-only">Hosting account</span>
              <select aria-label="Hosting account" value={accountId}
                onChange={(event) => { setAccountId(event.target.value); void loadBackups(event.target.value).catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load backups.")); }}
                disabled={loading || accounts.length === 0} className="nx-select min-w-56">
                {accounts.length === 0 && <option value="">No active hosting accounts</option>}
                {accounts.map((account) => <option key={account.id} value={account.id}>{account.username}{account.primary_domain ? " · " + account.primary_domain : ""}</option>)}
              </select>
            </label>
            <button onClick={() => void load()} disabled={loading} className="nx-btn-secondary"><RefreshCw size={15} /> Refresh</button>
            <button onClick={() => void createBackup()} disabled={!accountId || busy !== "" || loading} className="nx-btn-primary"><DatabaseBackup size={16} />{busy === "create" ? "Queueing…" : "Create backup"}</button>
          </>
        }
      />

      <div className="mt-6 flex items-start gap-3.5 rounded-2xl border border-amber-200 bg-amber-50 p-5">
        <HardDrive size={18} className="mt-0.5 shrink-0 text-amber-700" />
        <div>
          <p className="text-sm font-bold text-amber-900">Restore is staging-only</p>
          <p className="mt-1 text-sm leading-5 text-amber-800">Restore extracts website files and SQL dumps into a protected staging directory. It does not replace live files or import databases. Review and perform any live recovery separately after verification.</p>
        </div>
      </div>

      {error && <InlineAlert tone="error" onDismiss={() => setError("")} className="mt-5">{error}</InlineAlert>}
      {notice && <InlineAlert tone="success" onDismiss={() => setNotice("")} className="mt-5">{notice}</InlineAlert>}

      <div className="mt-6 grid gap-4 sm:grid-cols-3">
        <StatCard icon={DatabaseBackup} label="Total backups" value={backups.length} hint={selectedAccount ? `For ${selectedAccount.username}` : "Select an account"} />
        <StatCard icon={HardDrive} label="Available" value={available} hint="Ready to stage for recovery" />
        <StatCard icon={RotateCcw} label="In progress" value={pending} hint="Queued, running, restoring or deleting" />
      </div>

      <SectionCard
        className="mt-6"
        title="Backup inventory"
        description="Status refreshes automatically every five seconds while this page is open."
        flush
      >
        {loading ? (
          <p className="px-5 py-6 text-sm text-slate-500 sm:px-6">Loading backup inventory…</p>
        ) : backups.length === 0 ? (
          <EmptyState icon={HardDrive} title="No backups yet" description={selectedAccount ? `Create the first archive for ${selectedAccount.username}. Backups include the website document root and active managed databases.` : "Choose an active hosting account and create its first backup."}>
            <button onClick={() => void createBackup()} disabled={!accountId || busy !== ""} className="nx-btn-primary"><DatabaseBackup size={15} /> Create backup</button>
          </EmptyState>
        ) : (
          <TableFrame minWidth={880} head={<tr><Th>Created</Th><Th>Archive</Th><Th>Size</Th><Th>Databases</Th><Th>Status</Th><Th right>Actions</Th></tr>}>
            {backups.map((backup) => (
              <tr key={backup.id} className="align-top transition hover:bg-slate-50/70">
                <td className="px-5 py-4 text-xs text-slate-600">{new Date(backup.createdAt).toLocaleString()}</td>
                <td className="px-5 py-4">
                  <p className="font-semibold text-slate-800">{backup.archiveName || backup.id.slice(0, 8)}</p>
                  <p className="mt-1 font-mono text-[10px] text-slate-400">{backup.id}</p>
                </td>
                <td className="px-5 py-4 tabular-nums text-slate-600">{formatBytes(backup.sizeBytes)}</td>
                <td className="max-w-[220px] px-5 py-4 text-xs text-slate-600">{backup.databaseNames.length ? backup.databaseNames.join(", ") : "None"}</td>
                <td className="px-5 py-4">
                  <StatusBadge tone={statusTone(backup.status)} dot>{backup.status.replaceAll("_", " ")}</StatusBadge>
                  {backup.errorMessage && <p className="mt-1.5 max-w-xs text-xs leading-5 text-rose-600">{backup.errorMessage}</p>}
                  {backup.stagedAt && <p className="mt-1.5 text-xs text-slate-500">Staged {new Date(backup.stagedAt).toLocaleString()}</p>}
                </td>
                <td className="px-5 py-4">
                  <div className="flex justify-end gap-2">
                    <button onClick={() => void restoreBackup(backup)} disabled={busy !== "" || backup.status !== "AVAILABLE"} className="nx-btn-secondary nx-btn-sm disabled:opacity-40"><RotateCcw size={14} /> Stage restore</button>
                    <button onClick={() => void deleteBackup(backup)} disabled={busy !== "" || backup.status !== "AVAILABLE"} className="nx-btn-danger nx-btn-sm disabled:opacity-40"><Trash2 size={14} /> Delete</button>
                  </div>
                </td>
              </tr>
            ))}
          </TableFrame>
        )}
      </SectionCard>

      <p className="mt-5 text-xs leading-5 text-slate-400">
        Backups include the account&apos;s active managed databases and website document root. Files outside public_html, email data, and external object-storage replication are not included in this initial implementation.
      </p>
    </main>
  );
}

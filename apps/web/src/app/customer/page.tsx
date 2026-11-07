"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity, ArrowUpRight, CheckCircle2, ChevronDown, Cloud, Database,
  FolderOpen, Globe2, HardDrive, LockKeyhole, Mail, Network, RefreshCw,
  Server, ShieldCheck, Users,
} from "lucide-react";

type HostingAccount = {
  id: string;
  username: string;
  primary_domain: string | null;
  status: string;
  created_at: string;
  plan_name: string;
  disk_limit_bytes: number;
  bandwidth_limit_bytes: number | null;
  website_limit: number;
  database_limit: number;
  mailbox_limit: number;
  account_role: string;
};
type AccountOverview = HostingAccount & { websites: number; databases: number };

const modules = [
  { label: "Websites & Domains", description: "Manage domains and website settings", icon: Globe2 },
  { label: "File Manager", description: "Browse and manage website files", icon: FolderOpen },
  { label: "Databases", description: "Manage databases and database users", icon: Database },
  { label: "Email Accounts", description: "Create and manage mailboxes", icon: Mail },
  { label: "DNS Zones", description: "Manage DNS records", icon: Network },
  { label: "Backups", description: "Review and restore account backups", icon: HardDrive },
];

function formatBytes(value: number | null): string {
  if (value === null) return "Not metered";
  if (value >= 1024 ** 3) return (value / 1024 ** 3).toFixed(value % 1024 ** 3 === 0 ? 0 : 1) + " GB";
  if (value >= 1024 ** 2) return (value / 1024 ** 2).toFixed(0) + " MB";
  return value.toLocaleString() + " B";
}

function roleLabel(role: string): string {
  return role.replace("ACCOUNT_", "").toLowerCase().replace(/^./, value => value.toUpperCase());
}

export default function CustomerCpanelPage() {
  const router = useRouter();
  const [accounts, setAccounts] = useState<HostingAccount[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [overview, setOverview] = useState<AccountOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const selected = useMemo(() => accounts.find(account => account.id === selectedId) ?? null, [accounts, selectedId]);

  const loadAccounts = useCallback(async () => {
    setRefreshing(true);
    setError("");
    try {
      const response = await fetch("/api/control/customer/hosting-accounts", { cache: "no-store" });
      const data = await response.json();
      if (response.status === 401) {
        router.replace("/login");
        return;
      }
      if (!response.ok) throw new Error(data.message || "Unable to load your hosting accounts.");
      const available = (data.accounts ?? []) as HostingAccount[];
      setAccounts(available);
      setSelectedId(current => available.some(account => account.id === current) ? current : available[0]?.id ?? "");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load your hosting accounts.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [router]);

  useEffect(() => { void loadAccounts(); }, [loadAccounts]);

  useEffect(() => {
    if (!selectedId) {
      setOverview(null);
      return;
    }
    let active = true;
    setOverview(null);
    fetch("/api/control/customer/hosting-accounts/" + encodeURIComponent(selectedId) + "/overview", { cache: "no-store" })
      .then(async response => {
        const data = await response.json();
        if (response.status === 401) {
          router.replace("/login");
          throw new Error("Your session has expired.");
        }
        if (!response.ok) throw new Error(data.message || "Unable to load this hosting account.");
        if (active) setOverview(data.account as AccountOverview);
      })
      .catch(caught => {
        if (active) setError(caught instanceof Error ? caught.message : "Unable to load this hosting account.");
      });
    return () => { active = false; };
  }, [selectedId, router]);

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  if (loading) {
    return <main className="grid min-h-screen place-items-center bg-slate-50"><div className="text-center"><div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-blue-700" /><p className="mt-4 text-sm text-slate-500">Loading your hosting workspace…</p></div></main>;
  }

  return <main className="min-h-screen bg-[#f5f7fb] text-slate-900">
    <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/95 backdrop-blur">
      <div className="mx-auto flex h-[72px] max-w-[1500px] items-center justify-between gap-4 px-5 sm:px-8">
        <div className="flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 text-white shadow-sm"><Cloud size={21} /></span>
          <div><p className="text-[15px] font-bold tracking-tight">Nexora <span className="text-blue-700">cPanel</span></p><p className="text-[10px] font-medium uppercase tracking-[.17em] text-slate-400">Customer hosting</p></div>
        </div>
        <div className="flex items-center gap-2 sm:gap-3">
          {accounts.length > 0 && <label className="relative flex max-w-[220px] items-center">
            <select aria-label="Select hosting account" value={selectedId} onChange={event => setSelectedId(event.target.value)} className="w-full appearance-none rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-3 pr-9 text-xs font-semibold text-slate-700 outline-none focus:border-blue-400">
              {accounts.map(account => <option key={account.id} value={account.id}>{account.primary_domain || account.username}</option>)}
            </select><ChevronDown size={14} className="pointer-events-none absolute right-3 text-slate-400" />
          </label>}
          <button onClick={() => void loadAccounts()} disabled={refreshing} className="rounded-xl border border-slate-200 p-2.5 text-slate-500 hover:bg-slate-50 disabled:opacity-50" aria-label="Refresh accounts"><RefreshCw size={16} className={refreshing ? "animate-spin" : ""} /></button>
          <button onClick={() => void signOut()} className="rounded-xl px-3 py-2.5 text-xs font-semibold text-slate-500 hover:bg-slate-100">Sign out</button>
        </div>
      </div>
    </header>

    <div className="mx-auto grid max-w-[1500px] gap-7 px-5 py-8 sm:px-8 lg:grid-cols-[230px_minmax(0,1fr)]">
      <aside className="hidden lg:block">
        <div className="rounded-2xl border border-slate-200 bg-white p-3 shadow-sm">
          <p className="px-3 pb-3 pt-2 text-[10px] font-bold uppercase tracking-[.16em] text-slate-400">Hosting</p>
          <div className="flex items-center gap-3 rounded-xl bg-blue-50 px-3 py-3 text-sm font-semibold text-blue-800"><Activity size={17} /> Account Overview</div>
          <div className="mt-4 border-t border-slate-100 px-3 pt-4"><p className="text-[10px] font-bold uppercase tracking-[.16em] text-slate-400">Account tools</p>
            <div className="mt-3 space-y-3">{modules.map(module => <div key={module.label} className="flex items-center gap-3 text-xs text-slate-400"><module.icon size={16} /><span>{module.label}</span><LockKeyhole size={12} className="ml-auto" /></div>)}</div>
          </div>
        </div>
        <div className="mt-4 rounded-2xl border border-emerald-100 bg-emerald-50/70 p-4"><div className="flex items-center gap-2 text-xs font-semibold text-emerald-800"><ShieldCheck size={15} /> Account-scoped access</div><p className="mt-2 text-[11px] leading-5 text-emerald-700">Your account list and overview are restricted to active assignments.</p></div>
      </aside>

      <section className="min-w-0">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div><p className="text-xs font-semibold uppercase tracking-[.18em] text-blue-700">Customer control panel</p><h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950">Hosting dashboard</h1><p className="mt-2 text-sm text-slate-500">Manage the hosting accounts assigned to your Nexora login.</p></div>
          {overview && <span className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-semibold text-emerald-800"><CheckCircle2 size={14} /> {roleLabel(overview.account_role)} access</span>}
        </div>

        {error && <div role="alert" className="mt-6 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>}

        {!accounts.length ? <div className="mt-7 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-16 text-center">
          <span className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-blue-50 text-blue-700"><Server size={25} /></span>
          <h2 className="mt-5 text-lg font-semibold text-slate-900">No hosting accounts assigned</h2>
          <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">Your Nexora login is active, but no hosting account has been assigned to it yet. Ask your hosting administrator to grant access to an account.</p>
        </div> : !overview ? <div className="mt-7 rounded-2xl border border-slate-200 bg-white p-8 text-sm text-slate-500">Loading account details…</div> : <>
          <div className="mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><p className="text-xs text-slate-500">Websites</p><p className="mt-2 text-2xl font-bold tabular-nums">{overview.websites}<span className="ml-1 text-sm font-medium text-slate-400">/ {overview.website_limit}</span></p><p className="mt-1 text-[11px] text-slate-400">Configured domains</p></div>
            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><p className="text-xs text-slate-500">Databases</p><p className="mt-2 text-2xl font-bold tabular-nums">{overview.databases}<span className="ml-1 text-sm font-medium text-slate-400">/ {overview.database_limit}</span></p><p className="mt-1 text-[11px] text-slate-400">Provisioned databases</p></div>
            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><p className="text-xs text-slate-500">Disk allowance</p><p className="mt-2 text-2xl font-bold">{formatBytes(overview.disk_limit_bytes)}</p><p className="mt-1 text-[11px] text-slate-400">Plan quota · usage not yet reported</p></div>
            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><p className="text-xs text-slate-500">Bandwidth allowance</p><p className="mt-2 text-2xl font-bold">{formatBytes(overview.bandwidth_limit_bytes)}</p><p className="mt-1 text-[11px] text-slate-400">Plan quota</p></div>
          </div>

          <div className="mt-6 grid gap-5 xl:grid-cols-[1.3fr_.7fr]">
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between"><div><h2 className="font-semibold text-slate-900">Account details</h2><p className="mt-1 text-xs text-slate-500">Current hosting subscription</p></div><span className="rounded-full bg-emerald-50 px-3 py-1 text-[11px] font-semibold text-emerald-700">{overview.status}</span></div>
              <div className="mt-5 grid gap-5 sm:grid-cols-2">
                <div><p className="text-[11px] uppercase tracking-wide text-slate-400">Primary domain</p><p className="mt-1 break-all text-sm font-semibold text-slate-800">{overview.primary_domain || "Not configured"}</p></div>
                <div><p className="text-[11px] uppercase tracking-wide text-slate-400">System username</p><p className="mt-1 text-sm font-semibold text-slate-800">{overview.username}</p></div>
                <div><p className="text-[11px] uppercase tracking-wide text-slate-400">Hosting plan</p><p className="mt-1 text-sm font-semibold text-slate-800">{overview.plan_name}</p></div>
                <div><p className="text-[11px] uppercase tracking-wide text-slate-400">Email mailbox limit</p><p className="mt-1 text-sm font-semibold text-slate-800">{overview.mailbox_limit}</p></div>
              </div>
            </div>
            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <h2 className="font-semibold text-slate-900">Hosting services</h2><p className="mt-1 text-xs leading-5 text-slate-500">The cPanel service areas are being connected to account-level authorization.</p>
              <div className="mt-4 space-y-3">{modules.map(module => <div key={module.label} className="flex items-center gap-3 rounded-xl border border-slate-100 px-3 py-3"><span className="grid h-8 w-8 place-items-center rounded-lg bg-slate-50 text-slate-500"><module.icon size={16} /></span><div className="min-w-0 flex-1"><p className="text-xs font-semibold text-slate-700">{module.label}</p><p className="mt-0.5 text-[10px] text-slate-400">Access integration pending</p></div><LockKeyhole size={14} className="text-slate-300" /></div>)}</div>
            </div>
          </div>
          <p className="mt-5 flex items-start gap-2 text-[11px] leading-5 text-slate-400"><Users size={14} className="mt-0.5 shrink-0" /> Account access is granted by your hosting administrator. The customer portal does not expose WHM administration or unscoped hosting operations.</p>
        </>}
      </section>
    </div>
  </main>;
}

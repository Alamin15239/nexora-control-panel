"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity, AlertTriangle, CheckCircle2, ChevronDown, Cloud,
  FolderOpen, HardDrive, LockKeyhole, Mail, Network, Plus, RefreshCw,
  Server, ShieldCheck, Trash2, Users, X,
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
type CustomerDomain = { id: string; name: string; document_root: string; is_primary: number; job_status: string | null; created_at: string };
type CustomerDatabase = { id: string; name: string; engine: string; status: string; active_users: number; created_at: string };

const modules = [
  { label: "File Manager", description: "Browse and manage website files", icon: FolderOpen },
  { label: "Email Accounts", description: "Managed by your hosting administrator", icon: Mail },
  { label: "DNS Zones", description: "Managed by your hosting administrator", icon: Network },
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

function canManageDomains(role: string): boolean {
  return role === "ACCOUNT_OWNER" || role === "ACCOUNT_ADMIN";
}

function canManageDatabases(role: string): boolean {
  return role === "ACCOUNT_OWNER" || role === "ACCOUNT_ADMIN" || role === "ACCOUNT_DEVELOPER";
}

export default function CustomerCpanelPage() {
  const router = useRouter();
  const [accounts, setAccounts] = useState<HostingAccount[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [overview, setOverview] = useState<AccountOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [domains, setDomains] = useState<CustomerDomain[]>([]);
  const [databases, setDatabases] = useState<CustomerDatabase[]>([]);
  const [resourcesLoading, setResourcesLoading] = useState(false);
  // Dialog + mutation state
  const [addDomainOpen, setAddDomainOpen] = useState(false);
  const [domainName, setDomainName] = useState("");
  const [deleteDomain, setDeleteDomain] = useState<CustomerDomain | null>(null);
  const [addDatabaseOpen, setAddDatabaseOpen] = useState(false);
  const [databaseName, setDatabaseName] = useState("");
  const [deleteDatabase, setDeleteDatabase] = useState<CustomerDatabase | null>(null);
  const [submitting, setSubmitting] = useState(false);

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

  const loadResources = useCallback(async () => {
    if (!selectedId) {
      setDomains([]);
      setDatabases([]);
      return;
    }
    setResourcesLoading(true);
    try {
      const [domainResponse, databaseResponse] = await Promise.all([
        fetch("/api/control/customer/hosting-accounts/" + encodeURIComponent(selectedId) + "/domains", { cache: "no-store" }),
        fetch("/api/control/customer/hosting-accounts/" + encodeURIComponent(selectedId) + "/databases", { cache: "no-store" }),
      ]);
      const [domainData, databaseData] = await Promise.all([domainResponse.json(), databaseResponse.json()]);
      if (domainResponse.status === 401 || databaseResponse.status === 401) {
        router.replace("/login");
        throw new Error("Your session has expired.");
      }
      if (!domainResponse.ok) throw new Error(domainData.message || "Unable to load website inventory.");
      if (!databaseResponse.ok) throw new Error(databaseData.message || "Unable to load database inventory.");
      setDomains(domainData.domains ?? []);
      setDatabases(databaseData.databases ?? []);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load account resources.");
    } finally {
      setResourcesLoading(false);
    }
  }, [selectedId, router]);

  useEffect(() => { void loadResources(); }, [loadResources]);

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  async function submitDomainAdd() {
    if (!selectedId || !domainName.trim()) return;
    setSubmitting(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`/api/control/customer/hosting-accounts/${encodeURIComponent(selectedId)}/domains`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: domainName.trim().toLowerCase() }),
      });
      const data = await response.json();
      if (response.status === 401) { router.replace("/login"); return; }
      if (!response.ok) throw new Error(data.message || "Unable to add the domain.");
      setAddDomainOpen(false);
      setDomainName("");
      setNotice(String(data.message || "Domain saved. Server configuration is queued."));
      await loadResources();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to add the domain.");
    } finally {
      setSubmitting(false);
    }
  }

  async function submitDomainDelete() {
    if (!deleteDomain || !selectedId) return;
    setSubmitting(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`/api/control/customer/hosting-accounts/${encodeURIComponent(selectedId)}/domains/${encodeURIComponent(deleteDomain.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (response.status === 401) { router.replace("/login"); return; }
      if (!response.ok) throw new Error(data.message || "Unable to remove the domain.");
      setDeleteDomain(null);
      setNotice(String(data.message || "Domain removal queued."));
      await loadResources();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to remove the domain.");
    } finally {
      setSubmitting(false);
    }
  }

  async function submitDatabaseAdd() {
    if (!selectedId || !databaseName.trim()) return;
    setSubmitting(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`/api/control/customer/hosting-accounts/${encodeURIComponent(selectedId)}/databases`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: databaseName.trim().toLowerCase() }),
      });
      const data = await response.json();
      if (response.status === 401) { router.replace("/login"); return; }
      if (!response.ok) throw new Error(data.message || "Unable to create the database.");
      setAddDatabaseOpen(false);
      setDatabaseName("");
      setNotice(String(data.message || `Database ${data.name} creation queued.`));
      await loadResources();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create the database.");
    } finally {
      setSubmitting(false);
    }
  }

  async function submitDatabaseDelete() {
    if (!deleteDatabase || !selectedId) return;
    setSubmitting(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`/api/control/customer/hosting-accounts/${encodeURIComponent(selectedId)}/databases/${encodeURIComponent(deleteDatabase.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (response.status === 401) { router.replace("/login"); return; }
      if (!response.ok) throw new Error(data.message || "Unable to delete the database.");
      setDeleteDatabase(null);
      setNotice(String(data.message || "Database deletion queued."));
      await loadResources();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to delete the database.");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return <main className="grid min-h-screen place-items-center bg-slate-50"><div className="text-center"><div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-blue-700" /><p className="mt-4 text-sm text-slate-500">Loading your hosting workspace…</p></div></main>;
  }

  const domainMutationAllowed = overview ? canManageDomains(overview.account_role) : false;
  const databaseMutationAllowed = overview ? canManageDatabases(overview.account_role) : false;

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
          <button onClick={() => router.push("/customer/deploy")} className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50">Nexora Deploy</button>
          <button onClick={() => router.push("/plans")} className="rounded-xl bg-blue-700 px-3 py-2.5 text-xs font-semibold text-white hover:bg-blue-800">Buy hosting</button>
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
        <div className="mt-4 rounded-2xl border border-emerald-100 bg-emerald-50/70 p-4"><div className="flex items-center gap-2 text-xs font-semibold text-emerald-800"><ShieldCheck size={15} /> Account-scoped access</div><p className="mt-2 text-[11px] leading-5 text-emerald-700">Your account list, overview, and resource actions are restricted to active assignments for your login.</p></div>
      </aside>

      <section className="min-w-0">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div><p className="text-xs font-semibold uppercase tracking-[.18em] text-blue-700">Customer control panel</p><h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950">Hosting dashboard</h1><p className="mt-2 text-sm text-slate-500">Manage the hosting accounts assigned to your Nexora login.</p></div>
          {overview && <span className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-semibold text-emerald-800"><CheckCircle2 size={14} /> {roleLabel(overview.account_role)} access</span>}
        </div>

        {error && <div role="alert" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><span className="flex items-start gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{error}</span><button onClick={() => setError("")} aria-label="Dismiss error" className="text-rose-400 hover:text-rose-600"><X size={15} /></button></div>}
        {notice && <div role="status" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"><span className="flex items-start gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0" />{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message" className="text-emerald-400 hover:text-emerald-600"><X size={15} /></button></div>}

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
              <h2 className="font-semibold text-slate-900">Account tools</h2><p className="mt-1 text-xs leading-5 text-slate-500">Domains and databases are managed below. Other service areas remain managed by your hosting administrator.</p>
              <div className="mt-4 space-y-3">{modules.map(module => <div key={module.label} className="flex items-center gap-3 rounded-xl border border-slate-100 px-3 py-3"><span className="grid h-8 w-8 place-items-center rounded-lg bg-slate-50 text-slate-500"><module.icon size={16} /></span><div className="min-w-0 flex-1"><p className="text-xs font-semibold text-slate-700">{module.label}</p><p className="mt-0.5 text-[10px] text-slate-400">{module.description}</p></div><LockKeyhole size={14} className="text-slate-300" /></div>)}</div>
            </div>
          </div>

          <div className="mt-6 grid gap-5 xl:grid-cols-2">
            <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h2 className="font-semibold text-slate-900">Websites & domains</h2><p className="mt-1 text-xs text-slate-500">{domains.length} of {overview.website_limit} plan websites</p></div>
                {domainMutationAllowed && <button onClick={() => { setAddDomainOpen(true); setError(""); }} className="inline-flex items-center gap-1.5 rounded-xl bg-blue-700 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-800"><Plus size={14} /> Add domain</button>}
              </div>
              {resourcesLoading ? <p className="p-5 text-xs text-slate-400">Loading websites…</p> : domains.length === 0 ? <p className="p-5 text-xs text-slate-400">No domains are registered to this account yet.{domainMutationAllowed ? " Use “Add domain” to register the first one." : ""}</p> : <div className="divide-y divide-slate-100">{domains.map(domain => <div key={domain.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5"><div className="min-w-0"><p className="break-all text-sm font-semibold text-slate-800">{domain.name}{domain.is_primary ? <span className="ml-2 rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-semibold text-blue-700">Primary</span> : null}</p><p className="mt-1 break-all text-[11px] text-slate-400">{domain.document_root}</p></div><div className="flex items-center gap-2"><span className="rounded-full bg-slate-100 px-2.5 py-1 text-[10px] font-medium text-slate-600">{domain.job_status || "Registered"}</span>{domainMutationAllowed && !domain.is_primary && <button onClick={() => setDeleteDomain(domain)} className="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2 py-1 text-[10px] font-semibold text-rose-600 hover:bg-rose-50" aria-label={`Remove ${domain.name}`}><Trash2 size={12} /> Remove</button>}</div></div>)}</div>}
              {!domainMutationAllowed && <p className="border-t border-slate-100 px-5 py-3 text-[11px] text-slate-400">Your account role is read-only for domains. Ask an account owner or admin to make changes.</p>}
            </section>
            <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h2 className="font-semibold text-slate-900">Databases</h2><p className="mt-1 text-xs text-slate-500">{databases.length} of {overview.database_limit} plan databases · credentials are not displayed</p></div>
                {databaseMutationAllowed && <button onClick={() => { setAddDatabaseOpen(true); setError(""); }} className="inline-flex items-center gap-1.5 rounded-xl bg-blue-700 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-800"><Plus size={14} /> Create database</button>}
              </div>
              {resourcesLoading ? <p className="p-5 text-xs text-slate-400">Loading databases…</p> : databases.length === 0 ? <p className="p-5 text-xs text-slate-400">No databases are registered to this account yet.{databaseMutationAllowed ? " Use “Create database” to add the first one." : ""}</p> : <div className="divide-y divide-slate-100">{databases.map(database => <div key={database.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5"><div className="min-w-0"><p className="break-all text-sm font-semibold text-slate-800">{database.name}</p><p className="mt-1 text-[11px] text-slate-400">{database.engine} · {database.active_users} active users</p></div><div className="flex items-center gap-2"><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold "+(database.status==="ACTIVE"?"bg-emerald-50 text-emerald-700":database.status==="DELETING"?"bg-rose-50 text-rose-700":"bg-amber-50 text-amber-700")}>{database.status}</span>{databaseMutationAllowed && database.status !== "DELETING" && <button onClick={() => setDeleteDatabase(database)} className="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2 py-1 text-[10px] font-semibold text-rose-600 hover:bg-rose-50" aria-label={`Delete ${database.name}`}><Trash2 size={12} /> Delete</button>}</div></div>)}</div>}
              {!databaseMutationAllowed && <p className="border-t border-slate-100 px-5 py-3 text-[11px] text-slate-400">Your account role is read-only for databases. Ask an account owner, admin, or developer to make changes.</p>}
            </section>
          </div>
          <p className="mt-5 flex items-start gap-2 text-[11px] leading-5 text-slate-400"><Users size={14} className="mt-0.5 shrink-0" /> Domain and database changes are queued as provisioning jobs for the hosting server. Primary domains cannot be removed, and plan quotas are enforced by the API.</p>
        </>}
      </section>
    </div>

    {addDomainOpen && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Add domain">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold text-slate-900">Add a domain</h3><p className="mt-1 text-xs leading-5 text-slate-500">The domain is registered to this account and Nginx configuration is queued for the hosting server. Plan limit: {overview?.website_limit} websites.</p></div><button onClick={() => setAddDomainOpen(false)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Domain name</span>
          <input value={domainName} onChange={event => setDomainName(event.target.value)} placeholder="example.com" autoFocus className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setAddDomainOpen(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitDomainAdd()} disabled={submitting || !domainName.trim()} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Saving…" : "Add domain"}</button></div>
      </div>
    </div>}

    {deleteDomain && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Remove domain">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-rose-50 text-rose-600"><AlertTriangle size={18} /></span><div><h3 className="text-lg font-semibold text-slate-900">Remove {deleteDomain.name}?</h3><p className="mt-1 text-xs leading-5 text-slate-500">The domain is marked deleted and its server configuration removal is queued. This cannot be undone from the dashboard.</p></div></div>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setDeleteDomain(null)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitDomainDelete()} disabled={submitting} className="rounded-xl bg-rose-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50">{submitting ? "Removing…" : "Remove domain"}</button></div>
      </div>
    </div>}

    {addDatabaseOpen && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Create database">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold text-slate-900">Create a MariaDB database</h3><p className="mt-1 text-xs leading-5 text-slate-500">The name is prefixed with your account username (<span className="font-mono">{overview?.username}_</span>). Plan limit: {overview?.database_limit} databases.</p></div><button onClick={() => setAddDatabaseOpen(false)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Database name</span>
          <div className="mt-1.5 flex items-center overflow-hidden rounded-xl border border-slate-200 focus-within:border-blue-400"><span className="border-r border-slate-200 bg-slate-50 px-3 py-2.5 font-mono text-xs text-slate-500">{overview?.username}_</span><input value={databaseName} onChange={event => setDatabaseName(event.target.value)} placeholder="wordpress" autoFocus className="w-full px-3 py-2.5 text-sm outline-none" /></div>
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setAddDatabaseOpen(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitDatabaseAdd()} disabled={submitting || !databaseName.trim()} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Creating…" : "Create database"}</button></div>
      </div>
    </div>}

    {deleteDatabase && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Delete database">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-rose-50 text-rose-600"><AlertTriangle size={18} /></span><div><h3 className="text-lg font-semibold text-slate-900">Delete {deleteDatabase.name}?</h3><p className="mt-1 text-xs leading-5 text-slate-500">The database and its users are removed on the server. The database stays listed until the server confirms deletion. This cannot be undone.</p></div></div>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setDeleteDatabase(null)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitDatabaseDelete()} disabled={submitting} className="rounded-xl bg-rose-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50">{submitting ? "Deleting…" : "Delete database"}</button></div>
      </div>
    </div>}
  </main>;
}

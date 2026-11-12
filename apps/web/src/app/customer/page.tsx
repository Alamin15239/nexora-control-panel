"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity, AlertTriangle, CheckCircle2, Database, FolderOpen,
  Globe2, HardDrive, LockKeyhole, Mail, Network, Plus, RefreshCw, Server,
  ShieldCheck, Trash2, Users, Github, Boxes, CreditCard, LogOut,
} from "lucide-react";
import {
  EmptyState, InlineAlert, Meter, Modal, NexoraMark, PageHeader,
  SectionCard, StatCard, StatusBadge, statusTone,
} from "@/components/ui";

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

// Service areas rendered as quick actions on the dashboard. File, mail, DNS and
// backup services are operated by the hosting administrator in this release;
// the tiles explain that honestly instead of pretending in-panel management.
const managedModules = [
  { label: "File Manager", description: "Website files and document roots", icon: FolderOpen, note: "File Manager" },
  { label: "Email Accounts", description: "Mailboxes and delivery", icon: Mail, note: "Email accounts" },
  { label: "DNS Zones", description: "Records and routing", icon: Network, note: "DNS zones" },
  { label: "Backups", description: "Account archives and recovery", icon: HardDrive, note: "Backups" },
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
  const [lockedTool, setLockedTool] = useState("");
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
    return (
      <main className="grid min-h-screen place-items-center bg-canvas">
        <div className="text-center">
          <span className="mx-auto inline-block h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-brand-600" />
          <p className="mt-4 text-sm text-slate-500">Loading your hosting workspace…</p>
        </div>
      </main>
    );
  }

  const domainMutationAllowed = overview ? canManageDomains(overview.account_role) : false;
  const databaseMutationAllowed = overview ? canManageDatabases(overview.account_role) : false;

  return (
    <main className="min-h-screen bg-canvas text-slate-900">
      <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-gradient-to-r from-navy-950 via-navy-950 to-navy-900">
        <div className="mx-auto flex h-[72px] max-w-[1500px] items-center justify-between gap-4 px-5 sm:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <NexoraMark size={38} />
            <div className="min-w-0">
              <p className="text-[15px] font-bold tracking-tight text-white">Nexora <span className="text-brand-300">Hosting</span></p>
              <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">Customer workspace</p>
            </div>
          </div>
          <div className="flex items-center gap-2 sm:gap-2.5">
            {accounts.length > 0 && (
              <label className="relative flex max-w-[230px] items-center">
                <select aria-label="Select hosting account" value={selectedId} onChange={event => setSelectedId(event.target.value)} className="nx-select border-white/10 bg-white/[0.07] text-xs font-semibold text-white shadow-none [&>option]:text-slate-900">
                  {accounts.map(account => <option key={account.id} value={account.id}>{account.primary_domain || account.username}</option>)}
                </select>
              </label>
            )}
            <button onClick={() => router.push("/customer/deploy")} className="hidden items-center gap-2 rounded-xl border border-white/10 bg-white/[0.07] px-3.5 py-2.5 text-xs font-semibold text-slate-100 transition hover:bg-white/[0.12] sm:inline-flex">
              <Github size={14} /> Nexora Deploy
            </button>
            <button onClick={() => router.push("/plans")} className="nx-btn nx-btn-sm bg-brand-600 px-3.5 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-brand-700">
              <CreditCard size={14} /> Buy hosting
            </button>
            <button onClick={() => void loadAccounts()} disabled={refreshing} className="rounded-xl border border-white/10 p-2.5 text-slate-400 transition hover:bg-white/[0.08] hover:text-white disabled:opacity-50" aria-label="Refresh accounts">
              <RefreshCw size={16} className={refreshing ? "animate-spin" : ""} />
            </button>
            <button onClick={() => void signOut()} className="inline-flex items-center gap-1.5 rounded-xl px-3 py-2.5 text-xs font-semibold text-slate-400 transition hover:bg-white/[0.08] hover:text-white" aria-label="Sign out">
              <LogOut size={14} /> <span className="hidden sm:inline">Sign out</span>
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] px-5 py-8 sm:px-8">
        <PageHeader
          eyebrow="Customer control panel"
          title="Hosting dashboard"
          description="Manage the hosting accounts assigned to your Nexora login."
          actions={overview && <StatusBadge tone="success" dot>{roleLabel(overview.account_role)} access</StatusBadge>}
        />

        {error && <InlineAlert tone="error" onDismiss={() => setError("")} className="mt-6">{error}</InlineAlert>}
        {notice && <InlineAlert tone="success" onDismiss={() => setNotice("")} className="mt-6">{notice}</InlineAlert>}
        {lockedTool && (
          <InlineAlert tone="info" onDismiss={() => setLockedTool("")} className="mt-6">
            <span className="font-semibold">{lockedTool}</span> is operated by your hosting administrator in the current release. Your account data for this service stays protected on the platform; ask your administrator to provision or restore it for you.
          </InlineAlert>
        )}

        {!accounts.length ? (
          <div className="nx-card mt-8 px-6 py-16 text-center">
            <span className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-slate-200 bg-gradient-to-br from-brand-50 to-white text-brand-600 shadow-sm">
              <Server size={28} />
            </span>
            <h2 className="mt-6 text-lg font-bold tracking-tight text-slate-950">No hosting accounts assigned</h2>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
              Your Nexora login is active, but no hosting account has been assigned to it yet. Hosting accounts are created by your hosting administrator and appear here the moment one is granted to your login.
            </p>
            <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
              <button onClick={() => void loadAccounts()} disabled={refreshing} className="nx-btn-secondary"><RefreshCw size={15} className={refreshing ? "animate-spin" : ""} /> Check again</button>
              <button onClick={() => router.push("/plans")} className="nx-btn-primary">Browse hosting plans</button>
            </div>
            <p className="mx-auto mt-6 max-w-sm text-xs leading-5 text-slate-400">
              Need hosting right away? Choose a plan and your account will be provisioned after payment confirmation.
            </p>
          </div>
        ) : !overview ? (
          <div className="nx-card mt-8 p-8 text-sm text-slate-500">Loading account details…</div>
        ) : <>
          {/* Selected account summary band */}
          <div className="nx-card mt-7 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 bg-gradient-to-r from-brand-50/70 via-white to-white px-6 py-5">
              <div className="flex min-w-0 items-center gap-4">
                <span className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-brand-500 to-navy-900 text-white shadow-card"><Globe2 size={22} /></span>
                <div className="min-w-0">
                  <p className="truncate text-[15px] font-bold tracking-tight text-slate-950">{overview.primary_domain || overview.username}</p>
                  <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span className="inline-flex items-center gap-1"><Boxes size={12} /> {overview.plan_name}</span>
                    <span className="text-slate-300">·</span>
                    <span className="inline-flex items-center gap-1"><Users size={12} /> {overview.username}</span>
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <StatusBadge tone={statusTone(overview.status)} dot>{overview.status}</StatusBadge>
                <StatusBadge tone="brand">{roleLabel(overview.account_role)}</StatusBadge>
              </div>
            </div>
            <div className="grid gap-x-8 gap-y-5 px-6 py-5 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">Hosting plan</p>
                <p className="mt-1.5 text-sm font-semibold text-slate-800">{overview.plan_name}</p>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">Primary domain</p>
                <p className="mt-1.5 break-all text-sm font-semibold text-slate-800">{overview.primary_domain || "Not configured"}</p>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">Mailbox allowance</p>
                <p className="mt-1.5 text-sm font-semibold text-slate-800">{overview.mailbox_limit.toLocaleString()} mailboxes</p>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">Account since</p>
                <p className="mt-1.5 text-sm font-semibold text-slate-800">{new Date(overview.created_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}</p>
              </div>
            </div>
          </div>

          {/* Resource meters */}
          <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard icon={Globe2} label="Websites" value={overview.websites} unit={`/ ${overview.website_limit}`} hint="Configured domains on this account">
              <Meter value={(overview.websites / Math.max(1, overview.website_limit)) * 100} className="mt-3" />
              <p className="mt-1.5 text-[11px] text-slate-400">{Math.round((overview.websites / Math.max(1, overview.website_limit)) * 100)}% of the plan website quota used.</p>
            </StatCard>
            <StatCard icon={Database} label="Databases" value={overview.databases} unit={`/ ${overview.database_limit}`} hint="Provisioned MariaDB databases">
              <Meter value={(overview.databases / Math.max(1, overview.database_limit)) * 100} className="mt-3" />
              <p className="mt-1.5 text-[11px] text-slate-400">{Math.round((overview.databases / Math.max(1, overview.database_limit)) * 100)}% of the plan database quota used.</p>
            </StatCard>
            <StatCard icon={HardDrive} label="Disk allowance" value={formatBytes(overview.disk_limit_bytes)} hint="Plan storage quota">
              <Meter value={0} className="mt-3" />
              <p className="mt-1.5 text-[11px] text-slate-400">Per-account disk usage is not metered yet; the figure shown is your plan limit.</p>
            </StatCard>
            <StatCard icon={Activity} label="Bandwidth allowance" value={formatBytes(overview.bandwidth_limit_bytes)} hint="Monthly transfer quota">
              <Meter value={0} className="mt-3" />
              <p className="mt-1.5 text-[11px] text-slate-400">Per-account bandwidth metering is not reported yet; the figure shown is your plan limit.</p>
            </StatCard>
          </div>

          {/* Quick actions */}
          <SectionCard className="mt-6" title="Quick actions" description="Common tasks for this hosting account">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {domainMutationAllowed && (
                <button onClick={() => { setAddDomainOpen(true); setError(""); }} className="group flex items-start gap-3.5 rounded-2xl border border-slate-200 bg-white p-4 text-left shadow-sm transition hover:-translate-y-0.5 hover:border-brand-200 hover:shadow-lift">
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-brand-50 text-brand-600 transition group-hover:bg-brand-600 group-hover:text-white"><Plus size={18} /></span>
                  <span className="min-w-0"><span className="block text-sm font-semibold text-slate-900">Add a website</span><span className="mt-1 block text-xs leading-5 text-slate-500">Register a new domain on this account</span></span>
                </button>
              )}
              {databaseMutationAllowed && (
                <button onClick={() => { setAddDatabaseOpen(true); setError(""); }} className="group flex items-start gap-3.5 rounded-2xl border border-slate-200 bg-white p-4 text-left shadow-sm transition hover:-translate-y-0.5 hover:border-brand-200 hover:shadow-lift">
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-brand-50 text-brand-600 transition group-hover:bg-brand-600 group-hover:text-white"><Database size={18} /></span>
                  <span className="min-w-0"><span className="block text-sm font-semibold text-slate-900">Create a database</span><span className="mt-1 block text-xs leading-5 text-slate-500">Provision a new MariaDB database</span></span>
                </button>
              )}
              <button onClick={() => router.push("/customer/deploy")} className="group flex items-start gap-3.5 rounded-2xl border border-slate-200 bg-white p-4 text-left shadow-sm transition hover:-translate-y-0.5 hover:border-brand-200 hover:shadow-lift">
                <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-navy-950 text-white transition group-hover:bg-navy-900"><Github size={18} /></span>
                <span className="min-w-0"><span className="block text-sm font-semibold text-slate-900">Nexora Deploy</span><span className="mt-1 block text-xs leading-5 text-slate-500">Ship a website straight from GitHub</span></span>
              </button>
              {managedModules.map(module => (
                <button key={module.label} onClick={() => setLockedTool(module.note)} className="group flex items-start gap-3.5 rounded-2xl border border-slate-200 bg-white p-4 text-left shadow-sm transition hover:-translate-y-0.5 hover:border-slate-300 hover:shadow-lift">
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-slate-100 text-slate-500 transition group-hover:bg-slate-200"><module.icon size={18} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-semibold text-slate-900">{module.label}</span>
                    <span className="mt-1 block text-xs leading-5 text-slate-500">{module.description}</span>
                  </span>
                  <span className="mt-0.5 inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-500"><LockKeyhole size={10} /> Admin</span>
                </button>
              ))}
            </div>
          </SectionCard>

          {/* Account cards */}
          {accounts.length > 1 && (
            <SectionCard className="mt-6" title="Your hosting accounts" description="Select an account to load its details and resources">
              <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3">
                {accounts.map(account => {
                  const selected = account.id === selectedId;
                  return (
                    <button key={account.id} onClick={() => setSelectedId(account.id)} aria-pressed={selected}
                      className={"rounded-2xl border p-4 text-left transition " + (selected ? "border-brand-300 bg-brand-50/50 ring-2 ring-brand-500/15" : "border-slate-200 bg-white shadow-sm hover:border-slate-300 hover:shadow-card")}>
                      <div className="flex items-center justify-between gap-2">
                        <p className="min-w-0 truncate text-sm font-bold text-slate-950">{account.primary_domain || account.username}</p>
                        <StatusBadge tone={statusTone(account.status)} dot>{account.status}</StatusBadge>
                      </div>
                      <p className="mt-1.5 text-xs text-slate-500">{account.plan_name} · {roleLabel(account.account_role)}</p>
                      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-500">
                        <span>Websites {overview && selected ? overview.websites : "–"}/{account.website_limit}</span>
                        <span>Databases {overview && selected ? overview.databases : "–"}/{account.database_limit}</span>
                        <span>Disk {formatBytes(account.disk_limit_bytes)}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </SectionCard>
          )}

          {/* Inventory */}
          <div className="mt-6 grid gap-5 xl:grid-cols-2">
            <SectionCard
              title="Websites & domains"
              description={`${domains.length} of ${overview.website_limit} plan websites`}
              flush
              actions={domainMutationAllowed && <button onClick={() => { setAddDomainOpen(true); setError(""); }} className="nx-btn-primary nx-btn-sm"><Plus size={14} /> Add domain</button>}
            >
              {resourcesLoading ? (
                <p className="px-5 py-6 text-xs text-slate-400">Loading websites…</p>
              ) : domains.length === 0 ? (
                <EmptyState icon={Globe2} title="No domains yet" description={domainMutationAllowed ? "Register the first domain for this account to publish a website." : "Domains are registered by an account owner or administrator."}>
                  {domainMutationAllowed && <button onClick={() => { setAddDomainOpen(true); setError(""); }} className="nx-btn-primary nx-btn-sm"><Plus size={14} /> Add domain</button>}
                </EmptyState>
              ) : (
                <div className="divide-y divide-slate-100">
                  {domains.map(domain => (
                    <div key={domain.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 sm:px-6">
                      <div className="min-w-0">
                        <p className="break-all text-sm font-semibold text-slate-800">
                          {domain.name}
                          {domain.is_primary ? <span className="ml-2 rounded-full bg-brand-50 px-2 py-0.5 text-[10px] font-semibold text-brand-700 ring-1 ring-inset ring-brand-500/20">Primary</span> : null}
                        </p>
                        <p className="mt-1 break-all text-[11px] text-slate-400">{domain.document_root}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <StatusBadge tone={statusTone(domain.job_status)}>{domain.job_status || "Registered"}</StatusBadge>
                        {domainMutationAllowed && !domain.is_primary && (
                          <button onClick={() => setDeleteDomain(domain)} className="nx-btn-danger nx-btn-sm" aria-label={`Remove ${domain.name}`}><Trash2 size={12} /> Remove</button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {!domainMutationAllowed && <p className="border-t border-slate-100 bg-slate-50/60 px-5 py-3 text-[11px] text-slate-400 sm:px-6">Your account role is read-only for domains. Ask an account owner or admin to make changes.</p>}
            </SectionCard>

            <SectionCard
              title="Databases"
              description={`${databases.length} of ${overview.database_limit} plan databases · credentials are not displayed`}
              flush
              actions={databaseMutationAllowed && <button onClick={() => { setAddDatabaseOpen(true); setError(""); }} className="nx-btn-primary nx-btn-sm"><Plus size={14} /> Create database</button>}
            >
              {resourcesLoading ? (
                <p className="px-5 py-6 text-xs text-slate-400">Loading databases…</p>
              ) : databases.length === 0 ? (
                <EmptyState icon={Database} title="No databases yet" description={databaseMutationAllowed ? "Create the first MariaDB database for this account." : "Databases are created by an account owner, admin, or developer."}>
                  {databaseMutationAllowed && <button onClick={() => { setAddDatabaseOpen(true); setError(""); }} className="nx-btn-primary nx-btn-sm"><Plus size={14} /> Create database</button>}
                </EmptyState>
              ) : (
                <div className="divide-y divide-slate-100">
                  {databases.map(database => (
                    <div key={database.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 sm:px-6">
                      <div className="min-w-0">
                        <p className="break-all text-sm font-semibold text-slate-800">{database.name}</p>
                        <p className="mt-1 text-[11px] text-slate-400">{database.engine} · {database.active_users} active users</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <StatusBadge tone={statusTone(database.status)} dot>{database.status}</StatusBadge>
                        {databaseMutationAllowed && database.status !== "DELETING" && (
                          <button onClick={() => setDeleteDatabase(database)} className="nx-btn-danger nx-btn-sm" aria-label={`Delete ${database.name}`}><Trash2 size={12} /> Delete</button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {!databaseMutationAllowed && <p className="border-t border-slate-100 bg-slate-50/60 px-5 py-3 text-[11px] text-slate-400 sm:px-6">Your account role is read-only for databases. Ask an account owner, admin, or developer to make changes.</p>}
            </SectionCard>
          </div>

          <p className="mt-5 flex items-start gap-2 text-[11px] leading-5 text-slate-400">
            <ShieldCheck size={14} className="mt-0.5 shrink-0" /> Domain and database changes are queued as provisioning jobs for the hosting server. Primary domains cannot be removed, and plan quotas are enforced by the API.
          </p>
        </>}
      </div>

      {addDomainOpen && (
        <Modal title="Add a domain" description={`The domain is registered to this account and Nginx configuration is queued for the hosting server. Plan limit: ${overview?.website_limit} websites.`} onClose={() => setAddDomainOpen(false)}>
          <label className="mt-5 block">
            <span className="nx-label">Domain name</span>
            <input value={domainName} onChange={event => setDomainName(event.target.value)} placeholder="example.com" autoFocus className="nx-input mt-2" />
          </label>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setAddDomainOpen(false)} className="nx-btn-secondary">Cancel</button>
            <button onClick={() => void submitDomainAdd()} disabled={submitting || !domainName.trim()} className="nx-btn-primary">{submitting ? "Saving…" : "Add domain"}</button>
          </div>
        </Modal>
      )}

      {deleteDomain && (
        <Modal title={`Remove ${deleteDomain.name}?`} description="The domain is marked deleted and its server configuration removal is queued. This cannot be undone from the dashboard." onClose={() => setDeleteDomain(null)}>
          <div className="mt-5 flex items-start gap-3 rounded-xl border border-rose-100 bg-rose-50/70 p-3.5">
            <AlertTriangle size={16} className="mt-0.5 shrink-0 text-rose-600" />
            <p className="text-xs leading-5 text-rose-700">Websites served by this domain will stop once the hosting server applies the removal.</p>
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setDeleteDomain(null)} className="nx-btn-secondary">Cancel</button>
            <button onClick={() => void submitDomainDelete()} disabled={submitting} className="nx-btn nx-btn-sm rounded-xl bg-rose-600 px-4 py-2.5 text-white shadow-sm hover:bg-rose-700">{submitting ? "Removing…" : "Remove domain"}</button>
          </div>
        </Modal>
      )}

      {addDatabaseOpen && (
        <Modal title="Create a MariaDB database" description={<span>The name is prefixed with your account username (<span className="font-mono">{overview?.username}_</span>). Plan limit: {overview?.database_limit} databases.</span>} onClose={() => setAddDatabaseOpen(false)}>
          <label className="mt-5 block">
            <span className="nx-label">Database name</span>
            <div className="mt-2 flex items-center overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm focus-within:border-brand-400 focus-within:ring-4 focus-within:ring-brand-500/10">
              <span className="border-r border-slate-200 bg-slate-50 px-3.5 py-2.5 font-mono text-xs text-slate-500">{overview?.username}_</span>
              <input value={databaseName} onChange={event => setDatabaseName(event.target.value)} placeholder="wordpress" autoFocus className="w-full border-0 bg-transparent px-3.5 py-2.5 text-sm outline-none" />
            </div>
          </label>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setAddDatabaseOpen(false)} className="nx-btn-secondary">Cancel</button>
            <button onClick={() => void submitDatabaseAdd()} disabled={submitting || !databaseName.trim()} className="nx-btn-primary">{submitting ? "Creating…" : "Create database"}</button>
          </div>
        </Modal>
      )}

      {deleteDatabase && (
        <Modal title={`Delete ${deleteDatabase.name}?`} description="The database and its users are removed on the server. The database stays listed until the server confirms deletion. This cannot be undone." onClose={() => setDeleteDatabase(null)}>
          <div className="mt-5 flex items-start gap-3 rounded-xl border border-rose-100 bg-rose-50/70 p-3.5">
            <AlertTriangle size={16} className="mt-0.5 shrink-0 text-rose-600" />
            <p className="text-xs leading-5 text-rose-700">Applications using this database will lose their data connection immediately.</p>
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setDeleteDatabase(null)} className="nx-btn-secondary">Cancel</button>
            <button onClick={() => void submitDatabaseDelete()} disabled={submitting} className="nx-btn nx-btn-sm rounded-xl bg-rose-600 px-4 py-2.5 text-white shadow-sm hover:bg-rose-700">{submitting ? "Deleting…" : "Delete database"}</button>
          </div>
        </Modal>
      )}

      <footer className="border-t border-slate-200/70 py-6">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center justify-between gap-2 px-5 text-xs text-slate-400 sm:px-8">
          <span className="inline-flex items-center gap-1.5"><CheckCircle2 size={13} className="text-emerald-500" /> Account-scoped access — you only ever see the accounts assigned to your login.</span>
          <span>Nexora Hosting · Customer workspace</span>
        </div>
      </footer>
    </main>
  );
}

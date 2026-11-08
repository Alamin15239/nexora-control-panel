"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, Search, Users, Building2, Server, ShieldAlert } from "lucide-react";

type Customer = {
  userId: string; email: string; displayName: string | null; userStatus: string; registeredAt: string;
  organizationId: string; organizationName: string; organizationSlug: string; organizationStatus: string;
  hostingAccounts: number; activeHostingAccounts: number; pendingHostingAccounts: number;
};

export default function CustomerAccountsPage() {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const response = await fetch("/api/control/platform/customers", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load platform customers.");
      setCustomers(data.customers ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load platform customers."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q ? customers.filter(c => [c.email, c.displayName, c.organizationName, c.organizationSlug].some(v => (v ?? "").toLowerCase().includes(q))) : customers;
  }, [customers, search]);
  const formatDate = (value: string) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  };
  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85"><div className="mx-auto flex max-w-[1400px] items-center justify-between gap-4 px-6 py-4">
      <div className="flex items-center gap-3"><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Users size={20}/></span><div><p className="font-semibold">Customer accounts</p><p className="text-xs text-slate-500">WHM · Platform-wide customer directory</p></div></div>
      <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1400px] space-y-6 px-6 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-blue-700">WHM · Platform administration</p><h1 className="mt-1 text-3xl font-semibold tracking-tight">Registered customers</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">View customer logins and organizations created during registration, across the entire Nexora platform.</p></div><div className="grid grid-cols-2 gap-3"><div className="rounded-xl border border-slate-200 bg-white px-4 py-3"><p className="text-xs text-slate-500">Customer records</p><p className="mt-1 text-2xl font-semibold tabular-nums">{customers.length}</p></div><div className="rounded-xl border border-slate-200 bg-white px-4 py-3"><p className="text-xs text-slate-500">With hosting</p><p className="mt-1 text-2xl font-semibold tabular-nums">{customers.filter(c => c.hostingAccounts > 0).length}</p></div></div></div>
      {error && <div role="alert" className="flex items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"><ShieldAlert size={17} className="mt-0.5 shrink-0"/><div>{error}</div></div>}
      <div className="flex flex-wrap items-center justify-between gap-3"><label className="relative block w-full max-w-md"><Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search name, email or organization…" className="w-full rounded-xl border border-slate-200 bg-white py-2.5 pl-9 pr-3 text-sm outline-none focus:border-blue-500"/></label><span className="text-xs text-slate-500">Showing {filtered.length} of {customers.length}</span></div>
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        {loading ? <div className="p-12 text-center text-sm text-slate-500">Loading customer directory…</div> : filtered.length === 0 ? <div className="p-12 text-center"><Users size={30} className="mx-auto text-slate-300"/><p className="mt-3 text-sm text-slate-600">{customers.length ? "No customers match your search." : "No registered customer accounts found."}</p></div> : <div className="overflow-x-auto"><table className="w-full min-w-[950px] text-left text-sm"><thead className="bg-slate-50 text-[11px] uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-semibold">Customer</th><th className="px-5 py-3 font-semibold">Organization</th><th className="px-5 py-3 font-semibold">Registered</th><th className="px-5 py-3 font-semibold">Account status</th><th className="px-5 py-3 font-semibold">Hosting accounts</th></tr></thead><tbody className="divide-y divide-slate-100">{filtered.map(c => <tr key={c.userId+":"+c.organizationId} className="hover:bg-slate-50/70"><td className="px-5 py-4"><p className="font-semibold text-slate-800">{c.displayName || "—"}</p><p className="mt-1 text-xs text-slate-500">{c.email}</p></td><td className="px-5 py-4"><div className="flex items-center gap-2"><Building2 size={15} className="text-slate-400"/><div><p className="font-medium text-slate-700">{c.organizationName}</p><p className="mt-0.5 text-xs text-slate-400">{c.organizationSlug}</p></div></div></td><td className="px-5 py-4 text-slate-600">{formatDate(c.registeredAt)}</td><td className="px-5 py-4"><span className={"rounded-full px-2.5 py-1 text-xs font-medium "+(c.userStatus === "ACTIVE" ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-600")}>{c.userStatus}</span><p className="mt-1 text-[11px] text-slate-400">Workspace: {c.organizationStatus}</p></td><td className="px-5 py-4"><div className="flex items-center gap-2"><Server size={15} className="text-slate-400"/><span className="font-semibold tabular-nums">{c.hostingAccounts}</span><span className="text-xs text-slate-400">total</span></div><p className="mt-1 text-[11px] text-slate-500">{c.activeHostingAccounts} active · {c.pendingHostingAccounts} pending</p></td></tr>)}</tbody></table></div>}
      </section>
      <p className="text-xs leading-5 text-slate-400">Read-only platform directory. Passwords, session tokens and website files are never exposed here. Hosting lifecycle is managed separately under Hosting accounts.</p>
    </section>
  </main>;
}

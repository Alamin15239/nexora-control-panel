"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, Search, Users, Building2, Server, ShieldAlert, Trash2, AlertTriangle } from "lucide-react";

type Customer = {
  userId: string; email: string; displayName: string | null; userStatus: string; registeredAt: string;
  organizationId: string; organizationName: string; organizationSlug: string; organizationStatus: string;
  hostingAccounts: number; activeHostingAccounts: number; pendingHostingAccounts: number;
};

export default function CustomerAccountsPage() {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [search, setSearch] = useState("");
  const [deleting, setDeleting] = useState<Customer | null>(null);
  const [confirmEmail, setConfirmEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
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
  async function permanentlyDeleteCustomer() {
    if (!deleting || confirmEmail.trim().toLowerCase() !== deleting.email.toLowerCase()) return;
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/platform/customers/${encodeURIComponent(deleting.userId)}`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirmEmail: confirmEmail.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to delete the customer account.");
      setCustomers(current => current.filter(customer => customer.userId !== deleting.userId));
      setNotice(String(data.message || "Customer account permanently deleted."));
      setDeleting(null); setConfirmEmail("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to delete the customer account.");
    } finally { setSubmitting(false); }
  }
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
      {notice && <div role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</div>}
      {error && <div role="alert" className="flex items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"><ShieldAlert size={17} className="mt-0.5 shrink-0"/><div>{error}</div></div>}
      <div className="flex flex-wrap items-center justify-between gap-3"><label className="relative block w-full max-w-md"><Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search name, email or organization…" className="w-full rounded-xl border border-slate-200 bg-white py-2.5 pl-9 pr-3 text-sm outline-none focus:border-blue-500"/></label><span className="text-xs text-slate-500">Showing {filtered.length} of {customers.length}</span></div>
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        {loading ? <div className="p-12 text-center text-sm text-slate-500">Loading customer directory…</div> : filtered.length === 0 ? <div className="p-12 text-center"><Users size={30} className="mx-auto text-slate-300"/><p className="mt-3 text-sm text-slate-600">{customers.length ? "No customers match your search." : "No registered customer accounts found."}</p></div> : <div className="overflow-x-auto"><table className="w-full min-w-[950px] text-left text-sm"><thead className="bg-slate-50 text-[11px] uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-semibold">Customer</th><th className="px-5 py-3 font-semibold">Organization</th><th className="px-5 py-3 font-semibold">Registered</th><th className="px-5 py-3 font-semibold">Account status</th><th className="px-5 py-3 font-semibold">Hosting accounts</th><th className="px-5 py-3 font-semibold">Actions</th></tr></thead><tbody className="divide-y divide-slate-100">{filtered.map(c => <tr key={c.userId+":"+c.organizationId} className="hover:bg-slate-50/70"><td className="px-5 py-4"><p className="font-semibold text-slate-800">{c.displayName || "—"}</p><p className="mt-1 text-xs text-slate-500">{c.email}</p></td><td className="px-5 py-4"><div className="flex items-center gap-2"><Building2 size={15} className="text-slate-400"/><div><p className="font-medium text-slate-700">{c.organizationName}</p><p className="mt-0.5 text-xs text-slate-400">{c.organizationSlug}</p></div></div></td><td className="px-5 py-4 text-slate-600">{formatDate(c.registeredAt)}</td><td className="px-5 py-4"><span className={"rounded-full px-2.5 py-1 text-xs font-medium "+(c.userStatus === "ACTIVE" ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-600")}>{c.userStatus}</span><p className="mt-1 text-[11px] text-slate-400">Workspace: {c.organizationStatus}</p></td><td className="px-5 py-4"><div className="flex items-center gap-2"><Server size={15} className="text-slate-400"/><span className="font-semibold tabular-nums">{c.hostingAccounts}</span><span className="text-xs text-slate-400">total</span></div><p className="mt-1 text-[11px] text-slate-500">{c.activeHostingAccounts} active · {c.pendingHostingAccounts} pending</p></td><td className="px-5 py-4"><button type="button" onClick={() => { setDeleting(c); setConfirmEmail(""); setError(""); }} className="inline-flex items-center gap-1.5 rounded-lg border border-rose-200 px-2.5 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-50"><Trash2 size={13}/> Delete login</button></td></tr>)}</tbody></table></div>}
      </section>
      <p className="text-xs leading-5 text-slate-400">Deleting a login revokes all sessions and user access. It does not delete organizations, hosting accounts, website files, databases, backups, or billing history. Ownership must be transferred before deletion.</p>
    </section>
    {deleting && <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/50 p-4" role="dialog" aria-modal="true" aria-label="Permanently delete customer login">
      <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-2xl">
        <div className="flex items-start gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-rose-50 text-rose-700"><AlertTriangle size={19}/></span><div><h2 className="text-lg font-semibold text-slate-900">Permanently delete customer login?</h2><p className="mt-1 text-sm leading-6 text-slate-600">This permanently deletes <strong>{deleting.email}</strong>, revokes every session, and removes all organization and hosting-account access for this user. This cannot be undone.</p></div></div>
        <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900">Organizations, hosting accounts, websites, databases, backups, domains, subscriptions, invoices, and audit history are retained. Deletion is blocked if this user is the sole owner of an organization or hosting account, or has platform staff privileges.</div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Type the customer&apos;s email to confirm</span><input autoFocus value={confirmEmail} onChange={event => setConfirmEmail(event.target.value)} placeholder={deleting.email} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-rose-400"/></label>
        <div className="mt-6 flex justify-end gap-2"><button type="button" onClick={() => { setDeleting(null); setConfirmEmail(""); }} disabled={submitting} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50">Cancel</button><button type="button" onClick={() => void permanentlyDeleteCustomer()} disabled={submitting || confirmEmail.trim().toLowerCase() !== deleting.email.toLowerCase()} className="inline-flex items-center gap-1.5 rounded-xl bg-rose-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-rose-800 disabled:cursor-not-allowed disabled:opacity-40">{submitting ? "Deleting…" : <><Trash2 size={13}/> Permanently delete login</>}</button></div>
      </div>
    </div>}
  </main>;
}

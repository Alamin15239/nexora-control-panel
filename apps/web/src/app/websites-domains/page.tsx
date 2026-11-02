"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, CircleAlert, Globe2, Plus, RefreshCw } from "lucide-react";

type Account = { id: string; username: string; primary_domain: string | null; status: string };
type Domain = { id: string; name: string; document_root: string; is_primary: number; created_at: string; hosting_account_id: string; username: string; account_status: string; server_hostname: string; job_status: string | null };
const blank = { name: "", accountId: "", documentRoot: "", isPrimary: false };

export default function WebsitesDomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [form, setForm] = useState(blank);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [d, a] = await Promise.all([
        fetch("/api/control/domains", { cache: "no-store" }),
        fetch("/api/control/hosting-accounts", { cache: "no-store" }),
      ]);
      const [dd, ad] = await Promise.all([d.json(), a.json()]);
      if (!d.ok) throw new Error(dd.message || "Unable to load domains");
      if (!a.ok) throw new Error(ad.message || "Unable to load hosting accounts");
      setDomains(dd.domains || []); setAccounts(ad.accounts || []);
      setForm(v => ({ ...v, accountId: v.accountId || ad.accounts?.[0]?.id || "" }));
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load domain data"); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function addDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/domains", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(form),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to add domain");
      setNotice(data.message || "Domain saved.");
      setForm(v => ({ ...blank, accountId: v.accountId }));
      setShowForm(false); await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to add domain"); }
    finally { setBusy(false); }
  }

  return <main className="min-h-screen bg-slate-50 text-slate-900">
    <header className="border-b border-slate-200 bg-white"><div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
      <div className="flex items-center gap-3"><Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Globe2 size={20}/></span><div><p className="font-semibold">Websites & domains</p><p className="text-xs text-slate-500">Nexora Control / Websites</p></div></div>
      <button onClick={() => void load()} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-7xl space-y-6 px-5 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-blue-700">Website management</p><h1 className="mt-1 text-2xl font-semibold tracking-tight">Websites & domains</h1><p className="mt-2 max-w-2xl text-sm text-slate-500">Attach domains to customer hosting accounts and define their website document roots.</p></div><button onClick={() => setShowForm(v => !v)} disabled={accounts.length === 0} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-50"><Plus size={17}/> Add domain</button></div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      {showForm && <form onSubmit={addDomain} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-5"><h2 className="font-semibold">Add a domain</h2><p className="mt-1 text-xs text-slate-500">The domain record is saved now; virtual-host configuration is queued for a connected Linux agent.</p></div>
        <div className="grid gap-4 md:grid-cols-2">
          <label className="text-xs font-medium text-slate-600">Domain name<input required value={form.name} onChange={e=>setForm(v=>({...v,name:e.target.value.toLowerCase()}))} placeholder="example.com" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm outline-none focus:border-blue-500"/></label>
          <label className="text-xs font-medium text-slate-600">Hosting account<select required value={form.accountId} onChange={e=>setForm(v=>({...v,accountId:e.target.value}))} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm"><option value="">Select account</option>{accounts.map(a=><option key={a.id} value={a.id}>{a.username} · {a.status}</option>)}</select></label>
          <label className="text-xs font-medium text-slate-600 md:col-span-2">Document root (optional)<input value={form.documentRoot} onChange={e=>setForm(v=>({...v,documentRoot:e.target.value}))} placeholder="/home/username/public_html/example.com" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm outline-none focus:border-blue-500"/><span className="mt-1 block font-normal text-slate-400">Must be inside the selected account&apos;s public_html directory. Private home folders are not allowed. Leave blank to use the default path.</span></label>
          <label className="flex items-center gap-2 text-sm text-slate-600 md:col-span-2"><input type="checkbox" checked={form.isPrimary} onChange={e=>setForm(v=>({...v,isPrimary:e.target.checked}))}/> Set as the primary domain for this account</label>
        </div>
        <div className="mt-5 flex justify-end gap-2"><button type="button" onClick={()=>setShowForm(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-medium text-slate-600">Cancel</button><button disabled={busy} className="rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50">{busy?"Saving…":"Save domain"}</button></div>
      </form>}
      <div className="grid gap-4 sm:grid-cols-3"><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Domains</p><p className="mt-2 text-3xl font-semibold">{domains.length}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Primary domains</p><p className="mt-2 text-3xl font-semibold">{domains.filter(d=>d.is_primary===1).length}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Awaiting server setup</p><p className="mt-2 text-3xl font-semibold">{domains.filter(d => d.job_status !== "SUCCEEDED").length}</p></div></div>
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm"><div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Domain inventory</h2><p className="mt-1 text-xs text-slate-500">Domains registered in the current workspace.</p></div>
        {loading?<div className="p-10 text-center text-sm text-slate-500">Loading domains…</div>:domains.length===0?<div className="p-12 text-center"><Globe2 size={32} className="mx-auto text-slate-300"/><h3 className="mt-3 font-medium">No domains configured</h3><p className="mt-1 text-sm text-slate-500">Create a hosting account first, then attach its domain here.</p><Link href="/hosting-accounts" className="mt-4 inline-flex text-sm font-medium text-blue-700 hover:underline">Open hosting accounts</Link></div>:<div className="overflow-x-auto"><table className="w-full min-w-[850px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-medium">Domain</th><th className="px-5 py-3 font-medium">Hosting account</th><th className="px-5 py-3 font-medium">Document root</th><th className="px-5 py-3 font-medium">DNS</th><th className="px-5 py-3 font-medium">Server setup</th><th className="px-5 py-3 font-medium">SSL</th></tr></thead><tbody className="divide-y divide-slate-100">{domains.map(d=><tr key={d.id}><td className="px-5 py-4"><p className="font-medium">{d.name}</p>{d.is_primary===1&&<span className="mt-1 inline-flex rounded-full bg-blue-50 px-2 py-0.5 text-xs text-blue-700">Primary</span>}</td><td className="px-5 py-4"><p>{d.username}</p><p className="mt-1 text-xs text-slate-500">{d.server_hostname} · {d.account_status}</p></td><td className="px-5 py-4 font-mono text-xs text-slate-600">{d.document_root}</td><td className="px-5 py-4"><span className={"rounded-full px-2.5 py-1 text-xs " + (d.job_status === "SUCCEEDED" ? "bg-emerald-50 text-emerald-700" : d.job_status === "FAILED" ? "bg-red-50 text-red-700" : "bg-amber-50 text-amber-700")}>{d.job_status === "SUCCEEDED" ? "Configured" : d.job_status === "FAILED" ? "Failed" : d.job_status === "RUNNING" ? "Configuring" : "Queued"}</span></td><td className="px-5 py-4"><span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-600">Not issued</span></td></tr>)}</tbody></table></div>}
      </section>
      <p className="flex items-start gap-2 text-xs leading-5 text-slate-400"><CircleAlert size={14} className="mt-0.5 shrink-0"/> DNS records and SSL certificates are not configured by this screen yet. A connected hosting agent and DNS provider integration are required to verify DNS and install certificates.</p>
    </section>
  </main>;
}

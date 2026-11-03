"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Box, HardDrive, Globe2, Database, Mail, Plus, RefreshCw, ShieldCheck } from "lucide-react";

type Plan = {
  id: string;
  name: string;
  disk_limit_bytes: number;
  bandwidth_limit_bytes: number | null;
  website_limit: number;
  database_limit: number;
  mailbox_limit: number;
  active: number;
  created_at: string;
};

const emptyForm = { name: "", diskGb: "10", bandwidthGb: "100", websiteLimit: "1", databaseLimit: "2", mailboxLimit: "5" };
const gb = (bytes: number | null) => bytes == null ? "Unlimited" : `${(bytes / 1024 ** 3).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB`;

export default function HostingPlansPage() {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [editingPlanId, setEditingPlanId] = useState("");
  const [websiteLimitDraft, setWebsiteLimitDraft] = useState("5");

  const loadPlans = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/control/hosting-plans", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load hosting plans");
      setPlans(data.plans ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load hosting plans");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadPlans(); }, [loadPlans]);

  async function saveWebsiteLimit(planId: string) {
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/hosting-plans/${planId}/website-limit`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ websiteLimit: Number(websiteLimitDraft) }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to update website limit");
      setNotice(`Website limit for “${data.plan.name}” updated to ${data.plan.website_limit}.`);
      setEditingPlanId("");
      await loadPlans();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to update website limit");
    } finally {
      setBusy(false);
    }
  }

  async function createPlan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/hosting-plans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: form.name,
          diskGb: Number(form.diskGb),
          bandwidthGb: form.bandwidthGb === "" ? null : Number(form.bandwidthGb),
          websiteLimit: Number(form.websiteLimit),
          databaseLimit: Number(form.databaseLimit),
          mailboxLimit: Number(form.mailboxLimit),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to create hosting plan");
      setNotice(`Hosting plan “${data.plan.name}” created successfully.`);
      setForm(emptyForm); setShowForm(false);
      await loadPlans();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to create hosting plan");
    } finally {
      setBusy(false);
    }
  }

  return <main className="min-h-screen bg-slate-50 text-slate-900">
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
        <div className="flex items-center gap-3">
          <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Box size={20}/></span>
          <div><p className="font-semibold">Hosting plans</p><p className="text-xs text-slate-500">Nexora Control / Products</p></div>
        </div>
        <button onClick={() => void loadPlans()} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50"><RefreshCw size={15}/> Refresh</button>
      </div>
    </header>

    <section className="mx-auto max-w-7xl space-y-6 px-5 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div><p className="text-sm font-medium text-blue-700">Product configuration</p><h1 className="mt-1 text-2xl font-semibold tracking-tight">Hosting plans</h1><p className="mt-2 max-w-2xl text-sm text-slate-500">Define the resource quotas that can be assigned to customer hosting accounts. Plans are scoped to your active workspace.</p></div>
        <button onClick={() => setShowForm(v => !v)} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-800"><Plus size={17}/> Create plan</button>
      </div>

      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}

      {showForm && <form onSubmit={createPlan} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-5"><h2 className="font-semibold">New hosting plan</h2><p className="mt-1 text-xs text-slate-500">Set quotas for disk, bandwidth, websites, databases and mailboxes.</p></div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <label className="text-xs font-medium text-slate-600 sm:col-span-2 lg:col-span-3">Plan name<input required maxLength={80} value={form.name} onChange={e => setForm(v => ({...v,name:e.target.value}))} placeholder="Starter" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm outline-none focus:border-blue-500"/></label>
          {([{key:"diskGb",label:"Disk quota (GB)"},{key:"bandwidthGb",label:"Monthly bandwidth (GB)"},{key:"websiteLimit",label:"Websites"},{key:"databaseLimit",label:"Databases"},{key:"mailboxLimit",label:"Mailboxes"}] as const).map(item => <label key={item.key} className="text-xs font-medium text-slate-600">{item.label}<input type="number" min={item.key==="diskGb" || item.key==="bandwidthGb" ? 1 : 0} max={item.key==="bandwidthGb" ? 1000000 : 100000} step="1" value={form[item.key]} onChange={e => setForm(v => ({...v,[item.key]:e.target.value}))} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm outline-none focus:border-blue-500"/></label>)}
        </div>
        <div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setShowForm(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-medium text-slate-600">Cancel</button><button disabled={busy} className="rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60">{busy ? "Creating…" : "Create hosting plan"}</button></div>
      </form>}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Total plans</p><p className="mt-2 text-3xl font-semibold">{plans.length}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Active plans</p><p className="mt-2 text-3xl font-semibold">{plans.filter(p=>p.active===1).length}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Website quota</p><p className="mt-2 text-3xl font-semibold">{plans.reduce((n,p)=>n+p.website_limit,0)}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Database quota</p><p className="mt-2 text-3xl font-semibold">{plans.reduce((n,p)=>n+p.database_limit,0)}</p></div>
      </div>

      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h2 className="font-semibold">Plan catalogue</h2><p className="mt-1 text-xs text-slate-500">Resource limits configured for this workspace.</p></div><span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">{plans.length} plans</span></div>
        {loading ? <div className="p-10 text-center text-sm text-slate-500">Loading hosting plans…</div> : plans.length===0 ? <div className="p-12 text-center"><Box size={32} className="mx-auto text-slate-300"/><h3 className="mt-3 font-medium">No hosting plans yet</h3><p className="mt-1 text-sm text-slate-500">Create your first plan before provisioning customer accounts.</p><button onClick={()=>setShowForm(true)} className="mt-4 rounded-lg bg-blue-700 px-4 py-2 text-sm font-medium text-white">Create first plan</button></div> : <div className="grid gap-4 p-5 md:grid-cols-2 xl:grid-cols-3">{plans.map(plan=><article key={plan.id} className="rounded-2xl border border-slate-200 p-5"><div className="flex items-start justify-between gap-3"><div><h3 className="font-semibold">{plan.name}</h3><p className="mt-1 text-xs text-slate-500">Created {new Date(plan.created_at).toLocaleDateString()}</p></div><span className={"rounded-full px-2.5 py-1 text-xs font-medium "+(plan.active===1?"bg-emerald-50 text-emerald-700":"bg-slate-100 text-slate-500")}>{plan.active===1?"Active":"Inactive"}</span></div><div className="mt-5 grid grid-cols-2 gap-3"><div className="rounded-xl bg-slate-50 p-3"><HardDrive size={16} className="text-slate-500"/><p className="mt-2 text-sm font-semibold">{gb(plan.disk_limit_bytes)}</p><p className="text-xs text-slate-500">Disk</p></div><div className="rounded-xl bg-slate-50 p-3"><ActivityIcon/><p className="mt-2 text-sm font-semibold">{gb(plan.bandwidth_limit_bytes)}</p><p className="text-xs text-slate-500">Bandwidth</p></div><div className="rounded-xl bg-slate-50 p-3"><Globe2 size={16} className="text-slate-500"/><p className="mt-2 text-sm font-semibold">{plan.website_limit}</p><p className="text-xs text-slate-500">Websites</p></div><div className="rounded-xl bg-slate-50 p-3"><Database size={16} className="text-slate-500"/><p className="mt-2 text-sm font-semibold">{plan.database_limit}</p><p className="text-xs text-slate-500">Databases</p></div><div className="rounded-xl bg-slate-50 p-3"><Mail size={16} className="text-slate-500"/><p className="mt-2 text-sm font-semibold">{plan.mailbox_limit}</p><p className="text-xs text-slate-500">Mailboxes</p></div></div><div className="mt-4 flex flex-wrap items-center justify-between gap-2"><span className="flex items-center gap-2 text-xs text-slate-500"><ShieldCheck size={14}/> Workspace-isolated resource policy</span><button type="button" onClick={()=>{setEditingPlanId(editingPlanId===plan.id?"":plan.id);setWebsiteLimitDraft(String(plan.website_limit));}} className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50">{editingPlanId===plan.id?"Close":"Change website limit"}</button></div>{editingPlanId===plan.id&&<div className="mt-3 flex items-end gap-2 rounded-xl bg-slate-50 p-3"><label className="flex-1 text-xs font-medium text-slate-600">Websites allowed<input type="number" min="1" max="10000" step="1" value={websiteLimitDraft} onChange={e=>setWebsiteLimitDraft(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm"/></label><button type="button" disabled={busy||!/^[0-9]+$/.test(websiteLimitDraft)||Number(websiteLimitDraft)<1||Number(websiteLimitDraft)>10000} onClick={()=>void saveWebsiteLimit(plan.id)} className="rounded-lg bg-blue-700 px-3 py-2 text-xs font-semibold text-white disabled:opacity-50">{busy?"Saving…":"Save"}</button></div>}</article>)}</div>}
      </section>
      <p className="text-xs leading-5 text-slate-400">Plans define intended quotas only. Actual enforcement requires a connected Linux server agent and a supported hosting runtime; creating a plan does not provision a server or allocate physical resources.</p>
    </section>
  </main>;
}

function ActivityIcon() {
  return <HardDrive size={16} className="text-slate-500"/>;
}

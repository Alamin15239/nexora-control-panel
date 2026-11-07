"use client";

import { Fragment, FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, CircleAlert, Clock3, Globe2, Plus, RefreshCw, Server, Users, UserPlus } from "lucide-react";

type ServerItem = { id: string; hostname: string; status: string };
type PlanItem = { id: string; name: string; active: number; disk_limit_bytes: number; website_limit: number; database_limit: number; mailbox_limit: number };
type Account = { id: string; username: string; primary_domain: string | null; status: string; created_at: string; server_id: string; server_hostname: string; plan_id: string; plan_name: string; job_status: string | null };
type AccountMember = { id: string; userId: string; email: string; displayName: string | null; role: string; status: string; createdAt: string };

const blank = { username: "", primaryDomain: "", serverId: "", planId: "" };

export default function HostingAccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [servers, setServers] = useState<ServerItem[]>([]);
  const [plans, setPlans] = useState<PlanItem[]>([]);
  const [form, setForm] = useState(blank);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [membershipAccountId, setMembershipAccountId] = useState("");
  const [members, setMembers] = useState<AccountMember[]>([]);
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState("ACCOUNT_OWNER");
  const [memberBusy, setMemberBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [a, s, p] = await Promise.all([
        fetch("/api/control/hosting-accounts", { cache: "no-store" }),
        fetch("/api/control/servers", { cache: "no-store" }),
        fetch("/api/control/hosting-plans", { cache: "no-store" }),
      ]);
      const [ad, sd, pd] = await Promise.all([a.json(), s.json(), p.json()]);
      if (!a.ok) throw new Error(ad.message || "Unable to load hosting accounts");
      if (!s.ok) throw new Error(sd.message || "Unable to load servers");
      if (!p.ok) throw new Error(pd.message || "Unable to load hosting plans");
      setAccounts(ad.accounts ?? []); setServers(sd.servers ?? []); setPlans(pd.plans ?? []);
      setForm(v => ({ ...v, serverId: v.serverId || sd.servers?.[0]?.id || "", planId: v.planId || pd.plans?.find((x: PlanItem) => x.active === 1)?.id || "" }));
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load hosting data"); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function createAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/hosting-accounts", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to create hosting account");
      setNotice(data.message || "Hosting account request queued.");
      setForm(v => ({ ...blank, serverId: v.serverId, planId: v.planId }));
      setShowForm(false);
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to create hosting account"); }
    finally { setBusy(false); }
  }

  async function openMemberships(accountId: string) {
    setError(""); setNotice("");
    if (membershipAccountId === accountId) { setMembershipAccountId(""); setMembers([]); return; }
    setMembershipAccountId(accountId); setMembers([]);
    try {
      const response = await fetch(`/api/control/hosting-accounts/${encodeURIComponent(accountId)}/memberships`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load account access.");
      setMembers(data.memberships ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load account access."); }
  }

  async function assignMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!membershipAccountId) return;
    setMemberBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/hosting-accounts/${encodeURIComponent(membershipAccountId)}/memberships`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: memberEmail, role: memberRole }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to assign account access.");
      setMemberEmail(""); setNotice(data.message || "Account access assigned.");
      const refreshed = await fetch(`/api/control/hosting-accounts/${encodeURIComponent(membershipAccountId)}/memberships`, { cache: "no-store" });
      const refreshedData = await refreshed.json();
      if (refreshed.ok) setMembers(refreshedData.memberships ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to assign account access."); }
    finally { setMemberBusy(false); }
  }

  const pending = accounts.filter(a => a.status === "PENDING").length;
  const active = accounts.filter(a => a.status === "ACTIVE").length;

  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85 backdrop-blur-xl"><div className="mx-auto flex max-w-[1500px] items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3"><Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Users size={20}/></span><div><p className="font-semibold">Hosting accounts</p><p className="text-xs text-slate-500">Nexora Control / Customers</p></div></div>
      <button onClick={() => void load()} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1500px] space-y-7 px-6 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-blue-700">Customer hosting</p><h1 className="mt-1 text-3xl font-semibold tracking-tight text-slate-950">Hosting accounts</h1><p className="mt-2 max-w-2xl text-sm text-slate-500">Create customer hosting accounts, assign a Linux server and apply a workspace hosting plan.</p></div><button onClick={() => setShowForm(v => !v)} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800"><Plus size={17}/> Create account</button></div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      {showForm && <form onSubmit={createAccount} className="rounded-2xl border border-slate-200/80 bg-white p-5 shadow-[0_8px_30px_rgba(15,23,42,0.04)]">
        <div className="mb-5"><h2 className="font-semibold">New hosting account</h2><p className="mt-1 text-xs text-slate-500">The agent creates the restricted Linux account and document root. If you enter a primary domain, Nexora automatically queues its Nginx website configuration after account creation. DNS and TLS still require separate setup.</p></div>
        <div className="grid gap-4 md:grid-cols-2">
          <label className="text-xs font-medium text-slate-600">System username<input required minLength={3} maxLength={16} pattern="[a-z][a-z0-9_]{2,15}" value={form.username} onChange={e=>setForm(v=>({...v,username:e.target.value.toLowerCase()}))} placeholder="customer01" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm outline-none focus:border-blue-500"/><span className="mt-1 block font-normal text-slate-400">3–16 lowercase letters, numbers or underscores.</span></label>
          <label className="text-xs font-medium text-slate-600">Primary domain (optional)<input value={form.primaryDomain} onChange={e=>setForm(v=>({...v,primaryDomain:e.target.value.toLowerCase()}))} placeholder="example.com" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm outline-none focus:border-blue-500"/></label>
          <label className="text-xs font-medium text-slate-600">Linux server<select required value={form.serverId} onChange={e=>setForm(v=>({...v,serverId:e.target.value}))} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-blue-500"><option value="">Select server</option>{servers.map(s=><option key={s.id} value={s.id}>{s.hostname} · {s.status}</option>)}</select></label>
          <label className="text-xs font-medium text-slate-600">Hosting plan<select required value={form.planId} onChange={e=>setForm(v=>({...v,planId:e.target.value}))} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-blue-500"><option value="">Select plan</option>{plans.filter(p=>p.active===1).map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
        </div>
        {(servers.length===0 || plans.filter(p=>p.active===1).length===0) && <p className="mt-4 flex items-start gap-2 rounded-xl bg-amber-50 p-3 text-xs leading-5 text-amber-800"><CircleAlert size={16} className="mt-0.5 shrink-0"/>{servers.length===0 ? "Register a Linux server first. A server record alone does not provide hosting capacity." : "Create an active hosting plan first."}</p>}
        <div className="mt-5 flex justify-end gap-2"><button type="button" onClick={()=>setShowForm(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-medium text-slate-600">Cancel</button><button disabled={busy || servers.length===0 || plans.every(p=>p.active!==1)} className="rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50">{busy?"Queueing…":"Create hosting account"}</button></div>
      </form>}
      <div className="grid gap-4 sm:grid-cols-3"><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Total accounts</p><p className="mt-2 text-3xl font-semibold">{accounts.length}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Active</p><p className="mt-2 text-3xl font-semibold">{active}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Pending provisioning</p><p className="mt-2 text-3xl font-semibold">{pending}</p></div></div>
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm"><div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h2 className="font-semibold">Customer account inventory</h2><p className="mt-1 text-xs text-slate-500">Accounts and provisioning status for the current workspace.</p></div><span className="rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-600">{accounts.length} accounts</span></div>
        {loading?<div className="p-10 text-center text-sm text-slate-500">Loading hosting accounts…</div>:accounts.length===0?<div className="p-12 text-center"><Users size={32} className="mx-auto text-slate-300"/><h3 className="mt-3 font-medium">No hosting accounts yet</h3><p className="mt-1 text-sm text-slate-500">Create a hosting plan and register a server to prepare your first account.</p></div>:<div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-medium">Account</th><th className="px-5 py-3 font-medium">Server</th><th className="px-5 py-3 font-medium">Plan</th><th className="px-5 py-3 font-medium">Status</th><th className="px-5 py-3 font-medium">Provisioning job</th><th className="px-5 py-3 font-medium">Created</th><th className="px-5 py-3 font-medium">Access</th></tr></thead><tbody className="divide-y divide-slate-100">{accounts.map(a=><Fragment key={a.id}>
          <tr key={a.id} className="hover:bg-slate-50/70"><td className="px-5 py-4"><p className="font-medium">{a.username}</p><p className="mt-1 text-xs text-slate-500">{a.primary_domain||"No domain assigned"}</p></td><td className="px-5 py-4 text-slate-600">{a.server_hostname}</td><td className="px-5 py-4 text-slate-600">{a.plan_name}</td><td className="px-5 py-4"><span className={"rounded-full px-2.5 py-1 text-xs font-medium "+(a.status==="ACTIVE"?"bg-emerald-50 text-emerald-700":"bg-amber-50 text-amber-700")}>{a.status}</span></td><td className="px-5 py-4"><span className="inline-flex items-center gap-1.5 text-xs text-slate-600"><Clock3 size={13}/>{a.job_status||"No job"}</span></td><td className="px-5 py-4 text-xs text-slate-500">{new Date(a.created_at).toLocaleDateString()}</td><td className="px-5 py-4"><button onClick={() => void openMemberships(a.id)} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:border-blue-300 hover:text-blue-700"><UserPlus size={13}/>{membershipAccountId===a.id?"Close":"Access"}</button></td></tr>
          {membershipAccountId===a.id && <tr key={a.id+"-members"}><td colSpan={7} className="bg-slate-50/70 px-5 py-5">
            <div className="grid gap-5 lg:grid-cols-[1fr_1fr]">
              <div><h3 className="text-sm font-semibold text-slate-800">Assigned customer users</h3><p className="mt-1 text-xs text-slate-500">Any active Nexora login can be assigned to this hosting account.</p>
                {members.length===0?<p className="mt-4 rounded-xl border border-dashed border-slate-300 bg-white p-4 text-xs text-slate-500">No members assigned yet, or no active members were returned.</p>:<div className="mt-3 space-y-2">{members.map(member=><div key={member.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2.5"><div><p className="text-xs font-semibold text-slate-800">{member.displayName||member.email}</p><p className="mt-0.5 text-[11px] text-slate-500">{member.email}</p></div><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold "+(member.status==="ACTIVE"?"bg-emerald-50 text-emerald-700":"bg-slate-100 text-slate-500")}>{member.role.replace("ACCOUNT_","")} · {member.status}</span></div>)}</div>}
              </div>
              <form onSubmit={assignMember} className="rounded-xl border border-slate-200 bg-white p-4"><h3 className="text-sm font-semibold text-slate-800">Grant account access</h3><label className="mt-3 block text-xs font-medium text-slate-600">Customer Nexora login email<input required type="email" value={memberEmail} onChange={event=>setMemberEmail(event.target.value)} placeholder="customer@example.com" className="mt-1.5 w-full rounded-lg border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-500"/></label><label className="mt-3 block text-xs font-medium text-slate-600">Account role<select value={memberRole} onChange={event=>setMemberRole(event.target.value)} className="mt-1.5 w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm"><option value="ACCOUNT_OWNER">Account owner</option><option value="ACCOUNT_ADMIN">Account admin</option><option value="ACCOUNT_DEVELOPER">Developer</option><option value="ACCOUNT_READONLY">Read only</option></select></label><p className="mt-2 text-[11px] leading-5 text-slate-400">The customer must first register a Nexora login. You can then assign this hosting account even if their login belongs to a different workspace.</p><button disabled={memberBusy} className="mt-4 inline-flex items-center justify-center rounded-lg bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white disabled:opacity-50">{memberBusy?"Assigning…":"Grant access"}</button></form>
            </div>
          </td></tr>}
        </Fragment>)}</tbody></table></div>}
      </section>
      <p className="text-xs leading-5 text-slate-400">Provisioning creates a non-login Linux user and its public_html directory. A public website is not live until web-server, DNS and TLS services are configured.</p>
    </section>
  </main>;
}

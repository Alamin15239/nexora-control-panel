"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Database, Plus, RefreshCw, ShieldCheck, Users } from "lucide-react";

type Account = { id: string; username: string; status: string };
type Db = { id: string; name: string; engine: string; status: string; hosting_account_id: string; account_username: string; plan_database_limit: number; users: number };
type DbUser = { id: string; username: string; privileges: string; status: string };
const permissions = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "INDEX"];

export default function DatabasesPage() {
  const [databases, setDatabases] = useState<Db[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [users, setUsers] = useState<DbUser[]>([]);
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [engine, setEngine] = useState("MYSQL");
  const [username, setUsername] = useState("");
  const [privileges, setPrivileges] = useState<string[]>(["SELECT", "INSERT", "UPDATE", "DELETE"]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [d, a] = await Promise.all([
        fetch("/api/control/databases", { cache: "no-store" }),
        fetch("/api/control/hosting-accounts", { cache: "no-store" }),
      ]);
      const [dd, aa] = await Promise.all([d.json(), a.json()]);
      if (!d.ok) throw new Error(dd.message || "Unable to load databases");
      if (!a.ok) throw new Error(aa.message || "Unable to load hosting accounts");
      setDatabases(dd.databases || []); setAccounts(aa.accounts || []);
      setAccountId(v => v || aa.accounts?.[0]?.id || "");
      setSelected(v => v || dd.databases?.[0]?.id || "");
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load database information"); }
    finally { setLoading(false); }
  }, []);

  const loadUsers = useCallback(async (id: string) => {
    if (!id) { setUsers([]); return; }
    try {
      const response = await fetch(`/api/control/databases/${id}/users`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load database users");
      setUsers(data.users || []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load database users"); }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { void loadUsers(selected); }, [selected, loadUsers]);

  const current = databases.find(d => d.id === selected);
  return <main className="min-h-screen bg-slate-50 text-slate-900">
    <header className="border-b border-slate-200 bg-white"><div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
      <div className="flex items-center gap-3"><Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Database size={20}/></span><div><p className="font-semibold">Database management</p><p className="text-xs text-slate-500">Nexora Control / Databases</p></div></div>
      <button onClick={() => { void load(); if (selected) void loadUsers(selected); }} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-7xl space-y-6 px-5 py-8">
      <div><p className="text-sm font-medium text-blue-700">Customer resources</p><h1 className="mt-1 text-2xl font-semibold tracking-tight">Databases</h1><p className="mt-2 max-w-2xl text-sm text-slate-500">View database records and access policies. Provisioning controls remain unavailable until the Linux database service is installed and secured.</p></div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      <div className="grid gap-4 sm:grid-cols-3"><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Databases</p><p className="mt-2 text-3xl font-semibold">{databases.length}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Active</p><p className="mt-2 text-3xl font-semibold">{databases.filter(d=>d.status==="ACTIVE").length}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Pending provisioning</p><p className="mt-2 text-3xl font-semibold">{databases.filter(d=>d.status==="PENDING").length}</p></div></div>
      <div className="grid gap-6 xl:grid-cols-2">
        <form onSubmit={event => event.preventDefault()} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <h2 className="font-semibold">Create database</h2><p className="mt-1 text-xs text-amber-700">Unavailable: database-engine provisioning is not installed on the connected Linux agent yet.</p>
          <div className="mt-5 space-y-4">
            <label className="block text-xs font-medium text-slate-600">Database name<input disabled required minLength={2} maxLength={31} pattern="[a-z][a-z0-9_]{1,30}" value={name} onChange={e=>setName(e.target.value.toLowerCase())} placeholder="customer_db" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm"/></label>
            <label className="block text-xs font-medium text-slate-600">Hosting account<select disabled required value={accountId} onChange={e=>setAccountId(e.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm"><option value="">Select account</option>{accounts.map(a=><option key={a.id} value={a.id}>{a.username} · {a.status}</option>)}</select></label>
            <label className="block text-xs font-medium text-slate-600">Database engine<select disabled value={engine} onChange={e=>setEngine(e.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm"><option value="MYSQL">MySQL</option><option value="MARIADB">MariaDB</option><option value="POSTGRESQL">PostgreSQL</option></select></label>
          </div>
          <button type="button" disabled className="mt-5 rounded-xl bg-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-600">Database provisioning unavailable</button>
          {!accounts.length && <p className="mt-3 text-xs text-amber-700">Create a hosting account before adding a database.</p>}
        </form>
        <form onSubmit={event => event.preventDefault()} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <h2 className="font-semibold">Database users & privileges</h2><p className="mt-1 text-xs text-amber-700">Unavailable: secure database-user creation and password delivery are not implemented yet.</p>
          <div className="mt-5 space-y-4">
            <label className="block text-xs font-medium text-slate-600">Database<select disabled required value={selected} onChange={e=>setSelected(e.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm"><option value="">Select database</option>{databases.map(d=><option key={d.id} value={d.id}>{d.name} · {d.status}</option>)}</select></label>
            <label className="block text-xs font-medium text-slate-600">Database username<input disabled required minLength={2} maxLength={31} pattern="[a-z][a-z0-9_]{1,30}" value={username} onChange={e=>setUsername(e.target.value.toLowerCase())} placeholder="app_user" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm"/></label>
            <div><p className="mb-2 text-xs font-medium text-slate-600">Privileges</p><div className="grid grid-cols-2 gap-2 sm:grid-cols-3">{permissions.map(p=><label key={p} className="flex items-center gap-2 text-xs text-slate-600"><input type="checkbox" disabled checked={privileges.includes(p)} onChange={e=>setPrivileges(v=>e.target.checked?[...v,p]:v.filter(x=>x!==p))}/>{p}</label>)}</div></div>
          </div>
          <button type="button" disabled className="mt-5 rounded-xl bg-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-600">Database-user provisioning unavailable</button>
        </form>
      </div>
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Database inventory</h2><p className="mt-1 text-xs text-slate-500">Workspace databases and provisioning state.</p></div>
        {loading?<div className="p-10 text-center text-sm text-slate-500">Loading databases…</div>:databases.length===0?<div className="p-12 text-center"><Database size={32} className="mx-auto text-slate-300"/><h3 className="mt-3 font-medium">No databases yet</h3><p className="mt-1 text-sm text-slate-500">Database-engine provisioning is not available yet. Existing database records will appear here when present.</p></div>:<div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-medium">Database</th><th className="px-5 py-3 font-medium">Account</th><th className="px-5 py-3 font-medium">Engine</th><th className="px-5 py-3 font-medium">Users</th><th className="px-5 py-3 font-medium">Status</th></tr></thead><tbody className="divide-y divide-slate-100">{databases.map(d=><tr key={d.id} className={selected===d.id?"bg-blue-50/50":""}><td className="px-5 py-4"><button onClick={()=>setSelected(d.id)} className="font-medium text-blue-700 hover:underline">{d.name}</button></td><td className="px-5 py-4">{d.account_username}</td><td className="px-5 py-4">{d.engine}</td><td className="px-5 py-4">{d.users}</td><td className="px-5 py-4"><span className="rounded-full bg-amber-50 px-2.5 py-1 text-xs text-amber-800">{d.status}</span></td></tr>)}</tbody></table></div>}
      </section>
      <section className="rounded-2xl border border-slate-200 bg-white p-5"><div className="flex items-center gap-2"><Users size={17}/><h2 className="font-semibold">Users for {current?.name || "selected database"}</h2></div>
        {!selected?<p className="mt-3 text-sm text-slate-500">Select a database to view its users.</p>:users.length===0?<p className="mt-3 text-sm text-slate-500">No database users have been requested.</p>:<div className="mt-4 divide-y divide-slate-100">{users.map(u=><div key={u.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><p className="text-sm font-medium">{u.username}</p><p className="mt-1 text-xs text-slate-500">{JSON.parse(u.privileges).join(", ")}</p></div><span className="rounded-full bg-amber-50 px-2.5 py-1 text-xs text-amber-800">{u.status}</span></div>)}</div>}
      </section>
      <p className="flex items-start gap-2 text-xs leading-5 text-slate-400"><ShieldCheck size={14} className="mt-0.5 shrink-0"/> Database inventory is read-only until a database service is installed. Database passwords must be generated and delivered through a one-time secure workflow; they must never be stored in job results or ordinary audit logs.</p>
    </section>
  </main>;
}

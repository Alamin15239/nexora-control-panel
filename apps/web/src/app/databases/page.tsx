"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Copy, Database, RefreshCw, ShieldCheck, Users } from "lucide-react";

type Account = { id: string; username: string; status: string };
type Db = {
  id: string;
  name: string;
  engine: string;
  status: string;
  hosting_account_id: string;
  account_username: string;
  plan_database_limit: number;
  users: number;
  used_bytes: number | null;
  usage_collected_at: string | null;
};
type DbUser = { id: string; username: string; privileges: string; status: string; secret_available?: number };
const permissions = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "INDEX"];

export default function DatabasesPage() {
  const [databases, setDatabases] = useState<Db[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [users, setUsers] = useState<DbUser[]>([]);
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [engine] = useState("MARIADB");
  const [creating, setCreating] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);
  const [revealedCredential, setRevealedCredential] = useState<{ username: string; password: string } | null>(null);
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
      setAccountId(v => v || aa.accounts?.find((a: Account) => a.status === "ACTIVE")?.id || "");
      setSelected(v => v || dd.databases?.[0]?.id || "");
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load database information"); }
    finally { setLoading(false); }
  }, []);

  const loadUsers = useCallback(async (id: string) => {
    if (!id) { setUsers([]); setRevealedCredential(null); return; }
    setRevealedCredential(null);
    try {
      const response = await fetch(`/api/control/databases/${id}/users`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load database users");
      setUsers(data.users || []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load database users"); }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { void loadUsers(selected); }, [selected, loadUsers]);

  const createDatabase = async () => {
    setCreating(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/databases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ accountId, name: name.trim().toLowerCase(), engine: "MARIADB" }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to queue database creation");
      setNotice(data.message || "Database creation has been queued.");
      setName("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to create database");
    } finally {
      setCreating(false);
    }
  };

  const createDatabaseUser = async () => {
    setCreatingUser(true); setError(""); setNotice(""); setRevealedCredential(null);
    try {
      const response = await fetch("/api/control/databases/" + selected + "/users", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim().toLowerCase(), privileges }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to create database user");
      setNotice(data.message || "Database user provisioning has been queued.");
      setUsername(""); await loadUsers(selected);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to create database user"); }
    finally { setCreatingUser(false); }
  };

  const revokeDatabaseUser = async (userId: string) => {
    if (!window.confirm("Revoke this database user's access? Applications using this account will stop connecting.")) return;
    setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/databases/" + selected + "/users/" + userId + "/revoke", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to revoke database user");
      setNotice("Database-user revocation has been queued.");
      await loadUsers(selected);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to revoke database user"); }
  };
  const deleteDatabase = async () => {
    if (!current) return;
    const confirmed = window.confirm(
      `Permanently delete database "${current.name}" and all its data? All database users listed for this database will also be removed. This cannot be undone.`,
    );
    if (!confirmed) return;
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/databases/${current.id}/delete`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to queue database deletion");
      setNotice(data.message || "Database deletion has been queued.");
      await load();
      await loadUsers(current.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to delete database");
    }
  };

  const revealCredential = async (userId: string) => {
    setError(""); setNotice(""); setRevealedCredential(null);
    try {
      const response = await fetch("/api/control/databases/" + selected + "/users/" + userId + "/secret", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "One-time password is unavailable");
      setRevealedCredential(data.credential);
      setNotice("This password is shown once. Copy it now and store it in a secure password manager.");
      setUsers(current => current.map(user => user.id === userId ? { ...user, secret_available: 0 } : user));
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to reveal database password"); }
  };
  const current = databases.find(d => d.id === selected);
  const activeUsers = users.filter(user => user.status === "ACTIVE");

  const formatDatabaseSize = (bytes: number | null) => {
    if (bytes === null || !Number.isFinite(bytes) || bytes < 0) return "Not measured yet";
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let value = bytes / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${units[unit]}`;
  };

  const formatUsageTime = (value: string | null) => {
    if (!value) return "Awaiting first report";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Time unavailable";
    return date.toLocaleString();
  };

  const copyConnectionSettings = async (user: DbUser) => {
    if (!current) return;
    const settings = [
      "DB_CONNECTION=mysql",
      "DB_HOST=localhost",
      "DB_PORT=3306",
      `DB_DATABASE=${current.name}`,
      `DB_USERNAME=${user.username}`,
      "DB_PASSWORD=enter_the_password_you_saved",
    ].join("\n");
    try {
      await navigator.clipboard.writeText(settings);
      setNotice("Connection settings copied. Replace the password placeholder with the password you saved.");
      setError("");
    } catch {
      setError("Unable to copy connection settings. Check your browser clipboard permissions.");
    }
  };
  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85 backdrop-blur-xl"><div className="mx-auto flex max-w-[1500px] items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3"><Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Database size={20}/></span><div><p className="font-semibold">Database management</p><p className="text-xs text-slate-500">Nexora Control / Databases</p></div></div>
      <button onClick={() => { void load(); if (selected) void loadUsers(selected); }} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1500px] space-y-7 px-6 py-8">
      <div><p className="text-sm font-medium text-blue-700">Customer resources</p><h1 className="mt-1 text-3xl font-semibold tracking-tight text-slate-950">Databases</h1><p className="mt-2 max-w-2xl text-sm text-slate-500">Create and monitor MariaDB databases for active hosting accounts.</p></div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      <div className="grid gap-4 sm:grid-cols-3"><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Databases</p><p className="mt-2 text-3xl font-semibold">{databases.length}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Active</p><p className="mt-2 text-3xl font-semibold">{databases.filter(d=>d.status==="ACTIVE").length}</p></div><div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Pending provisioning</p><p className="mt-2 text-3xl font-semibold">{databases.filter(d=>d.status==="PENDING").length}</p></div></div>
      <div className="grid gap-6 xl:grid-cols-2">
        <form onSubmit={event => { event.preventDefault(); void createDatabase(); }} className="rounded-2xl border border-slate-200/80 bg-white p-5 shadow-[0_8px_30px_rgba(15,23,42,0.04)]">
          <h2 className="font-semibold">Create database</h2><p className="mt-1 text-xs text-slate-500">Creates an isolated MariaDB database on the selected hosting server. Add restricted users below to connect your hosted applications.</p>
          <div className="mt-5 space-y-4">
            <label className="block text-xs font-medium text-slate-600">Database name<input required minLength={2} maxLength={31} pattern="[a-z][a-z0-9_]{1,30}" value={name} onChange={e=>setName(e.target.value.toLowerCase())} placeholder="customer_db" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm"/></label>
            <label className="block text-xs font-medium text-slate-600">Hosting account<select required value={accountId} onChange={e=>setAccountId(e.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm"><option value="">Select account</option>{accounts.filter(a=>a.status==="ACTIVE").map(a=><option key={a.id} value={a.id}>{a.username} · {a.status}</option>)}</select></label>
            <label className="block text-xs font-medium text-slate-600">Database engine<input disabled value={engine} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-3 text-sm"/></label>
          </div>
          <button type="submit" disabled={creating || !accountId || !name.trim()} className="mt-5 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:bg-slate-300">{creating ? "Creating database…" : "Create database"}</button>
          {!accounts.length && <p className="mt-3 text-xs text-amber-700">Create a hosting account before adding a database.</p>}
        </form>
        <form onSubmit={event => { event.preventDefault(); void createDatabaseUser(); }} className="rounded-2xl border border-slate-200/80 bg-white p-5 shadow-[0_8px_30px_rgba(15,23,42,0.04)]">
          <h2 className="font-semibold">Database users & privileges</h2><p className="mt-1 text-xs text-slate-500">Create a restricted MariaDB login. Its generated password can be revealed once for 24 hours.</p>
          <div className="mt-5 space-y-4">
            <label className="block text-xs font-medium text-slate-600">Database<select required value={selected} onChange={e=>setSelected(e.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm"><option value="">Select database</option>{databases.map(d=><option key={d.id} value={d.id}>{d.name} · {d.status}</option>)}</select></label>
            <label className="block text-xs font-medium text-slate-600">Database username<input required minLength={2} maxLength={31} pattern="[a-z][a-z0-9_]{1,30}" value={username} onChange={e=>setUsername(e.target.value.toLowerCase())} placeholder="app_user" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm"/></label>
            <div><p className="mb-2 text-xs font-medium text-slate-600">Privileges</p><div className="grid grid-cols-2 gap-2 sm:grid-cols-3">{permissions.map(p=><label key={p} className="flex items-center gap-2 text-xs text-slate-600"><input type="checkbox" checked={privileges.includes(p)} onChange={e=>setPrivileges(v=>e.target.checked?[...v,p]:v.filter(x=>x!==p))}/>{p}</label>)}</div></div>
          </div>
          <button type="submit" disabled={creatingUser || !selected || current?.status !== "ACTIVE" || !username.trim() || privileges.length === 0} className="mt-5 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:bg-slate-300">{creatingUser ? "Creating database user…" : "Create database user"}</button>
        </form>
      </div>
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Database inventory</h2><p className="mt-1 text-xs text-slate-500">Workspace databases, provisioning state, and latest measured data and index size. Measurements are collected periodically.</p></div>
        {loading?<div className="p-10 text-center text-sm text-slate-500">Loading databases…</div>:databases.length===0?<div className="p-12 text-center"><Database size={32} className="mx-auto text-slate-300"/><h3 className="mt-3 font-medium">No databases yet</h3><p className="mt-1 text-sm text-slate-500">Create a database above to provision it on the connected MariaDB server.</p></div>:<div className="overflow-x-auto"><table className="w-full min-w-[900px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-medium">Database</th><th className="px-5 py-3 font-medium">Account</th><th className="px-5 py-3 font-medium">Engine</th><th className="px-5 py-3 font-medium">Users</th><th className="px-5 py-3 font-medium">Database size</th><th className="px-5 py-3 font-medium">Status</th></tr></thead><tbody className="divide-y divide-slate-100">{databases.map(d=><tr key={d.id} className={selected===d.id?"bg-blue-50/50":""}><td className="px-5 py-4"><button onClick={()=>setSelected(d.id)} className="font-medium text-blue-700 hover:underline">{d.name}</button></td><td className="px-5 py-4">{d.account_username}</td><td className="px-5 py-4">{d.engine}</td><td className="px-5 py-4">{d.users}</td><td className="px-5 py-4"><p className="font-medium tabular-nums">{formatDatabaseSize(d.used_bytes)}</p><p className="mt-1 text-xs text-slate-400">{formatUsageTime(d.usage_collected_at)}</p></td><td className="px-5 py-4"><span className="rounded-full bg-amber-50 px-2.5 py-1 text-xs text-amber-800">{d.status}</span></td></tr>)}</tbody></table></div>}
      </section>
      <p className="text-xs leading-5 text-slate-500">Database size is a logical estimate from MariaDB table data and index metadata. It is not the same as physical disk usage or the hosting account&apos;s disk quota.</p>
      <section className="rounded-2xl border border-slate-200 bg-white p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div className="flex items-center gap-2"><Users size={17}/><h2 className="font-semibold">Users for {current?.name || "selected database"}</h2></div>{current && ["ACTIVE", "FAILED"].includes(current.status) && <button type="button" onClick={() => void deleteDatabase()} className="rounded-lg border border-red-200 px-3 py-2 text-xs font-semibold text-red-700 hover:bg-red-50">Delete database</button>}{current?.status === "DELETING" && <button type="button" onClick={() => void deleteDatabase()} className="rounded-lg border border-amber-200 px-3 py-2 text-xs font-semibold text-amber-800 hover:bg-amber-50">Check / retry deletion</button>}</div>
        {!selected?<p className="mt-3 text-sm text-slate-500">Select a database to view its users.</p>:users.length===0?<p className="mt-3 text-sm text-slate-500">No database users have been requested.</p>:<div className="mt-4 divide-y divide-slate-100">{users.map(u=><div key={u.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><p className="text-sm font-medium">{u.username}</p><p className="mt-1 text-xs text-slate-500">{JSON.parse(u.privileges).join(", ")}</p><p className="mt-1 text-xs text-slate-500">{u.status === "ACTIVE" ? "Localhost access · selected database only" : "Provisioning state"}</p></div><div className="flex items-center gap-2"><span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-700">{u.status}</span>{u.status === "ACTIVE" && u.secret_available === 1 && <button type="button" onClick={() => void revealCredential(u.id)} className="rounded-lg border border-blue-200 px-3 py-2 text-xs font-medium text-blue-700 hover:bg-blue-50">Reveal one-time password</button>}{u.status === "ACTIVE" && <button type="button" onClick={() => void revokeDatabaseUser(u.id)} className="rounded-lg border border-red-200 px-3 py-2 text-xs font-medium text-red-700 hover:bg-red-50">Revoke</button>}</div></div>)}</div>}
      </section>
      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2"><Database size={17}/><h2 className="font-semibold">Connection details</h2></div>
        <p className="mt-1 text-xs text-slate-500">Use these settings in applications hosted on this same server. Remote database connections are disabled.</p>
        {!current ? <p className="mt-4 text-sm text-slate-500">Select a database to view its connection settings.</p> : activeUsers.length === 0 ? <p className="mt-4 rounded-xl bg-slate-50 px-4 py-3 text-sm text-slate-600">No active database users are available. Create a user and wait until its status is ACTIVE to generate connection settings.</p> : <div className="mt-4 space-y-3">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-xl bg-slate-50 p-3"><p className="text-xs text-slate-500">Host</p><p className="mt-1 font-mono text-sm">localhost</p></div>
            <div className="rounded-xl bg-slate-50 p-3"><p className="text-xs text-slate-500">Port</p><p className="mt-1 font-mono text-sm">3306</p></div>
            <div className="rounded-xl bg-slate-50 p-3"><p className="text-xs text-slate-500">Database</p><p className="mt-1 break-all font-mono text-sm">{current.name}</p></div>
          </div>
          {activeUsers.map(user => <div key={user.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 p-3">
            <div><p className="text-sm font-medium">{user.username}</p><p className="mt-1 text-xs text-slate-500">Active login · localhost only</p></div>
            <button type="button" onClick={() => void copyConnectionSettings(user)} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"><Copy size={14}/> Copy connection settings</button>
          </div>)}
          <p className="text-xs leading-5 text-slate-500">The copied settings include a password placeholder, not your password. Replace it with the password you saved. Keep credentials in your application&apos;s environment file and never commit that file to Git.</p>
        </div>}
      </section>
      {revealedCredential && <div className="rounded-xl border border-amber-200 bg-amber-50 p-4"><p className="text-sm font-semibold text-amber-950">One-time database credentials</p><p className="mt-2 text-xs text-amber-900">Username: <span className="font-mono">{revealedCredential.username}</span></p><p className="mt-1 break-all font-mono text-sm text-amber-950">Password: {revealedCredential.password}</p><button type="button" onClick={() => void navigator.clipboard.writeText(revealedCredential.password)} className="mt-3 rounded-lg border border-amber-300 px-3 py-2 text-xs font-semibold text-amber-950 hover:bg-amber-100">Copy password</button></div>}
      <p className="flex items-start gap-2 text-xs leading-5 text-slate-400"><ShieldCheck size={14} className="mt-0.5 shrink-0"/> Database credentials are encrypted temporarily and can be revealed once. Save the password securely; Nexora cannot show it again.</p>
    </section>
  </main>;
}

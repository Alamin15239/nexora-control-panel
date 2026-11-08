"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, RefreshCw, Shield, UserRound, UserX } from "lucide-react";

type WorkspaceUser = { id: string; email: string; displayName: string | null; userStatus: string; role: string; joinedAt: string; hostingAccounts: number };

export default function UserManagementPage() {
  const [users, setUsers] = useState<WorkspaceUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const response = await fetch("/api/control/users", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load workspace users.");
      setUsers(data.users ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load workspace users."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function removeUser(user: WorkspaceUser) {
    const label = user.displayName || user.email;
    if (!window.confirm(`Remove ${label} from this workspace? Their workspace role and hosting-account access in this workspace will be revoked, and active sessions will be invalidated. Their Nexora login may remain active in other workspaces.`)) return;
    setBusyId(user.id); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to remove workspace user.");
      setNotice(data.message || "User removed from this workspace.");
      setUsers(current => current.filter(item => item.id !== user.id));
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to remove workspace user."); }
    finally { setBusyId(""); }
  }

  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85"><div className="mx-auto flex max-w-[1200px] items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3"><Link href="/settings" aria-label="Back to security settings" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link><span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Shield size={20}/></span><div><p className="font-semibold">User management</p><p className="text-xs text-slate-500">Nexora Control / Access & security</p></div></div>
      <button onClick={() => void load()} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1200px] space-y-6 px-6 py-8">
      <div><p className="text-sm font-medium text-blue-700">Workspace administration</p><h1 className="mt-1 text-3xl font-semibold tracking-tight">Workspace users</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">Review customer and administrator logins in this workspace. Removing a user revokes their workspace membership, assigned hosting access in this workspace, and active sessions. It does not erase their login from other workspaces.</p></div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h2 className="font-semibold">User inventory</h2><p className="mt-1 text-xs text-slate-500">Administrators are protected from accidental removal when they are the last active admin.</p></div><span className="rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-600">{users.length} users</span></div>
        {loading ? <div className="p-10 text-center text-sm text-slate-500">Loading users…</div> : users.length === 0 ? <div className="p-12 text-center"><UserRound size={30} className="mx-auto text-slate-300"/><p className="mt-3 text-sm text-slate-500">No workspace users found.</p></div> : <div className="divide-y divide-slate-100">{users.map(user => <div key={user.id} className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <div className="min-w-0"><p className="text-sm font-semibold text-slate-800">{user.displayName || user.email}</p><p className="mt-1 text-xs text-slate-500">{user.email}</p><p className="mt-1 text-[11px] text-slate-400">{user.role} · {user.userStatus} · {user.hostingAccounts} hosting account(s)</p></div>
          <button disabled={busyId === user.id} onClick={() => void removeUser(user)} className="inline-flex items-center gap-2 rounded-lg border border-red-200 px-3 py-2 text-xs font-semibold text-red-700 hover:bg-red-50 disabled:opacity-50"><UserX size={14}/>{busyId === user.id ? "Removing…" : "Remove from workspace"}</button>
        </div>)}</div>}
      </section>
      <p className="text-xs leading-5 text-slate-400">The last active OWNER or ADMIN cannot be removed. To permanently erase a person&apos;s Nexora identity across all workspaces, use a separate platform-level identity deletion workflow.</p>
    </section>
  </main>;
}

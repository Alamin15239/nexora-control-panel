"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Activity, ArrowLeft, Check, Copy, Plus, RefreshCw, Server as ServerIcon, ShieldCheck, Terminal } from "lucide-react";

type ServerRecord = {
  id: string;
  hostname: string;
  primary_ip: string;
  region: string | null;
  agent_version: string | null;
  status: string;
  last_heartbeat_at: string | null;
  created_at: string;
};

type Enrollment = { serverId: string; enrollmentToken: string; expiresAt: string; message: string };

export default function ServersPage() {
  const [servers, setServers] = useState<ServerRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [copied, setCopied] = useState(false);
  const [form, setForm] = useState({ hostname: "", primaryIp: "", region: "" });

  const loadServers = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/control/servers", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load servers");
      setServers(data.servers ?? []);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load servers");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadServers(); }, [loadServers]);

  async function createServer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch("/api/control/servers", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to register server");
      setNotice(`Server ${data.server.hostname} registered. Generate an enrollment token to connect its agent.`);
      setForm({ hostname: "", primaryIp: "", region: "" });
      setShowForm(false);
      await loadServers();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to register server");
    } finally {
      setBusy(false);
    }
  }

  async function issueToken(serverId: string) {
    setBusy(true);
    setError("");
    setNotice("");
    setEnrollment(null);
    try {
      const response = await fetch(`/api/control/servers/${serverId}/enrollment-token`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to generate enrollment token");
      setEnrollment(data);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to generate enrollment token");
    } finally {
      setBusy(false);
    }
  }

  async function copyToken() {
    if (!enrollment) return;
    try {
      await navigator.clipboard.writeText(enrollment.enrollmentToken);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError("Clipboard access was blocked. Select and copy the token manually.");
    }
  }

  return <main className="min-h-screen bg-slate-50 text-slate-900">
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
        <div className="flex items-center gap-3">
          <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><ServerIcon size={20}/></span>
          <div><p className="font-semibold">Server management</p><p className="text-xs text-slate-500">Nexora Control / Infrastructure</p></div>
        </div>
        <button onClick={() => void loadServers()} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50"><RefreshCw size={15}/> Refresh</button>
      </div>
    </header>

    <section className="mx-auto max-w-7xl space-y-6 px-5 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div><p className="text-sm font-medium text-blue-700">Infrastructure</p><h1 className="mt-1 text-2xl font-semibold tracking-tight">Your servers</h1><p className="mt-2 text-sm text-slate-500">Register Linux nodes and issue short-lived, single-use agent enrollment tokens.</p></div>
        <button onClick={() => setShowForm((value) => !value)} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-800"><Plus size={17}/> Register server</button>
      </div>

      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}

      {showForm && <form onSubmit={createServer} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-5"><h2 className="font-semibold">Register a Linux server</h2><p className="mt-1 text-xs text-slate-500">This adds the node to your workspace. It does not install software or change the server.</p></div>
        <div className="grid gap-4 md:grid-cols-3">
          <label className="text-xs font-medium text-slate-600">Hostname<input required maxLength={253} value={form.hostname} onChange={(event) => setForm((current) => ({ ...current, hostname: event.target.value }))} placeholder="web-01.example.com" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm text-slate-900 outline-none focus:border-blue-500"/></label>
          <label className="text-xs font-medium text-slate-600">Primary IP address<input required value={form.primaryIp} onChange={(event) => setForm((current) => ({ ...current, primaryIp: event.target.value }))} placeholder="203.0.113.10" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm text-slate-900 outline-none focus:border-blue-500"/></label>
          <label className="text-xs font-medium text-slate-600">Region (optional)<input maxLength={80} value={form.region} onChange={(event) => setForm((current) => ({ ...current, region: event.target.value }))} placeholder="Dammam, Saudi Arabia" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-3 text-sm text-slate-900 outline-none focus:border-blue-500"/></label>
        </div>
        <div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setShowForm(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-medium text-slate-600">Cancel</button><button disabled={busy} className="rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60">{busy ? "Registering…" : "Add server"}</button></div>
      </form>}

      {enrollment && <section className="rounded-2xl border border-blue-200 bg-blue-50/70 p-5">
        <div className="flex items-start gap-3"><span className="rounded-xl bg-white p-2 text-blue-700"><Terminal size={19}/></span><div className="min-w-0 flex-1"><h2 className="font-semibold text-slate-900">Agent enrollment token</h2><p className="mt-1 text-sm text-slate-600">{enrollment.message}</p><div className="mt-4 flex flex-wrap items-center gap-2"><code className="min-w-0 flex-1 break-all rounded-lg border border-blue-100 bg-white px-3 py-3 text-sm text-slate-800">{enrollment.enrollmentToken}</code><button onClick={() => void copyToken()} className="inline-flex items-center gap-2 rounded-lg bg-blue-700 px-3 py-3 text-sm font-medium text-white">{copied ? <Check size={16}/> : <Copy size={16}/>} {copied ? "Copied" : "Copy token"}</button></div><p className="mt-2 text-xs text-slate-500">Expires: {new Date(enrollment.expiresAt).toLocaleString()}</p><p className="mt-2 text-xs text-amber-800">Keep this token private. The current Linux agent still needs its enrollment and mutual-TLS connection workflow implemented before it can use this token.</p></div></div>
      </section>}

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Registered servers</p><p className="mt-2 text-3xl font-semibold">{servers.length}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Online nodes</p><p className="mt-2 text-3xl font-semibold">{servers.filter((server) => server.status === "ONLINE").length}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Awaiting agent</p><p className="mt-2 text-3xl font-semibold">{servers.filter((server) => server.status === "PENDING").length}</p></div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h2 className="font-semibold">Server inventory</h2><p className="mt-1 text-xs text-slate-500">Only servers belonging to your active workspace are shown.</p></div><span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">{servers.length} total</span></div>
        {loading ? <div className="p-10 text-center text-sm text-slate-500">Loading server inventory…</div> : servers.length === 0 ? <div className="p-12 text-center"><ServerIcon className="mx-auto text-slate-300" size={32}/><h3 className="mt-3 font-medium">No servers registered</h3><p className="mt-1 text-sm text-slate-500">Add your first Linux node to start building your infrastructure inventory.</p><button onClick={() => setShowForm(true)} className="mt-4 rounded-lg bg-blue-700 px-4 py-2 text-sm font-medium text-white">Register first server</button></div> : <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-medium">Server</th><th className="px-5 py-3 font-medium">Region</th><th className="px-5 py-3 font-medium">Status</th><th className="px-5 py-3 font-medium">Agent</th><th className="px-5 py-3 font-medium">Last heartbeat</th><th className="px-5 py-3 text-right font-medium">Action</th></tr></thead><tbody className="divide-y divide-slate-100">{servers.map((server) => <tr key={server.id} className="hover:bg-slate-50/70"><td className="px-5 py-4"><p className="font-medium text-slate-900">{server.hostname}</p><p className="mt-1 text-xs text-slate-500">{server.primary_ip}</p></td><td className="px-5 py-4 text-slate-600">{server.region || "—"}</td><td className="px-5 py-4"><span className={"inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium " + (server.status === "ONLINE" ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700")}><Activity size={12}/>{server.status}</span></td><td className="px-5 py-4 text-slate-600">{server.agent_version || "Not connected"}</td><td className="px-5 py-4 text-slate-500">{server.last_heartbeat_at ? new Date(server.last_heartbeat_at).toLocaleString() : "Never"}</td><td className="px-5 py-4 text-right"><button disabled={busy} onClick={() => void issueToken(server.id)} className="rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-700 hover:border-blue-200 hover:text-blue-700 disabled:opacity-50">Generate token</button></td></tr>)}</tbody></table></div>}
      </div>

      <div className="flex items-start gap-3 rounded-2xl border border-slate-200 bg-white p-5"><ShieldCheck size={19} className="mt-0.5 shrink-0 text-emerald-600"/><div><h3 className="text-sm font-semibold">Workspace isolation enabled</h3><p className="mt-1 text-sm leading-6 text-slate-500">Server queries are scoped to the authenticated organization. Only workspace owners and administrators can register nodes or issue enrollment tokens. Token hashes—not raw tokens—are stored in D1.</p></div></div>
    </section>
  </main>;
}

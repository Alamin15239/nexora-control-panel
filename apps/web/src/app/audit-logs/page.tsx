"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Filter, ListTree, RefreshCw, Shield } from "lucide-react";

type AuditEntry = {
  id: string;
  createdAt: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  actorUserId: string | null;
  sourceIp: string | null;
  metadata: unknown;
};

type AuditResponse = {
  entries?: AuditEntry[];
  items?: AuditEntry[];
  auditLogs?: AuditEntry[];
};

export default function AuditLogsPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState("");
  const [resourceTypeFilter, setResourceTypeFilter] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams();
      if (actionFilter.trim()) params.set("action", actionFilter.trim());
      if (resourceTypeFilter.trim()) params.set("resourceType", resourceTypeFilter.trim());
      const query = params.toString();
      const response = await fetch(`/api/control/audit-logs${query ? `?${query}` : ""}`, { cache: "no-store" });
      const data: AuditResponse = await response.json();
      if (!response.ok) throw new Error((data as unknown as { message?: string }).message || "Unable to load audit logs.");
      const list = data.entries ?? data.items ?? data.auditLogs ?? [];
      setEntries(list);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load audit logs."); }
    finally { setLoading(false); }
  }, [actionFilter, resourceTypeFilter]);

  useEffect(() => { void load(); }, [load]);

  const formatDate = (iso: string) => {
    if (!iso) return "—";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso;
    return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  };

  const summary = (() => {
    if (entries.length === 0) return "No audit entries";
    const byAction = new Map<string, number>();
    for (const entry of entries) byAction.set(entry.action, (byAction.get(entry.action) ?? 0) + 1);
    return `${entries.length} entries · ${byAction.size} action types`;
  })();

  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85"><div className="mx-auto flex max-w-[1500px] items-center justify-between px-5 py-4">
      <div className="flex items-center gap-3">
        <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
        <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Shield size={20}/></span>
        <div><p className="font-semibold">Audit logs</p><p className="text-xs text-slate-500">Nexora Control / Access &amp; security</p></div>
      </div>
      <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1500px] space-y-6 px-5 py-8">
      <div>
        <p className="text-sm font-medium text-blue-700">Workspace activity</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">Audit trail</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">Sensitive control-plane actions are recorded for workspace audit readiness. Filter by action or resource type to scope the trail.</p>
      </div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
          <div><h2 className="font-semibold">Audit entries</h2><p className="mt-1 text-xs text-slate-500">Most recent entries appear first.</p></div>
          <span className="rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-600">{summary}</span>
        </div>
        <div className="flex flex-wrap items-end gap-3 border-b border-slate-100 bg-slate-50/50 px-5 py-4">
          <label className="block"><span className="mb-1 block text-xs font-semibold text-slate-700">Action</span>
            <input type="text" value={actionFilter} onChange={event => setActionFilter(event.target.value)} placeholder="e.g. UPDATE_PHP_POOL" className="w-64 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10"/>
          </label>
          <label className="block"><span className="mb-1 block text-xs font-semibold text-slate-700">Resource type</span>
            <input type="text" value={resourceTypeFilter} onChange={event => setResourceTypeFilter(event.target.value)} placeholder="e.g. hosting_account" className="w-64 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10"/>
          </label>
          <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"><Filter size={14}/> Apply filters</button>
        </div>
        {loading ? <div className="p-10 text-center text-sm text-slate-500">Loading audit entries…</div> : entries.length === 0 ? <div className="p-12 text-center"><ListTree size={30} className="mx-auto text-slate-300"/><p className="mt-3 text-sm text-slate-500">No audit entries match the current filters.</p></div> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-5 py-3 font-medium">Time</th>
                  <th className="px-5 py-3 font-medium">Action</th>
                  <th className="px-5 py-3 font-medium">Resource</th>
                  <th className="px-5 py-3 font-medium">Actor</th>
                  <th className="px-5 py-3 font-medium">IP address</th>
                  <th className="px-5 py-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {entries.map(entry => <tr key={entry.id} className="align-top">
                  <td className="px-5 py-4 text-xs text-slate-600">{formatDate(entry.createdAt)}</td>
                  <td className="px-5 py-4"><span className="rounded-full bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700">{entry.action}</span></td>
                  <td className="px-5 py-4"><p className="text-xs font-medium text-slate-700">{entry.resourceType}</p>{entry.resourceId && <p className="mt-1 break-all font-mono text-[11px] text-slate-400">{entry.resourceId}</p>}</td>
                  <td className="px-5 py-4 text-xs text-slate-600">{entry.actorUserId || "System"}</td>
                  <td className="px-5 py-4 font-mono text-[11px] text-slate-500">{entry.sourceIp || "—"}</td>
                  <td className="px-5 py-4 max-w-[420px] text-xs text-slate-500">{entry.metadata == null ? "—" : typeof entry.metadata === "string" ? entry.metadata : JSON.stringify(entry.metadata)}</td>
                </tr>)}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <p className="text-xs leading-5 text-slate-400">Audit entries are immutable workspace records. Contact the platform administrator to export the complete trail for compliance reviews.</p>
    </section>
  </main>;
}

"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, ListChecks, RefreshCw, RotateCcw, X } from "lucide-react";

type Job = {
  id: string; operation: string; status: string; attempts: number;
  requestedAt: string; startedAt: string | null; finishedAt: string | null;
  errorCode: string | null; errorMessage: string | null;
  hostingAccountId: string; accountUsername: string; accountStatus: string;
  organizationName: string; serverHostname: string | null; stalled: number;
};

function statusStyle(status: string): string {
  switch (status) {
    case "QUEUED": return "bg-blue-50 text-blue-700";
    case "RUNNING": return "bg-amber-50 text-amber-700";
    case "SUCCEEDED": return "bg-emerald-50 text-emerald-700";
    case "FAILED": return "bg-rose-50 text-rose-700";
    case "CANCELLED": return "bg-slate-100 text-slate-600";
    default: return "bg-slate-100 text-slate-600";
  }
}

const STATUS_FILTERS = ["", "QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"];

export default function ProvisioningJobsPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [retryableOperations, setRetryableOperations] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [retryingId, setRetryingId] = useState("");

  const loadJobs = useCallback(async (showRefresh: boolean) => {
    if (showRefresh) setRefreshing(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (statusFilter) params.set("status", statusFilter);
      const response = await fetch("/api/control/provisioning-jobs" + (params.toString() ? `?${params}` : ""), { cache: "no-store" });
      const data = await response.json();
      if (response.status === 401) return;
      if (!response.ok) throw new Error(data.message || "Unable to load provisioning jobs.");
      setJobs((data.jobs ?? []) as Job[]);
      setRetryableOperations((data.retryableOperations ?? []) as string[]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load provisioning jobs.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [statusFilter]);

  useEffect(() => { void loadJobs(false); }, [loadJobs]);

  async function retry(job: Job) {
    setRetryingId(job.id);
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/provisioning-jobs/${encodeURIComponent(job.id)}/retry`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to queue the retry.");
      setNotice(String(data.message || "Retry queued."));
      await loadJobs(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to queue the retry.");
    } finally {
      setRetryingId("");
    }
  }

  return <main className="mx-auto max-w-[1400px] px-5 py-8 sm:px-8">
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="text-xs font-semibold uppercase tracking-[.18em] text-blue-700">WHM · Operations</p><h1 className="mt-2 text-3xl font-bold tracking-tight">Provisioning jobs</h1><p className="mt-2 text-sm text-slate-500">Every privileged operation dispatched to the hosting agents, with failure reasons and guarded retries.</p></div>
      <button onClick={() => void loadJobs(true)} disabled={refreshing} className="rounded-xl border border-slate-200 bg-white p-2.5 text-slate-500 hover:bg-slate-50 disabled:opacity-50" aria-label="Refresh"><RefreshCw size={16} className={refreshing ? "animate-spin" : ""} /></button>
    </div>

    {error && <div role="alert" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><span className="flex items-start gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{error}</span><button onClick={() => setError("")} aria-label="Dismiss error" className="text-rose-400 hover:text-rose-600"><X size={15} /></button></div>}
    {notice && <div role="status" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">{notice}</div>}

    <div className="mt-7 flex flex-wrap items-center gap-2">
      <span className="text-xs font-semibold text-slate-500">Status</span>
      {STATUS_FILTERS.map(filter => <button key={filter || "all"} onClick={() => setStatusFilter(filter)}
        className={"rounded-full px-3 py-1.5 text-xs font-semibold transition-colors " + (statusFilter === filter ? "bg-slate-900 text-white" : "bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50")}>
        {filter || "All"}
      </button>)}
    </div>

    <section className="mt-5 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
        <div><h2 className="font-semibold">Job inventory</h2><p className="mt-1 text-xs text-slate-500">Retry is available only for failed jobs of idempotent operations: {retryableOperations.join(", ") || "loading…"}</p></div>
        <ListChecks size={16} className="text-slate-300" />
      </div>
      {loading ? <p className="p-5 text-xs text-slate-400">Loading jobs…</p> : jobs.length === 0 ? <p className="p-5 text-xs text-slate-400">No provisioning jobs match this filter.</p> :
        <div className="overflow-x-auto"><table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-[10px] uppercase tracking-wide text-slate-400">
            <tr><th className="px-5 py-3 font-semibold">Operation</th><th className="px-4 py-3 font-semibold">Account</th><th className="px-4 py-3 font-semibold">Organization</th><th className="px-4 py-3 font-semibold">Server</th><th className="px-4 py-3 font-semibold">Status</th><th className="px-4 py-3 font-semibold">Failure</th><th className="px-4 py-3 font-semibold">Requested</th><th className="px-4 py-3 font-semibold"></th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {jobs.map(job => <tr key={job.id} className={job.stalled ? "bg-amber-50/40" : undefined}>
              <td className="px-5 py-3 font-mono text-[11px] font-semibold text-slate-800">{job.operation}</td>
              <td className="px-4 py-3 text-slate-600">{job.accountUsername}</td>
              <td className="px-4 py-3 text-slate-600">{job.organizationName}</td>
              <td className="px-4 py-3 text-slate-500">{job.serverHostname || "—"}</td>
              <td className="px-4 py-3"><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold " + statusStyle(job.status)}>{job.status}</span>{job.stalled ? <span className="ml-1.5 rounded-full bg-amber-100 px-2 py-0.5 text-[9px] font-semibold text-amber-800">stalled</span> : null}</td>
              <td className="px-4 py-3 max-w-[260px] text-slate-500">{job.errorMessage ? <span>{job.errorCode ? <span className="font-mono text-[10px] font-semibold text-rose-600">{job.errorCode}: </span> : null}{job.errorMessage}</span> : "—"}</td>
              <td className="px-4 py-3 text-slate-500">{new Date(job.requestedAt).toLocaleString()}</td>
              <td className="px-4 py-3">{job.status === "FAILED" && retryableOperations.includes(job.operation) && <button onClick={() => void retry(job)} disabled={retryingId === job.id} className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1.5 text-[10px] font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"><RotateCcw size={11} /> {retryingId === job.id ? "Queueing…" : "Retry"}</button>}</td>
            </tr>)}
          </tbody>
        </table></div>}
    </section>
    <p className="mt-4 text-[11px] leading-5 text-slate-400">Destructive and non-idempotent operations (database restore, database deletion, file-manager jobs) are never retryable here — re-trigger them from their resource workflows so the current state is re-validated before dispatch.</p>
  </main>;
}

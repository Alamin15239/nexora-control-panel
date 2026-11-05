"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { Plus, RefreshCw, Pencil, Trash2, X, Globe2 } from "lucide-react";

type RecordType = "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "CAA";
type DnsRecord = {
  id: string; type: RecordType; name: string; content: string;
  ttl: number; proxied: boolean; priority?: number; comment?: string;
};
type DnsResponse = { zone: string | null; records: DnsRecord[]; canManage: boolean };
type Draft = {
  type: RecordType; name: string; content: string; ttl: number;
  proxied: boolean; priority: string; comment: string;
};
const emptyDraft: Draft = {
  type: "A", name: "", content: "", ttl: 3600, proxied: false, priority: "10", comment: "",
};

function errorMessage(data: unknown, fallback: string): string {
  return data && typeof data === "object" && "message" in data && typeof data.message === "string"
    ? data.message : fallback;
}

export default function DnsManagement() {
  const [data, setData] = useState<DnsResponse | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/control/dns-records", { cache: "no-store" });
      const payload = await response.json();
      if (!response.ok) throw new Error(errorMessage(payload, "Unable to load DNS records."));
      setData(payload as DnsResponse);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load DNS records.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  function startEdit(record: DnsRecord) {
    setEditingId(record.id);
    setDraft({
      type: record.type, name: record.name, content: record.content,
      ttl: record.ttl, proxied: record.proxied,
      priority: String(record.priority ?? 10), comment: record.comment ?? "",
    });
    setError("");
    setNotice("");
  }

  function resetForm() {
    setEditingId(null);
    setDraft(emptyDraft);
    setError("");
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!data?.canManage) return;
    setSaving(true);
    setError("");
    setNotice("");
    const body = {
      type: draft.type, name: draft.name, content: draft.content,
      ttl: draft.ttl, proxied: draft.proxied,
      ...(draft.type === "MX" ? { priority: Number(draft.priority) } : {}),
      ...(draft.comment.trim() ? { comment: draft.comment.trim() } : {}),
    };
    try {
      const response = await fetch(editingId ? `/api/control/dns-records/${editingId}` : "/api/control/dns-records", {
        method: editingId ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(errorMessage(payload, "Unable to save DNS record."));
      setNotice(editingId ? "DNS record updated." : "DNS record created.");
      resetForm();
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to save DNS record.");
    } finally {
      setSaving(false);
    }
  }

  async function remove(record: DnsRecord) {
    if (!data?.canManage || !window.confirm(`Permanently delete ${record.type} record ${record.name}?`)) return;
    setDeletingId(record.id);
    setError("");
    setNotice("");
    try {
      const response = await fetch(`/api/control/dns-records/${record.id}`, { method: "DELETE" });
      const payload = await response.json();
      if (!response.ok) throw new Error(errorMessage(payload, "Unable to delete DNS record."));
      if (editingId === record.id) resetForm();
      setNotice("DNS record deleted.");
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to delete DNS record.");
    } finally {
      setDeletingId(null);
    }
  }

  const showProxy = ["A", "AAAA", "CNAME"].includes(draft.type);
  return <div className="space-y-5">
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Globe2 size={18} className="text-blue-700"/>
          <div><h2 className="font-semibold">Authoritative DNS zone</h2><p className="text-xs text-slate-500">Cloudflare · {data?.zone ?? "nexoraedge.digital"}</p></div>
        </div>
        <button type="button" onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm hover:bg-slate-50 disabled:opacity-50">
          <RefreshCw size={14} className={loading ? "animate-spin" : ""}/> Refresh
        </button>
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-500">Changes publish directly to the Cloudflare DNS zone. This is a zone-wide workspace integration, not a per-customer DNS zone.</p>
    </section>

    {data?.canManage && <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="font-semibold">{editingId ? "Edit DNS record" : "Add DNS record"}</h2>
        {editingId && <button type="button" onClick={resetForm} className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900"><X size={15}/> Cancel edit</button>}
      </div>
      <form onSubmit={save} className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm"><span className="font-medium">Type</span>
          <select value={draft.type} onChange={e => setDraft(v => ({ ...v, type: e.target.value as RecordType, proxied: ["A", "AAAA", "CNAME"].includes(e.target.value) ? v.proxied : false }))} className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5">
            {(["A", "AAAA", "CNAME", "MX", "TXT", "CAA"] as RecordType[]).map(type => <option key={type}>{type}</option>)}
          </select>
        </label>
        <label className="block text-sm"><span className="font-medium">Name</span>
          <input required value={draft.name} onChange={e => setDraft(v => ({ ...v, name: e.target.value }))} placeholder="www.nexoraedge.digital" className="mt-1.5 w-full rounded-lg border border-slate-300 px-3 py-2.5"/>
        </label>
        <label className="block text-sm sm:col-span-2"><span className="font-medium">{draft.type === "A" ? "IPv4 address" : draft.type === "AAAA" ? "IPv6 address" : draft.type === "TXT" ? "Text value" : draft.type === "CAA" ? "CAA value (flags tag value)" : "Target / content"}</span>
          <input required value={draft.content} onChange={e => setDraft(v => ({ ...v, content: e.target.value }))} placeholder={draft.type === "A" ? "203.0.113.10" : draft.type === "CNAME" ? "target.example.com" : draft.type === "MX" ? "mail.example.com" : ""} className="mt-1.5 w-full rounded-lg border border-slate-300 px-3 py-2.5"/>
        </label>
        <label className="block text-sm"><span className="font-medium">TTL</span>
          <select value={draft.ttl} onChange={e => setDraft(v => ({ ...v, ttl: Number(e.target.value) }))} className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5">
            <option value={1}>Auto</option><option value={60}>1 minute</option><option value={300}>5 minutes</option><option value={600}>10 minutes</option><option value={1800}>30 minutes</option><option value={3600}>1 hour</option><option value={14400}>4 hours</option><option value={86400}>1 day</option>
          </select>
        </label>
        {draft.type === "MX" && <label className="block text-sm"><span className="font-medium">Priority</span><input type="number" min="0" max="65535" required value={draft.priority} onChange={e => setDraft(v => ({ ...v, priority: e.target.value }))} className="mt-1.5 w-full rounded-lg border border-slate-300 px-3 py-2.5"/></label>}
        {showProxy && <label className="flex items-center gap-2 self-end pb-3 text-sm"><input type="checkbox" checked={draft.proxied} onChange={e => setDraft(v => ({ ...v, proxied: e.target.checked }))} className="h-4 w-4"/> Proxied through Cloudflare</label>}
        <label className="block text-sm sm:col-span-2"><span className="font-medium">Comment (optional)</span><input value={draft.comment} onChange={e => setDraft(v => ({ ...v, comment: e.target.value }))} maxLength={500} placeholder="Purpose of this record" className="mt-1.5 w-full rounded-lg border border-slate-300 px-3 py-2.5"/></label>
        <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
          <button disabled={saving} className="inline-flex items-center gap-2 rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-800 disabled:opacity-50"><Plus size={15}/>{saving ? "Saving…" : editingId ? "Save changes" : "Create record"}</button>
          {!data.canManage && <span className="text-xs text-slate-500">Only workspace owners and administrators can change DNS.</span>}
        </div>
      </form>
    </section>}

    {error && <p role="alert" className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
    {notice && <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">{notice}</p>}

    <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">DNS records</h2><p className="mt-1 text-xs text-slate-500">{data?.records.length ?? 0} records in the managed zone</p></div>
      {loading ? <p className="p-5 text-sm text-slate-500">Loading DNS records…</p> : !data?.records.length ? <p className="p-5 text-sm text-slate-500">No DNS records were returned for this zone.</p> : <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-4 py-3">Type</th><th className="px-4 py-3">Name</th><th className="px-4 py-3">Content</th><th className="px-4 py-3">Proxy</th><th className="px-4 py-3">TTL</th><th className="px-4 py-3 text-right">Actions</th></tr></thead>
          <tbody className="divide-y divide-slate-100">{data.records.map(record => <tr key={record.id} className="align-top">
            <td className="px-4 py-3 font-semibold">{record.type}</td><td className="px-4 py-3 font-medium">{record.name}</td><td className="max-w-[320px] break-all px-4 py-3 text-slate-600">{record.content}{record.type === "MX" && <span className="ml-2 text-xs text-slate-400">Priority {record.priority}</span>}</td><td className="px-4 py-3">{record.proxied ? "Proxied" : "DNS only"}</td><td className="px-4 py-3">{record.ttl === 1 ? "Auto" : `${record.ttl}s`}</td>
            <td className="px-4 py-3 text-right">{data.canManage ? <div className="inline-flex gap-2"><button type="button" onClick={() => startEdit(record)} aria-label={`Edit ${record.name}`} className="rounded-md border border-slate-200 p-2 hover:bg-slate-50"><Pencil size={14}/></button><button type="button" onClick={() => void remove(record)} disabled={deletingId === record.id} aria-label={`Delete ${record.name}`} className="rounded-md border border-red-200 p-2 text-red-600 hover:bg-red-50 disabled:opacity-50"><Trash2 size={14}/></button></div> : <span className="text-xs text-slate-400">Read only</span>}</td>
          </tr>)}</tbody>
        </table>
      </div>}
    </section>
  </div>;
}

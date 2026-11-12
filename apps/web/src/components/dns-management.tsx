"use client";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Pencil, Plus, RefreshCw, Trash2, X, Globe2 } from "lucide-react";
import {
  EmptyState, InlineAlert, PageHeader, SectionCard, StatusBadge, TableFrame, Th,
} from "@/components/ui";

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

function recordTypeTone(type: RecordType): "brand" | "info" | "success" | "warning" | "neutral" {
  switch (type) {
    case "A": case "AAAA": return "brand";
    case "CNAME": return "info";
    case "MX": return "success";
    case "TXT": return "warning";
    default: return "neutral";
  }
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
    document.getElementById("dns-editor")?.scrollIntoView({ behavior: "smooth", block: "center" });
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

  return (
    <main className="mx-auto max-w-[1400px] px-5 py-8 lg:px-9">
      <PageHeader
        eyebrow="Hosting services · DNS"
        title="DNS zones"
        description="Authoritative DNS records for the Nexora managed zone, published straight to Cloudflare."
        actions={
          <button type="button" onClick={() => void load()} disabled={loading} className="nx-btn-secondary">
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} /> Refresh
          </button>
        }
      />

      {error && <InlineAlert tone="error" onDismiss={() => setError("")} className="mt-6">{error}</InlineAlert>}
      {notice && <InlineAlert tone="success" onDismiss={() => setNotice("")} className="mt-6">{notice}</InlineAlert>}

      <div className="mt-6 grid gap-5 xl:grid-cols-[1.5fr_1fr]">
        <SectionCard
          title="DNS records"
          description={`${data?.records.length ?? 0} records in the managed zone${data?.zone ? ` · ${data.zone}` : ""}`}
          flush
        >
          {loading ? (
            <p className="px-5 py-6 text-sm text-slate-500 sm:px-6">Loading DNS records…</p>
          ) : !data?.records.length ? (
            <EmptyState icon={Globe2} title="No DNS records were returned" description="Records you create publish directly to the authoritative Cloudflare zone." />
          ) : (
            <TableFrame minWidth={760} head={<tr><Th>Type</Th><Th>Name</Th><Th>Content</Th><Th>Proxy</Th><Th>TTL</Th><Th right>Actions</Th></tr>}>
              {data.records.map(record => (
                <tr key={record.id} className="align-top transition hover:bg-slate-50/70">
                  <td className="px-4 py-3.5"><StatusBadge tone={recordTypeTone(record.type)}>{record.type}</StatusBadge></td>
                  <td className="max-w-[220px] break-all px-4 py-3.5 font-medium text-slate-800">{record.name}</td>
                  <td className="max-w-[300px] break-all px-4 py-3.5 text-slate-600">
                    {record.content}
                    {record.type === "MX" && <span className="ml-2 text-xs text-slate-400">Priority {record.priority}</span>}
                  </td>
                  <td className="px-4 py-3.5">
                    <StatusBadge tone={record.proxied ? "brand" : "neutral"}>{record.proxied ? "Proxied" : "DNS only"}</StatusBadge>
                  </td>
                  <td className="px-4 py-3.5 text-xs tabular-nums text-slate-500">{record.ttl === 1 ? "Auto" : `${record.ttl}s`}</td>
                  <td className="px-4 py-3.5 text-right">
                    {data.canManage ? (
                      <div className="inline-flex gap-1.5">
                        <button type="button" onClick={() => startEdit(record)} aria-label={`Edit ${record.name}`} className="rounded-lg border border-slate-200 p-2 text-slate-600 transition hover:bg-slate-50"><Pencil size={14} /></button>
                        <button type="button" onClick={() => void remove(record)} disabled={deletingId === record.id} aria-label={`Delete ${record.name}`} className="rounded-lg border border-rose-200 p-2 text-rose-600 transition hover:bg-rose-50 disabled:opacity-50"><Trash2 size={14} /></button>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400">Read only</span>
                    )}
                  </td>
                </tr>
              ))}
            </TableFrame>
          )}
        </SectionCard>

        <div className="space-y-5">
          <div className="nx-card p-5">
            <div className="flex items-center gap-2.5">
              <span className="grid h-9 w-9 place-items-center rounded-xl bg-brand-50 text-brand-600"><Globe2 size={17} /></span>
              <div>
                <h2 className="text-[15px] font-semibold text-slate-900">Cloudflare zone</h2>
                <p className="mt-0.5 text-xs text-slate-500">{data?.zone ?? "nexoraedge.digital"} · authoritative</p>
              </div>
            </div>
            <p className="mt-3.5 text-xs leading-5 text-slate-500">Changes publish directly to the Cloudflare DNS zone. This is a zone-wide workspace integration, not a per-customer DNS zone. Verify record names and values before saving; deletions take effect at the authoritative provider.</p>
          </div>

          {data?.canManage ? (
            <SectionCard
              title={editingId ? "Edit DNS record" : "Add DNS record"}
              description={editingId ? `Updating ${draft.type} ${draft.name}` : "Publish a new record to the managed zone"}
              actions={editingId && (
                <button type="button" onClick={resetForm} className="inline-flex items-center gap-1 text-xs font-semibold text-slate-500 transition hover:text-slate-900"><X size={14} /> Cancel edit</button>
              )}
            >
              <form id="dns-editor" onSubmit={save} className="grid gap-4 sm:grid-cols-2">
                <label className="block text-xs font-semibold text-slate-600"><span className="nx-label">Type</span>
                  <select value={draft.type} onChange={e => setDraft(v => ({ ...v, type: e.target.value as RecordType, proxied: ["A", "AAAA", "CNAME"].includes(e.target.value) ? v.proxied : false }))} className="nx-select mt-2">
                    {(["A", "AAAA", "CNAME", "MX", "TXT", "CAA"] as RecordType[]).map(type => <option key={type}>{type}</option>)}
                  </select>
                </label>
                <label className="block text-xs font-semibold text-slate-600"><span className="nx-label">Name</span>
                  <input required value={draft.name} onChange={e => setDraft(v => ({ ...v, name: e.target.value }))} placeholder="www.nexoraedge.digital" className="nx-input mt-2" />
                </label>
                <label className="block text-xs font-semibold text-slate-600 sm:col-span-2"><span className="nx-label">{draft.type === "A" ? "IPv4 address" : draft.type === "AAAA" ? "IPv6 address" : draft.type === "TXT" ? "Text value" : draft.type === "CAA" ? "CAA value (flags tag value)" : "Target / content"}</span>
                  <input required value={draft.content} onChange={e => setDraft(v => ({ ...v, content: e.target.value }))} placeholder={draft.type === "A" ? "203.0.113.10" : draft.type === "CNAME" ? "target.example.com" : draft.type === "MX" ? "mail.example.com" : ""} className="nx-input mt-2" />
                </label>
                <label className="block text-xs font-semibold text-slate-600"><span className="nx-label">TTL</span>
                  <select value={draft.ttl} onChange={e => setDraft(v => ({ ...v, ttl: Number(e.target.value) }))} className="nx-select mt-2">
                    <option value={1}>Auto</option><option value={60}>1 minute</option><option value={300}>5 minutes</option><option value={600}>10 minutes</option><option value={1800}>30 minutes</option><option value={3600}>1 hour</option><option value={14400}>4 hours</option><option value={86400}>1 day</option>
                  </select>
                </label>
                {draft.type === "MX" && (
                  <label className="block text-xs font-semibold text-slate-600"><span className="nx-label">Priority</span>
                    <input type="number" min="0" max="65535" required value={draft.priority} onChange={e => setDraft(v => ({ ...v, priority: e.target.value }))} className="nx-input mt-2" />
                  </label>
                )}
                {showProxy && (
                  <label className="flex items-center gap-2.5 self-end pb-1 text-sm text-slate-600 sm:col-span-2">
                    <input type="checkbox" checked={draft.proxied} onChange={e => setDraft(v => ({ ...v, proxied: e.target.checked }))} className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500" />
                    Proxied through Cloudflare
                  </label>
                )}
                <label className="block text-xs font-semibold text-slate-600 sm:col-span-2"><span className="nx-label">Comment (optional)</span>
                  <input value={draft.comment} onChange={e => setDraft(v => ({ ...v, comment: e.target.value }))} maxLength={500} placeholder="Purpose of this record" className="nx-input mt-2" />
                </label>
                <div className="sm:col-span-2">
                  <button disabled={saving} className="nx-btn-primary w-full sm:w-auto"><Plus size={15} />{saving ? "Saving…" : editingId ? "Save changes" : "Create record"}</button>
                </div>
              </form>
            </SectionCard>
          ) : (
            <SectionCard title="Read-only zone" description="DNS changes require elevated permissions">
              <p className="text-xs leading-5 text-slate-500">Only workspace owners and administrators can publish DNS changes. You can review the records on the left, but creating, editing, and deleting are disabled for your role.</p>
            </SectionCard>
          )}
        </div>
      </div>
    </main>
  );
}

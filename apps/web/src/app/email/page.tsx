"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Info, Mail, Plus, RefreshCw, Trash2, X } from "lucide-react";

type EmailDomain = {
  id: string; domain: string; status: string; providerStatus: string;
  hostingAccountId: string | null; createdAt: string; mailboxCount: number; forwardCount: number;
};
type Mailbox = { id: string; address: string; quotaMb: number; status: string; providerStatus: string; createdAt: string };
type Forward = { id: string; source: string; destination: string; active: number; providerStatus: string; createdAt: string };
type MailStatus = {
  outboundNotification: { configured: boolean; purpose: string };
  mailboxHosting: {
    provider: string; available: boolean; purpose: string; requirements: string[];
    dnsRecordsRequired: Array<{ record: string; guidance: string }>;
  };
};

function providerStyle(status: string): string {
  switch (status) {
    case "provisioned": return "bg-emerald-50 text-emerald-700";
    case "provisioning": return "bg-blue-50 text-blue-700";
    case "failed": return "bg-rose-50 text-rose-700";
    default: return "bg-amber-50 text-amber-700";
  }
}

export default function EmailHostingPage() {
  const [domains, setDomains] = useState<EmailDomain[]>([]);
  const [status, setStatus] = useState<MailStatus | null>(null);
  const [selectedDomainId, setSelectedDomainId] = useState("");
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [mailboxLimit, setMailboxLimit] = useState<number | null>(null);
  const [forwards, setForwards] = useState<Forward[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [addDomainOpen, setAddDomainOpen] = useState(false);
  const [domainName, setDomainName] = useState("");
  const [addMailboxOpen, setAddMailboxOpen] = useState(false);
  const [mailboxLocalPart, setMailboxLocalPart] = useState("");
  const [mailboxQuotaMb, setMailboxQuotaMb] = useState("1024");
  const [addForwardOpen, setAddForwardOpen] = useState(false);
  const [forwardSource, setForwardSource] = useState("");
  const [forwardDestination, setForwardDestination] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadStatusAndDomains = useCallback(async (showRefresh: boolean) => {
    if (showRefresh) setRefreshing(true);
    setError("");
    try {
      const [statusResponse, domainsResponse] = await Promise.all([
        fetch("/api/control/email/status", { cache: "no-store" }),
        fetch("/api/control/email/domains", { cache: "no-store" }),
      ]);
      const statusData = await statusResponse.json();
      const domainsData = await domainsResponse.json();
      if (statusResponse.status === 401 || domainsResponse.status === 401) return;
      if (!statusResponse.ok) throw new Error(statusData.message || "Unable to load the email service status.");
      if (!domainsResponse.ok) throw new Error(domainsData.message || "Unable to load email domains.");
      setStatus(statusData as MailStatus);
      const list = (domainsData.domains ?? []) as EmailDomain[];
      setDomains(list);
      setSelectedDomainId(current => list.some(domain => domain.id === current) ? current : list[0]?.id ?? "");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load the email module.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void loadStatusAndDomains(false); }, [loadStatusAndDomains]);

  const loadDomainDetail = useCallback(async () => {
    if (!selectedDomainId) { setMailboxes([]); setForwards([]); setMailboxLimit(null); return; }
    try {
      const [mailboxResponse, forwardResponse] = await Promise.all([
        fetch(`/api/control/email/domains/${encodeURIComponent(selectedDomainId)}/mailboxes`, { cache: "no-store" }),
        fetch(`/api/control/email/domains/${encodeURIComponent(selectedDomainId)}/forwards`, { cache: "no-store" }),
      ]);
      const mailboxData = await mailboxResponse.json();
      const forwardData = await forwardResponse.json();
      if (!mailboxResponse.ok) throw new Error(mailboxData.message || "Unable to load mailboxes.");
      setMailboxes((mailboxData.mailboxes ?? []) as Mailbox[]);
      setMailboxLimit(Number(mailboxData.mailboxLimit ?? 0));
      setForwards(forwardResponse.ok ? ((forwardData.forwards ?? []) as Forward[]) : []);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load mailboxes.");
    }
  }, [selectedDomainId]);

  useEffect(() => { void loadDomainDetail(); }, [loadDomainDetail]);

  async function submitAddDomain() {
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/email/domains", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain: domainName.trim().toLowerCase() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to register the email domain.");
      setAddDomainOpen(false);
      setDomainName("");
      setNotice(String(data.provisioning?.message || "Email domain registered."));
      await loadStatusAndDomains(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to register the email domain.");
    } finally { setSubmitting(false); }
  }

  async function submitAddMailbox() {
    if (!selectedDomainId) return;
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/email/domains/${encodeURIComponent(selectedDomainId)}/mailboxes`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ localPart: mailboxLocalPart.trim().toLowerCase(), quotaMb: Number(mailboxQuotaMb) || 1024 }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to create the mailbox.");
      setAddMailboxOpen(false);
      setMailboxLocalPart("");
      setMailboxQuotaMb("1024");
      setNotice(String(data.provisioning?.message || "Mailbox recorded."));
      await loadDomainDetail();
      await loadStatusAndDomains(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create the mailbox.");
    } finally { setSubmitting(false); }
  }

  async function submitAddForward() {
    if (!selectedDomainId) return;
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/email/domains/${encodeURIComponent(selectedDomainId)}/forwards`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ source: forwardSource.trim().toLowerCase(), destination: forwardDestination.trim().toLowerCase() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to create the forwarding rule.");
      setAddForwardOpen(false);
      setForwardSource("");
      setForwardDestination("");
      setNotice(String(data.provisioning?.message || "Forwarding rule recorded."));
      await loadDomainDetail();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create the forwarding rule.");
    } finally { setSubmitting(false); }
  }

  async function deleteMailbox(mailbox: Mailbox) {
    if (!confirm(`Delete mailbox ${mailbox.address}? Mail delivery to it stops once a provider is connected.`)) return;
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/email/mailboxes/${encodeURIComponent(mailbox.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to delete the mailbox.");
      setNotice(String(data.message || "Mailbox deleted."));
      await loadDomainDetail();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to delete the mailbox.");
    } finally { setSubmitting(false); }
  }

  async function updateQuota(mailbox: Mailbox) {
    const next = prompt(`New quota in MB for ${mailbox.address} (128–51200):`, String(mailbox.quotaMb));
    if (next === null) return;
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/email/mailboxes/${encodeURIComponent(mailbox.id)}`, {
        method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ quotaMb: Number(next) }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to update the quota.");
      setNotice(String(data.message || "Mailbox updated."));
      await loadDomainDetail();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to update the quota.");
    } finally { setSubmitting(false); }
  }

  async function deleteForward(forward: Forward) {
    if (!confirm(`Remove the forwarding rule ${forward.source} → ${forward.destination}?`)) return;
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/email/forwards/${encodeURIComponent(forward.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to remove the forwarding rule.");
      setNotice(String(data.message || "Forwarding rule removed."));
      await loadDomainDetail();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to remove the forwarding rule.");
    } finally { setSubmitting(false); }
  }

  async function deleteDomain(emailDomain: EmailDomain) {
    if (!confirm(`Remove email domain ${emailDomain.domain} and all of its mailboxes and forwards from the inventory?`)) return;
    setSubmitting(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/email/domains/${encodeURIComponent(emailDomain.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to remove the email domain.");
      setNotice(String(data.message || "Email domain removed."));
      await loadStatusAndDomains(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to remove the email domain.");
    } finally { setSubmitting(false); }
  }

  if (loading) {
    return <main className="grid min-h-screen place-items-center"><div className="h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-blue-700" /></main>;
  }

  const providerAvailable = status?.mailboxHosting.available ?? false;

  return <main className="mx-auto max-w-[1300px] px-5 py-8 sm:px-8">
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="text-xs font-semibold uppercase tracking-[.18em] text-blue-700">Hosting services</p><h1 className="mt-2 text-3xl font-bold tracking-tight">Email hosting</h1><p className="mt-2 text-sm text-slate-500">Mail domains, mailbox plans, quotas, and forwarding rules for your organization.</p></div>
      <div className="flex items-center gap-2">
        <button onClick={() => void loadStatusAndDomains(true)} disabled={refreshing} className="rounded-xl border border-slate-200 bg-white p-2.5 text-slate-500 hover:bg-slate-50 disabled:opacity-50" aria-label="Refresh"><RefreshCw size={16} className={refreshing ? "animate-spin" : ""} /></button>
        <button onClick={() => setAddDomainOpen(true)} className="inline-flex items-center gap-1.5 rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800"><Plus size={14} /> Add mail domain</button>
      </div>
    </div>

    {!providerAvailable && status && <div className="mt-6 rounded-2xl border border-amber-200 bg-amber-50 p-5">
      <div className="flex items-start gap-3">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-amber-100 text-amber-700"><Info size={17} /></span>
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-amber-900">Mailbox hosting is not active — inventory mode</h2>
          <p className="mt-1 text-xs leading-5 text-amber-800">Outbound notification email (password resets, alerts) is {status.outboundNotification.configured ? "configured" : "not configured"} separately. Hosted IMAP/SMTP mailboxes require a mail server, which is not connected: every record below is a <strong>plan</strong> and is NOT provisioned on any mail server. Nothing is marked delivered or active until a provider confirms.</p>
          <ul className="mt-3 space-y-1 text-xs text-amber-800">{status.mailboxHosting.requirements.map((requirement, index) => <li key={index}>• {requirement}</li>)}</ul>
        </div>
      </div>
    </div>}

    {error && <div role="alert" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><span className="flex items-start gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{error}</span><button onClick={() => setError("")} aria-label="Dismiss error" className="text-rose-400 hover:text-rose-600"><X size={15} /></button></div>}
    {notice && <div role="status" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"><span className="flex items-start gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0" />{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message" className="text-emerald-400 hover:text-emerald-600"><X size={15} /></button></div>}

    <div className="mt-6 grid gap-5 xl:grid-cols-[1fr_1.6fr]">
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Mail domains</h2><span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-600">{domains.length}</span></div>
        {domains.length === 0 ? <p className="p-5 text-xs text-slate-400">No mail domains registered yet.</p> : <div className="divide-y divide-slate-100">
          {domains.map(emailDomain => <button key={emailDomain.id} onClick={() => setSelectedDomainId(emailDomain.id)}
            className={"flex w-full items-center justify-between gap-3 px-5 py-3.5 text-left transition-colors " + (selectedDomainId === emailDomain.id ? "bg-blue-50/60" : "hover:bg-slate-50")}>
            <div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-800">{emailDomain.domain}</p><p className="mt-0.5 text-[11px] text-slate-400">{emailDomain.mailboxCount} mailbox(es) · {emailDomain.forwardCount} forward(s)</p></div>
            <div className="flex items-center gap-2"><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold " + providerStyle(emailDomain.providerStatus)}>{emailDomain.providerStatus.replace(/_/g, " ")}</span>
              <span role="button" tabIndex={0} onClick={event => { event.stopPropagation(); void deleteDomain(emailDomain); }} onKeyDown={event => { if (event.key === "Enter") { event.stopPropagation(); void deleteDomain(emailDomain); } }} aria-label={`Remove ${emailDomain.domain}`} className="rounded-lg border border-rose-200 p-1.5 text-rose-500 hover:bg-rose-50"><Trash2 size={12} /></span></div>
          </button>)}
        </div>}
      </section>

      <div className="space-y-5">
        <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
            <div><h2 className="font-semibold">Mailboxes</h2><p className="mt-1 text-xs text-slate-500">{mailboxLimit !== null ? `${mailboxes.length} planned · plan limit ${mailboxLimit}` : "Select a mail domain"}</p></div>
            {selectedDomainId && <button onClick={() => setAddMailboxOpen(true)} className="inline-flex items-center gap-1.5 rounded-xl bg-blue-700 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-800"><Plus size={13} /> New mailbox</button>}
          </div>
          {!selectedDomainId ? <p className="p-5 text-xs text-slate-400">Select a mail domain to manage its mailboxes.</p> : mailboxes.length === 0 ? <p className="p-5 text-xs text-slate-400">No mailboxes planned for this domain yet.</p> : <div className="divide-y divide-slate-100">
            {mailboxes.map(mailbox => <div key={mailbox.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
              <div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-800">{mailbox.address}</p><p className="mt-0.5 text-[11px] text-slate-400">Quota {mailbox.quotaMb.toLocaleString()} MB</p></div>
              <div className="flex items-center gap-2"><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold " + providerStyle(mailbox.providerStatus)}>{mailbox.providerStatus.replace(/_/g, " ")}</span>
                <button onClick={() => void updateQuota(mailbox)} disabled={submitting} className="rounded-lg border border-slate-200 px-2 py-1.5 text-[10px] font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50">Quota</button>
                <button onClick={() => void deleteMailbox(mailbox)} disabled={submitting} className="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2 py-1.5 text-[10px] font-semibold text-rose-600 hover:bg-rose-50 disabled:opacity-50"><Trash2 size={12} /> Remove</button></div>
            </div>)}
          </div>}
        </section>

        <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
            <div><h2 className="font-semibold">Forwarding rules</h2><p className="mt-1 text-xs text-slate-500">source@domain → destination; also usable as simple aliases</p></div>
            {selectedDomainId && <button onClick={() => setAddForwardOpen(true)} className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"><Plus size={13} /> Add forward</button>}
          </div>
          {!selectedDomainId ? <p className="p-5 text-xs text-slate-400">Select a mail domain to manage forwarding rules.</p> : forwards.length === 0 ? <p className="p-5 text-xs text-slate-400">No forwarding rules for this domain yet.</p> : <div className="divide-y divide-slate-100">
            {forwards.map(forward => <div key={forward.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
              <div className="min-w-0"><p className="truncate text-xs font-semibold text-slate-800">{forward.source} → {forward.destination}</p></div>
              <div className="flex items-center gap-2"><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold " + providerStyle(forward.providerStatus)}>{forward.providerStatus.replace(/_/g, " ")}</span>
                <button onClick={() => void deleteForward(forward)} disabled={submitting} className="rounded-lg border border-rose-200 p-1.5 text-rose-500 hover:bg-rose-50 disabled:opacity-50" aria-label="Remove forward"><Trash2 size={12} /></button></div>
            </div>)}
          </div>}
        </section>

        {status && <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-semibold"><Mail size={15} className="text-blue-700" /> DNS records required for mail</div>
          <ul className="mt-3 space-y-2 text-xs leading-5 text-slate-600">{status.mailboxHosting.dnsRecordsRequired.map(record => <li key={record.record}><span className="font-mono text-[10px] font-bold text-slate-800">{record.record}</span> — {record.guidance}</li>)}</ul>
          <p className="mt-3 text-[11px] leading-5 text-slate-400">SPF authorizes the mail server to send for the domain, DKIM signs the messages, and DMARC tells receivers what to do when checks fail. Publish all three before expecting reliable delivery.</p>
        </section>}
      </div>
    </div>

    {addDomainOpen && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Add mail domain">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold">Add a mail domain</h3><p className="mt-1 text-xs leading-5 text-slate-500">The domain is registered in the email inventory. {providerAvailable ? "The configured mail provider will be asked to provision it." : "Mailbox hosting is not configured, so the domain is recorded as a plan only."}</p></div><button onClick={() => setAddDomainOpen(false)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Domain name</span>
          <input value={domainName} onChange={event => setDomainName(event.target.value)} placeholder="mail.example.test" autoFocus className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setAddDomainOpen(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitAddDomain()} disabled={submitting || !domainName.trim()} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Saving…" : "Add domain"}</button></div>
      </div>
    </div>}

    {addMailboxOpen && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="New mailbox">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold">Plan a mailbox</h3><p className="mt-1 text-xs leading-5 text-slate-500">{providerAvailable ? "The mailbox is created on the configured mail server." : "Mailbox hosting is not configured: this records the intended mailbox only — no IMAP/SMTP mailbox will exist."}</p></div><button onClick={() => setAddMailboxOpen(false)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Mailbox name</span>
          <input value={mailboxLocalPart} onChange={event => setMailboxLocalPart(event.target.value)} placeholder="hello" autoFocus className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <label className="mt-4 block"><span className="text-xs font-semibold text-slate-700">Quota (MB, 128–51200)</span>
          <input type="number" min={128} max={51200} value={mailboxQuotaMb} onChange={event => setMailboxQuotaMb(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setAddMailboxOpen(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitAddMailbox()} disabled={submitting || !mailboxLocalPart.trim()} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Saving…" : "Create mailbox"}</button></div>
      </div>
    </div>}

    {addForwardOpen && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Add forward">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold">Add a forwarding rule</h3><p className="mt-1 text-xs leading-5 text-slate-500">Deliver mail for a local address on the selected domain to any external mailbox.</p></div><button onClick={() => setAddForwardOpen(false)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Local source (on the domain)</span>
          <input value={forwardSource} onChange={event => setForwardSource(event.target.value)} placeholder="support" autoFocus className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <label className="mt-4 block"><span className="text-xs font-semibold text-slate-700">Destination address</span>
          <input value={forwardDestination} onChange={event => setForwardDestination(event.target.value)} placeholder="owner@example.test" className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setAddForwardOpen(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitAddForward()} disabled={submitting || !forwardSource.trim() || !forwardDestination.trim()} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Saving…" : "Add forward"}</button></div>
      </div>
    </div>}
  </main>;
}

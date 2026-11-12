"use client";

import { useCallback, useEffect, useState } from "react";
import { Info, Mail, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  EmptyState, InlineAlert, Modal, PageHeader, SectionCard, Spinner,
  StatusBadge,
} from "@/components/ui";

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

function providerTone(status: string): "success" | "info" | "danger" | "warning" {
  switch (status) {
    case "provisioned": return "success";
    case "provisioning": return "info";
    case "failed": return "danger";
    default: return "warning";
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
    return <main className="grid min-h-screen place-items-center"><Spinner className="h-8 w-8" /></main>;
  }

  const providerAvailable = status?.mailboxHosting.available ?? false;
  const selectedDomain = domains.find(item => item.id === selectedDomainId) ?? null;

  return (
    <main className="mx-auto max-w-[1400px] px-5 py-8 lg:px-9">
      <PageHeader
        eyebrow="Hosting services · Email"
        title="Email accounts"
        description="Mail domains, mailbox plans, quotas, and forwarding rules for your organization."
        actions={
          <>
            <button onClick={() => void loadStatusAndDomains(true)} disabled={refreshing} className="nx-btn-secondary" aria-label="Refresh"><RefreshCw size={16} className={refreshing ? "animate-spin" : ""} /> Refresh</button>
            <button onClick={() => setAddDomainOpen(true)} className="nx-btn-primary"><Plus size={15} /> Add mail domain</button>
          </>
        }
      />

      {!providerAvailable && status && (
        <div className="mt-6 flex items-start gap-3.5 rounded-2xl border border-amber-200 bg-amber-50 p-5">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-amber-100 text-amber-700"><Info size={17} /></span>
          <div className="min-w-0">
            <h2 className="text-sm font-bold text-amber-900">Mailbox hosting is not active — inventory mode</h2>
            <p className="mt-1 text-xs leading-5 text-amber-800">
              Outbound notification email (password resets, alerts) is {status.outboundNotification.configured ? "configured" : "not configured"} separately. Hosted IMAP/SMTP mailboxes require a mail server, which is not connected: every record below is a <strong>plan</strong> and is NOT provisioned on any mail server. Nothing is marked delivered or active until a provider confirms.
            </p>
            <ul className="mt-3 space-y-1 text-xs text-amber-800">{status.mailboxHosting.requirements.map((requirement, index) => <li key={index}>• {requirement}</li>)}</ul>
          </div>
        </div>
      )}

      {error && <InlineAlert tone="error" onDismiss={() => setError("")} className="mt-6">{error}</InlineAlert>}
      {notice && <InlineAlert tone="success" onDismiss={() => setNotice("")} className="mt-6">{notice}</InlineAlert>}

      <div className="mt-6 grid gap-5 xl:grid-cols-[1fr_1.6fr]">
        <SectionCard title="Mail domains" description={`${domains.length} registered`} flush>
          {domains.length === 0 ? (
            <EmptyState icon={Mail} title="No mail domains yet" description="Register a mail domain to plan its mailboxes and forwarding rules." >
              <button onClick={() => setAddDomainOpen(true)} className="nx-btn-primary nx-btn-sm"><Plus size={14} /> Add mail domain</button>
            </EmptyState>
          ) : (
            <div className="divide-y divide-slate-100">
              {domains.map(emailDomain => (
                <button key={emailDomain.id} onClick={() => setSelectedDomainId(emailDomain.id)}
                  aria-pressed={selectedDomainId === emailDomain.id}
                  className={"flex w-full items-center justify-between gap-3 px-5 py-3.5 text-left transition sm:px-6 " + (selectedDomainId === emailDomain.id ? "bg-brand-50/70" : "hover:bg-slate-50")}>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-slate-800">{emailDomain.domain}</p>
                    <p className="mt-0.5 text-[11px] text-slate-400">{emailDomain.mailboxCount} mailbox(es) · {emailDomain.forwardCount} forward(s)</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <StatusBadge tone={providerTone(emailDomain.providerStatus)}>{emailDomain.providerStatus.replace(/_/g, " ")}</StatusBadge>
                    <span role="button" tabIndex={0} onClick={event => { event.stopPropagation(); void deleteDomain(emailDomain); }} onKeyDown={event => { if (event.key === "Enter") { event.stopPropagation(); void deleteDomain(emailDomain); } }} aria-label={`Remove ${emailDomain.domain}`} className="rounded-lg border border-rose-200 p-1.5 text-rose-500 transition hover:bg-rose-50"><Trash2 size={12} /></span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </SectionCard>

        <div className="space-y-5">
          <SectionCard
            title="Mailboxes"
            description={selectedDomain ? (mailboxLimit !== null ? `${mailboxes.length} planned · plan limit ${mailboxLimit}` : "Plan limit unavailable") : "Select a mail domain"}
            flush
            actions={selectedDomainId && <button onClick={() => setAddMailboxOpen(true)} className="nx-btn-primary nx-btn-sm"><Plus size={13} /> New mailbox</button>}
          >
            {!selectedDomainId ? (
              <p className="px-5 py-5 text-xs text-slate-400 sm:px-6">Select a mail domain to manage its mailboxes.</p>
            ) : mailboxes.length === 0 ? (
              <EmptyState icon={Mail} title="No mailboxes planned" description={selectedDomain ? `Plan the first mailbox for ${selectedDomain.domain}.` : "Plan the first mailbox for this domain."} >
                <button onClick={() => setAddMailboxOpen(true)} className="nx-btn-primary nx-btn-sm"><Plus size={14} /> New mailbox</button>
              </EmptyState>
            ) : (
              <div className="divide-y divide-slate-100">
                {mailboxes.map(mailbox => (
                  <div key={mailbox.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 sm:px-6">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-slate-800">{mailbox.address}</p>
                      <p className="mt-0.5 text-[11px] text-slate-400">Quota {mailbox.quotaMb.toLocaleString()} MB</p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <StatusBadge tone={providerTone(mailbox.providerStatus)}>{mailbox.providerStatus.replace(/_/g, " ")}</StatusBadge>
                      <button onClick={() => void updateQuota(mailbox)} disabled={submitting} className="nx-btn-secondary nx-btn-sm">Quota</button>
                      <button onClick={() => void deleteMailbox(mailbox)} disabled={submitting} className="nx-btn-danger nx-btn-sm"><Trash2 size={12} /> Remove</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </SectionCard>

          <SectionCard
            title="Forwarding rules"
            description="source@domain → destination; also usable as simple aliases"
            flush
            actions={selectedDomainId && <button onClick={() => setAddForwardOpen(true)} className="nx-btn-secondary nx-btn-sm"><Plus size={13} /> Add forward</button>}
          >
            {!selectedDomainId ? (
              <p className="px-5 py-5 text-xs text-slate-400 sm:px-6">Select a mail domain to manage forwarding rules.</p>
            ) : forwards.length === 0 ? (
              <EmptyState icon={Mail} title="No forwarding rules" description="Deliver mail for a local address on the selected domain to any external mailbox." />
            ) : (
              <div className="divide-y divide-slate-100">
                {forwards.map(forward => (
                  <div key={forward.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 sm:px-6">
                    <p className="min-w-0 truncate font-mono text-xs font-semibold text-slate-800">{forward.source} → {forward.destination}</p>
                    <div className="flex shrink-0 items-center gap-2">
                      <StatusBadge tone={providerTone(forward.providerStatus)}>{forward.providerStatus.replace(/_/g, " ")}</StatusBadge>
                      <button onClick={() => void deleteForward(forward)} disabled={submitting} aria-label="Remove forward" className="rounded-lg border border-rose-200 p-1.5 text-rose-500 transition hover:bg-rose-50 disabled:opacity-50"><Trash2 size={12} /></button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </SectionCard>

          {status && (
            <SectionCard title="DNS records required for mail" description="Publish these before expecting reliable delivery">
              <ul className="space-y-2.5 text-xs leading-5 text-slate-600">
                {status.mailboxHosting.dnsRecordsRequired.map(record => (
                  <li key={record.record} className="flex flex-wrap items-baseline gap-2">
                    <span className="rounded-md bg-slate-100 px-2 py-1 font-mono text-[10px] font-bold text-slate-800">{record.record}</span>
                    <span className="min-w-0 flex-1">{record.guidance}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-4 text-[11px] leading-5 text-slate-400">SPF authorizes the mail server to send for the domain, DKIM signs the messages, and DMARC tells receivers what to do when checks fail.</p>
            </SectionCard>
          )}
        </div>
      </div>

      {addDomainOpen && (
        <Modal title="Add a mail domain" description={providerAvailable ? "The domain is registered in the email inventory and the configured mail provider will be asked to provision it." : "Mailbox hosting is not configured, so the domain is recorded as a plan only."} onClose={() => setAddDomainOpen(false)}>
          <label className="mt-5 block">
            <span className="nx-label">Domain name</span>
            <input value={domainName} onChange={event => setDomainName(event.target.value)} placeholder="mail.example.test" autoFocus className="nx-input mt-2" />
          </label>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setAddDomainOpen(false)} className="nx-btn-secondary">Cancel</button>
            <button onClick={() => void submitAddDomain()} disabled={submitting || !domainName.trim()} className="nx-btn-primary">{submitting ? "Saving…" : "Add domain"}</button>
          </div>
        </Modal>
      )}

      {addMailboxOpen && (
        <Modal title="Plan a mailbox" description={providerAvailable ? "The mailbox is created on the configured mail server." : "Mailbox hosting is not configured: this records the intended mailbox only — no IMAP/SMTP mailbox will exist."} onClose={() => setAddMailboxOpen(false)}>
          <label className="mt-5 block">
            <span className="nx-label">Mailbox name</span>
            <input value={mailboxLocalPart} onChange={event => setMailboxLocalPart(event.target.value)} placeholder="hello" autoFocus className="nx-input mt-2" />
          </label>
          <label className="mt-4 block">
            <span className="nx-label">Quota (MB, 128–51200)</span>
            <input type="number" min={128} max={51200} value={mailboxQuotaMb} onChange={event => setMailboxQuotaMb(event.target.value)} className="nx-input mt-2" />
          </label>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setAddMailboxOpen(false)} className="nx-btn-secondary">Cancel</button>
            <button onClick={() => void submitAddMailbox()} disabled={submitting || !mailboxLocalPart.trim()} className="nx-btn-primary">{submitting ? "Saving…" : "Create mailbox"}</button>
          </div>
        </Modal>
      )}

      {addForwardOpen && (
        <Modal title="Add a forwarding rule" description="Deliver mail for a local address on the selected domain to any external mailbox." onClose={() => setAddForwardOpen(false)}>
          <label className="mt-5 block">
            <span className="nx-label">Local source (on the domain)</span>
            <input value={forwardSource} onChange={event => setForwardSource(event.target.value)} placeholder="support" autoFocus className="nx-input mt-2" />
          </label>
          <label className="mt-4 block">
            <span className="nx-label">Destination address</span>
            <input value={forwardDestination} onChange={event => setForwardDestination(event.target.value)} placeholder="owner@example.test" className="nx-input mt-2" />
          </label>
          <div className="mt-6 flex justify-end gap-2">
            <button onClick={() => setAddForwardOpen(false)} className="nx-btn-secondary">Cancel</button>
            <button onClick={() => void submitAddForward()} disabled={submitting || !forwardSource.trim() || !forwardDestination.trim()} className="nx-btn-primary">{submitting ? "Saving…" : "Add forward"}</button>
          </div>
        </Modal>
      )}
    </main>
  );
}

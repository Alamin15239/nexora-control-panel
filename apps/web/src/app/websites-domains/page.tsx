"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { CircleAlert, Globe2, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  EmptyState, InlineAlert, PageHeader, SectionCard, StatCard, StatusBadge,
  statusTone, TableFrame, Th,
} from "@/components/ui";

type Account = { id: string; username: string; primary_domain: string | null; status: string };
type Domain = { id: string; name: string; document_root: string; is_primary: number; created_at: string; hosting_account_id: string; username: string; account_status: string; server_hostname: string; job_status: string | null; cloudflare_custom_hostname_id?: string | null; cloudflare_hostname_status?: string | null; cloudflare_ssl_status?: string | null; cloudflare_cname_target?: string | null; cloudflare_error?: string | null };
type CloudflareState = { hostnameStatus?: string; sslStatus?: string; cnameTarget?: string; ready?: boolean; validation?: { ownershipVerification?: { name?: string; type?: string; value?: string } | null; sslValidationRecords?: Array<{ txt_name?: string; txt_value?: string; cname?: string; cname_target?: string; status?: string }>; sslValidationErrors?: unknown[] }; error?: string };
type DnsCheck = { status: string; expectedAddress?: string; observedAddresses?: string[]; message: string; records?: Array<{ type: string; name: string; value: string }> };
const blank = { name: "", accountId: "", documentRoot: "", isPrimary: false };

export default function WebsitesDomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [form, setForm] = useState(blank);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [retryingId, setRetryingId] = useState("");
  const [deletingId, setDeletingId] = useState("");
  const [dnsChecks, setDnsChecks] = useState<Record<string, DnsCheck>>({});
  const [checkingDnsId, setCheckingDnsId] = useState("");
  const [cloudflareStates, setCloudflareStates] = useState<Record<string, CloudflareState>>({});
  const [cloudflareBusyId, setCloudflareBusyId] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [d, a] = await Promise.all([
        fetch("/api/control/domains", { cache: "no-store" }),
        fetch("/api/control/hosting-accounts", { cache: "no-store" }),
      ]);
      const [dd, ad] = await Promise.all([d.json(), a.json()]);
      if (!d.ok) throw new Error(dd.message || "Unable to load domains");
      if (!a.ok) throw new Error(ad.message || "Unable to load hosting accounts");
      const loadedDomains = (dd.domains || []) as Domain[];
      setDomains(loadedDomains); setAccounts(ad.accounts || []);
      setForm(v => ({ ...v, accountId: v.accountId || ad.accounts?.[0]?.id || "" }));
      const hostnameDomains = loadedDomains.filter(domain => domain.cloudflare_custom_hostname_id);
      const liveStates = await Promise.all(hostnameDomains.map(async domain => {
        try {
          const response = await fetch(`/api/control/domains/${domain.id}/cloudflare-hostname`, { cache: "no-store" });
          if (!response.ok) return null;
          const data = await response.json();
          return [domain.id, data.cloudflare as CloudflareState] as const;
        } catch { return null; }
      }));
      setCloudflareStates(current => ({ ...current, ...Object.fromEntries(liveStates.filter((item): item is NonNullable<typeof item> => item !== null)) }));
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load domain data"); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function checkDns(domainId: string) {
    setCheckingDnsId(domainId);
    try {
      const response = await fetch(`/api/control/domains/${domainId}/dns-check`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok && response.status !== 502) throw new Error(data.message || "DNS check failed");
      setDnsChecks(current => ({ ...current, [domainId]: data as DnsCheck }));
    } catch (e) {
      setDnsChecks(current => ({ ...current, [domainId]: { status: "CHECK_FAILED", message: e instanceof Error ? e.message : "DNS check failed" } }));
    } finally { setCheckingDnsId(""); }
  }

  async function deleteDomain(domain: Domain) {
    if (domain.is_primary === 1 && domain.account_status === "ACTIVE") {
      setError("The primary domain of an active hosting account cannot be removed.");
      return;
    }
    if (!window.confirm(`Queue removal of ${domain.name}? Its Nginx virtual host will be removed by the connected server agent.`)) return;
    setDeletingId(domain.id); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/domains/${domain.id}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to remove domain");
      setNotice(data.message || "Domain removal queued.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to remove domain"); }
    finally { setDeletingId(""); }
  }

  async function retryDomain(domainId: string) {
    setRetryingId(domainId); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/domains/${domainId}/retry`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to retry domain setup");
      setNotice(data.message || "Domain setup queued again.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to retry domain setup"); }
    finally { setRetryingId(""); }
  }


  async function syncCloudflareHostname(domainId: string) {
    setCloudflareBusyId(domainId); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/domains/${domainId}/cloudflare-hostname`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Cloudflare hostname setup failed");
      setCloudflareStates(current => ({ ...current, [domainId]: data.cloudflare || {} }));
      setNotice(data.message || "Cloudflare hostname status refreshed.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Cloudflare hostname setup failed"); }
    finally { setCloudflareBusyId(""); }
  }

  async function revalidateCloudflareCertificate(domainId: string) {
    setCloudflareBusyId(domainId); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/domains/${domainId}/cloudflare-hostname/revalidate`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Cloudflare certificate revalidation failed");
      setCloudflareStates(current => ({ ...current, [domainId]: data.cloudflare || {} }));
      setNotice(data.message || "Cloudflare certificate revalidation requested.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Cloudflare certificate revalidation failed");
    } finally { setCloudflareBusyId(""); }
  }

  async function addDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/domains", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(form),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to add domain");
      setNotice(data.message || "Domain saved.");
      setForm(v => ({ ...blank, accountId: v.accountId }));
      setShowForm(false); await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to add domain"); }
    finally { setBusy(false); }
  }

  return (
    <main className="mx-auto max-w-[1400px] px-5 py-8 lg:px-9">
      <PageHeader
        eyebrow="Hosting services · Websites"
        title="Websites & domains"
        description="Attach domains to customer hosting accounts and define their website document roots."
        actions={
          <>
            <button onClick={() => void load()} className="nx-btn-secondary"><RefreshCw size={15} /> Refresh</button>
            <button onClick={() => setShowForm(v => !v)} disabled={accounts.length === 0} className="nx-btn-primary"><Plus size={16} /> Add domain</button>
          </>
        }
      />
      {error && <InlineAlert tone="error" onDismiss={() => setError("")} className="mt-6">{error}</InlineAlert>}
      {notice && <InlineAlert tone="success" onDismiss={() => setNotice("")} className="mt-6">{notice}</InlineAlert>}
      {showForm && (
        <SectionCard className="mt-6" title="Add a domain" description="The domain record is saved now; virtual-host configuration is queued for a connected Linux agent.">
          <form onSubmit={addDomain} className="grid gap-4 md:grid-cols-2">
            <label className="block"><span className="nx-label">Domain name</span>
              <input required value={form.name} onChange={e => setForm(v => ({ ...v, name: e.target.value.toLowerCase() }))} placeholder="example.com" className="nx-input mt-2" />
            </label>
            <label className="block"><span className="nx-label">Hosting account</span>
              <select required value={form.accountId} onChange={e => setForm(v => ({ ...v, accountId: e.target.value }))} className="nx-select mt-2">
                <option value="">Select account</option>
                {accounts.map(a => <option key={a.id} value={a.id}>{a.username} · {a.status}</option>)}
              </select>
            </label>
            <label className="block md:col-span-2"><span className="nx-label">Document root (optional)</span>
              <input value={form.documentRoot} onChange={e => setForm(v => ({ ...v, documentRoot: e.target.value }))} placeholder="/home/username/public_html/example.com" className="nx-input mt-2" />
              <span className="mt-1.5 block text-xs font-normal text-slate-400">Must be inside the selected account&apos;s public_html directory. Private home folders are not allowed. Leave blank to use the default path.</span>
            </label>
            <label className="flex items-center gap-2.5 text-sm text-slate-600 md:col-span-2">
              <input type="checkbox" checked={form.isPrimary} onChange={e => setForm(v => ({ ...v, isPrimary: e.target.checked }))} className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500" />
              Set as the primary domain for this account
            </label>
            <div className="flex justify-end gap-2 md:col-span-2">
              <button type="button" onClick={() => setShowForm(false)} className="nx-btn-secondary">Cancel</button>
              <button disabled={busy} className="nx-btn-primary">{busy ? "Saving…" : "Save domain"}</button>
            </div>
          </form>
        </SectionCard>
      )}
      <div className="mt-6 grid gap-4 sm:grid-cols-3">
        <StatCard icon={Globe2} label="Domains" value={domains.length} hint="Registered in this workspace" />
        <StatCard icon={Globe2} label="Primary domains" value={domains.filter(d => d.is_primary === 1).length} hint="One primary per hosting account" />
        <StatCard icon={RefreshCw} label="Awaiting server setup" value={domains.filter(d => d.job_status !== "SUCCEEDED").length} hint="Nginx configuration pending on the agent" />
      </div>
      <SectionCard className="mt-6" title="Domain inventory" description="Domains registered in the current workspace." flush>
        {loading ? <div className="p-10 text-center text-sm text-slate-500">Loading domains…</div> : domains.length === 0 ? (
          <EmptyState icon={Globe2} title="No domains configured" description="Create a hosting account first, then attach its domain here.">
            <Link href="/hosting-accounts" className="nx-btn-primary">Open hosting accounts</Link>
          </EmptyState>
        ) : (
          <TableFrame minWidth={960} head={<tr><Th>Domain</Th><Th>Hosting account</Th><Th>Document root</Th><Th>DNS</Th><Th>Server setup</Th><Th>SSL</Th><Th>Cloudflare for SaaS</Th><Th right>Actions</Th></tr>}>
            {domains.map(d => (
              <tr key={d.id} className="align-top transition hover:bg-slate-50/70">
                <td className="px-5 py-4">
                  <p className="font-semibold text-slate-800">{d.name}</p>
                  {d.is_primary === 1 && <span className="mt-1.5 inline-flex rounded-full bg-brand-50 px-2 py-0.5 text-[10px] font-semibold text-brand-700 ring-1 ring-inset ring-brand-500/20">Primary</span>}
                </td>
                <td className="px-5 py-4"><p className="font-medium text-slate-700">{d.username}</p><p className="mt-1 text-xs text-slate-500">{d.server_hostname} · {d.account_status}</p></td>
                <td className="px-5 py-4 font-mono text-xs text-slate-500">{d.document_root}</td>
                <td className="px-5 py-4">
                  <div className="flex flex-col items-start gap-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge tone={dnsChecks[d.id]?.status === "VERIFIED" ? "success" : !dnsChecks[d.id] || dnsChecks[d.id]?.status === "PENDING" ? "warning" : "neutral"}>
                        {dnsChecks[d.id]?.status === "VERIFIED" ? "Verified" : dnsChecks[d.id]?.status === "NOT_PUBLIC_DOMAIN" ? "Test domain" : dnsChecks[d.id]?.status === "SERVER_IP_NOT_PUBLIC" ? "Private server IP" : dnsChecks[d.id]?.status === "PENDING" ? "Not pointing here" : dnsChecks[d.id]?.status === "CHECK_FAILED" ? "Check failed" : "Not checked"}
                      </StatusBadge>
                      <button onClick={() => void checkDns(d.id)} disabled={checkingDnsId !== ""} className="nx-btn-secondary nx-btn-sm disabled:opacity-50"><RefreshCw size={12} />{checkingDnsId === d.id ? "Checking…" : "Check"}</button>
                    </div>
                    {dnsChecks[d.id]?.expectedAddress && <span className="font-mono text-[11px] text-slate-500">A → {dnsChecks[d.id].expectedAddress}</span>}
                    {dnsChecks[d.id]?.message && <span className="max-w-[220px] text-[11px] text-slate-500">{dnsChecks[d.id].message}</span>}
                  </div>
                </td>
                <td className="px-5 py-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge tone={statusTone(d.job_status)}>{d.job_status === "SUCCEEDED" ? "Configured" : d.job_status === "FAILED" ? "Failed" : d.job_status === "RUNNING" ? "Configuring" : d.job_status === "QUEUED" ? "Queued" : "Not configured"}</StatusBadge>
                    {(!d.job_status || d.job_status === "FAILED") && (
                      <button onClick={() => void retryDomain(d.id)} disabled={retryingId !== ""} className="nx-btn-secondary nx-btn-sm disabled:opacity-50"><RefreshCw size={12} />{retryingId === d.id ? "Queuing…" : d.job_status === "FAILED" ? "Retry" : "Set up"}</button>
                    )}
                  </div>
                </td>
                <td className="px-5 py-4"><StatusBadge tone={(cloudflareStates[d.id]?.sslStatus || d.cloudflare_ssl_status) === "active" ? "success" : (cloudflareStates[d.id]?.sslStatus || d.cloudflare_ssl_status) ? "warning" : "neutral"}>{(cloudflareStates[d.id]?.sslStatus || d.cloudflare_ssl_status) === "active" ? "Active" : (cloudflareStates[d.id]?.sslStatus || d.cloudflare_ssl_status) || "Not issued"}</StatusBadge></td>
                <td className="px-5 py-4">
                  <div className="min-w-[230px] space-y-2">
                    <div className="flex flex-wrap gap-1.5">
                      <StatusBadge tone="neutral">Host: {cloudflareStates[d.id]?.hostnameStatus || d.cloudflare_hostname_status || "Not registered"}</StatusBadge>
                      <StatusBadge tone="neutral">SSL: {cloudflareStates[d.id]?.sslStatus || d.cloudflare_ssl_status || "Not issued"}</StatusBadge>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button onClick={() => void syncCloudflareHostname(d.id)} disabled={cloudflareBusyId !== ""} className="nx-btn-secondary nx-btn-sm disabled:opacity-50">{cloudflareBusyId === d.id ? "Working…" : d.cloudflare_custom_hostname_id ? "Refresh status" : "Register hostname"}</button>
                      {d.cloudflare_custom_hostname_id && (cloudflareStates[d.id]?.sslStatus || d.cloudflare_ssl_status) !== "active" && (
                        <button onClick={() => void revalidateCloudflareCertificate(d.id)} disabled={cloudflareBusyId !== ""} className="nx-btn-secondary nx-btn-sm border-amber-200 text-amber-800 hover:bg-amber-50 disabled:opacity-50">{cloudflareBusyId === d.id ? "Revalidating…" : "Revalidate certificate"}</button>
                      )}
                    </div>
                    {(cloudflareStates[d.id]?.cnameTarget || d.cloudflare_cname_target) && <p className="break-all text-[11px] text-slate-500">Customer CNAME → {cloudflareStates[d.id]?.cnameTarget || d.cloudflare_cname_target}</p>}
                    {cloudflareStates[d.id]?.validation?.ownershipVerification?.name && <p className="break-all text-[11px] text-slate-500">Ownership TXT: {cloudflareStates[d.id].validation?.ownershipVerification?.name} = {cloudflareStates[d.id].validation?.ownershipVerification?.value}</p>}
                    {cloudflareStates[d.id]?.validation?.sslValidationRecords?.map((record, index) => <p key={index} className="break-all text-[11px] text-slate-500">SSL TXT: {record.txt_name} = {record.txt_value}</p>)}
                    {cloudflareStates[d.id]?.validation?.sslValidationErrors?.map((item, index) => <p key={index} className="max-w-[240px] break-words text-[11px] text-rose-600">SSL validation: {typeof item === "string" ? item : JSON.stringify(item)}</p>)}
                    {d.cloudflare_error && <p className="max-w-[240px] text-[11px] text-rose-600">{d.cloudflare_error}</p>}
                  </div>
                </td>
                <td className="px-5 py-4">
                  <button onClick={() => void deleteDomain(d)} disabled={deletingId !== "" || d.is_primary === 1} title={d.is_primary === 1 ? "Set another domain as primary before removing this domain" : "Queue domain removal"} className="nx-btn-danger nx-btn-sm disabled:cursor-not-allowed disabled:opacity-40"><Trash2 size={13} />{deletingId === d.id ? "Removing…" : "Remove"}</button>
                </td>
              </tr>
            ))}
          </TableFrame>
        )}
      </SectionCard>
      <p className="mt-5 flex items-start gap-2 text-xs leading-5 text-slate-400">
        <CircleAlert size={14} className="mt-0.5 shrink-0" />
        Use Check for the legacy public A-record test. For Cloudflare for SaaS, register the hostname, publish the displayed ownership and certificate validation records, then point the customer CNAME to the displayed SaaS target. HTTPS is ready only when both Cloudflare hostname and SSL statuses are active.
      </p>
    </main>
  );
}

"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Ban, CheckCircle2, CreditCard, PlayCircle, PauseCircle, RefreshCw, X } from "lucide-react";

type Subscription = {
  id: string; organizationId: string; organizationName: string;
  hostingAccountId: string | null; accountUsername: string | null; primaryDomain: string | null;
  planId: string; planName: string; status: string; billingPeriod: string; provider: string;
  amountSarMinor: number | null; currentPeriodEnd: string | null; trialEnd: string | null;
  cancelAtPeriodEnd: number; cancelledAt: string | null; suspendedAt: string | null; createdAt: string;
};
type Invoice = {
  id: string; organizationName: string; invoiceNumber: string; amountSarMinor: number;
  status: string; billingPeriod: string; paidAt: string | null; paymentMethod: string | null; createdAt: string;
};
type PlanOption = { id: string; name: string; active: number; price_sar_minor: number | null };

function sar(minor: number | null): string {
  if (minor === null) return "—";
  return `SAR ${(minor / 100).toFixed(2)}`;
}

function statusStyle(status: string): string {
  switch (status) {
    case "ACTIVE": return "bg-emerald-50 text-emerald-700";
    case "TRIALING": return "bg-blue-50 text-blue-700";
    case "PAST_DUE": return "bg-amber-50 text-amber-700";
    case "SUSPENDED": return "bg-orange-50 text-orange-700";
    case "CANCELLED": return "bg-slate-100 text-slate-600";
    case "EXPIRED": return "bg-rose-50 text-rose-700";
    default: return "bg-slate-100 text-slate-600";
  }
}

export default function SubscriptionsAdminPage() {
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [plans, setPlans] = useState<PlanOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [renewFor, setRenewFor] = useState<Subscription | null>(null);
  const [renewReference, setRenewReference] = useState("");
  const [planChangeFor, setPlanChangeFor] = useState<Subscription | null>(null);
  const [targetPlanId, setTargetPlanId] = useState("");
  const [planViolations, setPlanViolations] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const loadData = useCallback(async (showRefresh: boolean) => {
    if (showRefresh) setRefreshing(true);
    setError("");
    try {
      const [subscriptionResponse, invoiceResponse, planResponse] = await Promise.all([
        fetch("/api/control/subscriptions", { cache: "no-store" }),
        fetch("/api/control/invoices", { cache: "no-store" }),
        fetch("/api/control/hosting-plans", { cache: "no-store" }),
      ]);
      const [subscriptionData, invoiceData, planData] = await Promise.all([
        subscriptionResponse.json(), invoiceResponse.json(), planResponse.json(),
      ]);
      if (subscriptionResponse.status === 401) return;
      if (!subscriptionResponse.ok) throw new Error(subscriptionData.message || "Unable to load subscriptions.");
      if (!invoiceResponse.ok) throw new Error(invoiceData.message || "Unable to load invoices.");
      setSubscriptions((subscriptionData.subscriptions ?? []) as Subscription[]);
      setInvoices((invoiceData.invoices ?? []) as Invoice[]);
      setPlans((planData.plans ?? []) as PlanOption[]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load billing data.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void loadData(false); }, [loadData]);

  async function action(subscription: Subscription, verb: "cancel" | "suspend" | "reactivate", body: Record<string, unknown> = {}) {
    setSubmitting(true);
    setError(""); setNotice(""); setPlanViolations([]);
    try {
      const response = await fetch(`/api/control/subscriptions/${encodeURIComponent(subscription.id)}/${verb}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "The action was not completed.");
      setNotice(String(data.message || "Done."));
      await loadData(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The action was not completed.");
    } finally { setSubmitting(false); }
  }

  async function submitRenew() {
    if (!renewFor || !renewReference.trim()) return;
    setSubmitting(true);
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/subscriptions/${encodeURIComponent(renewFor.id)}/renew`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ transferReference: renewReference.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to record the renewal.");
      setRenewFor(null);
      setRenewReference("");
      setNotice(data.duplicate ? "This payment was already recorded." : `Renewal recorded as invoice ${data.invoice?.invoiceNumber}.`);
      await loadData(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to record the renewal.");
    } finally { setSubmitting(false); }
  }

  async function openPlanChange(subscription: Subscription) {
    setPlanChangeFor(subscription);
    setPlanViolations([]);
    setTargetPlanId(subscription.planId);
  }

  async function submitPlanChange() {
    if (!planChangeFor) return;
    setSubmitting(true);
    setError(""); setNotice(""); setPlanViolations([]);
    try {
      const response = await fetch(`/api/control/subscriptions/${encodeURIComponent(planChangeFor.id)}/plan`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ planId: targetPlanId }),
      });
      const data = await response.json();
      if (!response.ok) {
        if (Array.isArray(data.violations)) setPlanViolations(data.violations as string[]);
        throw new Error(data.message || "Unable to change the plan.");
      }
      setPlanChangeFor(null);
      setNotice(String(data.message || "Plan changed."));
      await loadData(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to change the plan.");
    } finally { setSubmitting(false); }
  }

  if (loading) {
    return <main className="grid min-h-screen place-items-center"><div className="h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-blue-700" /></main>;
  }

  return <main className="mx-auto max-w-[1400px] px-5 py-8 sm:px-8">
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="text-xs font-semibold uppercase tracking-[.18em] text-blue-700">WHM · Billing</p><h1 className="mt-2 text-3xl font-bold tracking-tight">Subscriptions & billing</h1><p className="mt-2 text-sm text-slate-500">Subscription lifecycle, invoices, and payment records. Nothing is marked paid without an explicit, traceable record.</p></div>
      <div className="flex items-center gap-2">
        <button onClick={() => void loadData(true)} disabled={refreshing} className="rounded-xl border border-slate-200 bg-white p-2.5 text-slate-500 hover:bg-slate-50 disabled:opacity-50" aria-label="Refresh"><RefreshCw size={16} className={refreshing ? "animate-spin" : ""} /></button>
        <button onClick={() => setCreateOpen(true)} className="inline-flex items-center gap-1.5 rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800"><CreditCard size={14} /> New subscription</button>
      </div>
    </div>

    {error && <div role="alert" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><span className="flex items-start gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{error}</span><button onClick={() => setError("")} aria-label="Dismiss error" className="text-rose-400 hover:text-rose-600"><X size={15} /></button></div>}
    {notice && <div role="status" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"><span className="flex items-start gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0" />{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message" className="text-emerald-400 hover:text-emerald-600"><X size={15} /></button></div>}

    <section className="mt-7 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Subscriptions</h2><p className="mt-1 text-xs text-slate-500">Plan changes validate current usage; downgrades that would violate quotas are rejected with the reason.</p></div>
      {subscriptions.length === 0 ? <p className="p-5 text-xs text-slate-400">No subscriptions yet. Create one for an active hosting account.</p> :
        <div className="overflow-x-auto"><table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-[10px] uppercase tracking-wide text-slate-400">
            <tr><th className="px-5 py-3 font-semibold">Customer</th><th className="px-4 py-3 font-semibold">Account</th><th className="px-4 py-3 font-semibold">Plan</th><th className="px-4 py-3 font-semibold">Amount</th><th className="px-4 py-3 font-semibold">Status</th><th className="px-4 py-3 font-semibold">Renews / ends</th><th className="px-4 py-3 font-semibold">Actions</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {subscriptions.map(subscription => <tr key={subscription.id}>
              <td className="px-5 py-3 font-semibold text-slate-800">{subscription.organizationName}</td>
              <td className="px-4 py-3 text-slate-600">{subscription.primaryDomain || subscription.accountUsername || "—"}</td>
              <td className="px-4 py-3 text-slate-600">{subscription.planName}<span className="ml-1 text-[10px] text-slate-400">({subscription.billingPeriod})</span></td>
              <td className="px-4 py-3 tabular-nums text-slate-700">{sar(subscription.amountSarMinor)}</td>
              <td className="px-4 py-3"><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold " + statusStyle(subscription.status)}>{subscription.status.replace(/_/g, " ")}{subscription.cancelAtPeriodEnd ? " · ends at period end" : ""}</span></td>
              <td className="px-4 py-3 text-slate-600">{subscription.currentPeriodEnd ? new Date(subscription.currentPeriodEnd).toLocaleDateString() : "—"}</td>
              <td className="px-4 py-3"><div className="flex flex-wrap items-center gap-1.5">
                {["ACTIVE", "TRIALING", "PAST_DUE", "SUSPENDED", "EXPIRED"].includes(subscription.status) && <button onClick={() => { setRenewFor(subscription); setRenewReference(""); }} className="rounded-lg border border-slate-200 px-2 py-1.5 text-[10px] font-semibold text-slate-700 hover:bg-slate-50">Record renewal</button>}
                {["ACTIVE", "TRIALING", "PAST_DUE"].includes(subscription.status) && <button onClick={() => void openPlanChange(subscription)} className="rounded-lg border border-slate-200 px-2 py-1.5 text-[10px] font-semibold text-slate-700 hover:bg-slate-50">Change plan</button>}
                {["ACTIVE", "TRIALING", "PAST_DUE"].includes(subscription.status) && <button onClick={() => void action(subscription, "suspend")} disabled={submitting} className="inline-flex items-center gap-1 rounded-lg border border-orange-200 px-2 py-1.5 text-[10px] font-semibold text-orange-700 hover:bg-orange-50 disabled:opacity-50"><PauseCircle size={12} /> Suspend</button>}
                {subscription.status === "SUSPENDED" && <button onClick={() => void action(subscription, "reactivate")} disabled={submitting} className="inline-flex items-center gap-1 rounded-lg border border-emerald-200 px-2 py-1.5 text-[10px] font-semibold text-emerald-700 hover:bg-emerald-50 disabled:opacity-50"><PlayCircle size={12} /> Reactivate</button>}
                {["ACTIVE", "TRIALING", "PAST_DUE"].includes(subscription.status) && <button onClick={() => void action(subscription, "cancel", { immediate: true })} disabled={submitting} className="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2 py-1.5 text-[10px] font-semibold text-rose-600 hover:bg-rose-50 disabled:opacity-50"><Ban size={12} /> Cancel</button>}
              </div></td>
            </tr>)}
          </tbody>
        </table></div>}
    </section>

    <section className="mt-6 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Payment history</h2><p className="mt-1 text-xs text-slate-500">Invoices recorded from bank-transfer renewals and provider webhooks.</p></div>
      {invoices.length === 0 ? <p className="p-5 text-xs text-slate-400">No invoices recorded yet.</p> :
        <div className="overflow-x-auto"><table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-[10px] uppercase tracking-wide text-slate-400">
            <tr><th className="px-5 py-3 font-semibold">Invoice</th><th className="px-4 py-3 font-semibold">Customer</th><th className="px-4 py-3 font-semibold">Amount</th><th className="px-4 py-3 font-semibold">Status</th><th className="px-4 py-3 font-semibold">Method</th><th className="px-4 py-3 font-semibold">Paid at</th></tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {invoices.map(invoice => <tr key={invoice.id}>
              <td className="px-5 py-3 font-mono text-[11px] font-semibold text-slate-800">{invoice.invoiceNumber}</td>
              <td className="px-4 py-3 text-slate-600">{invoice.organizationName}</td>
              <td className="px-4 py-3 tabular-nums text-slate-700">{sar(invoice.amountSarMinor)}</td>
              <td className="px-4 py-3"><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold " + (invoice.status === "PAID" ? "bg-emerald-50 text-emerald-700" : invoice.status === "VOID" ? "bg-slate-100 text-slate-500" : "bg-amber-50 text-amber-700")}>{invoice.status}</span></td>
              <td className="px-4 py-3 text-slate-500">{invoice.paymentMethod?.replace(/_/g, " ") || "—"}</td>
              <td className="px-4 py-3 text-slate-500">{invoice.paidAt ? new Date(invoice.paidAt).toLocaleString() : "—"}</td>
            </tr>)}
          </tbody>
        </table></div>}
    </section>

    {createOpen && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="New subscription">
      <CreateSubscriptionDialog plans={plans} onClose={() => setCreateOpen(false)} onCreated={async message => { setCreateOpen(false); setNotice(message); await loadData(true); }} />
    </div>}

    {renewFor && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Record renewal">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold">Record a renewal payment</h3><p className="mt-1 text-xs leading-5 text-slate-500">For {renewFor.organizationName} · {renewFor.primaryDomain || renewFor.accountUsername || "account"} on {renewFor.planName}. The transfer reference makes this payment traceable and the record idempotent — replaying the same reference never double-extends the period.</p></div><button onClick={() => setRenewFor(null)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Bank transfer reference</span>
          <input value={renewReference} onChange={event => setRenewReference(event.target.value)} placeholder="e.g. TRN-20261112-0042" autoFocus className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setRenewFor(null)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitRenew()} disabled={submitting || !renewReference.trim()} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Recording…" : "Record renewal"}</button></div>
      </div>
    </div>}

    {planChangeFor && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Change plan">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold">Change plan</h3><p className="mt-1 text-xs leading-5 text-slate-500">Current usage is validated against the target plan. Downgrades that would exceed the target quotas are rejected.</p></div><button onClick={() => setPlanChangeFor(null)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        {planViolations.length > 0 && <ul className="mt-4 space-y-1.5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-xs text-amber-800">{planViolations.map((violation, index) => <li key={index}>• {violation}</li>)}</ul>}
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Target plan</span>
          <select value={targetPlanId} onChange={event => setTargetPlanId(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none focus:border-blue-400">
            {plans.filter(plan => plan.active).map(plan => <option key={plan.id} value={plan.id}>{plan.name} · {sar(plan.price_sar_minor)}</option>)}
          </select>
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setPlanChangeFor(null)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitPlanChange()} disabled={submitting || targetPlanId === planChangeFor.planId} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Applying…" : "Change plan"}</button></div>
      </div>
    </div>}
  </main>;
}

function CreateSubscriptionDialog({ plans, onClose, onCreated }: { plans: PlanOption[]; onClose: () => void; onCreated: (message: string) => Promise<void> }) {
  const [hostingAccounts, setHostingAccounts] = useState<Array<{ id: string; primary_domain: string | null; username: string; plan_name: string }>>([]);
  const [accountId, setAccountId] = useState("");
  const [planId, setPlanId] = useState("");
  const [billingPeriod, setBillingPeriod] = useState("monthly");
  const [trialDays, setTrialDays] = useState("0");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/control/hosting-accounts", { cache: "no-store" })
      .then(response => response.json())
      .then(data => {
        const list = (data.accounts ?? []) as Array<{ id: string; primary_domain: string | null; username: string; plan_name: string }>;
        setHostingAccounts(list);
        setAccountId(list[0]?.id ?? "");
      })
      .catch(() => setError("Unable to load hosting accounts."));
  }, []);

  async function submit() {
    setSubmitting(true);
    setError("");
    try {
      const response = await fetch("/api/control/subscriptions", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ hostingAccountId: accountId, planId, billingPeriod, trialDays: Number(trialDays) || 0 }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to create the subscription.");
      await onCreated(`Subscription created (${data.subscription?.status}).`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create the subscription.");
    } finally { setSubmitting(false); }
  }

  return <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
    <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold">New subscription</h3><p className="mt-1 text-xs leading-5 text-slate-500">Attach a billing subscription to an active hosting account. One live subscription per account.</p></div><button onClick={onClose} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
    {error && <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">{error}</p>}
    <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Hosting account</span>
      <select value={accountId} onChange={event => setAccountId(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none focus:border-blue-400">
        {hostingAccounts.map(account => <option key={account.id} value={account.id}>{account.primary_domain || account.username} ({account.plan_name})</option>)}
      </select>
    </label>
    <label className="mt-4 block"><span className="text-xs font-semibold text-slate-700">Plan</span>
      <select value={planId} onChange={event => setPlanId(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none focus:border-blue-400">
        <option value="">Select a plan…</option>
        {plans.filter(plan => plan.active).map(plan => <option key={plan.id} value={plan.id}>{plan.name} · {sar(plan.price_sar_minor)}</option>)}
      </select>
    </label>
    <div className="mt-4 grid grid-cols-2 gap-4">
      <label className="block"><span className="text-xs font-semibold text-slate-700">Billing period</span>
        <select value={billingPeriod} onChange={event => setBillingPeriod(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none focus:border-blue-400">
          <option value="monthly">Monthly</option><option value="yearly">Yearly</option>
        </select>
      </label>
      <label className="block"><span className="text-xs font-semibold text-slate-700">Trial days (0–90)</span>
        <input type="number" min={0} max={90} value={trialDays} onChange={event => setTrialDays(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
      </label>
    </div>
    <div className="mt-6 flex justify-end gap-2"><button onClick={onClose} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submit()} disabled={submitting || !accountId || !planId} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Creating…" : "Create subscription"}</button></div>
  </div>;
}

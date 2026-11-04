"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowLeft, CheckCircle2, Clock3, LockKeyhole, Mail, Network, HardDrive, Activity, Settings2, ShieldCheck, Server, AlertTriangle } from "lucide-react";
import MonitoringDashboard from "@/components/monitoring-dashboard";

type Item = { title: string; description: string; state: "ready" | "pending" | "blocked" };
const configs: Record<string, { title: string; subtitle: string; icon: typeof Mail; items: Item[]; note: string }> = {
  email: {
    title: "Email hosting", subtitle: "Customer mailboxes, domains, quotas and delivery services.", icon: Mail,
    items: [
      { title: "Mailbox inventory", description: "Create and manage mailboxes attached to customer domains.", state: "pending" },
      { title: "Mailbox quotas", description: "Apply mailbox storage and account limits from hosting plans.", state: "pending" },
      { title: "SMTP and IMAP services", description: "Connect authenticated mail transport and mailbox services.", state: "blocked" },
      { title: "Spam and abuse controls", description: "Prepare rate limits, outbound restrictions and abuse monitoring.", state: "pending" },
    ], note: "Mailbox creation, SMTP/IMAP delivery and spam filtering require a connected mail server or external mail provider. No mailboxes are active yet."
  },
  dns: {
    title: "DNS management", subtitle: "Manage zone records and domain routing.", icon: Network,
    items: [
      { title: "DNS zone inventory", description: "Track zones associated with customer domains.", state: "pending" },
      { title: "A, AAAA and CNAME records", description: "Manage address and canonical-name records.", state: "pending" },
      { title: "MX, TXT and verification records", description: "Prepare mail routing, SPF, DKIM, DMARC and domain verification.", state: "pending" },
      { title: "Authoritative DNS provider", description: "Connect a provider API before publishing DNS changes.", state: "blocked" },
    ], note: "DNS records are not published by this control panel yet. A DNS provider integration and domain ownership verification are required."
  },
  backups: {
    title: "Backups", subtitle: "Plan customer backup policies and recovery workflows.", icon: HardDrive,
    items: [
      { title: "Scheduled backup policies", description: "Define daily, weekly and monthly retention policies.", state: "pending" },
      { title: "Customer restore requests", description: "Track restore requests and approval history.", state: "pending" },
      { title: "Backup storage destination", description: "Connect object storage with encryption and lifecycle rules.", state: "blocked" },
      { title: "Restore verification", description: "Require integrity checks before declaring a restore successful.", state: "pending" },
    ], note: "No backups are being taken. Actual backup and restore operations need a connected hosting node and configured object storage."
  },
  security: {
    title: "Access & security", subtitle: "Workspace access, authentication and audit readiness.", icon: ShieldCheck,
    items: [
      { title: "Workspace owner authentication", description: "Login sessions and protected workspace routes are enabled.", state: "ready" },
      { title: "Role-based permissions", description: "Workspace roles are defined; individual feature permissions need further enforcement.", state: "pending" },
      { title: "Multi-factor authentication", description: "MFA enrollment and recovery workflows are not yet connected.", state: "pending" },
      { title: "Audit trail", description: "Sensitive provisioning requests are recorded in workspace audit logs.", state: "ready" },
      { title: "Agent trust and enrollment", description: "Secure Linux agent enrollment, key rotation and signed job execution remain to be completed.", state: "blocked" },
    ], note: "This is a readiness view, not a security certification. Do not connect production hosting nodes until agent authentication, authorization and execution isolation are complete."
  },
  monitoring: {
    title: "Monitoring", subtitle: "Infrastructure health, capacity and service events.", icon: Activity,
    items: [
      { title: "Server heartbeat", description: "Authenticated Linux agents report server connectivity and last-heartbeat status.", state: "ready" },
      { title: "CPU, memory and disk telemetry", description: "Signed resource measurements are stored and displayed with history.", state: "ready" },
      { title: "Systemd service checks", description: "Six allowlisted Linux services report read-only unit states through agent heartbeats.", state: "ready" },
      { title: "Capacity thresholds and notifications", description: "Alert thresholds and notification delivery still need configuration.", state: "pending" },
      { title: "HTTP, DNS and mail probes", description: "External application and network probes are not configured.", state: "blocked" },
    ], note: "Server telemetry and systemd service states are available from connected agents. Alert delivery and external probes are separate unfinished capabilities."
  },
  settings: {
    title: "System settings", subtitle: "Workspace configuration and service integrations.", icon: Settings2,
    items: [
      { title: "Workspace profile", description: "Organization profile and owner settings.", state: "pending" },
      { title: "API and service connections", description: "Cloudflare API and D1 are connected for the control plane.", state: "ready" },
      { title: "Email notifications", description: "Configure a transactional email provider before sending alerts.", state: "pending" },
      { title: "Storage integrations", description: "Connect encrypted backup and customer file storage.", state: "pending" },
      { title: "Billing integration", description: "Customer billing, invoices and payment collection are not connected.", state: "blocked" },
    ], note: "Cloudflare currently hosts the Nexora control plane. Customer hosting, mail, backups and billing integrations are separate services."
  }
};


type NotificationSettings = {
  enabled: boolean;
  recipients: string[];
  providerConfigured: boolean;
  sender: string | null;
  canManage: boolean;
};

function EmailNotificationSettings() {
  const [settings, setSettings] = useState<NotificationSettings | null>(null);
  const [recipientsText, setRecipientsText] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [testSending, setTestSending] = useState(false);
  const [testMessage, setTestMessage] = useState("");
  const [testError, setTestError] = useState("");

  useEffect(() => {
    let active = true;
    fetch("/api/control/notification-settings", { cache: "no-store" })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Unable to load notification settings.");
        return data as NotificationSettings;
      })
      .then((data) => {
        if (!active) return;
        setSettings(data);
        setEnabled(data.enabled);
        setRecipientsText(data.recipients.join("\n"));
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Unable to load notification settings.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  async function saveSettings(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setMessage("");

    const recipients = [...new Set(
      recipientsText.split(/[,\n;]/).map((email) => email.trim().toLowerCase()).filter(Boolean)
    )];

    try {
      const response = await fetch("/api/control/notification-settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled, recipients }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to save notification settings.");

      setSettings((current) => current ? {
        ...current,
        enabled: data.enabled,
        recipients: data.recipients,
        providerConfigured: data.providerConfigured,
      } : current);
      setRecipientsText(data.recipients.join("\n"));
      setMessage("Notification settings saved.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to save notification settings.");
    } finally {
      setSaving(false);
    }
  }


  async function sendTestEmail() {
    setTestSending(true);
    setTestError("");
    setTestMessage("");

    try {
      const response = await fetch("/api/control/notification-settings/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to send test email.");
      setTestMessage(
        data.emailId
          ? `Resend accepted the test email. Message ID: ${data.emailId}`
          : "Resend accepted the test email."
      );
    } catch (reason) {
      setTestError(reason instanceof Error ? reason.message : "Unable to send test email.");
    } finally {
      setTestSending(false);
    }
  }

  return <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
    <div className="border-b border-slate-100 px-5 py-4">
      <div className="flex items-center gap-2">
        <Mail size={18} className="text-blue-700"/>
        <h2 className="font-semibold">Incident email notifications</h2>
      </div>
      <p className="mt-1 text-xs text-slate-500">Choose who receives incident-opened and incident-recovery alerts for this workspace.</p>
    </div>
    <div className="space-y-4 p-5">
      {loading ? <p className="text-sm text-slate-500">Loading notification settings…</p> : <>
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div>
            <p className="text-sm font-medium">Resend delivery provider</p>
            <p className="mt-1 text-xs text-slate-500">
              {settings?.providerConfigured
                ? `Configured${settings.sender ? ` · ${settings.sender}` : ""}`
                : "Not configured. Add RESEND_API_KEY and EMAIL_FROM to the API Worker before sending."}
            </p>
          </div>
          <span className={"rounded-full px-2.5 py-1 text-xs font-medium " + (settings?.providerConfigured ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-800")}>
            {settings?.providerConfigured ? "Provider ready" : "Setup required"}
          </span>
        </div>

        <form onSubmit={saveSettings} className="space-y-4">
          <label className="flex items-start gap-3">
            <input
              type="checkbox"
              checked={enabled}
              disabled={!settings?.canManage || saving}
              onChange={(event) => setEnabled(event.target.checked)}
              className="mt-1 h-4 w-4 rounded border-slate-300"
            />
            <span>
              <span className="block text-sm font-medium">Enable incident email notifications</span>
              <span className="mt-1 block text-xs text-slate-500">When active, new incidents and their recovery will be sent to the recipients below once delivery is enabled.</span>
            </span>
          </label>

          <label className="block">
            <span className="text-sm font-medium">Recipient email addresses</span>
            <textarea
              value={recipientsText}
              onChange={(event) => setRecipientsText(event.target.value)}
              disabled={!settings?.canManage || saving}
              rows={4}
              maxLength={2540}
              placeholder={"ops@example.com\nadmin@example.com"}
              className="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 disabled:bg-slate-50"
            />
            <span className="mt-1 block text-xs text-slate-500">Separate addresses with a new line, comma or semicolon. Maximum 10 recipients.</span>
          </label>

          {!settings?.canManage && <p className="text-xs text-slate-500">Only workspace owners and administrators can change these settings.</p>}
          {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
          {message && <p role="status" className="text-sm text-emerald-700">{message}</p>}

          {settings?.canManage && <button
            type="submit"
            disabled={saving}
            className="rounded-lg bg-blue-700 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {saving ? "Saving…" : "Save notification settings"}
          </button>}
          {settings?.canManage && <div className="space-y-2 border-t border-slate-100 pt-4">
            <button
              type="button"
              onClick={sendTestEmail}
              disabled={testSending || saving || loading || !settings.enabled || !settings.providerConfigured || settings.recipients.length === 0}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {testSending ? "Sending test email…" : "Send test email"}
            </button>
            <p className="text-xs text-slate-500">Sends a clearly labelled test message to the saved recipients. Does not create an incident. One test per 60 seconds.</p>
            {testError && <p role="alert" className="text-sm text-red-600">{testError}</p>}
            {testMessage && <p role="status" className="break-all text-sm text-emerald-700">{testMessage}</p>}
          </div>}
        </form>
      </>}
    </div>
  </section>;
}

export default function OperationsModule({ module }: { module: string }) {
  const config = configs[module] ?? configs.settings;
  const Icon = config.icon;
  const [notificationReadiness, setNotificationReadiness] = useState<"ready" | "pending">("pending");

  useEffect(() => {
    if (module !== "settings") return;
    let active = true;

    fetch("/api/control/notification-settings", { cache: "no-store" })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Unable to load notification readiness.");
        return data as NotificationSettings;
      })
      .then((data) => {
        if (!active) return;
        const ready =
          data.providerConfigured &&
          data.enabled &&
          data.recipients.length > 0;
        setNotificationReadiness(ready ? "ready" : "pending");
      })
      .catch(() => {
        if (active) setNotificationReadiness("pending");
      });

    return () => { active = false; };
  }, [module]);

  if (module === "monitoring") return <MonitoringDashboard/>;

  const items = config.items.map(item =>
    module === "settings" && item.title === "Email notifications"
      ? {
          ...item,
          description: notificationReadiness === "ready"
            ? "Transactional email provider is configured, notifications are enabled, and recipients are saved."
            : "Enable notifications, configure a transactional email provider, and save at least one recipient.",
          state: notificationReadiness,
        }
      : item
  );

  const ready = items.filter(x => x.state === "ready").length;
  const pending = items.filter(x => x.state === "pending").length;
  const blocked = items.filter(x => x.state === "blocked").length;
  return <main className="min-h-screen bg-slate-50 text-slate-900">
    <header className="border-b border-slate-200 bg-white"><div className="mx-auto flex max-w-7xl items-center gap-3 px-5 py-4">
      <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
      <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Icon size={20}/></span>
      <div><p className="font-semibold">Nexora Control</p><p className="text-xs text-slate-500">Infrastructure / {config.title}</p></div>
    </div></header>
    <section className="mx-auto max-w-7xl space-y-6 px-5 py-8">
      <div><p className="text-sm font-medium text-blue-700">Infrastructure services</p><h1 className="mt-1 text-2xl font-semibold tracking-tight">{config.title}</h1><p className="mt-2 text-sm text-slate-500">{config.subtitle}</p></div>
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Ready</p><p className="mt-2 text-3xl font-semibold">{ready}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Pending setup</p><p className="mt-2 text-3xl font-semibold">{pending}</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">External dependency</p><p className="mt-2 text-3xl font-semibold">{blocked}</p></div>
      </div>
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Service readiness</h2><p className="mt-1 text-xs text-slate-500">Current implementation and infrastructure dependencies.</p></div>
        <div className="divide-y divide-slate-100">{items.map(item => <div key={item.title} className="flex flex-wrap items-start gap-3 px-5 py-5">
          <span className="mt-0.5 rounded-lg bg-slate-50 p-2 text-slate-600">{item.state === "ready" ? <CheckCircle2 size={18}/> : item.state === "blocked" ? <AlertTriangle size={18}/> : <Clock3 size={18}/>}</span>
          <div className="min-w-0 flex-1"><p className="text-sm font-medium">{item.title}</p><p className="mt-1 text-sm leading-5 text-slate-500">{item.description}</p></div>
          <span className={"rounded-full px-2.5 py-1 text-xs font-medium " + (item.state === "ready" ? "bg-emerald-50 text-emerald-700" : item.state === "blocked" ? "bg-amber-50 text-amber-800" : "bg-slate-100 text-slate-600")}>{item.state === "ready" ? "Ready" : item.state === "blocked" ? "External dependency" : "Pending"}</span>
        </div>)}</div>
      </div>
      {module === "settings" && <EmailNotificationSettings/>}
      <div className="rounded-2xl border border-blue-100 bg-blue-50/70 p-5"><div className="flex gap-3"><span className="rounded-xl bg-white p-2 text-blue-700"><LockKeyhole size={19}/></span><div><h2 className="text-sm font-semibold">Infrastructure status</h2><p className="mt-1 text-sm leading-6 text-slate-600">{config.note}</p></div></div></div>
      <div className="flex flex-wrap gap-3 text-sm"><Link href="/servers" className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-700 hover:bg-slate-50"><Server size={14} className="mr-2 inline"/>Server management</Link><Link href="/hosting-accounts" className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-slate-700 hover:bg-slate-50">Hosting accounts</Link></div>
    </section>
  </main>;
}

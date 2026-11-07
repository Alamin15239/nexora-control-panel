"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, AlertTriangle, ArrowUpRight, Box, Database, Globe2, HardDrive, Plus, Server, ShieldCheck, Users, Zap, FolderOpen, Mail, Network, Github } from "lucide-react";

const quickTools = [
  { label: "Websites & domains", description: "Add domains and manage website routing", href: "/websites-domains", icon: Globe2 },
  { label: "File Manager", description: "Browse website files and document roots", href: "/file-manager", icon: FolderOpen },
  { label: "Databases", description: "Create MariaDB databases and users", href: "/databases", icon: Database },
  { label: "Email accounts", description: "Manage mailboxes and delivery settings", href: "/email", icon: Mail },
  { label: "DNS zones", description: "Manage DNS records and hostnames", href: "/dns", icon: Network },
  { label: "Git deployments", description: "Connect repositories and releases", href: "/github-deployments", icon: Github },
];
function Metric({ label, value, note, icon: Icon }: { label: string; value: string; note: string; icon: typeof Server }) {
  return <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex items-center justify-between"><p className="text-sm text-slate-500">{label}</p><span className="rounded-xl bg-slate-50 p-2 text-slate-600"><Icon size={18}/></span></div><p className="mt-4 text-3xl font-semibold tracking-tight text-slate-900">{value}</p><p className="mt-1 text-xs text-slate-500">{note}</p></div>;
}

type DashboardServer = {
  id: string; hostname: string; primary_ip: string; status: string;
  last_heartbeat_at: string | null; agent_version: string | null;
};
type DashboardTelemetry = {
  cpu_usage_percent: number; memory_total_bytes: number; memory_used_bytes: number;
  disk_total_bytes: number; disk_used_bytes: number; load_average_1m: number; collected_at: string;
};
type DashboardIncident = {
  id: string; serverHostname: string; severity: string; status: string;
  title: string; description: string; openedAt: string;
};
type DashboardDetails = {
  servers: DashboardServer[];
  telemetry: Record<string, DashboardTelemetry | null>;
  accounts: { id: string; username: string; primary_domain: string; status: string; plan_name: string }[];
  plans: { id: string; name: string; active: number }[];
  domains: { id: string; name: string; cloudflare_hostname_status: string | null; cloudflare_ssl_status: string | null }[];
  databases: { id: string; name: string; status: string }[];
  incidents: DashboardIncident[];
};

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return `${amount.toFixed(amount >= 10 ? 0 : 1)} ${units[unit]}`;
}
function usagePercent(used: number, total: number): number {
  return total > 0 ? Math.max(0, Math.min(100, used / total * 100)) : 0;
}
function relativeTime(value: string | null): string {
  if (!value) return "No heartbeat";
  const age = Date.now() - Date.parse(value);
  if (!Number.isFinite(age)) return "Unknown";
  if (age < 60_000) return "Just now";
  if (age < 3_600_000) return `${Math.floor(age / 60_000)} min ago`;
  return `${Math.floor(age / 3_600_000)} hr ago`;
}

type OverviewData = {
  counts: { servers: number; onlineServers: number; hostingAccounts: number; websites: number; hostingPlans: number; databases: number };
  checks: { api: boolean; database: boolean; schema: boolean; agent: boolean; server: boolean };
  updatedAt: string;
};

export default function Home() {
  const router = useRouter();
  const [identity, setIdentity] = useState<{ displayName: string | null; email: string; role?: string; customerAccess?: boolean } | null>(null);
  const [checking, setChecking] = useState(true);
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [overviewError, setOverviewError] = useState("");
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [details, setDetails] = useState<DashboardDetails | null>(null);
  const [detailsError, setDetailsError] = useState("");
  const [detailsLoading, setDetailsLoading] = useState(true);

  useEffect(() => {
    let active = true;
    fetch("/api/auth/me", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Not signed in");
        return response.json();
      })
      .then((user) => {
        if (!active) return;
        if (user.role === "MEMBER" || user.customerAccess) {
          router.replace("/customer");
          return;
        }
        setIdentity(user);
      })
      .catch(() => { if (active) router.replace("/login"); })
      .finally(() => { if (active) setChecking(false); });
    return () => { active = false; };
  }, [router]);

  useEffect(() => {
    let active = true;
    async function loadOverview() {
      setOverviewLoading(true);
      setOverviewError("");
      try {
        const response = await fetch("/api/control/overview", { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Unable to load infrastructure status");
        if (active) setOverview(data as OverviewData);
      } catch (error) {
        if (active) setOverviewError(error instanceof Error ? error.message : "Unable to load infrastructure status");
      } finally {
        if (active) setOverviewLoading(false);
      }
    }
    void loadOverview();
    const interval = window.setInterval(() => void loadOverview(), 60_000);
    return () => { active = false; window.clearInterval(interval); };
  }, []);

  useEffect(() => {
    let active = true;
    async function loadDetails() {
      setDetailsLoading(true);
      setDetailsError("");
      try {
        const endpoints = ["servers", "hosting-accounts", "hosting-plans", "domains", "databases", "incidents"];
        const responses = await Promise.all(endpoints.map(endpoint => fetch(`/api/control/${endpoint}`, { cache: "no-store" })));
        const payloads = await Promise.all(responses.map(async response => {
          const data = await response.json();
          if (!response.ok) throw new Error(data.message || "Unable to load dashboard inventory.");
          return data;
        }));
        const servers = (payloads[0].servers ?? []) as DashboardServer[];
        const telemetryPairs = await Promise.all(servers.map(async server => {
          const response = await fetch(`/api/control/servers/${server.id}/telemetry`, { cache: "no-store" });
          if (!response.ok) return [server.id, null] as const;
          const data = await response.json();
          return [server.id, (data.latest ?? null) as DashboardTelemetry | null] as const;
        }));
        if (!active) return;
        setDetails({
          servers,
          telemetry: Object.fromEntries(telemetryPairs),
          accounts: payloads[1].accounts ?? [],
          plans: payloads[2].plans ?? [],
          domains: payloads[3].domains ?? [],
          databases: payloads[4].databases ?? [],
          incidents: (payloads[5].incidents ?? []).filter((incident: DashboardIncident) => incident.status !== "RESOLVED"),
        });
      } catch (error) {
        if (active) setDetailsError(error instanceof Error ? error.message : "Unable to load dashboard inventory.");
      } finally {
        if (active) setDetailsLoading(false);
      }
    }
    void loadDetails();
    const interval = window.setInterval(() => void loadDetails(), 60_000);
    return () => { active = false; window.clearInterval(interval); };
  }, []);

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  if (checking || !identity) return <main className="grid min-h-screen place-items-center bg-slate-50"><div className="text-center"><div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-blue-700"/><p className="mt-4 text-sm text-slate-500">Securing your workspace…</p></div></main>;

  return <main className="min-h-screen">
    <section className="min-w-0 flex-1">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 bg-white px-6 py-4 lg:px-9"><div><p className="text-xs text-slate-500">WHM / Platform administration</p><h1 className="mt-1 text-lg font-semibold">Hosting overview</h1></div><div className="flex items-center gap-3"><span className="hidden rounded-full border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-800 sm:inline-flex">Development environment</span><span className="max-w-40 truncate text-xs text-slate-600">{identity.displayName || identity.email}</span><button onClick={signOut} className="rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-600 hover:bg-slate-50">Sign out</button></div></header>
      <div className="mx-auto max-w-7xl space-y-7 px-5 py-8 lg:px-9">
        <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-blue-700">WHM · Administrator home</p><h2 className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">Manage your hosting platform.</h2><p className="mt-2 max-w-2xl text-sm text-slate-500">Manage customer accounts, hosting packages and server health, then jump directly into the tools customers use to operate their websites.</p></div><button onClick={() => router.push("/servers")} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-blue-800"><Plus size={16}/> Register server</button></div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"><Metric label="Managed servers" value={overviewLoading && !overview ? "…" : String(overview?.counts.servers ?? "—")} note={overview ? `${overview.counts.onlineServers} online · live agent heartbeats` : "Live server inventory"} icon={Server}/><Metric label="Hosting accounts" value={overviewLoading && !overview ? "…" : String(overview?.counts.hostingAccounts ?? "—")} note="Provisioned customer accounts" icon={Users}/><Metric label="Websites" value={overviewLoading && !overview ? "…" : String(overview?.counts.websites ?? "—")} note="Domains registered in this workspace" icon={Globe2}/><Metric label="System status" value={overview ? (overview.checks.api && overview.checks.database && overview.checks.schema ? (overview.checks.agent ? "Online" : "Setup") : "Attention") : overviewLoading ? "Checking" : "Unavailable"} note={overview ? (overview.checks.agent ? "API, database and agent responding" : "Control plane ready · waiting for agent") : overviewError || "Checking control-plane services"} icon={Activity}/></div>
        <section aria-labelledby="hosting-tools-heading" className="space-y-3">
          <div className="flex flex-wrap items-end justify-between gap-2"><div><p className="text-xs font-semibold uppercase tracking-[.14em] text-slate-400">cPanel-style shortcuts</p><h3 id="hosting-tools-heading" className="mt-1 text-base font-semibold text-slate-900">Hosting tools</h3></div><a href="/hosting-accounts" className="text-xs font-semibold text-blue-700 hover:text-blue-800">Manage customer accounts <ArrowUpRight size={13} className="ml-1 inline"/></a></div>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {quickTools.map(({ label, description, href, icon: Icon }) => <a key={href} href={href} className="group flex items-start gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-md">
              <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-blue-50 text-blue-700 transition group-hover:bg-blue-700 group-hover:text-white"><Icon size={19}/></span>
              <span className="min-w-0"><span className="block text-sm font-semibold text-slate-900">{label}</span><span className="mt-1 block text-xs leading-5 text-slate-500">{description}</span></span>
              <ArrowUpRight size={15} className="ml-auto shrink-0 text-slate-300 transition group-hover:text-blue-700"/>
            </a>)}
          </div>
        </section>
        <section className="grid gap-4 xl:grid-cols-[1.35fr_1fr]">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div><h3 className="font-semibold">Server health</h3><p className="mt-1 text-xs text-slate-500">Latest authenticated Linux agent readings</p></div>
              <a href="/monitoring" className="text-sm font-medium text-blue-700 hover:text-blue-800">Full monitoring <ArrowUpRight size={14} className="ml-1 inline"/></a>
            </div>
            {detailsLoading && !details ? <p className="mt-5 text-sm text-slate-500">Loading server health…</p> : details?.servers.length ? <div className="mt-4 space-y-3">
              {details.servers.slice(0, 3).map(server => {
                const sample = details.telemetry[server.id];
                const cpu = sample?.cpu_usage_percent ?? null;
                const memory = sample ? usagePercent(sample.memory_used_bytes, sample.memory_total_bytes) : null;
                const disk = sample ? usagePercent(sample.disk_used_bytes, sample.disk_total_bytes) : null;
                const online = server.status === "ONLINE";
                return <div key={server.id} className="rounded-xl border border-slate-100 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2"><div><p className="text-sm font-semibold">{server.hostname}</p><p className="mt-0.5 text-xs text-slate-500">{server.primary_ip} · Heartbeat {relativeTime(server.last_heartbeat_at)}</p></div><span className={`rounded-full px-2.5 py-1 text-xs font-medium ${online ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-800"}`}>{online ? "Online" : server.status}</span></div>
                  <div className="mt-4 grid grid-cols-3 gap-3">
                    {[{label:"CPU",value:cpu === null ? "No data" : `${cpu.toFixed(1)}%`,pct:cpu},{label:"Memory",value:memory === null ? "No data" : `${memory.toFixed(1)}%`,pct:memory},{label:"Disk",value:disk === null ? "No data" : `${disk.toFixed(1)}%`,pct:disk}].map(metric => <div key={metric.label}><div className="flex items-center justify-between gap-1"><span className="text-xs text-slate-500">{metric.label}</span><span className="text-xs font-semibold tabular-nums">{metric.value}</span></div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-100"><div className={`h-full rounded-full ${(metric.pct ?? 0) >= 90 ? "bg-red-500" : (metric.pct ?? 0) >= 75 ? "bg-amber-500" : "bg-blue-600"}`} style={{width:`${metric.pct ?? 0}%`}}/></div></div>)}
                  </div>
                  {sample && <p className="mt-3 text-[11px] text-slate-400">Node-wide usage · {new Date(sample.collected_at).toLocaleTimeString()} · Load {sample.load_average_1m.toFixed(2)}</p>}
                </div>;
              })}
            </div> : <p className="mt-5 text-sm text-slate-500">No registered servers yet.</p>}
            {detailsError && <p role="alert" className="mt-3 text-xs text-amber-700">{detailsError}</p>}
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between"><div><h3 className="font-semibold">Hosting inventory</h3><p className="mt-1 text-xs text-slate-500">Current workspace resources</p></div><Box size={18} className="text-slate-400"/></div>
            <div className="mt-4 grid grid-cols-2 gap-3">
              {[{label:"Hosting plans",value:details?.plans.length},{label:"Active accounts",value:details?.accounts.filter(account => account.status === "ACTIVE").length},{label:"Domains",value:details?.domains.length},{label:"Databases",value:details?.databases.length}].map(item => <div key={item.label} className="rounded-xl bg-slate-50 p-3"><p className="text-xs text-slate-500">{item.label}</p><p className="mt-1 text-2xl font-semibold tabular-nums">{detailsLoading && !details ? "—" : item.value ?? 0}</p></div>)}
            </div>
            <p className="mt-4 text-xs leading-5 text-slate-500">Resource quotas are defined by hosting plans. Per-account disk and bandwidth consumption is not yet reported in this summary.</p>
          </div>
        </section>

        <section className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between gap-2"><div><h3 className="font-semibold">Active incidents</h3><p className="mt-1 text-xs text-slate-500">Open infrastructure alerts requiring attention</p></div><a href="/monitoring" className="text-sm font-medium text-blue-700">View all</a></div>
            {details?.incidents.length ? <div className="mt-3 divide-y divide-slate-100">{details.incidents.slice(0,4).map(incident => <div key={incident.id} className="flex items-start gap-3 py-3"><span className={`mt-0.5 rounded-lg p-2 ${incident.severity === "CRITICAL" ? "bg-red-50 text-red-600" : "bg-amber-50 text-amber-700"}`}><AlertTriangle size={16}/></span><div className="min-w-0 flex-1"><p className="text-sm font-medium">{incident.title}</p><p className="mt-1 text-xs text-slate-500">{incident.serverHostname} · {incident.status} · {new Date(incident.openedAt).toLocaleString()}</p></div></div>)}</div> : <div className="py-6 text-center"><ShieldCheck size={23} className="mx-auto text-emerald-600"/><p className="mt-2 text-sm font-medium">{detailsLoading ? "Checking incidents…" : "No active incidents"}</p><p className="mt-1 text-xs text-slate-500">Open server and service alerts appear here.</p></div>}
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center gap-2"><Zap size={17} className="text-amber-500"/><h3 className="font-semibold">Quick actions</h3></div>
            <div className="mt-4 grid grid-cols-2 gap-2">
              {[{label:"Add server",href:"/servers",icon:Server},{label:"Create plan",href:"/hosting-plans",icon:Box},{label:"New account",href:"/hosting-accounts",icon:Users},{label:"Add website",href:"/websites-domains",icon:Globe2},{label:"Create database",href:"/databases",icon:Database},{label:"Manage backups",href:"/backups",icon:HardDrive}].map(({label,href,icon: Icon}) => <a key={label} href={href} className="flex items-center gap-2 rounded-xl border border-slate-200 px-3 py-3 text-sm font-medium text-slate-700 transition hover:border-blue-200 hover:bg-blue-50"><Icon size={16} className="text-blue-700"/>{label}</a>)}
            </div>
          </div>
        </section>


        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2"><div><h3 className="font-semibold">Infrastructure readiness</h3><p className="mt-1 text-xs text-slate-500">Live setup checks · refreshed every minute</p></div><span className="rounded-lg bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700">{overview ? `${[overview.checks.api, overview.checks.database && overview.checks.schema, overview.checks.agent, overview.checks.server].filter(Boolean).length} / 4 complete` : overviewLoading ? "Checking…" : "Unavailable"}</span></div>
          <div className="mt-5 h-2 overflow-hidden rounded-full bg-slate-100"><div className="h-full rounded-full bg-blue-600 transition-all" style={{width: overview ? `${[overview.checks.api, overview.checks.database && overview.checks.schema, overview.checks.agent, overview.checks.server].filter(Boolean).length * 25}%` : "0%"}}/></div>
          <div className="mt-5 grid gap-4 sm:grid-cols-2">{[{label:"Deploy the control-plane API",done:overview?.checks.api,detail:"API health endpoint"},{label:"Verify Cloudflare D1 database",done:overview?.checks.database && overview?.checks.schema,detail:"Database connectivity and schema"},{label:"Install the Linux server agent",done:overview?.checks.agent,detail:"Recent authenticated heartbeat"},{label:"Verify your connected Linux server",done:overview?.checks.server,detail:"At least one server online"}].map((item,i)=><div key={item.label} className="flex items-center gap-3"><span className={`grid h-7 w-7 place-items-center rounded-full border text-xs ${item.done ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 text-slate-500"}`}>{item.done ? <ShieldCheck size={15}/> : i+1}</span><span className="min-w-0 flex-1"><span className="block text-sm text-slate-700">{item.label}</span><span className="block text-xs text-slate-400">{item.detail}</span></span><span className={`text-xs ${item.done ? "font-medium text-emerald-700" : "text-slate-400"}`}>{item.done ? "Complete" : overviewLoading ? "Checking" : "Pending"}</span></div>)}</div>
          {overviewError && <p role="alert" className="mt-4 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">{overviewError}</p>}
        </section>

        <div className="rounded-2xl border border-blue-100 bg-blue-50/70 p-5"><div className="flex gap-3"><div className="rounded-xl bg-white p-2 text-blue-700"><ShieldCheck size={19}/></div><div><h3 className="text-sm font-semibold text-slate-900">Control-plane foundation</h3><p className="mt-1 max-w-4xl text-sm leading-6 text-slate-600">Overview metrics and readiness checks are now loaded from the authenticated control-plane API. Server actions still require the authenticated agent and explicit operation policies.</p></div></div></div>
        <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 pt-5 text-xs text-slate-400"><span>Nexora Control · Private development</span><span>Infrastructure management platform</span></footer>
      </div>
    </section>
  </main>;
}

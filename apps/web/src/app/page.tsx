"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Activity, AlertTriangle, ArrowUpRight, Box, Database, Globe2, HardDrive, Plus,
  Server, ShieldCheck, Users, Zap, FolderOpen, Mail, Network, Github,
} from "lucide-react";
import {
  EmptyState, InlineAlert, Meter, NexoraMark, PageHeader, SectionCard, StatCard,
  StatusBadge,
} from "@/components/ui";

const quickTools = [
  { label: "Websites & domains", description: "Add domains and manage website routing", href: "/websites-domains", icon: Globe2 },
  { label: "File Manager", description: "Browse website files and document roots", href: "/file-manager", icon: FolderOpen },
  { label: "Databases", description: "Create MariaDB databases and users", href: "/databases", icon: Database },
  { label: "Email accounts", description: "Manage mailboxes and delivery settings", href: "/email", icon: Mail },
  { label: "DNS zones", description: "Manage DNS records and hostnames", href: "/dns", icon: Network },
  { label: "Nexora Deploy", description: "Connect repositories and Git-based releases", href: "/github-deployments", icon: Github },
];

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

  if (checking || !identity) return (
    <main className="grid min-h-screen place-items-center bg-canvas">
      <div className="text-center">
        <span className="mx-auto inline-block h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-brand-600" />
        <p className="mt-4 text-sm text-slate-500">Securing your workspace…</p>
      </div>
    </main>
  );

  const readinessChecks = overview ? [overview.checks.api, overview.checks.database && overview.checks.schema, overview.checks.agent, overview.checks.server].filter(Boolean).length : 0;

  return (
    <main className="min-h-screen">
      <section className="min-w-0 flex-1">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200/80 bg-white/85 px-6 py-4 backdrop-blur-xl lg:px-9">
          <div>
            <p className="text-xs font-medium text-slate-500">WHM / Platform administration</p>
            <h1 className="mt-0.5 text-lg font-bold tracking-tight text-slate-950">Hosting overview</h1>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden rounded-full border border-amber-200 bg-amber-50 px-3 py-1.5 text-[11px] font-semibold text-amber-800 sm:inline-flex">Development environment</span>
            <span className="max-w-44 truncate text-xs font-medium text-slate-600">{identity.displayName || identity.email}</span>
            <button onClick={signOut} className="rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-600 shadow-sm transition hover:bg-slate-50">Sign out</button>
          </div>
        </header>
        <div className="mx-auto max-w-[1400px] space-y-8 px-5 py-8 lg:px-9">
          <PageHeader
            eyebrow="WHM · Administrator home"
            title="Manage your hosting platform."
            description="Manage customer accounts, hosting packages and server health, then jump directly into the tools customers use to operate their websites."
            actions={
              <button onClick={() => router.push("/servers")} className="nx-btn-primary"><Plus size={16} /> Register server</button>
            }
          />

          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={Server}
              label="Managed servers"
              value={overviewLoading && !overview ? "…" : String(overview?.counts.servers ?? "—")}
              hint={overview ? `${overview.counts.onlineServers} online · live agent heartbeats` : "Live server inventory"}
            />
            <StatCard
              icon={Users}
              label="Hosting accounts"
              value={overviewLoading && !overview ? "…" : String(overview?.counts.hostingAccounts ?? "—")}
              hint="Provisioned customer accounts"
            />
            <StatCard
              icon={Globe2}
              label="Websites"
              value={overviewLoading && !overview ? "…" : String(overview?.counts.websites ?? "—")}
              hint="Domains registered in this workspace"
            />
            <StatCard
              icon={Activity}
              label="System status"
              value={overview ? (overview.checks.api && overview.checks.database && overview.checks.schema ? (overview.checks.agent ? "Online" : "Setup") : "Attention") : overviewLoading ? "Checking" : "Unavailable"}
              hint={overview ? (overview.checks.agent ? "API, database and agent responding" : "Control plane ready · waiting for agent") : overviewError || "Checking control-plane services"}
            />
          </div>

          <section aria-labelledby="hosting-tools-heading" className="space-y-3.5">
            <div className="flex flex-wrap items-end justify-between gap-2">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">cPanel-style shortcuts</p>
                <h3 id="hosting-tools-heading" className="mt-1 text-base font-semibold text-slate-900">Hosting tools</h3>
              </div>
              <Link href="/hosting-accounts" className="inline-flex items-center gap-1 text-xs font-semibold text-brand-600 transition hover:text-brand-700">Manage customer accounts <ArrowUpRight size={13} /></Link>
            </div>
            <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3">
              {quickTools.map(({ label, description, href, icon: Icon }) => (
                <Link key={href} href={href} className="group nx-card flex items-start gap-3.5 p-4 transition hover:-translate-y-0.5 hover:shadow-lift">
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-brand-50 text-brand-600 transition group-hover:bg-brand-600 group-hover:text-white"><Icon size={19} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-semibold text-slate-900">{label}</span>
                    <span className="mt-1 block text-xs leading-5 text-slate-500">{description}</span>
                  </span>
                  <ArrowUpRight size={15} className="mt-1 shrink-0 text-slate-300 transition group-hover:text-brand-600" />
                </Link>
              ))}
            </div>
          </section>

          <section className="grid gap-4 xl:grid-cols-[1.35fr_1fr]">
            <SectionCard
              title="Server health"
              description="Latest authenticated Linux agent readings"
              actions={<Link href="/monitoring" className="inline-flex items-center gap-1 text-xs font-semibold text-brand-600 hover:text-brand-700">Full monitoring <ArrowUpRight size={13} /></Link>}
            >
              {detailsLoading && !details ? (
                <p className="text-sm text-slate-500">Loading server health…</p>
              ) : details?.servers.length ? (
                <div className="space-y-3">
                  {details.servers.slice(0, 3).map(server => {
                    const sample = details.telemetry[server.id];
                    const cpu = sample?.cpu_usage_percent ?? null;
                    const memory = sample ? usagePercent(sample.memory_used_bytes, sample.memory_total_bytes) : null;
                    const disk = sample ? usagePercent(sample.disk_used_bytes, sample.disk_total_bytes) : null;
                    const online = server.status === "ONLINE";
                    return (
                      <div key={server.id} className="rounded-xl border border-slate-100 bg-slate-50/50 p-4">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="min-w-0">
                            <p className="text-sm font-semibold text-slate-900">{server.hostname}</p>
                            <p className="mt-0.5 text-xs text-slate-500">{server.primary_ip} · Heartbeat {relativeTime(server.last_heartbeat_at)}</p>
                          </div>
                          <StatusBadge tone={online ? "success" : "warning"} dot>{online ? "Online" : server.status}</StatusBadge>
                        </div>
                        <div className="mt-4 grid grid-cols-3 gap-4">
                          {[{ label: "CPU", value: cpu === null ? "No data" : `${cpu.toFixed(1)}%`, pct: cpu }, { label: "Memory", value: memory === null ? "No data" : `${memory.toFixed(1)}%`, pct: memory }, { label: "Disk", value: disk === null ? "No data" : `${disk.toFixed(1)}%`, pct: disk }].map(metric => (
                            <div key={metric.label}>
                              <div className="flex items-center justify-between gap-1">
                                <span className="text-xs text-slate-500">{metric.label}</span>
                                <span className="text-xs font-semibold tabular-nums text-slate-700">{metric.value}</span>
                              </div>
                              <Meter value={metric.pct ?? 0} className="mt-2" />
                            </div>
                          ))}
                        </div>
                        {sample && <p className="mt-3 text-[11px] text-slate-400">Node-wide usage · {new Date(sample.collected_at).toLocaleTimeString()} · Load {sample.load_average_1m.toFixed(2)}</p>}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <EmptyState icon={Server} title="No registered servers yet" description="Register your first Linux server to start receiving authenticated agent heartbeats and telemetry." />
              )}
              {detailsError && <p role="alert" className="mt-3 text-xs text-amber-700">{detailsError}</p>}
            </SectionCard>

            <SectionCard title="Hosting inventory" description="Current workspace resources">
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "Hosting plans", value: details?.plans.length },
                  { label: "Active accounts", value: details?.accounts.filter(account => account.status === "ACTIVE").length },
                  { label: "Domains", value: details?.domains.length },
                  { label: "Databases", value: details?.databases.length },
                ].map(item => (
                  <div key={item.label} className="rounded-xl border border-slate-100 bg-slate-50/70 p-4">
                    <p className="text-xs font-medium text-slate-500">{item.label}</p>
                    <p className="mt-1 text-2xl font-bold tabular-nums text-slate-950">{detailsLoading && !details ? "—" : item.value ?? 0}</p>
                  </div>
                ))}
              </div>
              <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-slate-500"><Box size={14} className="mt-0.5 shrink-0 text-slate-400" /> Resource quotas are defined by hosting plans. Per-account disk and bandwidth consumption is not yet reported in this summary.</p>
            </SectionCard>
          </section>

          <section className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
            <SectionCard
              title="Active incidents"
              description="Open infrastructure alerts requiring attention"
              actions={<Link href="/monitoring" className="text-xs font-semibold text-brand-600 hover:text-brand-700">View all</Link>}
              flush
            >
              {details?.incidents.length ? (
                <div className="divide-y divide-slate-100">
                  {details.incidents.slice(0, 4).map(incident => (
                    <div key={incident.id} className="flex items-start gap-3.5 px-5 py-3.5 sm:px-6">
                      <span className={"mt-0.5 rounded-lg p-2 " + (incident.severity === "CRITICAL" ? "bg-rose-50 text-rose-600" : "bg-amber-50 text-amber-700")}><AlertTriangle size={16} /></span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-slate-900">{incident.title}</p>
                        <p className="mt-1 text-xs text-slate-500">{incident.serverHostname} · {incident.status} · {new Date(incident.openedAt).toLocaleString()}</p>
                      </div>
                      <StatusBadge tone={incident.severity === "CRITICAL" ? "danger" : "warning"}>{incident.severity.toLowerCase()}</StatusBadge>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState icon={ShieldCheck} title={detailsLoading ? "Checking incidents…" : "No active incidents"} description="Open server and service alerts appear here." />
              )}
            </SectionCard>

            <SectionCard title="Quick actions" description="Jump straight into a workflow">
              <div className="grid grid-cols-2 gap-2.5">
                {[
                  { label: "Add server", href: "/servers", icon: Server },
                  { label: "Create plan", href: "/hosting-plans", icon: Box },
                  { label: "New account", href: "/hosting-accounts", icon: Users },
                  { label: "Add website", href: "/websites-domains", icon: Globe2 },
                  { label: "Create database", href: "/databases", icon: Database },
                  { label: "Manage backups", href: "/backups", icon: HardDrive },
                ].map(({ label, href, icon: Icon }) => (
                  <Link key={label} href={href} className="flex items-center gap-2.5 rounded-xl border border-slate-200 bg-white px-3.5 py-3 text-sm font-medium text-slate-700 shadow-sm transition hover:border-brand-200 hover:bg-brand-50/60 hover:text-brand-700">
                    <Icon size={16} className="text-brand-600" />{label}
                  </Link>
                ))}
              </div>
            </SectionCard>
          </section>

          <SectionCard
            title="Infrastructure readiness"
            description="Live setup checks · refreshed every minute"
            actions={<StatusBadge tone={readinessChecks === 4 ? "success" : "info"}>{overview ? `${readinessChecks} / 4 complete` : overviewLoading ? "Checking…" : "Unavailable"}</StatusBadge>}
          >
            <Meter value={overview ? readinessChecks * 25 : 0} tone={readinessChecks === 4 ? "success" : "brand"} />
            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              {[
                { label: "Deploy the control-plane API", done: overview?.checks.api, detail: "API health endpoint" },
                { label: "Verify Cloudflare D1 database", done: overview?.checks.database && overview?.checks.schema, detail: "Database connectivity and schema" },
                { label: "Install the Linux server agent", done: overview?.checks.agent, detail: "Recent authenticated heartbeat" },
                { label: "Verify your connected Linux server", done: overview?.checks.server, detail: "At least one server online" },
              ].map((item, i) => (
                <div key={item.label} className="flex items-center gap-3.5">
                  <span className={"grid h-8 w-8 shrink-0 place-items-center rounded-full border text-xs font-semibold " + (item.done ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 bg-white text-slate-500")}>
                    {item.done ? <ShieldCheck size={15} /> : i + 1}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium text-slate-800">{item.label}</span>
                    <span className="block text-xs text-slate-400">{item.detail}</span>
                  </span>
                  <StatusBadge tone={item.done ? "success" : "neutral"}>{item.done ? "Complete" : overviewLoading ? "Checking" : "Pending"}</StatusBadge>
                </div>
              ))}
            </div>
            {overviewError && <InlineAlert tone="warning" className="mt-4">{overviewError}</InlineAlert>}
          </SectionCard>

          <div className="nx-card flex flex-col gap-4 bg-gradient-to-br from-brand-50/80 via-white to-white p-6 sm:flex-row sm:items-center">
            <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-white shadow-sm ring-1 ring-brand-100"><NexoraMark size={30} /></span>
            <div className="min-w-0">
              <h3 className="text-sm font-bold text-slate-900">Control-plane foundation</h3>
              <p className="mt-1 max-w-4xl text-sm leading-6 text-slate-600">Overview metrics and readiness checks are now loaded from the authenticated control-plane API. Server actions still require the authenticated agent and explicit operation policies.</p>
            </div>
            <Zap size={18} className="shrink-0 text-amber-500 sm:ml-auto" />
          </div>
          <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 pt-5 text-xs text-slate-400">
            <span>Nexora Control · Private development</span>
            <span>Infrastructure management platform</span>
          </footer>
        </div>
      </section>
    </main>
  );
}

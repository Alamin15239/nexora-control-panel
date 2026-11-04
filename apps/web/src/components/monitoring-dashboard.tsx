"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, ArrowLeft, CheckCircle2, Clock3, Cpu, HardDrive, MemoryStick, RefreshCw, Server, ShieldAlert } from "lucide-react";

type ServerRecord = {
  id: string;
  hostname: string;
  primary_ip: string;
  region: string | null;
  agent_version: string | null;
  status: string;
  last_heartbeat_at: string | null;
};
type TelemetrySample = {
  id: string;
  agent_version: string;
  cpu_usage_percent: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  load_average_1m: number;
  collected_at: string;
};
type ServiceCheck = {
  service_key: string;
  display_name: string;
  status: string;
  checked_at: string;
};
type Incident = {
  id: string;
  serverId: string;
  serverHostname: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  openedAt: string;
};

type MonitoredServer = {
  server: ServerRecord;
  latest: TelemetrySample | null;
  samples: TelemetrySample[];
  services: ServiceCheck[];
};

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "—";
  const units = ["B", "KB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit++;
    if (unit === 1) unit++;
  }
  return `${amount.toFixed(amount >= 10 ? 0 : 1)} ${units[unit]}`;
}

function percent(used: number, total: number): number {
  if (!total || !Number.isFinite(used / total)) return 0;
  return Math.min(100, Math.max(0, (used / total) * 100));
}

function timeAgo(value: string | null): string {
  if (!value) return "No heartbeat received";
  const age = Math.max(0, Date.now() - Date.parse(value));
  if (!Number.isFinite(age)) return "Unknown";
  if (age < 60_000) return "Just now";
  if (age < 3_600_000) return `${Math.floor(age / 60_000)} min ago`;
  return `${Math.floor(age / 3_600_000)} hr ago`;
}

function Metric({ label, value, detail, icon: Icon, percentage }: {
  label: string; value: string; detail: string; icon: typeof Cpu; percentage?: number;
}) {
  const width = Math.max(0, Math.min(100, percentage ?? 0));
  return <div className="rounded-xl border border-slate-200 bg-white p-4">
    <div className="flex items-center justify-between gap-2">
      <p className="text-sm text-slate-500">{label}</p>
      <Icon size={17} className="text-slate-400"/>
    </div>
    <p className="mt-2 text-2xl font-semibold tabular-nums">{value}</p>
    <p className="mt-1 text-xs text-slate-500">{detail}</p>
    {percentage !== undefined && <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-100">
      <div className={`h-full rounded-full ${percentage >= 90 ? "bg-red-500" : percentage >= 75 ? "bg-amber-500" : "bg-blue-600"}`} style={{ width: `${width}%` }}/>
    </div>}
  </div>;
}

export default function MonitoringDashboard() {
  const [servers, setServers] = useState<MonitoredServer[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  const load = useCallback(async (background = false) => {
    if (background) setRefreshing(true);
    else setLoading(true);
    setError("");
    try {
      const serverResponse = await fetch("/api/control/servers", { cache: "no-store" });
      const serverData = await serverResponse.json();
      if (!serverResponse.ok) throw new Error(serverData.message || "Unable to load servers.");
      const records = (serverData.servers ?? []) as ServerRecord[];
      const [monitored, incidentResponse] = await Promise.all([
        Promise.all(records.map(async (server): Promise<MonitoredServer> => {
          const [telemetryResponse, serviceResponse] = await Promise.all([
            fetch(`/api/control/servers/${server.id}/telemetry`, { cache: "no-store" }),
            fetch(`/api/control/servers/${server.id}/services`, { cache: "no-store" }),
          ]);
          const telemetryData = telemetryResponse.ok ? await telemetryResponse.json() : {};
          const serviceData = serviceResponse.ok ? await serviceResponse.json() : {};
          return {
            server,
            latest: telemetryData.latest ?? null,
            samples: telemetryData.samples ?? [],
            services: serviceData.services ?? [],
          };
        })),
        fetch("/api/control/incidents", { cache: "no-store" }),
      ]);
      if (!incidentResponse.ok) throw new Error("Unable to load infrastructure incidents.");
      const incidentData = await incidentResponse.json();
      setServers(monitored);
      setIncidents((incidentData.incidents ?? []).filter((incident: Incident) => incident.status !== "RESOLVED"));
      setUpdatedAt(new Date().toISOString());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load monitoring data.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(true), 30_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const onlineCount = servers.filter(item => item.server.status === "ONLINE").length;
  const criticalCount = incidents.filter(item => item.severity === "CRITICAL").length;

  return <main className="min-h-screen bg-slate-50 text-slate-900">
    <header className="border-b border-slate-200 bg-white"><div className="mx-auto flex max-w-7xl items-center gap-3 px-5 py-4">
      <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
      <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Activity size={20}/></span>
      <div className="min-w-0 flex-1"><p className="font-semibold">Nexora Control</p><p className="text-xs text-slate-500">Infrastructure / Monitoring</p></div>
      <button onClick={() => void load(true)} disabled={refreshing} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50">
        <RefreshCw size={15} className={refreshing ? "animate-spin" : ""}/><span className="hidden sm:inline">Refresh</span>
      </button>
    </div></header>

    <section className="mx-auto max-w-7xl space-y-6 px-5 py-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><p className="text-sm font-medium text-blue-700">Live infrastructure</p><h1 className="mt-1 text-2xl font-semibold tracking-tight">Server monitoring</h1><p className="mt-2 text-sm text-slate-500">Authenticated agent telemetry, Linux service health and active incidents.</p></div>
        <p className="text-xs text-slate-500">{updatedAt ? `Updated ${new Date(updatedAt).toLocaleTimeString()}` : "Waiting for first refresh"} · auto-refresh 30 sec</p>
      </div>

      {error && <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>}

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Managed servers</p><p className="mt-2 text-3xl font-semibold">{loading ? "—" : servers.length}</p><p className="mt-1 text-xs text-slate-500">{onlineCount} online</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Open incidents</p><p className="mt-2 text-3xl font-semibold">{loading ? "—" : incidents.length}</p><p className="mt-1 text-xs text-slate-500">{criticalCount} critical</p></div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5"><p className="text-sm text-slate-500">Telemetry source</p><p className="mt-2 text-xl font-semibold">Linux agent</p><p className="mt-1 text-xs text-slate-500">Signed heartbeat · read-only checks</p></div>
      </div>

      {loading && <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500">Loading server telemetry…</div>}
      {!loading && servers.length === 0 && <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center"><Server className="mx-auto text-slate-400" size={28}/><p className="mt-3 font-medium">No servers registered</p><p className="mt-1 text-sm text-slate-500">Register and enroll a Linux node to begin monitoring.</p><Link href="/servers" className="mt-4 inline-flex rounded-lg bg-blue-700 px-4 py-2 text-sm font-medium text-white">Open server management</Link></div>}

      {servers.map(({ server, latest, samples, services }) => {
        const cpu = latest?.cpu_usage_percent ?? 0;
        const memory = latest ? percent(latest.memory_used_bytes, latest.memory_total_bytes) : 0;
        const disk = latest ? percent(latest.disk_used_bytes, latest.disk_total_bytes) : 0;
        const heartbeatFresh = !!server.last_heartbeat_at && Date.now() - Date.parse(server.last_heartbeat_at) < 180_000;
        return <section key={server.id} className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
            <div className="flex items-center gap-3"><span className="rounded-xl bg-slate-100 p-2.5 text-slate-600"><Server size={19}/></span><div><h2 className="font-semibold">{server.hostname}</h2><p className="mt-0.5 text-xs text-slate-500">{server.primary_ip}{server.region ? ` · ${server.region}` : ""} · Agent {server.agent_version ?? "unknown"}</p></div></div>
            <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${heartbeatFresh ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-800"}`}><span className={`h-1.5 w-1.5 rounded-full ${heartbeatFresh ? "bg-emerald-500" : "bg-amber-500"}`}/>{heartbeatFresh ? "Online" : server.status}</span>
          </div>
          <div className="space-y-5 p-5">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Metric label="CPU usage" value={latest ? `${cpu.toFixed(1)}%` : "No data"} detail={latest ? `Load average ${latest.load_average_1m.toFixed(2)}` : "Waiting for agent telemetry"} icon={Cpu} percentage={latest ? cpu : undefined}/>
              <Metric label="Memory" value={latest ? `${memory.toFixed(1)}%` : "No data"} detail={latest ? `${formatBytes(latest.memory_used_bytes)} of ${formatBytes(latest.memory_total_bytes)}` : "Waiting for agent telemetry"} icon={MemoryStick} percentage={latest ? memory : undefined}/>
              <Metric label="Root disk" value={latest ? `${disk.toFixed(1)}%` : "No data"} detail={latest ? `${formatBytes(latest.disk_used_bytes)} of ${formatBytes(latest.disk_total_bytes)}` : "Waiting for agent telemetry"} icon={HardDrive} percentage={latest ? disk : undefined}/>
              <Metric label="Last heartbeat" value={timeAgo(server.last_heartbeat_at)} detail={latest ? `Sample ${new Date(latest.collected_at).toLocaleTimeString()}` : "No telemetry sample"} icon={Clock3}/>
            </div>

            <div className="grid gap-5 lg:grid-cols-2">
              <div className="rounded-xl border border-slate-200 p-4">
                <div className="flex items-center justify-between"><h3 className="text-sm font-semibold">CPU history</h3><span className="text-xs text-slate-500">Last {samples.length} samples</span></div>
                {samples.length ? <div className="mt-4 flex h-24 items-end gap-1">{samples.slice(-30).map((sample, index) => <div key={sample.id} title={`${sample.cpu_usage_percent.toFixed(1)}% · ${new Date(sample.collected_at).toLocaleString()}`} className="min-w-0 flex-1 rounded-t bg-blue-500/80" style={{ height: `${Math.max(3, sample.cpu_usage_percent)}%` }} />)}</div> : <p className="mt-4 text-sm text-slate-500">No history received yet.</p>}
              </div>
              <div className="rounded-xl border border-slate-200 p-4">
                <h3 className="text-sm font-semibold">Linux services</h3>
                {services.length ? <div className="mt-3 grid gap-2 sm:grid-cols-2">{services.map(service => {
                  const healthy = service.status === "ACTIVE";
                  const warning = service.status === "INACTIVE" || service.status === "FAILED";
                  return <div key={service.service_key} className="flex items-center justify-between gap-2 rounded-lg bg-slate-50 px-3 py-2">
                    <span className="truncate text-sm text-slate-700">{service.display_name}</span>
                    <span className={`shrink-0 rounded-full px-2 py-1 text-[11px] font-medium ${healthy ? "bg-emerald-50 text-emerald-700" : warning ? "bg-red-50 text-red-700" : "bg-slate-200 text-slate-600"}`}>{service.status.replace("_", " ")}</span>
                  </div>;
                })}</div> : <p className="mt-3 text-sm text-slate-500">No service checks reported by this agent.</p>}
              </div>
            </div>
          </div>
        </section>;
      })}

      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white">
        <div className="flex items-center gap-2 border-b border-slate-100 px-5 py-4"><ShieldAlert size={18} className="text-slate-500"/><div><h2 className="font-semibold">Active incidents</h2><p className="mt-1 text-xs text-slate-500">Service failures and agent health events.</p></div></div>
        {incidents.length ? <div className="divide-y divide-slate-100">{incidents.map(incident => <div key={incident.id} className="flex flex-wrap items-start gap-3 px-5 py-4"><span className={`mt-0.5 rounded-lg p-2 ${incident.severity === "CRITICAL" ? "bg-red-50 text-red-600" : "bg-amber-50 text-amber-700"}`}><AlertTriangle size={17}/></span><div className="min-w-0 flex-1"><p className="text-sm font-medium">{incident.title}</p><p className="mt-1 text-xs text-slate-500">{incident.serverHostname} · {new Date(incident.openedAt).toLocaleString()}</p><p className="mt-1 text-sm text-slate-600">{incident.description}</p></div><span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-600">{incident.status}</span></div>)}</div> : <div className="px-5 py-8 text-center"><CheckCircle2 size={25} className="mx-auto text-emerald-600"/><p className="mt-2 text-sm font-medium">No active incidents</p><p className="mt-1 text-xs text-slate-500">No open service or heartbeat incidents are currently recorded.</p></div>}
      </section>
      <p className="text-xs leading-5 text-slate-500">Metrics are reported by the authenticated Nexora Linux agent. CPU, memory and disk values describe the node as a whole; they are not per-customer quota measurements.</p>
    </section>
  </main>;
}

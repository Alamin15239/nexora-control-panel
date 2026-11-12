"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, CheckCircle2, ExternalLink, Github, GitBranch, Link2, Loader2, RefreshCw, ShieldCheck, Unplug } from "lucide-react";

type Connection = { login: string; scopes: string; connectedAt: string } | null;
type Repository = { id: number; name: string; fullName: string; private: boolean; defaultBranch: string; htmlUrl: string; installationId: number; owner: string };
type Account = { id: string; username: string; primary_domain: string | null; status: string };
type Project = { id: string; hostingAccountId: string; repositoryFullName: string; productionBranch: string; rootDirectory: string; outputDirectory: string; framework: string; status: string; createdAt: string };
type Deployment = { id: string; commitSha: string; branch: string; triggerType: string; status: string; commitMessage: string | null; deploymentUrl: string | null; logExcerpt: string | null; requestedAt: string; startedAt: string | null; finishedAt: string | null };

type RuntimeProfile = { id: string; runtimeFamily: string; profileKey: string; displayName: string; enabled: boolean; selectable: boolean };
type RuntimePlanLimits = { cpuMillis: number; memoryMiB: number; diskMiB: number; processLimit: number; buildMinutesPerMonth: number };
type RuntimeUsage = { periodStart: string; buildMinutesLimit: number; buildMinutesUsed: number; buildSecondsRemaining: number; quotaExhausted: boolean; meteringStatus: string; executionEnabled: boolean };

function RuntimeProjectSettings({ projectId }: { projectId: string }) {
  const [expanded, setExpanded] = useState(false);
  const [profiles, setProfiles] = useState<RuntimeProfile[]>([]);
  const [runtimeProfileId, setRuntimeProfileId] = useState("");
  const [buildMethod, setBuildMethod] = useState("managed");
  const [buildContext, setBuildContext] = useState(".");
  const [buildCommand, setBuildCommand] = useState("");
  const [outputDirectory, setOutputDirectory] = useState("");
  const [startCommand, setStartCommand] = useState("");
  const [listenPort, setListenPort] = useState("");
  const [healthCheckPath, setHealthCheckPath] = useState("/");
  const [cpuMillis, setCpuMillis] = useState("500");
  const [memoryMiB, setMemoryMiB] = useState("512");
  const [diskMiB, setDiskMiB] = useState("2048");
  const [processLimit, setProcessLimit] = useState("128");
  const [planLimits, setPlanLimits] = useState<RuntimePlanLimits | null>(null);
  const [usage, setUsage] = useState<RuntimeUsage | null>(null);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function openSettings() {
    const next = !expanded;
    setExpanded(next);
    if (!next || profiles.length) return;
    setLoading(true); setError("");
    try {
      const [profileResponse, settingsResponse, usageResponse] = await Promise.all([
        fetch("/api/control/applications/runtime-profiles", { cache: "no-store" }),
        fetch(`/api/control/applications/projects/${projectId}/settings`, { cache: "no-store" }),
        fetch(`/api/control/applications/projects/${projectId}/usage`, { cache: "no-store" }),
      ]);
      const [profileData, settingsData, usageData] = await Promise.all([profileResponse.json(), settingsResponse.json(), usageResponse.json()]);
      if (!profileResponse.ok) throw new Error(profileData.message ?? "Unable to load runtime catalog.");
      if (!settingsResponse.ok) throw new Error(settingsData.message ?? "Unable to load project runtime settings.");
      if (!usageResponse.ok) throw new Error(usageData.message ?? "Unable to load monthly build usage.");
      setProfiles(profileData.profiles ?? []);
      setPlanLimits(settingsData.planLimits ?? null);
      setUsage(usageData);
      const current = settingsData.settings;
      if (current) {
        setRuntimeProfileId(current.runtimeProfileId ?? "");
        setBuildMethod(current.buildMethod ?? "managed");
        setBuildContext(current.buildContext ?? ".");
        setBuildCommand(current.buildCommand ?? "");
        setOutputDirectory(current.outputDirectory ?? "");
        setStartCommand(current.startCommand ?? "");
        setListenPort(current.listenPort ? String(current.listenPort) : "");
        setHealthCheckPath(current.healthCheckPath ?? "/");
        setCpuMillis(String(current.resources?.cpuMillis ?? settingsData.planLimits?.cpuMillis ?? 500));
        setMemoryMiB(String(current.resources?.memoryMiB ?? settingsData.planLimits?.memoryMiB ?? 512));
        setDiskMiB(String(current.resources?.diskMiB ?? settingsData.planLimits?.diskMiB ?? 2048));
        setProcessLimit(String(current.resources?.processLimit ?? settingsData.planLimits?.processLimit ?? 128));
      } else if (settingsData.planLimits) {
        setCpuMillis(String(Math.min(500, settingsData.planLimits.cpuMillis)));
        setMemoryMiB(String(Math.min(512, settingsData.planLimits.memoryMiB)));
        setDiskMiB(String(Math.min(2048, settingsData.planLimits.diskMiB)));
        setProcessLimit(String(Math.min(128, settingsData.planLimits.processLimit)));
      }
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to load runtime settings."); }
    finally { setLoading(false); }
  }

  const selectedProfile = profiles.find(profile => profile.id === runtimeProfileId);

  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!runtimeProfileId) { setError("Choose a runtime profile."); return; }
    setSaving(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/applications/projects/${projectId}/settings`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runtimeProfileId, buildMethod, buildContext, buildCommand: buildCommand || null,
          outputDirectory: outputDirectory || null, startCommand: startCommand || null,
          listenPort: listenPort ? Number(listenPort) : null,
          healthCheckPath: healthCheckPath || null,
          cpuMillis: Number(cpuMillis),
          memoryMiB: Number(memoryMiB),
          diskMiB: Number(diskMiB),
          processLimit: Number(processLimit),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Unable to save runtime settings.");
      setNotice(data.message ?? "Runtime settings saved.");
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to save runtime settings."); }
    finally { setSaving(false); }
  }

  return <div className="border-t border-slate-100 px-6 py-3">
    <button type="button" onClick={openSettings} className="text-xs font-semibold text-blue-700 hover:underline">
      {expanded ? "Hide runtime settings" : "Configure application runtime"}
    </button>
    {expanded && <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
      {error && <p role="alert" className="mb-3 text-xs text-rose-700">{error}</p>}
      {notice && <p role="status" className="mb-3 text-xs text-emerald-700">{notice}</p>}
      {usage && <div className="mb-3 rounded-lg border border-slate-200 bg-white p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-semibold text-slate-700">Monthly build allowance · {usage.periodStart}</p>
          <span className="text-[11px] text-slate-500">{usage.buildMinutesUsed.toLocaleString()} / {usage.buildMinutesLimit.toLocaleString()} minutes</span>
        </div>
        <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100">
          <div className="h-full rounded-full bg-blue-600" style={{ width: `${usage.buildMinutesLimit > 0 ? Math.min(100, (usage.buildMinutesUsed / usage.buildMinutesLimit) * 100) : usage.quotaExhausted ? 100 : 0}%` }}/>
        </div>
        <p className="mt-2 text-[11px] text-amber-700">{usage.meteringStatus !== "active" ? "Builder metering has not reported usage yet. This is an allowance preview, not measured usage; build dispatch and quota enforcement remain disabled." : usage.quotaExhausted ? "Monthly build allowance exhausted. Dispatch enforcement is not enabled." : "Usage has been reported by the authenticated builder. Dispatch quota enforcement remains disabled."}</p>
      </div>}
      {loading ? <p className="text-xs text-slate-500">Loading runtime catalog…</p> : <form onSubmit={save} className="grid gap-3 md:grid-cols-2">
        <label className="space-y-1 text-xs font-medium text-slate-700 md:col-span-2">Runtime profile
          <select required value={runtimeProfileId} onChange={event => {
            const profile = profiles.find(item => item.id === event.target.value);
            setRuntimeProfileId(event.target.value);
            if (profile?.runtimeFamily === "static") { setBuildMethod("static"); setOutputDirectory("dist"); }
            else if (profile?.runtimeFamily === "container") setBuildMethod("dockerfile");
            else setBuildMethod("managed");
          }} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm">
            <option value="">Choose runtime profile</option>
            {profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.displayName} · {profile.enabled ? "Enabled" : "Catalog only"}</option>)}
          </select>
        </label>
        <label className="space-y-1 text-xs font-medium text-slate-700">Build method
          <select value={buildMethod} onChange={event => setBuildMethod(event.target.value)} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm">
            <option value="managed">Managed build</option><option value="static">Static output</option><option value="dockerfile">Dockerfile / OCI</option>
          </select>
        </label>
        <label className="space-y-1 text-xs font-medium text-slate-700">Build context
          <input value={buildContext} onChange={event => setBuildContext(event.target.value)} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm"/>
        </label>
        <label className="space-y-1 text-xs font-medium text-slate-700">Build command (stored, not executed)
          <input value={buildCommand} onChange={event => setBuildCommand(event.target.value)} maxLength={1000} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm" placeholder="npm run build"/>
        </label>
        <label className="space-y-1 text-xs font-medium text-slate-700">Output directory
          <input value={outputDirectory} onChange={event => setOutputDirectory(event.target.value)} maxLength={240} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm" placeholder="dist"/>
        </label>
        <label className="space-y-1 text-xs font-medium text-slate-700">Start command (stored, not executed)
          <input value={startCommand} onChange={event => setStartCommand(event.target.value)} maxLength={1000} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm" placeholder="npm start"/>
        </label>
        <label className="space-y-1 text-xs font-medium text-slate-700">Application port
          <input type="number" min="1" max="65535" value={listenPort} onChange={event => setListenPort(event.target.value)} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm" placeholder="3000"/>
        </label>
        <label className="space-y-1 text-xs font-medium text-slate-700">Health check path
          <input value={healthCheckPath} onChange={event => setHealthCheckPath(event.target.value)} maxLength={200} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm" placeholder="/health"/>
        </label>
        <div className="md:col-span-2 rounded-lg border border-slate-200 bg-white p-3">
          <p className="mb-3 text-xs font-semibold text-slate-700">Requested runtime resources</p>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <label className="space-y-1 text-xs text-slate-600">CPU (millicores)
              <input type="number" min="100" max={planLimits?.cpuMillis ?? 8000} value={cpuMillis} onChange={event => setCpuMillis(event.target.value)} className="w-full rounded-lg border border-slate-200 px-2 py-2 text-sm"/>
            </label>
            <label className="space-y-1 text-xs text-slate-600">Memory (MiB)
              <input type="number" min="128" max={planLimits?.memoryMiB ?? 16384} value={memoryMiB} onChange={event => setMemoryMiB(event.target.value)} className="w-full rounded-lg border border-slate-200 px-2 py-2 text-sm"/>
            </label>
            <label className="space-y-1 text-xs text-slate-600">Storage (MiB)
              <input type="number" min="128" max={planLimits?.diskMiB ?? 65536} value={diskMiB} onChange={event => setDiskMiB(event.target.value)} className="w-full rounded-lg border border-slate-200 px-2 py-2 text-sm"/>
            </label>
            <label className="space-y-1 text-xs text-slate-600">Process limit
              <input type="number" min="16" max={planLimits?.processLimit ?? 512} value={processLimit} onChange={event => setProcessLimit(event.target.value)} className="w-full rounded-lg border border-slate-200 px-2 py-2 text-sm"/>
            </label>
          </div>
          {planLimits && <p className="mt-2 text-[11px] text-slate-500">Hosting plan ceilings: {planLimits.cpuMillis} mCPU · {planLimits.memoryMiB} MiB RAM · {planLimits.diskMiB} MiB storage · {planLimits.processLimit} processes.</p>}
        </div>
        <div className="md:col-span-2 flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-amber-700">{selectedProfile?.enabled ? "Runtime profile enabled; deployment still gated." : "Catalog only: execution is disabled. Settings are saved as metadata."}</p>
          <button type="submit" disabled={saving || !runtimeProfileId} className="rounded-lg bg-blue-700 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{saving ? "Saving…" : "Save runtime settings"}</button>
        </div>
      </form>}
    </div>}
  </div>;
}

export default function GithubDeployments({ customerMode = false }: { customerMode?: boolean } = {}) {
  const [connection, setConnection] = useState<Connection>(null);
  const [connected, setConnected] = useState(false);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [deploymentsByProject, setDeploymentsByProject] = useState<Record<string, Deployment[]>>({});
  const [selectedRepository, setSelectedRepository] = useState("");
  const [hostingAccountId, setHostingAccountId] = useState("");
  const [branch, setBranch] = useState("main");
  const [rootDirectory, setRootDirectory] = useState(".");
  const [outputDirectory, setOutputDirectory] = useState("dist");
  const [framework, setFramework] = useState("auto");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const selected = useMemo(() => repositories.find(repo => String(repo.id) === selectedRepository) ?? null, [repositories, selectedRepository]);

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [connectionResponse, accountsResponse, projectsResponse] = await Promise.all([
        fetch("/api/control/github/connection", { cache: "no-store" }),
        fetch(customerMode ? "/api/control/customer/hosting-accounts" : "/api/control/hosting-accounts", { cache: "no-store" }),
        fetch("/api/control/github/projects", { cache: "no-store" }),
      ]);
      const [connectionData, accountsData, projectsData] = await Promise.all([connectionResponse.json(), accountsResponse.json(), projectsResponse.json()]);
      if (!connectionResponse.ok) throw new Error(connectionData.message ?? "Unable to load GitHub connection.");
      if (!accountsResponse.ok) throw new Error(accountsData.message ?? "Unable to load hosting accounts.");
      if (!projectsResponse.ok) throw new Error(projectsData.message ?? "Unable to load linked repositories.");
      setConnected(Boolean(connectionData.connected)); setConnection(connectionData.connection ?? null);
      setAccounts((accountsData.accounts ?? []).filter((account: Account) => account.status === "ACTIVE"));
      const linkedProjects: Project[] = projectsData.projects ?? [];
      const deploymentResults = await Promise.all(linkedProjects.map(async (project) => {
        const response = await fetch(`/api/control/github/projects/${project.id}/deployments`, { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message ?? `Unable to load deployment history for ${project.repositoryFullName}.`);
        return [project.id, (data.deployments ?? []) as Deployment[]] as const;
      }));
      setProjects(linkedProjects);
      setDeploymentsByProject(Object.fromEntries(deploymentResults));
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to load GitHub deployment settings."); }
    finally { setLoading(false); }
  }, [customerMode]);

  const loadRepositories = useCallback(async () => {
    if (!connected) return;
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/control/github/repositories", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Unable to load repositories.");
      setRepositories(data.repositories ?? []);
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to load repositories."); }
    finally { setBusy(false); }
  }, [connected]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (connected) void loadRepositories(); }, [connected, loadRepositories]);
  useEffect(() => {
    const status = new URLSearchParams(window.location.search).get("github");
    if (status === "connected") { setNotice("GitHub account connected successfully."); window.history.replaceState({}, "", customerMode ? "/customer/deploy" : "/github-deployments"); void load(); }
    else if (status === "denied") { setError("GitHub authorization was cancelled."); window.history.replaceState({}, "", customerMode ? "/customer/deploy" : "/github-deployments"); }
    else if (status === "error") { setError("GitHub connection failed. Check the GitHub App configuration and try again."); window.history.replaceState({}, "", customerMode ? "/customer/deploy" : "/github-deployments"); }
  }, [load, customerMode]);

  async function connectGithub() {
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/control/github/connect", { method: "POST" });
      const data = await response.json();
      if (!response.ok || !data.authorizationUrl) throw new Error(data.message ?? "Unable to start GitHub authorization.");
      window.location.assign(data.authorizationUrl);
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to connect GitHub."); setBusy(false); }
  }

  async function linkRepository(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/api/control/github/projects", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ hostingAccountId, repositoryId: selected.id, installationId: selected.installationId, repositoryFullName: selected.fullName, productionBranch: branch, rootDirectory, outputDirectory, framework }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Unable to link repository.");
      setNotice(data.message ?? "Repository linked.");
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to link repository."); }
    finally { setBusy(false); }
  }

  async function disconnectGithub() {
    if (!window.confirm("Disconnect this GitHub account? This removes the linked GitHub project configurations and the locally stored GitHub credentials from Nexora. It does not delete any already-published website files.")) return;
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/control/github/connection", { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Unable to disconnect GitHub.");
      setRepositories([]); setConnected(false); setConnection(null); setNotice("GitHub account disconnected."); await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to disconnect GitHub."); }
    finally { setBusy(false); }
  }

  return <main className="min-h-screen bg-[#f4f6fb]">
    <header className="border-b border-slate-200 bg-white"><div className="mx-auto flex max-w-[1500px] items-center gap-3 px-5 py-5">
      <Link href={customerMode ? "/customer" : "/"} className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
      <span className="grid h-10 w-10 place-items-center rounded-xl bg-slate-950 text-white"><Github size={20}/></span>
      <div><p className="font-semibold text-slate-950">{customerMode ? "Nexora Deploy" : "GitHub deployments"}</p><p className="text-xs text-slate-500">{customerMode ? "Projects and Git-based website setup" : "Connect repositories and configure website builds"}</p></div>
    </div></header>
    <section className="mx-auto max-w-[1100px] space-y-6 px-5 py-8">
      <div><p className="text-sm font-medium text-blue-700">{customerMode ? "Nexora Deploy · Projects" : "Developer workflow"}</p><h1 className="mt-1 text-3xl font-semibold tracking-tight text-slate-950">{customerMode ? "Deploy your website" : "Deploy from GitHub"}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">Link a repository to an active Nexora hosting account. Choose the production branch and static build output. Builds will become available after the GitHub-hosted workflow and isolated static publisher pass platform acceptance.</p></div>
      {error && <div role="alert" className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>}
      {notice && <div role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</div>}
      {loading ? <div className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-white p-8 text-sm text-slate-500"><Loader2 className="animate-spin" size={18}/> Loading GitHub settings…</div> : <>
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-4"><div className="flex items-start gap-3"><span className="rounded-xl bg-slate-100 p-3 text-slate-800"><Github size={22}/></span><div><h2 className="font-semibold text-slate-950">GitHub account</h2><p className="mt-1 text-sm text-slate-500">Authorize the Nexora GitHub App to access repositories you select.</p></div></div>
            {connected ? <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1.5 text-xs font-semibold text-emerald-700"><CheckCircle2 size={14}/> Connected</span> : <span className="rounded-full bg-slate-100 px-3 py-1.5 text-xs font-medium text-slate-600">Not connected</span>}</div>
          {connected ? <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-50 p-4"><div><p className="text-sm font-semibold text-slate-900">@{connection?.login}</p><p className="mt-1 text-xs text-slate-500">Connected {connection?.connectedAt ? new Date(connection.connectedAt).toLocaleString() : ""}</p></div><button onClick={disconnectGithub} disabled={busy} title="Disconnect this GitHub account from Nexora" className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"><Unplug size={15}/> Disconnect</button></div> : <button onClick={connectGithub} disabled={busy} className="mt-5 inline-flex items-center gap-2 rounded-xl bg-slate-950 px-4 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"><Github size={17}/> Connect GitHub</button>}
          <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-slate-500"><ShieldCheck size={15} className="mt-0.5 shrink-0"/> GitHub App permissions are configured by Nexora. Tokens are encrypted before storage and are never sent to the browser.</p>
        </div>
        {connected && <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="font-semibold text-slate-950">Link a repository</h2><p className="mt-1 text-sm text-slate-500">Select an installed repository and the hosting account that will serve its built files.</p></div><button onClick={loadRepositories} disabled={busy} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={14}/> Refresh repositories</button></div>
          <form onSubmit={linkRepository} className="mt-5 grid gap-4 md:grid-cols-2">
            <label className="space-y-1.5 text-sm font-medium text-slate-700 md:col-span-2">GitHub repository<select required value={selectedRepository} onChange={event => { const repo = repositories.find(item => String(item.id) === event.target.value); setSelectedRepository(event.target.value); if (repo) setBranch(repo.defaultBranch); }} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm"><option value="">Choose a repository</option>{repositories.map(repo => <option key={`${repo.installationId}-${repo.id}`} value={repo.id}>{repo.fullName}{repo.private ? " · Private" : " · Public"}</option>)}</select></label>
            <label className="space-y-1.5 text-sm font-medium text-slate-700 md:col-span-2">Nexora hosting account<select required value={hostingAccountId} onChange={event => setHostingAccountId(event.target.value)} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm"><option value="">Choose an active hosting account</option>{accounts.map(account => <option key={account.id} value={account.id}>{account.username}{account.primary_domain ? ` · ${account.primary_domain}` : ""}</option>)}</select></label>
            <label className="space-y-1.5 text-sm font-medium text-slate-700">Production branch<input required value={branch} onChange={event => setBranch(event.target.value)} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm" placeholder="main"/></label>
            <label className="space-y-1.5 text-sm font-medium text-slate-700">Framework<select value={framework} onChange={event => setFramework(event.target.value)} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm"><option value="auto">Auto detect</option><option value="static">Static HTML</option><option value="vite">Vite</option><option value="react">React</option><option value="vue">Vue</option><option value="astro">Astro (static)</option><option value="next-static">Next.js static export</option></select></label>
            <label className="space-y-1.5 text-sm font-medium text-slate-700">Repository root<input required value={rootDirectory} onChange={event => setRootDirectory(event.target.value)} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm" placeholder="."/></label>
            <label className="space-y-1.5 text-sm font-medium text-slate-700">Build output directory<input required value={outputDirectory} onChange={event => setOutputDirectory(event.target.value)} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm" placeholder="dist"/></label>
            <div className="md:col-span-2"><button type="submit" disabled={busy || !selected || !hostingAccountId} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-800 disabled:opacity-50"><Link2 size={16}/> Save repository configuration</button></div>
          </form>
          {!repositories.length && <p className="mt-4 text-xs text-slate-500">No repositories are visible yet. Install the Nexora GitHub App on an account or organization and grant access to at least one repository.</p>}
        </div>}
        <div className="rounded-2xl border border-slate-200 bg-white shadow-sm"><div className="border-b border-slate-100 px-6 py-4"><h2 className="font-semibold text-slate-950">Linked projects</h2><p className="mt-1 text-xs text-slate-500">Repository-to-hosting-account configurations.</p></div>
          {projects.length ? <div className="divide-y divide-slate-100">{projects.map(project => <div key={project.id}><div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4"><div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-900">{project.repositoryFullName}</p><p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500"><GitBranch size={13}/>{project.productionBranch}<span>·</span>{project.framework}<span>·</span>Output: {project.outputDirectory}</p></div><span className="rounded-full bg-amber-50 px-3 py-1 text-xs font-medium text-amber-800">Configured · build worker pending</span></div><div className="border-t border-slate-100 px-6 py-4">
              <div className="mb-3 flex items-center justify-between gap-3"><p className="text-xs font-semibold text-slate-700">Deployment history</p><span className="text-[11px] text-slate-400">{(deploymentsByProject[project.id] ?? []).length} records</span></div>
              {(deploymentsByProject[project.id] ?? []).length ? <div className="space-y-3">{(deploymentsByProject[project.id] ?? []).map(deployment => <div key={deployment.id} className="rounded-lg border border-slate-200 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-xs font-semibold text-slate-800">{deployment.status.replaceAll("_", " ")}</span><span className="text-[11px] text-slate-500">{deployment.requestedAt ? new Date(deployment.requestedAt).toLocaleString() : "Time unavailable"}</span></div>
                <p className="mt-1 text-xs text-slate-600">{deployment.branch} · {deployment.commitSha.slice(0, 12)} · {deployment.triggerType}</p>
                {deployment.commitMessage && <p className="mt-1 text-xs text-slate-500">{deployment.commitMessage}</p>}
                {deployment.deploymentUrl && <a href={deployment.deploymentUrl} target="_blank" rel="noreferrer" className="mt-2 inline-flex text-xs font-medium text-blue-700 hover:underline">Open deployment URL</a>}
                {deployment.logExcerpt && <details className="mt-2"><summary className="cursor-pointer text-xs font-medium text-slate-600">View latest log excerpt</summary><pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-md bg-slate-950 p-3 text-[11px] text-slate-100">{deployment.logExcerpt}</pre></details>}
              </div>)}</div> : <p className="text-xs text-slate-500">No deployment records yet.</p>}
            </div>{!customerMode && <RuntimeProjectSettings projectId={project.id}/ >}</div>)}</div> : <div className="px-6 py-8 text-center text-sm text-slate-500">No repositories linked yet.</div>}
        </div>
      </>}
      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-5"><p className="text-sm font-semibold text-amber-900">Deployment execution is not enabled yet</p><p className="mt-1 text-sm leading-6 text-amber-800">Repository connection and project configuration are available in this milestone. Actual builds, automatic push deployments, deployment logs and rollback remain disabled until the GitHub-hosted build workflow and a separately enrolled, isolated static publisher pass end-to-end acceptance tests.</p></div>
      <p className="text-xs text-slate-400">Repository links are saved to the current workspace. <a href="https://github.com/settings/installations" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-blue-700 hover:underline">Manage GitHub App installations <ExternalLink size={11}/></a></p>
    </section>
  </main>;
}

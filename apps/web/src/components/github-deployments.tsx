"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, ExternalLink, Github, GitBranch, KeyRound, Link2, Loader2, RefreshCw, ScrollText, Unplug, Rocket } from "lucide-react";
import {
  EmptyState, InlineAlert, Meter, Modal, NexoraMark, PageHeader, SectionCard,
  Spinner, StatusBadge, statusTone,
} from "@/components/ui";

type Connection = { login: string; scopes: string; connectedAt: string; installed: boolean; installationAccount: string | null; installationAccountType: string | null } | null;
type Repository = { id: number; name: string; fullName: string; private: boolean; defaultBranch: string; htmlUrl: string; installationId: number; owner: string };
type Account = { id: string; username: string; primary_domain: string | null; status: string };
type Project = { id: string; hostingAccountId: string; repositoryFullName: string; productionBranch: string; rootDirectory: string; outputDirectory: string; framework: string; status: string; createdAt: string; previewEnabled?: number; autoDeploy?: number; ignoredBuildPaths?: string[] };
type Deployment = { id: string; commitSha: string; branch: string; triggerType: string; status: string; deploymentKind?: string; commitMessage: string | null; deploymentUrl: string | null; logExcerpt: string | null; requestedAt: string; startedAt: string | null; finishedAt: string | null };

type RuntimeProfile = { id: string; runtimeFamily: string; profileKey: string; displayName: string; enabled: boolean; selectable: boolean };
type RuntimePlanLimits = { cpuMillis: number; memoryMiB: number; diskMiB: number; processLimit: number; buildMinutesPerMonth: number };
type RuntimeUsage = { periodStart: string; buildMinutesLimit: number; buildMinutesUsed: number; buildSecondsRemaining: number; quotaExhausted: boolean; meteringStatus: string; executionEnabled: boolean };

function normalizeIgnoredBuildPaths(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string").map(item => item.trim()).filter(Boolean);
  if (typeof value !== "string" || !value.trim()) return [];
  const trimmed = value.trim();
  if (trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return parsed.filter((item): item is string => typeof item === "string").map(item => item.trim()).filter(Boolean);
    } catch { /* Accept legacy comma-separated values below. */ }
  }
  return trimmed.split(",").map(item => item.trim()).filter(Boolean);
}

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

  return (
    <div className="border-t border-slate-100 px-6 py-3">
      <button type="button" onClick={openSettings} className="text-xs font-semibold text-brand-600 transition hover:text-brand-700 hover:underline">
        {expanded ? "Hide runtime settings" : "Configure application runtime"}
      </button>
      {expanded && (
        <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50/80 p-4">
          {error && <p role="alert" className="mb-3 text-xs text-rose-700">{error}</p>}
          {notice && <p role="status" className="mb-3 text-xs text-emerald-700">{notice}</p>}
          {usage && (
            <div className="mb-3 rounded-lg border border-slate-200 bg-white p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs font-semibold text-slate-700">Monthly build allowance · {usage.periodStart}</p>
                <span className="text-[11px] tabular-nums text-slate-500">{usage.buildMinutesUsed.toLocaleString()} / {usage.buildMinutesLimit.toLocaleString()} minutes</span>
              </div>
              <Meter className="mt-2" value={usage.buildMinutesLimit > 0 ? Math.min(100, (usage.buildMinutesUsed / usage.buildMinutesLimit) * 100) : usage.quotaExhausted ? 100 : 0} />
              <p className="mt-2 text-[11px] leading-4 text-amber-700">{usage.meteringStatus !== "active" ? "Builder metering has not reported usage yet. This is an allowance preview, not measured usage; build dispatch and quota enforcement remain disabled." : usage.quotaExhausted ? "Monthly build allowance exhausted. Dispatch enforcement is not enabled." : "Usage has been reported by the authenticated builder. Dispatch quota enforcement remains disabled."}</p>
            </div>
          )}
          {loading ? <p className="text-xs text-slate-500">Loading runtime catalog…</p> : (
            <form onSubmit={save} className="grid gap-3 md:grid-cols-2">
              <label className="space-y-1.5 text-xs font-semibold text-slate-600 md:col-span-2">Runtime profile
                <select required value={runtimeProfileId} onChange={event => {
                  const profile = profiles.find(item => item.id === event.target.value);
                  setRuntimeProfileId(event.target.value);
                  if (profile?.runtimeFamily === "static") { setBuildMethod("static"); setOutputDirectory("dist"); }
                  else if (profile?.runtimeFamily === "container") setBuildMethod("dockerfile");
                  else setBuildMethod("managed");
                }} className="nx-select">
                  <option value="">Choose runtime profile</option>
                  {profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.displayName} · {profile.enabled ? "Enabled" : "Catalog only"}</option>)}
                </select>
              </label>
              <label className="space-y-1.5 text-xs font-semibold text-slate-600">Build method
                <select value={buildMethod} onChange={event => setBuildMethod(event.target.value)} className="nx-select">
                  <option value="managed">Managed build</option><option value="static">Static output</option><option value="dockerfile">Dockerfile / OCI</option>
                </select>
              </label>
              <label className="space-y-1.5 text-xs font-semibold text-slate-600">Build context
                <input value={buildContext} onChange={event => setBuildContext(event.target.value)} className="nx-input" />
              </label>
              <label className="space-y-1.5 text-xs font-semibold text-slate-600">Build command (stored, not executed)
                <input value={buildCommand} onChange={event => setBuildCommand(event.target.value)} maxLength={1000} className="nx-input" placeholder="npm run build" />
              </label>
              <label className="space-y-1.5 text-xs font-semibold text-slate-600">Output directory
                <input value={outputDirectory} onChange={event => setOutputDirectory(event.target.value)} maxLength={240} className="nx-input" placeholder="dist" />
              </label>
              <label className="space-y-1.5 text-xs font-semibold text-slate-600">Start command (stored, not executed)
                <input value={startCommand} onChange={event => setStartCommand(event.target.value)} maxLength={1000} className="nx-input" placeholder="npm start" />
              </label>
              <label className="space-y-1.5 text-xs font-semibold text-slate-600">Application port
                <input type="number" min="1" max="65535" value={listenPort} onChange={event => setListenPort(event.target.value)} className="nx-input" placeholder="3000" />
              </label>
              <label className="space-y-1.5 text-xs font-semibold text-slate-600">Health check path
                <input value={healthCheckPath} onChange={event => setHealthCheckPath(event.target.value)} maxLength={200} className="nx-input" placeholder="/health" />
              </label>
              <div className="md:col-span-2 rounded-lg border border-slate-200 bg-white p-3.5">
                <p className="mb-3 text-xs font-semibold text-slate-700">Requested runtime resources</p>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  <label className="space-y-1.5 text-xs text-slate-600">CPU (millicores)
                    <input type="number" min="100" max={planLimits?.cpuMillis ?? 8000} value={cpuMillis} onChange={event => setCpuMillis(event.target.value)} className="nx-input" />
                  </label>
                  <label className="space-y-1.5 text-xs text-slate-600">Memory (MiB)
                    <input type="number" min="128" max={planLimits?.memoryMiB ?? 16384} value={memoryMiB} onChange={event => setMemoryMiB(event.target.value)} className="nx-input" />
                  </label>
                  <label className="space-y-1.5 text-xs text-slate-600">Storage (MiB)
                    <input type="number" min="128" max={planLimits?.diskMiB ?? 65536} value={diskMiB} onChange={event => setDiskMiB(event.target.value)} className="nx-input" />
                  </label>
                  <label className="space-y-1.5 text-xs text-slate-600">Process limit
                    <input type="number" min="16" max={planLimits?.processLimit ?? 512} value={processLimit} onChange={event => setProcessLimit(event.target.value)} className="nx-input" />
                  </label>
                </div>
                {planLimits && <p className="mt-2.5 text-[11px] text-slate-500">Hosting plan ceilings: {planLimits.cpuMillis} mCPU · {planLimits.memoryMiB} MiB RAM · {planLimits.diskMiB} MiB storage · {planLimits.processLimit} processes.</p>}
              </div>
              <div className="md:col-span-2 flex flex-wrap items-center justify-between gap-3">
                <p className="text-xs text-amber-700">{selectedProfile?.enabled ? "Runtime profile enabled; deployment still gated." : "Catalog only: execution is disabled. Settings are saved as metadata."}</p>
                <button type="submit" disabled={saving || !runtimeProfileId} className="nx-btn-primary nx-btn-sm">{saving ? "Saving…" : "Save runtime settings"}</button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
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
  const [detection, setDetection] = useState<{ framework: string; outputDirectory: string; detectedFrom: string } | null>(null);
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

  // Framework detection is best-effort: it prefills the build contract from
  // the repository's actual contents and never blocks manual selection.
  const onRepositorySelected = async (id: string) => {
    const repo = repositories.find(item => String(item.id) === id);
    setSelectedRepository(id);
    setDetection(null);
    if (!repo) return;
    setBranch(repo.defaultBranch);
    try {
      const response = await fetch("/api/control/github/projects/detect-framework", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ repositoryId: repo.id, installationId: repo.installationId, repositoryFullName: repo.fullName, branch: repo.defaultBranch }),
      });
      const data = await response.json() as { framework?: string; outputDirectory?: string; detectedFrom?: string };
      if (response.ok && typeof data.framework === "string") {
        const known = ["static", "vite", "react", "vue", "astro", "next-static"];
        if (known.includes(data.framework)) setFramework(data.framework);
        if (typeof data.outputDirectory === "string" && data.outputDirectory) setOutputDirectory(data.outputDirectory);
        setDetection({ framework: data.framework, outputDirectory: String(data.outputDirectory ?? ""), detectedFrom: String(data.detectedFrom ?? "") });
      }
    } catch { /* detection is best-effort; manual selection still works */ }
  };

  const loadRepositories = useCallback(async () => {
    if (!connected || !connection?.installed) { setRepositories([]); return; }
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/control/github/repositories", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) {
        const diagnostic = data.diagnostics?.requestId ? ` Support reference: ${data.diagnostics.requestId}.` : "";
        throw new Error((data.message ?? "Unable to load repositories.") + diagnostic);
      }
      setRepositories(data.repositories ?? []);
      if (!data.repositories?.length && data.message) setNotice(data.message);
      else if (!data.repositories?.length) setNotice("");
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to load repositories."); }
    finally { setBusy(false); }
  }, [connected, connection?.installed]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (connected && connection?.installed) void loadRepositories(); }, [connected, connection?.installed, loadRepositories]);
  useEffect(() => {
    const status = new URLSearchParams(window.location.search).get("github");
    if (status === "connected") { setNotice("GitHub account connected successfully."); window.history.replaceState({}, "", customerMode ? "/customer/deploy" : "/github-deployments"); void load(); }
    else if (status === "installed") { setNotice("Nexora GitHub App installed successfully. Loading repositories…"); window.history.replaceState({}, "", customerMode ? "/customer/deploy" : "/github-deployments"); void load(); }
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
  async function installGithubApp() {
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/control/github/installations/start", { method: "POST" });
      const data = await response.json();
      if (!response.ok || !data.installationUrl) throw new Error(data.message ?? "Unable to start GitHub App installation.");
      window.location.assign(data.installationUrl);
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to install the Nexora GitHub App."); setBusy(false); }
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

  return (
    <main className="min-h-screen bg-canvas">
      {customerMode && (
        <header className="sticky top-0 z-30 border-b border-white/[0.06] bg-gradient-to-r from-navy-950 via-navy-950 to-navy-900">
          <div className="mx-auto flex h-[72px] max-w-[1500px] items-center justify-between gap-4 px-5 sm:px-8">
            <div className="flex min-w-0 items-center gap-3">
              <NexoraMark size={38} />
              <div className="min-w-0">
                <p className="text-[15px] font-bold tracking-tight text-white">Nexora <span className="text-brand-300">Deploy</span></p>
                <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">Git-based deployments</p>
              </div>
            </div>
            <Link href="/customer" className="rounded-xl border border-white/10 bg-white/[0.07] px-3.5 py-2.5 text-xs font-semibold text-slate-100 transition hover:bg-white/[0.12]">Back to hosting</Link>
          </div>
        </header>
      )}
      <section className="mx-auto max-w-[1150px] space-y-6 px-5 py-8 lg:px-9">
        {!customerMode && (
          <PageHeader
            eyebrow="Hosting services · Git deployments"
            title="Nexora Deploy"
            description="Connect repositories to hosting accounts and configure website builds. Builds run in isolated GitHub-hosted runners and publish through the static release pipeline."
            actions={
              <span className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-600 shadow-sm"><Rocket size={13} className="text-brand-600" /> Deployment platform</span>
            }
          />
        )}
        {customerMode && (
          <PageHeader
            eyebrow="Nexora Deploy · Projects"
            title="Deploy your website"
            description="Link a repository to an active Nexora hosting account. Choose the production branch and static build output. Builds become available after the GitHub-hosted workflow and isolated static publisher pass platform acceptance."
          />
        )}
        {error && <InlineAlert tone="error">{error}</InlineAlert>}
        {notice && <InlineAlert tone="success">{notice}</InlineAlert>}
        {loading ? (
          <div className="nx-card flex items-center gap-2.5 p-8 text-sm text-slate-500"><Loader2 className="animate-spin" size={18} /> Loading GitHub settings…</div>
        ) : <>
          <SectionCard
            title="GitHub account"
            description="Authorize the Nexora GitHub App to access repositories you select."
            actions={connected
              ? <StatusBadge tone="success" dot>Connected</StatusBadge>
              : <StatusBadge tone="neutral">Not connected</StatusBadge>}
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <span className="grid h-11 w-11 place-items-center rounded-xl bg-navy-950 text-white"><Github size={21} /></span>
                <div>
                  <p className="text-sm font-semibold text-slate-900">GitHub App authorization</p>
                  <p className="mt-1 text-xs leading-5 text-slate-500">Tokens are encrypted before storage and are never sent to the browser.</p>
                </div>
              </div>
              {connected ? (
                <button onClick={disconnectGithub} disabled={busy} title="Disconnect this GitHub account from Nexora" className="nx-btn-secondary"><Unplug size={15} /> Disconnect</button>
              ) : (
                <button onClick={connectGithub} disabled={busy} className="nx-btn bg-navy-950 text-white shadow-sm hover:bg-navy-900"><Github size={16} /> Connect GitHub</button>
              )}
            </div>
            {connected && (
              <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-100 bg-slate-50/70 p-4">
                <div>
                  <p className="text-sm font-bold text-slate-900">@{connection?.login}</p>
                  <p className="mt-0.5 text-xs text-slate-500">Connected {connection?.connectedAt ? new Date(connection.connectedAt).toLocaleString() : ""}</p>
                  <p className="mt-1 text-xs font-medium text-slate-600">{connection?.installed ? "Nexora GitHub App installed · repository access enabled" : "GitHub authorized; Nexora GitHub App installation required."}</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={installGithubApp}
                    disabled={busy}
                    className="nx-btn bg-navy-950 text-white shadow-sm hover:bg-navy-900"
                    title="Start a fresh, state-protected GitHub App installation or repair flow"
                  >
                    <Github size={15} /> Install / repair Nexora GitHub App
                  </button>
                </div>
              </div>
            )}
          </SectionCard>


          {connected && connection?.installed && (
            <SectionCard
              title="Link a repository"
              description="Select an installed repository and the hosting account that will serve its built files."
              actions={<button onClick={loadRepositories} disabled={busy} className="nx-btn-secondary nx-btn-sm"><RefreshCw size={14} /> Refresh repositories</button>}
            >
              <form onSubmit={linkRepository} className="grid gap-4 md:grid-cols-2">
                <label className="space-y-1.5 text-xs font-semibold text-slate-600 md:col-span-2">GitHub repository
                  <select required value={selectedRepository} onChange={event => onRepositorySelected(event.target.value)} className="nx-select">
                    <option value="">Choose a repository</option>
                    {repositories.map(repo => <option key={`${repo.installationId}-${repo.id}`} value={repo.id}>{repo.fullName}{repo.private ? " · Private" : " · Public"}</option>)}
                  </select>
                </label>
                <label className="space-y-1.5 text-xs font-semibold text-slate-600 md:col-span-2">Nexora hosting account
                  <select required value={hostingAccountId} onChange={event => setHostingAccountId(event.target.value)} className="nx-select">
                    <option value="">Choose an active hosting account</option>
                    {accounts.map(account => <option key={account.id} value={account.id}>{account.username}{account.primary_domain ? ` · ${account.primary_domain}` : ""}</option>)}
                  </select>
                </label>
                <label className="space-y-1.5 text-xs font-semibold text-slate-600">Production branch
                  <input required value={branch} onChange={event => setBranch(event.target.value)} className="nx-input" placeholder="main" />
                </label>
                <label className="space-y-1.5 text-xs font-semibold text-slate-600">Framework
                  <select value={framework} onChange={event => setFramework(event.target.value)} className="nx-select">
                    <option value="auto">Auto detect</option><option value="static">Static HTML</option><option value="vite">Vite</option><option value="react">React</option><option value="vue">Vue</option><option value="astro">Astro (static)</option><option value="next-static">Next.js static export</option>
                  </select>
                </label>
                <label className="space-y-1.5 text-xs font-semibold text-slate-600">Repository root
                  <input required value={rootDirectory} onChange={event => setRootDirectory(event.target.value)} className="nx-input" placeholder="." />
                </label>
                <label className="space-y-1.5 text-xs font-semibold text-slate-600">Build output directory
                  <input required value={outputDirectory} onChange={event => setOutputDirectory(event.target.value)} className="nx-input" placeholder="dist" />
                </label>
                {detection && (
                  <p className="md:col-span-2 text-xs text-slate-500">
                    Detected <span className="font-semibold text-slate-700">{detection.framework}</span> from {detection.detectedFrom || "repository contents"} — build output prefilled to {detection.outputDirectory}.
                  </p>
                )}
                <div className="md:col-span-2">
                  <button type="submit" disabled={busy || !selected || !hostingAccountId} className="nx-btn-primary"><Link2 size={16} /> Save repository configuration</button>
                </div>
              </form>
              {!repositories.length && (
                <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/70 p-4 text-xs leading-5 text-slate-600">
                  <p className="font-semibold text-slate-800">No repositories are visible yet.</p>
                  <p className="mt-1">Connecting the GitHub account authorizes OAuth sign-in; repositories only appear after the Nexora GitHub App is <span className="font-semibold">installed</span> and granted repository access. Use “Install Nexora GitHub App” above, then refresh repositories.</p>
                </div>
              )}
            </SectionCard>
          )}

          <SectionCard title="Linked projects" description="Repository-to-hosting-account configurations." flush>
            {projects.length ? (
              <div className="divide-y divide-slate-100">
                {projects.map(project => (
                  <div key={project.id}>
                    <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-bold text-slate-900">{project.repositoryFullName}</p>
                        <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500"><GitBranch size={13} className="text-slate-400" />{project.productionBranch}<span className="text-slate-300">·</span>{project.framework}<span className="text-slate-300">·</span>Output: {project.outputDirectory}</p>
                      </div>
                      <StatusBadge tone={statusTone(project.status)} dot>{project.status === "configured" ? "Configured · build worker pending" : project.status}</StatusBadge>
                    </div>
                    <ProjectDeployTools project={project} onChanged={() => { void load(); }} />
                    <div className="border-t border-slate-100 bg-slate-50/50 px-6 py-4">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <p className="text-xs font-semibold text-slate-700">Deployment history</p>
                        <span className="text-[11px] text-slate-400">{(deploymentsByProject[project.id] ?? []).length} records</span>
                      </div>
                      {(deploymentsByProject[project.id] ?? []).length ? (
                        <div className="space-y-2.5">
                          {(deploymentsByProject[project.id] ?? []).map(deployment => (
                            <div key={deployment.id} className="rounded-xl border border-slate-200 bg-white p-3.5">
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <StatusBadge tone={statusTone(deployment.status)} dot>{deployment.status.replaceAll("_", " ")}</StatusBadge>
                                <DeploymentActions projectId={project.id} deployment={deployment} onChanged={() => { void load(); }} />
                              </div>
                              <p className="mt-2 font-mono text-xs text-slate-600">{deployment.branch} · {deployment.commitSha.slice(0, 12)} · {deployment.triggerType} · {deployment.deploymentKind === "preview" ? "preview" : "production"}</p>
                              {deployment.commitMessage && <p className="mt-1 text-xs leading-5 text-slate-500">{deployment.commitMessage}</p>}
                              {deployment.deploymentUrl && <a href={deployment.deploymentUrl} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-brand-600 hover:underline">Open deployment URL <ExternalLink size={11} /></a>}
                              {deployment.logExcerpt && (
                                <details className="mt-2">
                                  <summary className="cursor-pointer text-xs font-semibold text-slate-600 hover:text-slate-900">View latest log excerpt</summary>
                                  <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-navy-950 p-3 font-mono text-[11px] leading-5 text-slate-100">{deployment.logExcerpt}</pre>
                                </details>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : <p className="text-xs text-slate-500">No deployment records yet.</p>}
                    </div>
                    {!customerMode && <RuntimeProjectSettings projectId={project.id} />}
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={Github} title="No repositories linked yet" description="Connect the GitHub account above, then link a repository to an active hosting account to create the first project." />
            )}
          </SectionCard>

          <div className="flex items-start gap-3.5 rounded-2xl border border-amber-200 bg-amber-50 p-5">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-amber-100 text-amber-700"><Rocket size={17} /></span>
            <div>
              <p className="text-sm font-bold text-amber-900">Public serving and rollback are still in acceptance</p>
              <p className="mt-1 text-sm leading-6 text-amber-800">Repository configuration, manual dispatch, push/PR webhooks with preview deployments, environment variables, webhook secrets, and build logs are wired end to end. Public serving of deployment hostnames and one-click rollback remain gated until the isolated static publisher passes end-to-end acceptance on the production runtime.</p>
            </div>
          </div>
          <p className="text-xs text-slate-400">Repository links are saved to the current workspace. <a href="https://github.com/settings/installations" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-semibold text-brand-600 hover:underline">Manage GitHub App installations <ExternalLink size={11} /></a></p>
        </>}
      </section>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Nexora Deploy batch-6 wiring: environment variables, deploy settings,
// webhook secret rotation, deployment logs, and preview promotion. All calls
// go through the /api/control proxy (session + route allowlist); the control
// plane enforces role, tenant, and encryption boundaries.
// ---------------------------------------------------------------------------

type EnvVar = { id: string; keyName: string; environment: string; target: string; isSecret: boolean; createdAt: string; updatedAt: string };
type LogLine = { seq: number; source: string; message: string; emittedAt: string };

function EnvVarsPanel({ projectId }: { projectId: string }) {
  const [variables, setVariables] = useState<EnvVar[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [keyName, setKeyName] = useState("");
  const [value, setValue] = useState("");
  const [environment, setEnvironment] = useState("production");
  const [target, setTarget] = useState("runtime");
  const [isSecret, setIsSecret] = useState(true);

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/control/github/projects/${projectId}/env-vars`, { cache: "no-store" });
      const data = await response.json();
      if (response.ok) setVariables(data.variables ?? []);
      else setError(data.message ?? "Unable to load environment variables.");
    } catch { setError("Unable to load environment variables."); }
    finally { setLoading(false); }
  }, [projectId]);

  useEffect(() => { void load(); }, [load]);

  const add = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true); setError("");
    try {
      const response = await fetch(`/api/control/github/projects/${projectId}/env-vars`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key: keyName, value, environment, target, isSecret }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Unable to save the variable.");
      setKeyName(""); setValue("");
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to save the variable."); }
    finally { setBusy(false); }
  };

  const remove = async (id: string) => {
    setBusy(true); setError("");
    try {
      const response = await fetch(`/api/control/github/projects/${projectId}/env-vars/${id}`, { method: "DELETE" });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.message ?? "Unable to delete the variable.");
      }
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to delete the variable."); }
    finally { setBusy(false); }
  };

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-bold text-slate-800">Environment variables</p>
        <span className="text-[11px] text-slate-400">{variables.length} · values never leave the control plane</span>
      </div>
      {error && <div className="mt-2"><InlineAlert tone="error">{error}</InlineAlert></div>}
      {loading ? (
        <p className="mt-3 flex items-center gap-2 text-xs text-slate-500"><Spinner className="h-3.5 w-3.5" /> Loading…</p>
      ) : (
        <div className="mt-3 space-y-1.5">
          {variables.length ? variables.map(variable => (
            <div key={variable.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50/70 px-3 py-2">
              <div className="min-w-0 font-mono text-xs text-slate-700">
                {variable.keyName}
                <span className="ml-2 inline-flex items-center gap-1 font-sans text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                  {variable.environment} · {variable.target}{variable.isSecret ? " · secret" : ""}
                </span>
              </div>
              <button onClick={() => remove(variable.id)} disabled={busy} className="text-[11px] font-semibold text-rose-600 hover:underline disabled:opacity-50">Remove</button>
            </div>
          )) : <p className="text-xs text-slate-500">No variables yet. Build-target values for the selected environment are injected into the builder at deploy time and redacted from logs.</p>}
        </div>
      )}
      <form onSubmit={add} className="mt-3 grid gap-2 md:grid-cols-12">
        <input required value={keyName} onChange={event => setKeyName(event.target.value)} maxLength={128} placeholder="KEY_NAME" className="nx-input md:col-span-3 font-mono text-xs" aria-label="Variable key" />
        <input required type="password" value={value} onChange={event => setValue(event.target.value)} maxLength={32768} placeholder="Value" className="nx-input md:col-span-4 text-xs" aria-label="Variable value" />
        <select value={environment} onChange={event => setEnvironment(event.target.value)} className="nx-select md:col-span-2 text-xs" aria-label="Environment">
          <option value="production">Production</option><option value="preview">Preview</option><option value="development">Development</option>
        </select>
        <select value={target} onChange={event => setTarget(event.target.value)} className="nx-select md:col-span-2 text-xs" aria-label="Target">
          <option value="build">Build</option><option value="runtime">Runtime</option><option value="both">Both</option>
        </select>
        <button type="submit" disabled={busy} className="nx-btn-secondary nx-btn-sm md:col-span-1 justify-center">Add</button>
        <label className="flex items-center gap-1.5 text-[11px] text-slate-500 md:col-span-12">
          <input type="checkbox" checked={isSecret} onChange={event => setIsSecret(event.target.checked)} className="h-3.5 w-3.5 rounded border-slate-300" />
          Mask as secret in the dashboard (values are never returned by the API regardless).
        </label>
      </form>
    </div>
  );
}

function DeploySettingsPanel({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const [previewEnabled, setPreviewEnabled] = useState(project.previewEnabled === 1);
  const [autoDeploy, setAutoDeploy] = useState(project.autoDeploy !== 0);
  const [ignoredPaths, setIgnoredPaths] = useState(normalizeIgnoredBuildPaths(project.ignoredBuildPaths).join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const save = async (next: { previewEnabled: boolean; autoDeploy: boolean; ignoredBuildPaths: string[] }) => {
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/github/projects/${project.id}/deploy-settings`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(next),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Unable to save deploy settings.");
      setPreviewEnabled(data.settings.previewEnabled);
      setAutoDeploy(data.settings.autoDeploy);
      setIgnoredPaths(normalizeIgnoredBuildPaths(data.settings?.ignoredBuildPaths).join(", "));
      setNotice("Deploy settings saved.");
      onChanged();
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to save deploy settings."); }
    finally { setBusy(false); }
  };

  const pathList = () => ignoredPaths.split(",").map(item => item.trim()).filter(Boolean);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <p className="text-xs font-bold text-slate-800">Deploy settings</p>
      {error && <div className="mt-2"><InlineAlert tone="error">{error}</InlineAlert></div>}
      {notice && <div className="mt-2"><InlineAlert tone="success">{notice}</InlineAlert></div>}
      <div className="mt-3 space-y-2.5 text-xs text-slate-600">
        <label className="flex items-center justify-between gap-3">
          <span>Auto-deploy on push to the production branch</span>
          <input type="checkbox" checked={autoDeploy} onChange={event => { setAutoDeploy(event.target.checked); void save({ previewEnabled, autoDeploy: event.target.checked, ignoredBuildPaths: pathList() }); }} disabled={busy} className="h-4 w-4 rounded border-slate-300" />
        </label>
        <label className="flex items-center justify-between gap-3">
          <span>Preview deployments for pull requests</span>
          <input type="checkbox" checked={previewEnabled} onChange={event => { setPreviewEnabled(event.target.checked); void save({ previewEnabled: event.target.checked, autoDeploy, ignoredBuildPaths: pathList() }); }} disabled={busy} className="h-4 w-4 rounded border-slate-300" />
        </label>
        <div>
          <input value={ignoredPaths} onChange={event => setIgnoredPaths(event.target.value)} placeholder="docs/, README.md, .github/" className="nx-input text-xs" aria-label="Ignored build paths" />
          <p className="mt-1 text-[11px] text-slate-400">Comma-separated path prefixes; pushes that only touch these paths skip the deploy.</p>
        </div>
        <button onClick={() => void save({ previewEnabled, autoDeploy, ignoredBuildPaths: pathList() })} disabled={busy} className="nx-btn-secondary nx-btn-sm">Save ignored paths</button>
      </div>
    </div>
  );
}

function ProjectDeployTools({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const [rotating, setRotating] = useState(false);
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null);
  const [error, setError] = useState("");

  const rotateSecret = async () => {
    if (!window.confirm("Rotate the webhook secret for this repository? The previous secret stops working immediately and GitHub rejects deliveries signed with it until you update the repository webhook settings.")) return;
    setRotating(true); setError("");
    try {
      const response = await fetch(`/api/control/github/projects/${project.id}/webhook-secret`, { method: "PUT" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Unable to rotate the webhook secret.");
      setRotatedSecret(String(data.webhookSecret ?? ""));
      onChanged();
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to rotate the webhook secret."); }
    finally { setRotating(false); }
  };

  return (
    <div className="grid gap-3 border-t border-slate-100 bg-slate-50/70 px-6 py-4 md:grid-cols-2">
      <div className="space-y-3">
        <DeploySettingsPanel project={project} onChanged={onChanged} />
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs font-bold text-slate-800">Push & PR webhooks</p>
            <button onClick={rotateSecret} disabled={rotating} className="nx-btn-secondary nx-btn-sm"><KeyRound size={13} /> {rotating ? "Rotating…" : "Rotate secret"}</button>
          </div>
          {error && <div className="mt-2"><InlineAlert tone="error">{error}</InlineAlert></div>}
          {rotatedSecret && (
            <div className="mt-2">
              <InlineAlert tone="success">
                <span className="block font-semibold">Copy this secret now</span>
                <span className="mt-1 block break-all font-mono text-[11px]">{rotatedSecret}</span>
                Store it in the repository&apos;s GitHub webhook settings. It is encrypted at rest and cannot be retrieved again.
              </InlineAlert>
            </div>
          )}
          <p className="mt-2 text-[11px] leading-5 text-slate-400">Deliveries are verified per-project with HMAC-SHA256; every push and pull-request decision is recorded with its outcome.</p>
        </div>
      </div>
      <EnvVarsPanel projectId={project.id} />
    </div>
  );
}

function DeploymentActions({ projectId, deployment, onChanged }: { projectId: string; deployment: Deployment; onChanged: () => void }) {
  const [logsOpen, setLogsOpen] = useState(false);
  const [promoting, setPromoting] = useState(false);
  const [error, setError] = useState("");
  const promotable = deployment.deploymentKind === "preview" && deployment.status === "succeeded";

  const promote = async () => {
    if (!window.confirm("Promote this preview to production? Production traffic re-points to this build's artifact without rebuilding.")) return;
    setPromoting(true); setError("");
    try {
      const response = await fetch(`/api/control/github/projects/${projectId}/deployments/${deployment.id}/promote`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message ?? "Promotion failed.");
      onChanged();
    } catch (err) { setError(err instanceof Error ? err.message : "Promotion failed."); }
    finally { setPromoting(false); }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      {error && <span className="text-[11px] font-semibold text-rose-600">{error}</span>}
      <button onClick={() => setLogsOpen(true)} className="nx-btn-secondary nx-btn-sm"><ScrollText size={13} /> Logs</button>
      {promotable && (
        <button onClick={promote} disabled={promoting} className="nx-btn-primary nx-btn-sm"><ArrowUpRight size={13} /> {promoting ? "Promoting…" : "Promote"}</button>
      )}
      {logsOpen && <DeploymentLogsModal projectId={projectId} deploymentId={deployment.id} initialStatus={deployment.status} onClose={() => setLogsOpen(false)} />}
    </div>
  );
}

function DeploymentLogsModal({ projectId, deploymentId, initialStatus, onClose }: { projectId: string; deploymentId: string; initialStatus: string; onClose: () => void }) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [status, setStatus] = useState(initialStatus);
  const [cursor, setCursor] = useState<number | null>(-1);
  const [error, setError] = useState("");
  const tailRef = useRef<number>(-1);

  useEffect(() => {
    let cancelled = false;
    const terminal = ["succeeded", "failed", "cancelled"];
    const poll = async () => {
      try {
        const after = tailRef.current;
        const response = await fetch(`/api/control/github/projects/${projectId}/deployments/${deploymentId}/logs?after=${after}&limit=200`, { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message ?? "Unable to load build logs.");
        if (cancelled) return;
        setStatus(String(data.status ?? initialStatus));
        const incoming = (data.lines ?? []) as LogLine[];
        if (incoming.length) {
          tailRef.current = incoming[incoming.length - 1].seq;
          setLines(previous => [...previous, ...incoming]);
        }
        setCursor(data.nextCursor === null ? null : Number(data.nextCursor));
        if (terminal.includes(String(data.status ?? ""))) return; // stop polling on terminal state
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unable to load build logs.");
        return;
      }
      if (!cancelled) window.setTimeout(() => { void poll(); }, 4000);
    };
    void poll();
    return () => { cancelled = true; };
  }, [projectId, deploymentId, initialStatus]);

  return (
    <Modal title="Build logs" description={`Deployment ${deploymentId.slice(0, 8)} · ${status} · secrets are redacted before storage`} onClose={onClose} labelledBy="Build logs">
      <pre className="mt-4 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-navy-950 p-3 font-mono text-[11px] leading-5 text-slate-100">
        {lines.length ? lines.map(line => <span key={line.seq} className="block">{line.message}</span>) : (error ? String(error) : "No log lines have streamed yet.")}
      </pre>
      {cursor !== null && !["succeeded", "failed", "cancelled"].includes(status) && (
        <p className="mt-2 flex items-center gap-2 text-[11px] text-slate-500"><Spinner className="h-3 w-3" /> Streaming… new lines appear automatically.</p>
      )}
    </Modal>
  );
}
"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Eye, RefreshCw, Save, Server } from "lucide-react";

type PhpSettings = {
  phpVersion: string;
  memoryLimitMib: number;
  maxExecutionTimeSeconds: number;
  uploadMaxFilesizeMib: number;
  maxInputVars: number;
  displayErrors: number;
};

const PHP_VERSIONS = ["8.1", "8.2", "8.3", "8.4"];

const defaultSettings: PhpSettings = {
  phpVersion: "8.3",
  memoryLimitMib: 256,
  maxExecutionTimeSeconds: 30,
  uploadMaxFilesizeMib: 64,
  maxInputVars: 1000,
  displayErrors: 0,
};

export default function HostingAccountPhpPage() {
  const params = useParams<{ id: string }>();
  const accountId = params?.id ?? "";
  const [settings, setSettings] = useState<PhpSettings>(defaultSettings);
  const [original, setOriginal] = useState<PhpSettings>(defaultSettings);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    if (!accountId) return;
    setLoading(true); setError("");
    try {
      const response = await fetch(`/api/control/hosting-accounts/${encodeURIComponent(accountId)}/php`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to load PHP settings.");
      const next: PhpSettings = {
        phpVersion: data.phpVersion || defaultSettings.phpVersion,
        memoryLimitMib: Number(data.memoryLimitMib ?? defaultSettings.memoryLimitMib),
        maxExecutionTimeSeconds: Number(data.maxExecutionTimeSeconds ?? defaultSettings.maxExecutionTimeSeconds),
        uploadMaxFilesizeMib: Number(data.uploadMaxFilesizeMib ?? defaultSettings.uploadMaxFilesizeMib),
        maxInputVars: Number(data.maxInputVars ?? defaultSettings.maxInputVars),
        displayErrors: Number(data.displayErrors ?? 0),
      };
      setSettings(next);
      setOriginal(next);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load PHP settings."); }
    finally { setLoading(false); }
  }, [accountId]);

  useEffect(() => { void load(); }, [load]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true); setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/hosting-accounts/${encodeURIComponent(accountId)}/php`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(settings),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to save PHP settings.");
      setNotice(data.message || "PHP-FPM pool updated. Changes were reloaded on the hosting node.");
      setOriginal(settings);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to save PHP settings."); }
    finally { setSaving(false); }
  }

  const dirty = JSON.stringify(settings) !== JSON.stringify(original);
  const field = <T extends keyof PhpSettings>(key: T) => (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setSettings(current => {
      const source = event.target;
      if (key === "displayErrors") {
        const checked = (source as HTMLInputElement).checked;
        return { ...current, displayErrors: checked ? 1 : 0 };
      }
      const value = source.value;
      const numeric: PhpSettings[T] = (Number(value) || 0) as unknown as PhpSettings[T];
      return { ...current, [key]: key === "phpVersion" ? (value as PhpSettings[T]) : numeric };
    });

  return <main className="min-h-full bg-transparent text-slate-900">
    <header className="border-b border-slate-200/70 bg-white/85"><div className="mx-auto flex max-w-[1200px] items-center justify-between px-6 py-4">
      <div className="flex items-center gap-3">
        <Link href="/hosting-accounts" aria-label="Back to hosting accounts" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
        <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Server size={20}/></span>
        <div><p className="font-semibold">PHP-FPM settings</p><p className="text-xs text-slate-500">Nexora Control / Hosting accounts</p></div>
      </div>
      <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={15}/> Refresh</button>
    </div></header>
    <section className="mx-auto max-w-[1200px] space-y-6 px-6 py-8">
      <div>
        <p className="text-sm font-medium text-blue-700">Per-account PHP runtime</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight">PHP-FPM pool configuration</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">Tune the PHP version and per-account limits for this hosting account&apos;s dedicated PHP-FPM pool. Changes are validated and reloaded on the hosting node.</p>
      </div>
      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}
      {loading ? <div className="rounded-2xl border border-slate-200 bg-white p-10 text-center text-sm text-slate-500 shadow-sm">Loading PHP settings…</div> : (
        <form onSubmit={save} className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold">Runtime directives</h2><p className="mt-1 text-xs text-slate-500">Limits are applied as php_admin_value directives in the account pool.</p></div>
          <div className="grid gap-5 px-5 py-6 md:grid-cols-2">
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-700">PHP version</span>
              <select value={settings.phpVersion} onChange={field("phpVersion")} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10">
                {PHP_VERSIONS.map(v => <option key={v} value={v}>{v}</option>)}
              </select>
              <span className="mt-1 block text-[11px] text-slate-400">Choose the PHP runtime used by this account.</span>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-700">Memory limit (MiB)</span>
              <input type="number" min={64} max={4096} step={1} value={settings.memoryLimitMib} onChange={field("memoryLimitMib")} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10"/>
              <span className="mt-1 block text-[11px] text-slate-400">Range 64–4096 MiB. Default 256 MiB.</span>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-700">Max execution time (seconds)</span>
              <input type="number" min={5} max={300} step={1} value={settings.maxExecutionTimeSeconds} onChange={field("maxExecutionTimeSeconds")} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10"/>
              <span className="mt-1 block text-[11px] text-slate-400">Range 5–300 seconds. Default 30 seconds.</span>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-700">Upload max filesize (MiB)</span>
              <input type="number" min={1} max={2048} step={1} value={settings.uploadMaxFilesizeMib} onChange={field("uploadMaxFilesizeMib")} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10"/>
              <span className="mt-1 block text-[11px] text-slate-400">Range 1–2048 MiB. Default 64 MiB.</span>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-slate-700">Max input vars</span>
              <input type="number" min={100} max={10000} step={1} value={settings.maxInputVars} onChange={field("maxInputVars")} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10"/>
              <span className="mt-1 block text-[11px] text-slate-400">Range 100–10000. Default 1000.</span>
            </label>
            <label className="flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50/60 px-4 py-3.5">
              <input type="checkbox" checked={settings.displayErrors === 1} onChange={field("displayErrors")} className="mt-0.5 h-4 w-4 rounded border-slate-300 text-blue-700 focus:ring-blue-500/20"/>
              <span><span className="block text-xs font-semibold text-slate-700">Display errors (display_errors)</span><span className="mt-1 block text-[11px] leading-5 text-slate-500">When enabled, PHP emits errors to the response. Recommended off in production.</span></span>
            </label>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 bg-slate-50/50 px-5 py-4">
            <span className="text-xs text-slate-500">{dirty ? "You have unsaved changes." : "All changes saved."}</span>
            <div className="flex items-center gap-2">
              <Eye size={14} className="text-slate-400"/>
              <span className="text-xs text-slate-400">Limits apply per-request through the dedicated FPM pool.</span>
            </div>
            <button type="submit" disabled={saving || !dirty} className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-blue-700/20 transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"><Save size={16}/>{saving ? "Saving…" : "Save PHP settings"}</button>
          </div>
        </form>
      )}
      <p className="text-xs leading-5 text-slate-400">Updates write the account pool at /etc/php/&lt;version&gt;/fpm/pool.d/nexora-&lt;account&gt;.conf, validate the FPM configuration, and reload the matching php&lt;version&gt;-fpm service. Security directives such as disable_functions and open_basedir are always enforced by the agent.</p>
    </section>
  </main>;
}

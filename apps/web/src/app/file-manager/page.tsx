"use client";

import { ChangeEvent, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ChevronRight, Download, File, FilePlus2, Folder, FolderPlus, RefreshCw, Save, Trash2, Upload, X } from "lucide-react";

type Account = { id: string; username: string; status: string; server_hostname: string };
type FileEntry = { name: string; isDir: boolean; size: number; modifiedAt: string };
type OperationResult = { path?: string; entries?: FileEntry[]; contentBase64?: string; size?: number; success?: boolean };
type JobResponse = { job?: { id: string; status: string; errorMessage?: string | null; result?: OperationResult | null }; message?: string };

function bytesLabel(value: number): string {
  if (value < 1024) return value + " B";
  if (value < 1024 * 1024) return (value / 1024).toFixed(1) + " KB";
  return (value / (1024 * 1024)).toFixed(1) + " MB";
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export default function FileManagerPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [accountId, setAccountId] = useState("");
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [editorPath, setEditorPath] = useState("");
  const [editorContent, setEditorContent] = useState("");
  const [showEditor, setShowEditor] = useState(false);

  const selectedAccount = useMemo(() => accounts.find(item => item.id === accountId) ?? null, [accounts, accountId]);

  const execute = useCallback(async (operation: string, filePath: string, extra: Record<string, string> = {}): Promise<OperationResult> => {
    if (!accountId) throw new Error("Select an active hosting account first.");
    const response = await fetch("/api/control/hosting-accounts/" + encodeURIComponent(accountId) + "/files", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ operation, path: filePath, ...extra }),
    });
    const queued = await response.json() as JobResponse;
    if (!response.ok || !queued.job?.id) throw new Error(queued.message || "Unable to queue file operation");
    for (let attempt = 0; attempt < 90; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const statusResponse = await fetch("/api/control/file-manager/jobs/" + encodeURIComponent(queued.job.id), { cache: "no-store" });
      const statusData = await statusResponse.json() as JobResponse;
      if (!statusResponse.ok || !statusData.job) throw new Error(statusData.message || "Unable to retrieve file operation status");
      if (statusData.job.status === "SUCCEEDED") return statusData.job.result ?? {};
      if (statusData.job.status === "FAILED") throw new Error(statusData.job.errorMessage || "The server could not complete the file operation");
    }
    throw new Error("The server has not completed this operation yet. Refresh the directory to check again.");
  }, [accountId]);

  const loadDirectory = useCallback(async (nextPath: string) => {
    setBusy(true);
    setError("");
    try {
      const result = await execute("LIST_FILES", nextPath);
      setPath(nextPath);
      setEntries(result.entries ?? []);
      setShowEditor(false);
      setEditorPath("");
      setNotice("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load this directory");
    } finally {
      setBusy(false);
      setLoading(false);
    }
  }, [execute]);

  useEffect(() => {
    let active = true;
    fetch("/api/control/hosting-accounts", { cache: "no-store" })
      .then(async response => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Unable to load hosting accounts");
        if (!active) return;
        const available = (data.accounts ?? []).filter((item: Account) => item.status === "ACTIVE");
        setAccounts(available);
        if (available.length) setAccountId(available[0].id);
        else setLoading(false);
      })
      .catch(e => { if (active) { setError(e instanceof Error ? e.message : "Unable to load accounts"); setLoading(false); } });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (accountId) void loadDirectory("");
    else { setEntries([]); setPath(""); }
  }, [accountId, loadDirectory]);

  const parentPath = path.split("/").slice(0, -1).join("/");
  const segments = path ? path.split("/") : [];

  async function refresh() { await loadDirectory(path); }

  async function openFile(filePath: string) {
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await execute("READ_FILE", filePath);
      const bytes = fromBase64(result.contentBase64 ?? "");
      setEditorPath(filePath);
      setEditorContent(new TextDecoder().decode(bytes));
      setShowEditor(true);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to open file"); }
    finally { setBusy(false); }
  }

  async function saveFile() {
    setBusy(true); setError(""); setNotice("");
    try {
      const encoded = toBase64(new TextEncoder().encode(editorContent));
      await execute("WRITE_FILE", editorPath, { contentBase64: encoded });
      setNotice("File saved successfully.");
      await loadDirectory(path);
      setEditorPath(editorPath);
      setShowEditor(true);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to save file"); }
    finally { setBusy(false); }
  }

  async function downloadFile(filePath: string) {
    setBusy(true); setError("");
    try {
      const result = await execute("READ_FILE", filePath);
      const downloadBytes = fromBase64(result.contentBase64 ?? "");
      const downloadBuffer = new ArrayBuffer(downloadBytes.byteLength);
      new Uint8Array(downloadBuffer).set(downloadBytes);
      const blob = new Blob([downloadBuffer], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filePath.split("/").pop() || "download";
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to download file"); }
    finally { setBusy(false); }
  }

  async function createFolder() {
    const name = window.prompt("New folder name");
    if (!name) return;
    setBusy(true); setError(""); setNotice("");
    try {
      await execute("CREATE_DIRECTORY", path ? path + "/" + name : name);
      setNotice("Folder created.");
      await loadDirectory(path);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to create folder"); }
    finally { setBusy(false); }
  }

  async function createEmptyFile() {
    const name = window.prompt("New file name");
    if (!name) return;
    setBusy(true); setError(""); setNotice("");
    try {
      await execute("WRITE_FILE", path ? path + "/" + name : name, { contentBase64: "" });
      setNotice("File created.");
      await loadDirectory(path);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to create file"); }
    finally { setBusy(false); }
  }

  async function renameEntry(entry: FileEntry) {
    const nextName = window.prompt("New name", entry.name);
    if (!nextName || nextName === entry.name) return;
    const source = path ? path + "/" + entry.name : entry.name;
    const destination = path ? path + "/" + nextName : nextName;
    setBusy(true); setError(""); setNotice("");
    try {
      await execute("RENAME_PATH", source, { newPath: destination });
      setNotice("Item renamed.");
      await loadDirectory(path);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to rename item"); }
    finally { setBusy(false); }
  }

  async function deleteEntry(entry: FileEntry) {
    if (!window.confirm("Permanently delete " + entry.name + "?")) return;
    const target = path ? path + "/" + entry.name : entry.name;
    setBusy(true); setError(""); setNotice("");
    try {
      await execute("DELETE_PATH", target);
      setNotice("Item deleted.");
      await loadDirectory(path);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to delete item"); }
    finally { setBusy(false); }
  }

  async function uploadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > 256 * 1024) { setError("Uploads are limited to 256 KiB per file."); return; }
    setBusy(true); setError(""); setNotice("");
    try {
      const contentBase64 = toBase64(new Uint8Array(await file.arrayBuffer()));
      const target = path ? path + "/" + file.name : file.name;
      await execute("WRITE_FILE", target, { contentBase64 });
      setNotice("File uploaded.");
      await loadDirectory(path);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to upload file"); }
    finally { setBusy(false); }
  }

  return <main className="min-h-screen bg-slate-50 text-slate-900">
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-5 py-4">
        <div className="flex items-center gap-3">
          <Link href="/" aria-label="Back to overview" className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"><ArrowLeft size={17}/></Link>
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Folder size={20}/></span>
          <div><p className="font-semibold">File Manager</p><p className="text-xs text-slate-500">Nexora Control / Websites</p></div>
        </div>
        <button onClick={() => void refresh()} disabled={!accountId || busy} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 disabled:opacity-50"><RefreshCw size={15}/> Refresh</button>
      </div>
    </header>

    <section className="mx-auto max-w-7xl space-y-5 px-5 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div><p className="text-sm font-medium text-blue-700">Website files</p><h1 className="mt-1 text-2xl font-semibold tracking-tight">Manage website files</h1><p className="mt-2 max-w-2xl text-sm text-slate-500">Browse, upload, edit and organize files inside a hosting account&apos;s public_html directory.</p></div>
        <label className="text-xs font-medium text-slate-600">Hosting account
          <select value={accountId} onChange={e => setAccountId(e.target.value)} className="mt-1.5 block min-w-56 rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm">
            {accounts.map(account => <option key={account.id} value={account.id}>{account.username} · {account.server_hostname}</option>)}
          </select>
        </label>
      </div>

      {error && <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</p>}

      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
          <div className="min-w-0">
            <p className="text-sm font-semibold">{selectedAccount ? selectedAccount.username + " / public_html" : "No active hosting account"}</p>
            <div className="mt-1 flex flex-wrap items-center gap-1 text-xs text-slate-500">
              <button onClick={() => void loadDirectory("")} className="hover:text-blue-700">public_html</button>
              {segments.map((segment, index) => {
                const target = segments.slice(0, index + 1).join("/");
                return <span key={target} className="inline-flex items-center gap-1"><ChevronRight size={12}/><button onClick={() => void loadDirectory(target)} className="hover:text-blue-700">{segment}</button></span>;
              })}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => void createEmptyFile()} disabled={!accountId || busy} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 disabled:opacity-50"><FilePlus2 size={14}/> New file</button>
            <button onClick={() => void createFolder()} disabled={!accountId || busy} className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 disabled:opacity-50"><FolderPlus size={14}/> New folder</button>
            <label className={"inline-flex cursor-pointer items-center gap-2 rounded-lg bg-blue-700 px-3 py-2 text-xs font-semibold text-white " + (!accountId || busy ? "pointer-events-none opacity-50" : "")}><Upload size={14}/> Upload<input type="file" className="hidden" onChange={uploadFile} disabled={!accountId || busy}/></label>
          </div>
        </div>

        {showEditor && <div className="border-b border-slate-200 bg-slate-50 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><div><p className="text-sm font-semibold">Editing {editorPath}</p><p className="text-xs text-slate-500">Text editor · maximum 256 KiB</p></div><div className="flex gap-2"><button onClick={() => void saveFile()} disabled={busy} className="inline-flex items-center gap-2 rounded-lg bg-blue-700 px-3 py-2 text-xs font-semibold text-white disabled:opacity-50"><Save size={14}/> Save</button><button onClick={() => setShowEditor(false)} className="rounded-lg border border-slate-200 p-2 text-slate-600"><X size={14}/></button></div></div>
          <textarea value={editorContent} onChange={e => setEditorContent(e.target.value)} spellCheck={false} className="min-h-72 w-full rounded-xl border border-slate-200 bg-white p-4 font-mono text-xs leading-5 text-slate-800 outline-none focus:border-blue-500"/>
        </div>}

        {loading ? <div className="p-12 text-center text-sm text-slate-500">Connecting to the hosting server…</div> :
          !selectedAccount ? <div className="p-12 text-center"><Folder size={32} className="mx-auto text-slate-300"/><h3 className="mt-3 font-medium">No active hosting accounts</h3><p className="mt-1 text-sm text-slate-500">Provision a hosting account before managing website files.</p></div> :
          <div className="overflow-x-auto">
            <table className="w-full min-w-[650px] text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3 font-medium">Name</th><th className="px-5 py-3 font-medium">Size</th><th className="px-5 py-3 font-medium">Modified</th><th className="px-5 py-3 text-right font-medium">Actions</th></tr></thead>
              <tbody className="divide-y divide-slate-100">
                {path && <tr><td colSpan={4} className="px-5 py-3"><button onClick={() => void loadDirectory(parentPath)} className="text-xs font-medium text-blue-700 hover:underline">.. Parent directory</button></td></tr>}
                {entries.map(entry => {
                  const itemPath = path ? path + "/" + entry.name : entry.name;
                  return <tr key={itemPath} className="hover:bg-slate-50/70">
                    <td className="px-5 py-3"><button onClick={() => entry.isDir ? void loadDirectory(itemPath) : void openFile(itemPath)} className="inline-flex items-center gap-2 font-medium text-slate-800 hover:text-blue-700">{entry.isDir ? <Folder size={16} className="text-amber-500"/> : <File size={16} className="text-slate-400"/>}{entry.name}</button></td>
                    <td className="px-5 py-3 text-xs text-slate-500">{entry.isDir ? "—" : bytesLabel(entry.size)}</td>
                    <td className="px-5 py-3 text-xs text-slate-500">{new Date(entry.modifiedAt).toLocaleString()}</td>
                    <td className="px-5 py-3"><div className="flex justify-end gap-1">
                      {!entry.isDir && <button title="Download" onClick={() => void downloadFile(itemPath)} disabled={busy} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"><Download size={15}/></button>}
                      <button title="Rename" onClick={() => void renameEntry(entry)} disabled={busy} className="rounded-lg px-2 py-1 text-xs text-slate-600 hover:bg-slate-100">Rename</button>
                      <button title="Delete" onClick={() => void deleteEntry(entry)} disabled={busy} className="rounded-lg p-2 text-slate-500 hover:bg-red-50 hover:text-red-600"><Trash2 size={15}/></button>
                    </div></td>
                  </tr>;
                })}
                {!entries.length && <tr><td colSpan={4} className="px-5 py-12 text-center text-sm text-slate-500">This directory is empty.</td></tr>}
              </tbody>
            </table>
          </div>}
        {busy && <div className="border-t border-slate-100 px-5 py-3 text-xs text-blue-700">Waiting for the connected Linux agent…</div>}
      </section>
      <p className="text-xs leading-5 text-slate-400">Security boundary: operations are restricted to the selected account&apos;s public_html directory. Symlinks are excluded, and individual file transfers are limited to 256 KiB in this initial version.</p>
    </section>
  </main>;
}

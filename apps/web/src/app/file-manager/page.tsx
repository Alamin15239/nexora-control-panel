"use client";

import { ChangeEvent, useCallback, useEffect, useMemo, useState } from "react";
import { ChevronRight, Download, File, FilePlus2, Folder, FolderPlus, RefreshCw, Save, Trash2, Upload, X, Pencil } from "lucide-react";
import {
  EmptyState, InlineAlert, PageHeader, SectionCard, Spinner, StatusBadge,
  TableFrame, Th,
} from "@/components/ui";

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
      const fileBytes = new TextEncoder().encode(editorContent);
      const encoded = toBase64(fileBytes);
      await execute("WRITE_FILE", editorPath, { contentBase64: encoded });
      const savedAt = new Date().toISOString();
      setEntries(current => current.map(entry =>
        (path ? path + "/" : "") + entry.name === editorPath
          ? { ...entry, size: fileBytes.byteLength, modifiedAt: savedAt }
          : entry
      ));
      setNotice("File saved successfully.");
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

  return (
    <main className="mx-auto max-w-[1400px] px-5 py-8 lg:px-9">
      <PageHeader
        eyebrow="Hosting services · Website files"
        title="File Manager"
        description="Browse, upload, edit and organize files inside a hosting account's public_html directory."
        actions={
          <>
            <label className="text-xs font-semibold text-slate-500">
              <span className="sr-only">Hosting account</span>
              <select aria-label="Hosting account" value={accountId} onChange={e => setAccountId(e.target.value)} className="nx-select min-w-56">
                {accounts.length === 0 && <option value="">No active accounts</option>}
                {accounts.map(account => <option key={account.id} value={account.id}>{account.username} · {account.server_hostname}</option>)}
              </select>
            </label>
            <button onClick={() => void refresh()} disabled={!accountId || busy} className="nx-btn-secondary"><RefreshCw size={15} /> Refresh</button>
          </>
        }
      />

      {error && <InlineAlert tone="error" onDismiss={() => setError("")} className="mt-6">{error}</InlineAlert>}
      {notice && <InlineAlert tone="success" onDismiss={() => setNotice("")} className="mt-6">{notice}</InlineAlert>}

      <SectionCard
        className="mt-6"
        flush
        title={selectedAccount ? selectedAccount.username + " / public_html" : "No active hosting account"}
        description={selectedAccount ? "Operations run as queued jobs on the connected Linux agent" : undefined}
        actions={
          <div className="flex flex-wrap gap-2">
            <button onClick={() => void createEmptyFile()} disabled={!accountId || busy} className="nx-btn-secondary nx-btn-sm"><FilePlus2 size={14} /> New file</button>
            <button onClick={() => void createFolder()} disabled={!accountId || busy} className="nx-btn-secondary nx-btn-sm"><FolderPlus size={14} /> New folder</button>
            <label className={"nx-btn-primary nx-btn-sm cursor-pointer " + (!accountId || busy ? "pointer-events-none opacity-50" : "")}>
              <Upload size={14} /> Upload
              <input type="file" className="hidden" onChange={uploadFile} disabled={!accountId || busy} aria-label="Upload file" />
            </label>
          </div>
        }
      >
        <div className="border-b border-slate-100 bg-slate-50/60 px-5 py-3 sm:px-6">
          <nav className="flex flex-wrap items-center gap-1 text-xs text-slate-500" aria-label="Directory path">
            <button onClick={() => void loadDirectory("")} className="rounded px-1.5 py-0.5 font-semibold text-slate-700 transition hover:bg-slate-200/60 hover:text-brand-700">public_html</button>
            {segments.map((segment, index) => {
              const target = segments.slice(0, index + 1).join("/");
              return (
                <span key={target} className="inline-flex items-center gap-1">
                  <ChevronRight size={12} className="text-slate-300" />
                  <button onClick={() => void loadDirectory(target)} className="rounded px-1.5 py-0.5 transition hover:bg-slate-200/60 hover:text-brand-700">{segment}</button>
                </span>
              );
            })}
          </nav>
        </div>

        {showEditor && (
          <div className="border-b border-slate-200 bg-slate-900 p-4 sm:p-5">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate font-mono text-xs font-semibold text-slate-100">Editing {editorPath}</p>
                <p className="mt-0.5 text-[11px] text-slate-400">Text editor · maximum 256 KiB per file</p>
              </div>
              <div className="flex gap-2">
                <button onClick={() => void saveFile()} disabled={busy} className="nx-btn-primary nx-btn-sm"><Save size={14} /> Save</button>
                <button onClick={() => setShowEditor(false)} aria-label="Close editor" className="rounded-lg border border-white/15 p-2 text-slate-300 transition hover:bg-white/10"><X size={14} /></button>
              </div>
            </div>
            <textarea value={editorContent} onChange={e => setEditorContent(e.target.value)} spellCheck={false} aria-label="File content editor"
              className="min-h-72 w-full rounded-xl border border-white/10 bg-navy-950 p-4 font-mono text-xs leading-5 text-slate-100 outline-none focus:border-brand-400 focus:ring-4 focus:ring-brand-500/20" />
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center gap-3 py-14 text-sm text-slate-500"><Spinner /> Connecting to the hosting server…</div>
        ) : !selectedAccount ? (
          <EmptyState icon={Folder} title="No active hosting accounts" description="Provision a hosting account before managing website files." />
        ) : (
          <TableFrame minWidth={640} head={<tr><Th>Name</Th><Th>Size</Th><Th>Modified</Th><Th right>Actions</Th></tr>}>
            {path && (
              <tr className="hover:bg-slate-50/70">
                <td colSpan={4} className="px-5 py-2.5">
                  <button onClick={() => void loadDirectory(parentPath)} className="text-xs font-semibold text-brand-600 hover:underline">.. Parent directory</button>
                </td>
              </tr>
            )}
            {entries.map(entry => {
              const itemPath = path ? path + "/" + entry.name : entry.name;
              return (
                <tr key={itemPath} className="transition hover:bg-slate-50/70">
                  <td className="px-5 py-3">
                    <button onClick={() => entry.isDir ? void loadDirectory(itemPath) : void openFile(itemPath)} className="inline-flex items-center gap-2.5 font-medium text-slate-800 transition hover:text-brand-700">
                      {entry.isDir
                        ? <Folder size={16} className="shrink-0 text-amber-500" />
                        : <File size={16} className="shrink-0 text-slate-400" />}
                      {entry.name}
                    </button>
                  </td>
                  <td className="px-5 py-3 text-xs tabular-nums text-slate-500">{entry.isDir ? "—" : bytesLabel(entry.size)}</td>
                  <td className="px-5 py-3 text-xs text-slate-500">{new Date(entry.modifiedAt).toLocaleString()}</td>
                  <td className="px-5 py-3">
                    <div className="flex justify-end gap-1.5">
                      {!entry.isDir && <button title="Download" aria-label={`Download ${entry.name}`} onClick={() => void downloadFile(itemPath)} disabled={busy} className="rounded-lg p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-800 disabled:opacity-40"><Download size={15} /></button>}
                      <button title="Rename" aria-label={`Rename ${entry.name}`} onClick={() => void renameEntry(entry)} disabled={busy} className="rounded-lg p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-800 disabled:opacity-40"><Pencil size={14} /></button>
                      <button title="Delete" aria-label={`Delete ${entry.name}`} onClick={() => void deleteEntry(entry)} disabled={busy} className="rounded-lg p-2 text-slate-500 transition hover:bg-rose-50 hover:text-rose-600 disabled:opacity-40"><Trash2 size={15} /></button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {!entries.length && (
              <tr><td colSpan={4}><EmptyState icon={Folder} title="This directory is empty" description="Upload a file or create a new folder to get started." /></td></tr>
            )}
          </TableFrame>
        )}
        {busy && (
          <div className="flex items-center gap-2.5 border-t border-slate-100 px-5 py-3 text-xs text-slate-500 sm:px-6">
            <Spinner className="h-3.5 w-3.5" /> Waiting for the connected Linux agent…
          </div>
        )}
      </SectionCard>

      <p className="mt-5 flex items-start gap-2 text-xs leading-5 text-slate-400">
        <StatusBadge tone="neutral">Security boundary</StatusBadge>
        <span>Operations are restricted to the selected account&apos;s public_html directory. Symlinks are excluded, and individual file transfers are limited to 256 KiB in this initial version.</span>
      </p>
    </main>
  );
}

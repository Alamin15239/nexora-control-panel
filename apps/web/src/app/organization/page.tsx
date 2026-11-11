"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Building2, CheckCircle2, Plus, ShieldCheck, Trash2, Users, X } from "lucide-react";

type Organization = {
  id: string; name: string; slug: string; status: string; createdAt: string;
  hostingAccountCount: number; activeHostingAccountCount: number;
};
type OrgMember = { userId: string; email: string; displayName: string | null; userStatus: string; role: string; memberSince: string };
type AuditEvent = { id: string; action: string; resourceType: string; resourceId: string | null; metadata: string | null; createdAt: string; actorEmail: string | null };

const ORG_ROLES = ["OWNER", "ADMIN", "BILLING", "SUPPORT", "MEMBER"];

export default function OrganizationAdminPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [owners, setOwners] = useState(0);
  const [admins, setAdmins] = useState(0);
  const [detail, setDetail] = useState<Organization | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState("MEMBER");
  const [removeMember, setRemoveMember] = useState<OrgMember | null>(null);
  const [closeOrgOpen, setCloseOrgOpen] = useState(false);
  const [orgName, setOrgName] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadOrganizations = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/control/organizations?scope=all", { cache: "no-store" });
      const data = await response.json();
      if (response.status === 401) return;
      if (!response.ok) throw new Error(data.message || "Unable to load organizations.");
      const list = (data.organizations ?? []) as Organization[];
      setOrganizations(list);
      setSelectedId(current => list.some(org => org.id === current) ? current : list[0]?.id ?? "");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load organizations.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadOrganizations(); }, [loadOrganizations]);

  const loadDetail = useCallback(async () => {
    if (!selectedId) { setDetail(null); setMembers([]); setAuditEvents([]); return; }
    setError("");
    try {
      const [detailResponse, auditResponse] = await Promise.all([
        fetch(`/api/control/organizations/${encodeURIComponent(selectedId)}`, { cache: "no-store" }),
        fetch(`/api/control/organizations/${encodeURIComponent(selectedId)}/audit-logs?limit=30`, { cache: "no-store" }),
      ]);
      const detailData = await detailResponse.json();
      if (!detailResponse.ok) throw new Error(detailData.message || "Unable to load the organization.");
      setDetail(detailData.organization as Organization);
      setMembers((detailData.members ?? []) as OrgMember[]);
      setOwners(Number(detailData.owners ?? 0));
      setAdmins(Number(detailData.admins ?? 0));
      if (auditResponse.ok) {
        const auditData = await auditResponse.json();
        setAuditEvents((auditData.events ?? []) as AuditEvent[]);
      } else {
        setAuditEvents([]);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load the organization.");
    }
  }, [selectedId]);

  useEffect(() => { void loadDetail(); }, [loadDetail]);

  async function renameOrganization() {
    if (!detail || !orgName.trim()) return;
    setSubmitting(true);
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/organizations/${encodeURIComponent(detail.id)}`, {
        method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: orgName.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to rename the organization.");
      setNotice("Organization renamed.");
      setOrgName("");
      await Promise.all([loadOrganizations(), loadDetail()]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to rename the organization.");
    } finally { setSubmitting(false); }
  }

  async function submitAddMember() {
    if (!detail || !memberEmail.trim()) return;
    setSubmitting(true);
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/organizations/${encodeURIComponent(detail.id)}/members`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: memberEmail.trim().toLowerCase(), role: memberRole }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to add the member.");
      setAddOpen(false);
      setMemberEmail("");
      setMemberRole("MEMBER");
      setNotice(`Member added with the ${memberRole} role.`);
      await loadDetail();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to add the member.");
    } finally { setSubmitting(false); }
  }

  async function changeRole(member: OrgMember, role: string) {
    if (!detail) return;
    setSubmitting(true);
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/organizations/${encodeURIComponent(detail.id)}/members/${encodeURIComponent(member.userId)}`, {
        method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ role }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to change the role.");
      setNotice(`${member.email} is now ${role}.`);
      await loadDetail();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to change the role.");
    } finally { setSubmitting(false); }
  }

  async function submitRemoveMember() {
    if (!removeMember || !detail) return;
    setSubmitting(true);
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/organizations/${encodeURIComponent(detail.id)}/members/${encodeURIComponent(removeMember.userId)}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to remove the member.");
      setRemoveMember(null);
      setNotice(String(data.message || "Membership revoked."));
      await loadDetail();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to remove the member.");
    } finally { setSubmitting(false); }
  }

  async function submitCloseOrganization() {
    if (!detail) return;
    setSubmitting(true);
    setError(""); setNotice("");
    try {
      const response = await fetch(`/api/control/organizations/${encodeURIComponent(detail.id)}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Unable to close the organization.");
      setCloseOrgOpen(false);
      setNotice(String(data.message || "Organization closed."));
      await Promise.all([loadOrganizations(), loadDetail()]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to close the organization.");
    } finally { setSubmitting(false); }
  }

  if (loading) {
    return <main className="grid min-h-screen place-items-center"><div className="h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-blue-700" /></main>;
  }

  return <main className="mx-auto max-w-[1200px] px-5 py-8 sm:px-8">
    <div><p className="text-xs font-semibold uppercase tracking-[.18em] text-blue-700">WHM · Organizations</p><h1 className="mt-2 text-3xl font-bold tracking-tight">Organization administration</h1><p className="mt-2 text-sm text-slate-500">Workspaces, members, roles, and the audited lifecycle of every organization on the platform.</p></div>

    {error && <div role="alert" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><span className="flex items-start gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{error}</span><button onClick={() => setError("")} aria-label="Dismiss error" className="text-rose-400 hover:text-rose-600"><X size={15} /></button></div>}
    {notice && <div role="status" className="mt-6 flex items-start justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"><span className="flex items-start gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0" />{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message" className="text-emerald-400 hover:text-emerald-600"><X size={15} /></button></div>}

    {!organizations.length ? <div className="mt-8 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-16 text-center">
      <span className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-blue-50 text-blue-700"><Building2 size={25} /></span>
      <h2 className="mt-5 text-lg font-semibold">No organizations yet</h2>
      <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">Organizations are created when customers register. Once the first signup exists, its workspace appears here.</p>
    </div> : <>
      <div className="mt-7 flex flex-wrap items-center gap-3">
        <label className="relative flex max-w-xs items-center">
          <select aria-label="Select organization" value={selectedId} onChange={event => setSelectedId(event.target.value)} className="w-full appearance-none rounded-xl border border-slate-200 bg-white px-3 py-2.5 pr-9 text-xs font-semibold text-slate-700 outline-none focus:border-blue-400">
            {organizations.map(org => <option key={org.id} value={org.id}>{org.name} ({org.status})</option>)}
          </select>
        </label>
        {detail && <span className="rounded-full bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600">{detail.activeHostingAccountCount} active / {detail.hostingAccountCount} hosting accounts</span>}
      </div>

      {detail && <div className="mt-6 grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
            <div><h2 className="font-semibold">Members</h2><p className="mt-1 text-xs text-slate-500">{owners} owner(s) · {admins} administrator(s). The last owner and the last administrator are protected.</p></div>
            <button onClick={() => { setAddOpen(true); setError(""); }} className="inline-flex items-center gap-1.5 rounded-xl bg-blue-700 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-800"><Plus size={14} /> Add member</button>
          </div>
          {members.length === 0 ? <p className="p-5 text-xs text-slate-400">This organization has no members.</p> : <div className="divide-y divide-slate-100">
            {members.map(member => <div key={member.userId} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
              <div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-800">{member.email}</p><p className="mt-0.5 text-[11px] text-slate-400">{member.displayName || "—"} · member since {new Date(member.memberSince).toLocaleDateString()}</p></div>
              <div className="flex items-center gap-2">
                <select aria-label={`Role for ${member.email}`} value={member.role} onChange={event => void changeRole(member, event.target.value)} disabled={submitting} className="rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-[11px] font-semibold text-slate-700 outline-none focus:border-blue-400 disabled:opacity-50">
                  {ORG_ROLES.map(role => <option key={role} value={role}>{role}</option>)}
                </select>
                <button onClick={() => setRemoveMember(member)} className="inline-flex items-center gap-1 rounded-lg border border-rose-200 px-2 py-1.5 text-[10px] font-semibold text-rose-600 hover:bg-rose-50"><Trash2 size={12} /> Remove</button>
              </div>
            </div>)}
          </div>}
        </section>

        <div className="space-y-5">
          <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="font-semibold">Workspace</h2>
            <dl className="mt-4 space-y-3 text-sm">
              <div className="flex items-center justify-between gap-3"><dt className="text-xs text-slate-500">Name</dt><dd className="font-semibold">{detail.name}</dd></div>
              <div className="flex items-center justify-between gap-3"><dt className="text-xs text-slate-500">Slug</dt><dd className="font-mono text-xs">{detail.slug}</dd></div>
              <div className="flex items-center justify-between gap-3"><dt className="text-xs text-slate-500">Status</dt><dd><span className={"rounded-full px-2.5 py-1 text-[10px] font-semibold " + (detail.status === "ACTIVE" ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700")}>{detail.status}</span></dd></div>
              <div className="flex items-center justify-between gap-3"><dt className="text-xs text-slate-500">Created</dt><dd className="text-xs">{new Date(detail.createdAt).toLocaleString()}</dd></div>
            </dl>
            <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">Rename organization</span>
              <div className="mt-1.5 flex gap-2">
                <input value={orgName} onChange={event => setOrgName(event.target.value)} placeholder={detail.name} className="w-full rounded-xl border border-slate-200 px-3 py-2 text-xs outline-none focus:border-blue-400" />
                <button onClick={() => void renameOrganization()} disabled={submitting || !orgName.trim()} className="rounded-xl bg-slate-900 px-3 py-2 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50">Save</button>
              </div>
            </label>
          </section>

          <section className="rounded-2xl border border-rose-100 bg-rose-50/60 p-5">
            <div className="flex items-center gap-2 text-sm font-semibold text-rose-800"><ShieldCheck size={15} /> Close organization</div>
            <p className="mt-2 text-[11px] leading-5 text-rose-700">Closing revokes every member session and blocks sign-in. It is refused while hosting accounts, open payment orders, or live subscriptions exist. History is preserved.</p>
            <button onClick={() => setCloseOrgOpen(true)} disabled={submitting} className="mt-3 inline-flex items-center gap-1.5 rounded-xl bg-rose-600 px-3 py-2 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50"><Trash2 size={13} /> Close organization</button>
          </section>
        </div>
      </div>}

      <section className="mt-6 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4"><div><h2 className="font-semibold">Organization audit history</h2><p className="mt-1 text-xs text-slate-500">Most recent 30 audited events for the selected organization</p></div><Users size={16} className="text-slate-300" /></div>
        {auditEvents.length === 0 ? <p className="p-5 text-xs text-slate-400">No audited events recorded yet.</p> : <div className="divide-y divide-slate-100">
          {auditEvents.map(event => <div key={event.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
            <div className="min-w-0"><p className="text-xs font-semibold text-slate-800">{event.action}</p><p className="mt-0.5 truncate text-[11px] text-slate-400">{event.actorEmail || "system"} · {event.resourceType}{event.resourceId ? ` · ${event.resourceId.slice(0, 13)}…` : ""}</p></div>
            <span className="text-[11px] text-slate-400">{new Date(event.createdAt).toLocaleString()}</span>
          </div>)}
        </div>}
      </section>
    </>}

    {addOpen && detail && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Add member">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between"><div><h3 className="text-lg font-semibold">Add member to {detail.name}</h3><p className="mt-1 text-xs leading-5 text-slate-500">The user must already have an active Nexora login. Only owners can grant the OWNER role.</p></div><button onClick={() => setAddOpen(false)} aria-label="Close" className="text-slate-400 hover:text-slate-600"><X size={17} /></button></div>
        <label className="mt-5 block"><span className="text-xs font-semibold text-slate-700">User email</span>
          <input value={memberEmail} onChange={event => setMemberEmail(event.target.value)} placeholder="user@example.test" autoFocus className="mt-1.5 w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm outline-none focus:border-blue-400" />
        </label>
        <label className="mt-4 block"><span className="text-xs font-semibold text-slate-700">Organization role</span>
          <select value={memberRole} onChange={event => setMemberRole(event.target.value)} className="mt-1.5 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none focus:border-blue-400">
            {ORG_ROLES.map(role => <option key={role} value={role}>{role}</option>)}
          </select>
        </label>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setAddOpen(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitAddMember()} disabled={submitting || !memberEmail.trim()} className="rounded-xl bg-blue-700 px-4 py-2.5 text-xs font-semibold text-white hover:bg-blue-800 disabled:opacity-50">{submitting ? "Adding…" : "Add member"}</button></div>
      </div>
    </div>}

    {removeMember && detail && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Remove member">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-rose-50 text-rose-600"><AlertTriangle size={18} /></span><div><h3 className="text-lg font-semibold">Remove {removeMember.email}?</h3><p className="mt-1 text-xs leading-5 text-slate-500">The membership is revoked immediately and the member&apos;s sessions for this organization are invalidated. The last owner or administrator cannot be removed.</p></div></div>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setRemoveMember(null)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitRemoveMember()} disabled={submitting} className="rounded-xl bg-rose-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50">{submitting ? "Removing…" : "Remove member"}</button></div>
      </div>
    </div>}

    {closeOrgOpen && detail && <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/40 p-4" role="dialog" aria-modal="true" aria-label="Close organization">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-rose-50 text-rose-600"><AlertTriangle size={18} /></span><div><h3 className="text-lg font-semibold">Close {detail.name}?</h3><p className="mt-1 text-xs leading-5 text-slate-500">All member sessions are revoked and the workspace is closed. This is refused while hosting accounts, open payment orders, or live subscriptions exist. The action is audited.</p></div></div>
        <div className="mt-6 flex justify-end gap-2"><button onClick={() => setCloseOrgOpen(false)} className="rounded-xl border border-slate-200 px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-slate-50">Cancel</button><button onClick={() => void submitCloseOrganization()} disabled={submitting} className="rounded-xl bg-rose-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50">{submitting ? "Closing…" : "Close organization"}</button></div>
      </div>
    </div>}
  </main>;
}

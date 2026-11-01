"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, ArrowUpRight, Box, Cloud, Cpu, Database, Globe2, HardDrive, LayoutDashboard, LockKeyhole, Mail, Network, Plus, Server, Settings2, ShieldCheck, Users, Zap } from "lucide-react";

const nav = [
  { label: "Overview", icon: LayoutDashboard, active: true },
  { label: "Servers", icon: Server },
  { label: "Hosting accounts", icon: Users },
  { label: "Websites & domains", icon: Globe2 },
  { label: "Databases", icon: Database },
  { label: "Email", icon: Mail },
  { label: "DNS management", icon: Network },
  { label: "Backups", icon: HardDrive },
];

function Metric({ label, value, note, icon: Icon }: { label: string; value: string; note: string; icon: typeof Server }) {
  return <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex items-center justify-between"><p className="text-sm text-slate-500">{label}</p><span className="rounded-xl bg-slate-50 p-2 text-slate-600"><Icon size={18}/></span></div><p className="mt-4 text-3xl font-semibold tracking-tight text-slate-900">{value}</p><p className="mt-1 text-xs text-slate-500">{note}</p></div>;
}

export default function Home() {
  const router = useRouter();
  const [identity, setIdentity] = useState<{ displayName: string | null; email: string } | null>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let active = true;
    fetch("/api/auth/me", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Not signed in");
        return response.json();
      })
      .then((user) => { if (active) setIdentity(user); })
      .catch(() => { if (active) router.replace("/login"); })
      .finally(() => { if (active) setChecking(false); });
    return () => { active = false; };
  }, [router]);

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

  if (checking || !identity) return <main className="grid min-h-screen place-items-center bg-slate-50"><div className="text-center"><div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-slate-200 border-t-blue-700"/><p className="mt-4 text-sm text-slate-500">Securing your workspace…</p></div></main>;

  return <main className="min-h-screen lg:flex">
    <aside className="w-full border-b border-slate-200 bg-white px-5 py-5 lg:fixed lg:inset-y-0 lg:w-64 lg:border-b-0 lg:border-r">
      <div className="flex items-center gap-3 px-2"><div className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><Cloud size={21}/></div><div><p className="font-semibold tracking-tight">Nexora <span className="text-blue-700">Control</span></p><p className="text-xs text-slate-500">Infrastructure platform</p></div></div>
      <p className="mt-9 hidden px-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400 lg:block">Workspace</p>
      <nav className="mt-3 grid grid-cols-2 gap-1 sm:grid-cols-4 lg:grid-cols-1">{nav.map(({label, icon: Icon, active}) => <a key={label} href="#" className={"flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition " + (active ? "bg-blue-50 font-medium text-blue-700" : "text-slate-600 hover:bg-slate-50")}><Icon size={17}/>{label}</a>)}</nav>
      <p className="mt-8 hidden px-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400 lg:block">System</p>
      <div className="mt-3 hidden space-y-1 lg:block"><a className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-600 hover:bg-slate-50" href="#"><LockKeyhole size={17}/> Access & security</a><a className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-600 hover:bg-slate-50" href="#"><Settings2 size={17}/> Settings</a></div>
      <div className="mt-10 hidden rounded-2xl bg-slate-50 p-4 lg:block"><div className="flex items-center gap-2 text-sm font-medium"><ShieldCheck size={16} className="text-emerald-600"/> Secure by design</div><p className="mt-2 text-xs leading-5 text-slate-500">Privileged operations will use authenticated agents and explicit operation policies.</p></div>
    </aside>
    <section className="min-w-0 flex-1 lg:ml-64">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 bg-white px-6 py-4 lg:px-9"><div><p className="text-xs text-slate-500">Control plane / Workspace</p><h1 className="mt-1 text-lg font-semibold">Overview</h1></div><div className="flex items-center gap-3"><span className="hidden rounded-full border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-800 sm:inline-flex">Development environment</span><span className="max-w-40 truncate text-xs text-slate-600">{identity.displayName || identity.email}</span><button onClick={signOut} className="rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-600 hover:bg-slate-50">Sign out</button></div></header>
      <div className="mx-auto max-w-7xl space-y-7 px-5 py-8 lg:px-9">
        <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-blue-700">Welcome to Nexora Control</p><h2 className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">Your hosting infrastructure, in one place.</h2><p className="mt-2 max-w-2xl text-sm text-slate-500">A unified control plane for servers, websites, databases and customers. Connect your first Linux node to begin.</p></div><button className="inline-flex items-center gap-2 rounded-xl bg-blue-700 px-4 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-blue-800"><Plus size={16}/> Register server</button></div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"><Metric label="Managed servers" value="0" note="No server agents connected" icon={Server}/><Metric label="Hosting accounts" value="0" note="Provisioned customer accounts" icon={Users}/><Metric label="Websites" value="0" note="Managed virtual hosts" icon={Globe2}/><Metric label="System status" value="Setup" note="Awaiting infrastructure setup" icon={Activity}/></div>
        <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex items-center justify-between"><div><h3 className="font-semibold">Infrastructure readiness</h3><p className="mt-1 text-xs text-slate-500">Initial setup checklist</p></div><span className="rounded-lg bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700">0 / 4 complete</span></div><div className="mt-6 h-2 overflow-hidden rounded-full bg-slate-100"><div className="h-full w-0 rounded-full bg-blue-600"/></div><div className="mt-5 space-y-4">{["Deploy the control-plane API", "Configure the PostgreSQL database", "Install the Linux server agent", "Connect and verify your first server"].map((item, i) => <div key={item} className="flex items-center gap-3"><span className="grid h-7 w-7 place-items-center rounded-full border border-slate-200 text-xs text-slate-500">{i+1}</span><span className="text-sm text-slate-700">{item}</span><span className="ml-auto text-xs text-slate-400">Pending</span></div>)}</div></div>
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex items-center gap-2"><Zap size={17} className="text-amber-500"/><h3 className="font-semibold">Next actions</h3></div><div className="mt-4 space-y-3">{[{title:"Register a server",desc:"Connect a Linux node to the control plane",icon:Server},{title:"Create a hosting plan",desc:"Define storage, websites and resource limits",icon:Box},{title:"Review security",desc:"Configure access policies and audit events",icon:ShieldCheck},{title:"Monitor capacity",desc:"Prepare CPU, memory and disk telemetry",icon:Cpu}].map(({title,desc,icon: Icon}) => <div key={title} className="flex items-center gap-3 rounded-xl border border-slate-100 p-3"><span className="rounded-lg bg-slate-100 p-2 text-slate-700"><Icon size={17}/></span><span className="min-w-0 flex-1"><span className="block text-sm font-medium text-slate-800">{title}</span><span className="mt-0.5 block text-xs text-slate-500">{desc}</span></span><ArrowUpRight size={15} className="text-slate-400"/></div>)}</div></div>
        </div>
        <div className="rounded-2xl border border-blue-100 bg-blue-50/70 p-5"><div className="flex gap-3"><div className="rounded-xl bg-white p-2 text-blue-700"><ShieldCheck size={19}/></div><div><h3 className="text-sm font-semibold text-slate-900">Control-plane foundation</h3><p className="mt-1 max-w-4xl text-sm leading-6 text-slate-600">This initial interface is a development shell. Metrics are placeholders until the API and authenticated server agents are connected. No server changes are performed from this screen yet.</p></div></div></div>
        <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 pt-5 text-xs text-slate-400"><span>Nexora Control · Private development</span><span>Infrastructure management platform</span></footer>
      </div>
    </section>
  </main>;
}

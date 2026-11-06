"use client";
import { useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, ArrowLeftFromLine, ArrowRightFromLine, Box, ChevronDown, Cloud, Database, FolderOpen, Globe2, HardDrive, LayoutDashboard, LockKeyhole, Mail, Menu, Network, Server, Settings2, ShieldCheck, Users, X, Github } from "lucide-react";
const workspaceLinks = [
  {label:"Overview",href:"/",icon:LayoutDashboard},{label:"Servers",href:"/servers",icon:Server},{label:"Hosting plans",href:"/hosting-plans",icon:Box},{label:"Hosting accounts",href:"/hosting-accounts",icon:Users},{label:"File Manager",href:"/file-manager",icon:FolderOpen},{label:"Websites & domains",href:"/websites-domains",icon:Globe2},{label:"GitHub deployments",href:"/github-deployments",icon:Github},{label:"Databases",href:"/databases",icon:Database},{label:"Email",href:"/email",icon:Mail},{label:"DNS management",href:"/dns",icon:Network},{label:"Backups",href:"/backups",icon:HardDrive}
];
const systemLinks = [{label:"Access & security",href:"/security",icon:LockKeyhole},{label:"Settings",href:"/settings",icon:Settings2},{label:"Monitoring",href:"/monitoring",icon:Activity}];
export default function AppShell({children}:{children:ReactNode}) {
 const pathname=usePathname(); const [collapsed,setCollapsed]=useState(false); const [systemOpen,setSystemOpen]=useState(true); const [mobileOpen,setMobileOpen]=useState(false);
 if(pathname==="/login") return <>{children}</>;
 const linkClass=(href:string)=>"group flex items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all "+((href==="/"?pathname==="/":pathname.startsWith(href))?"bg-blue-500/15 text-white ring-1 ring-blue-400/20":"text-slate-400 hover:bg-white/[0.06] hover:text-white");
 return <div className="min-h-screen bg-[#f4f6fb] text-slate-900">
 {mobileOpen&&<button aria-label="Close navigation" onClick={()=>setMobileOpen(false)} className="fixed inset-0 z-40 bg-slate-950/55 backdrop-blur-sm lg:hidden"/>}
 <aside className={"fixed inset-y-0 left-0 z-50 flex flex-col border-r border-white/[0.06] bg-[#101a2d] text-white shadow-2xl transition-all duration-200 "+(mobileOpen?"translate-x-0 ":"-translate-x-full lg:translate-x-0 ")+(collapsed?"w-[272px] lg:w-[76px]":"w-[272px]")}>
  <div className={"flex h-[76px] shrink-0 items-center border-b border-white/[0.07] "+(collapsed?"justify-center px-3":"justify-between px-5")}>
   <Link href="/" onClick={()=>setMobileOpen(false)} className="flex min-w-0 items-center gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 shadow-lg"><Cloud size={21}/></span>{!collapsed&&<span><span className="block text-[15px] font-semibold">Nexora <span className="text-blue-300">Control</span></span><span className="mt-0.5 block text-[10px] uppercase tracking-[.18em] text-slate-500">Infrastructure platform</span></span>}</Link>
   <button aria-label="Close navigation" onClick={()=>setMobileOpen(false)} className="rounded-lg p-2 text-slate-400 hover:bg-white/10 lg:hidden"><X size={18}/></button>
  </div>
  <nav className="min-h-0 flex-1 overflow-y-auto px-3 py-5">
   {!collapsed&&<p className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[.18em] text-slate-500">Workspace</p>}
   <div className="space-y-1">{workspaceLinks.map(({label,href,icon:Icon})=><Link key={href} href={href} title={collapsed?label:undefined} onClick={()=>setMobileOpen(false)} className={linkClass(href)}><Icon size={18} className="shrink-0"/>{!collapsed&&<span className="truncate">{label}</span>}</Link>)}</div>
   <div className="mt-7"><button onClick={()=>setSystemOpen(v=>!v)} aria-expanded={systemOpen} title={collapsed?"System":undefined} className={"flex w-full items-center rounded-xl px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[.18em] text-slate-500 hover:bg-white/[0.05] "+(collapsed?"justify-center":"justify-between")}><span>{collapsed?<Settings2 size={18}/>: "System"}</span>{!collapsed&&<ChevronDown size={14} className={"transition-transform "+(systemOpen?"rotate-180":"")}/>}</button>
   {systemOpen&&<div className="mt-1 space-y-1">{systemLinks.map(({label,href,icon:Icon})=><Link key={href} href={href} title={collapsed?label:undefined} onClick={()=>setMobileOpen(false)} className={linkClass(href)}><Icon size={18} className="shrink-0"/>{!collapsed&&<span>{label}</span>}</Link>)}</div>}</div>
  </nav>
  {!collapsed&&<div className="mx-3 mb-3 rounded-2xl border border-white/[0.07] bg-white/[0.04] p-3.5"><div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><ShieldCheck size={15} className="text-emerald-400"/> Secure by design</div><p className="mt-2 text-[11px] leading-5 text-slate-500">Privileged operations use authenticated agents and explicit policies.</p><div className="mt-3 flex items-center gap-2 text-[10px] font-medium text-emerald-400"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400"/> Control plane connected</div></div>}
  <div className="hidden h-[60px] shrink-0 items-center border-t border-white/[0.07] px-3 lg:flex"><button onClick={()=>setCollapsed(v=>!v)} aria-label={collapsed?"Expand sidebar":"Collapse sidebar"} className="flex w-full items-center justify-center gap-2 rounded-xl px-3 py-2 text-xs text-slate-500 hover:bg-white/[0.06] hover:text-white">{collapsed?<ArrowRightFromLine size={17}/>:<><ArrowLeftFromLine size={17}/><span>Collapse sidebar</span></>}</button></div>
 </aside>
 <div className={"min-h-screen transition-[margin] duration-200 "+(collapsed?"lg:ml-[76px]":"lg:ml-[272px]")}>
  <div className="sticky top-0 z-30 flex h-[58px] items-center gap-3 border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-xl lg:hidden"><button onClick={()=>setMobileOpen(true)} aria-label="Open navigation" className="rounded-xl border border-slate-200 p-2 text-slate-600"><Menu size={18}/></button><span className="text-sm font-semibold">Nexora <span className="text-blue-700">Control</span></span></div>
  {children}
 </div>
 </div>;
}
"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity, ArrowLeftFromLine, ArrowRightFromLine, Box, ChevronDown, Cloud,
  Database, FolderOpen, Globe2, HardDrive, LayoutDashboard, LockKeyhole,
  Mail, Menu, Network, Search, Server, Settings2, ShieldCheck, Users, X, Github,
} from "lucide-react";

const navigation = [
  {
    title: "Home",
    items: [{ label: "Overview", href: "/", icon: LayoutDashboard }],
  },
  {
    title: "Hosting services",
    items: [
      { label: "Websites & domains", href: "/websites-domains", icon: Globe2 },
      { label: "File Manager", href: "/file-manager", icon: FolderOpen },
      { label: "Databases", href: "/databases", icon: Database },
      { label: "Email accounts", href: "/email", icon: Mail },
      { label: "DNS zones", href: "/dns", icon: Network },
      { label: "Backups", href: "/backups", icon: HardDrive },
      { label: "Git deployments", href: "/github-deployments", icon: Github },
    ],
  },
  {
    title: "WHM · Platform administration",
    items: [
      { label: "Servers & nodes", href: "/servers", icon: Server },
      { label: "Hosting packages", href: "/hosting-plans", icon: Box },
      { label: "Customer accounts", href: "/hosting-accounts", icon: Users },
      { label: "Monitoring", href: "/monitoring", icon: Activity },
    ],
  },
  {
    title: "Configuration",
    items: [
      { label: "Security & access", href: "/security", icon: LockKeyhole },
      { label: "Settings", href: "/settings", icon: Settings2 },
    ],
  },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [accessChecking, setAccessChecking] = useState(true);
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    Home: true,
    "Hosting services": true,
    "WHM · Platform administration": true,
    Configuration: true,
  });

  useEffect(() => {
    if (["/login", "/signup", "/forgot-password", "/reset-password"].includes(pathname) || pathname === "/customer" || pathname.startsWith("/customer/")) {
      setAccessChecking(false);
      return;
    }
    let active = true;
    setAccessChecking(true);
    fetch("/api/auth/me", { cache: "no-store" })
      .then(async response => {
        if (!response.ok) throw new Error("Not authenticated");
        return response.json();
      })
      .then(user => {
        if (!active) return;
        if (user.role === "MEMBER" || user.customerAccess) {
          router.replace("/customer");
          return;
        }
        setAccessChecking(false);
      })
      .catch(() => {
        if (active) router.replace("/login");
      });
    return () => { active = false; };
  }, [pathname, router]);

  const filteredNavigation = useMemo(() => {
    const query = search.trim().toLowerCase();
    return navigation.map(group => ({
      ...group,
      items: group.items.filter(item => !query || item.label.toLowerCase().includes(query) || group.title.toLowerCase().includes(query)),
    })).filter(group => group.items.length > 0);
  }, [search]);

  if (["/login", "/signup", "/forgot-password", "/reset-password"].includes(pathname) || pathname === "/customer" || pathname.startsWith("/customer/")) return <>{children}</>;
  if (accessChecking) return <main className="grid min-h-screen place-items-center bg-slate-50"><p className="text-sm text-slate-500">Checking workspace access…</p></main>;

  const isActive = (href: string) => href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
  const activeLabel = navigation.flatMap(group => group.items).find(item => isActive(item.href))?.label ?? "Workspace";
  const linkClass = (active: boolean) =>
    "group flex min-h-10 items-center gap-3 rounded-xl px-3 py-2 text-[13px] font-medium transition-colors " +
    (active
      ? "bg-blue-500/15 text-white ring-1 ring-inset ring-blue-400/20"
      : "text-slate-400 hover:bg-white/[0.06] hover:text-white");

  return (
    <div className="min-h-screen bg-[#f4f6fb] text-slate-900">
      {mobileOpen && <button aria-label="Close navigation" onClick={() => setMobileOpen(false)} className="fixed inset-0 z-40 bg-slate-950/55 backdrop-blur-sm lg:hidden" />}
      <aside className={"fixed inset-y-0 left-0 z-50 flex flex-col border-r border-white/[0.06] bg-[#101a2d] text-white shadow-2xl transition-all duration-200 " +
        (mobileOpen ? "translate-x-0 " : "-translate-x-full lg:translate-x-0 ") +
        (collapsed ? "w-[272px] lg:w-[76px]" : "w-[272px]")}>
        <div className={"flex h-[76px] shrink-0 items-center border-b border-white/[0.07] " + (collapsed ? "justify-center px-3" : "justify-between px-5")}>
          <Link href="/" onClick={() => setMobileOpen(false)} className="flex min-w-0 items-center gap-3">
            <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 shadow-lg"><Cloud size={21} /></span>
            {!collapsed && <span><span className="block text-[15px] font-semibold">Nexora <span className="text-blue-300">Control</span></span><span className="mt-0.5 block text-[10px] uppercase tracking-[.18em] text-slate-500">Hosting control panel</span></span>}
          </Link>
          <button aria-label="Close navigation" onClick={() => setMobileOpen(false)} className="rounded-lg p-2 text-slate-400 hover:bg-white/10 lg:hidden"><X size={18} /></button>
        </div>

        {!collapsed && <div className="mx-3 mt-4 flex items-center gap-2 rounded-xl border border-blue-400/15 bg-blue-500/[0.08] px-3 py-2.5">
          <span className="grid h-7 w-7 place-items-center rounded-lg bg-blue-400/15 text-blue-200"><ShieldCheck size={15} /></span>
          <span className="min-w-0"><span className="block text-[11px] font-semibold text-slate-100">WHM · Administrator</span><span className="block text-[10px] text-slate-500">Platform workspace</span></span>
        </div>}

        <nav className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
          {filteredNavigation.map(group => (
            <section key={group.title} className="mb-5">
              {!collapsed && <button
                onClick={() => setExpanded(value => ({ ...value, [group.title]: !value[group.title] }))}
                aria-expanded={expanded[group.title]}
                className="mb-2 flex w-full items-center justify-between px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-[.16em] text-slate-500 hover:text-slate-300"
              >
                <span>{group.title}</span><ChevronDown size={13} className={"transition-transform " + (expanded[group.title] ? "rotate-180" : "")} />
              </button>}
              {(collapsed || expanded[group.title] || search.trim()) && <div className="space-y-1">
                {group.items.map(({ label, href, icon: Icon }) => (
                  <Link key={href} href={href} title={collapsed ? label : undefined} onClick={() => setMobileOpen(false)} className={linkClass(isActive(href))}>
                    <Icon size={17} className="shrink-0" />{!collapsed && <span className="truncate">{label}</span>}
                    {!collapsed && isActive(href) && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-300" />}
                  </Link>
                ))}
              </div>}
            </section>
          ))}
          {filteredNavigation.every(group => group.items.length === 0) && !collapsed && <p className="px-3 py-5 text-xs text-slate-500">No matching tools.</p>}
        </nav>

        {!collapsed && <div className="mx-3 mb-3 rounded-2xl border border-white/[0.07] bg-white/[0.04] p-3.5">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><ShieldCheck size={15} className="text-emerald-400" /> Secure operations</div>
          <p className="mt-2 text-[11px] leading-5 text-slate-500">Server actions are dispatched through authenticated agents and scoped policies.</p>
          <div className="mt-3 flex items-center gap-2 text-[10px] font-medium text-emerald-400"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Control plane status is monitored</div>
        </div>}
        <div className="hidden h-[60px] shrink-0 items-center border-t border-white/[0.07] px-3 lg:flex">
          <button onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} className="flex w-full items-center justify-center gap-2 rounded-xl px-3 py-2 text-xs text-slate-500 hover:bg-white/[0.06] hover:text-white">
            {collapsed ? <ArrowRightFromLine size={17} /> : <><ArrowLeftFromLine size={17} /><span>Collapse navigation</span></>}
          </button>
        </div>
      </aside>

      <div className={"min-h-screen transition-[margin] duration-200 " + (collapsed ? "lg:ml-[76px]" : "lg:ml-[272px]")}>
        <header className="sticky top-0 z-30 hidden h-[66px] items-center justify-between border-b border-slate-200/80 bg-white/90 px-7 backdrop-blur-xl lg:flex">
          <div className="flex items-center gap-3 text-sm"><span className="text-slate-400">Nexora</span><span className="text-slate-300">/</span><span className="font-semibold text-slate-800">{activeLabel}</span></div>
          <div className="flex items-center gap-3">
            <label className="flex w-64 items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-slate-400 focus-within:border-blue-300 focus-within:bg-white">
              <Search size={15} /><input aria-label="Search hosting tools" value={search} onChange={event => setSearch(event.target.value)} placeholder="Find a hosting tool…" className="w-full bg-transparent text-xs text-slate-700 outline-none placeholder:text-slate-400" />
              {search && <button type="button" aria-label="Clear search" onClick={() => setSearch("")} className="text-xs text-slate-400 hover:text-slate-700">×</button>}
            </label>
            <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1.5 text-[11px] font-medium text-amber-800">Development environment</span>
          </div>
        </header>
        <div className="sticky top-0 z-30 flex h-[58px] items-center gap-3 border-b border-slate-200/80 bg-white/95 px-4 backdrop-blur-xl lg:hidden">
          <button onClick={() => setMobileOpen(true)} aria-label="Open navigation" className="rounded-xl border border-slate-200 p-2 text-slate-600"><Menu size={18} /></button>
          <span className="text-sm font-semibold">Nexora <span className="text-blue-700">Control</span></span>
          <span className="ml-auto truncate text-xs text-slate-500">{activeLabel}</span>
        </div>
        {children}
      </div>
    </div>
  );
}

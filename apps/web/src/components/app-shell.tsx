"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity, ArrowLeftFromLine, ArrowRightFromLine, Box, Building2, ChevronDown,
  CreditCard, Database, FolderOpen, Globe2, HardDrive, LayoutDashboard, ListChecks,
  LockKeyhole, Mail, Menu, Monitor, Network, Search, Server, Settings2, Shield,
  ShieldCheck, Users, X, Github,
} from "lucide-react";
import { NexoraMark } from "@/components/ui";

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
      { label: "Nexora Deploy", href: "/github-deployments", icon: Github },
    ],
  },
  {
    title: "Platform administration",
    items: [
      { label: "Servers & nodes", href: "/servers", icon: Server },
      { label: "Hosting packages", href: "/hosting-plans", icon: Box },
      { label: "Payment orders", href: "/payment-orders", icon: Users },
      { label: "Payment settings", href: "/payment-settings", icon: Settings2 },
      { label: "Customer accounts", href: "/customer-accounts", icon: Users },
      { label: "Hosting accounts", href: "/hosting-accounts", icon: Server },
      { label: "Organizations", href: "/organization", icon: Building2 },
      { label: "Subscriptions & billing", href: "/subscriptions", icon: CreditCard },
      { label: "Provisioning jobs", href: "/provisioning-jobs", icon: ListChecks },
      { label: "User management", href: "/user-management", icon: Users },
      { label: "Audit logs", href: "/audit-logs", icon: Shield },
      { label: "Monitoring", href: "/monitoring", icon: Activity },
    ],
  },
  {
    title: "Configuration",
    items: [
      { label: "Security & access", href: "/security", icon: LockKeyhole },
      { label: "Active sessions", href: "/sessions", icon: Monitor },
      { label: "Settings", href: "/settings", icon: Settings2 },
    ],
  },
];

export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  // Normalize trailing slashes and treat auth routes as public by path segment.
  // This prevents the workspace guard from bouncing recovery URLs back to /login.
  const normalizedPathname = (pathname || "/").replace(/\/+$/, "") || "/";
  const isPublicAuthRoute = ["/login", "/signup", "/plans", "/forgot-password", "/reset-password"]
    .some(route => normalizedPathname === route || normalizedPathname.startsWith(`${route}/`));
  const isCustomerRoute = normalizedPathname === "/customer" || normalizedPathname.startsWith("/customer/") || normalizedPathname === "/store" || normalizedPathname.startsWith("/store/");
  const [accessChecking, setAccessChecking] = useState(true);
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    Home: true,
    "Hosting services": true,
    "Platform administration": true,
    Configuration: true,
  });

  useEffect(() => {
    if (isPublicAuthRoute) {
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
        const isPlatformAdministrator = Boolean(user.platformRole);
        if (isPlatformAdministrator && isCustomerRoute) {
          router.replace("/");
          return;
        }
        if (!isPlatformAdministrator && !isCustomerRoute) {
          router.replace("/customer");
          return;
        }
        setAccessChecking(false);
      })
      .catch(() => {
        if (active) router.replace("/login");
      });
    return () => { active = false; };
  }, [isPublicAuthRoute, isCustomerRoute, pathname, router]);

  const filteredNavigation = useMemo(() => {
    const query = search.trim().toLowerCase();
    return navigation.map(group => ({
      ...group,
      items: group.items.filter(item => !query || item.label.toLowerCase().includes(query) || group.title.toLowerCase().includes(query)),
    })).filter(group => group.items.length > 0);
  }, [search]);

  if (isPublicAuthRoute) return <>{children}</>;
  if (accessChecking) return <main className="grid min-h-screen place-items-center bg-canvas"><p className="text-sm text-slate-500">Checking workspace access…</p></main>;

  if (isCustomerRoute) return <>{children}</>;

  const isActive = (href: string) => href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
  const activeLabel = navigation.flatMap(group => group.items).find(item => isActive(item.href))?.label ?? "Workspace";
  const linkClass = (active: boolean) =>
    "group relative flex min-h-10 items-center gap-3 rounded-xl px-3 py-2 text-[13px] font-medium transition-colors " +
    (active
      ? "bg-white/[0.08] text-white"
      : "text-slate-400 hover:bg-white/[0.05] hover:text-slate-100");

  return (
    <div className="min-h-screen bg-canvas text-slate-900">
      {mobileOpen && <button aria-label="Close navigation" onClick={() => setMobileOpen(false)} className="fixed inset-0 z-40 bg-navy-950/60 backdrop-blur-sm lg:hidden" />}
      <aside className={"fixed inset-y-0 left-0 z-50 flex flex-col border-r border-white/[0.06] bg-gradient-to-b from-navy-950 via-navy-950 to-navy-900 text-white transition-all duration-200 " +
        (mobileOpen ? "translate-x-0 shadow-2xl " : "-translate-x-full lg:translate-x-0 ") +
        (collapsed ? "w-[272px] lg:w-[78px]" : "w-[272px]")}>
        <div className={"flex h-[72px] shrink-0 items-center border-b border-white/[0.06] " + (collapsed ? "justify-center px-3" : "justify-between px-5")}>
          <Link href="/" onClick={() => setMobileOpen(false)} className="flex min-w-0 items-center gap-3">
            <NexoraMark size={38} />
            {!collapsed && (
              <span className="min-w-0">
                <span className="block text-[15px] font-bold tracking-tight text-white">Nexora <span className="text-brand-300">Control</span></span>
                <span className="mt-0.5 block text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">Hosting platform</span>
              </span>
            )}
          </Link>
          <button aria-label="Close navigation" onClick={() => setMobileOpen(false)} className="rounded-lg p-2 text-slate-400 hover:bg-white/10 lg:hidden"><X size={18} /></button>
        </div>

        {!collapsed && (
          <div className="mx-3 mt-4 flex items-center gap-2.5 rounded-xl border border-white/[0.07] bg-white/[0.04] px-3 py-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-brand-500/20 text-brand-300"><ShieldCheck size={15} /></span>
            <span className="min-w-0">
              <span className="block text-[11px] font-semibold text-slate-100">Platform administrator</span>
              <span className="block text-[10px] text-slate-500">WHM · full workspace scope</span>
            </span>
          </div>
        )}

        <nav className="min-h-0 flex-1 overflow-y-auto px-3 py-4" aria-label="Workspace navigation">
          {filteredNavigation.map(group => (
            <section key={group.title} className="mb-5">
              {!collapsed && (
                <button
                  onClick={() => setExpanded(value => ({ ...value, [group.title]: !value[group.title] }))}
                  aria-expanded={expanded[group.title]}
                  className="mb-2 flex w-full items-center justify-between px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500 transition hover:text-slate-300"
                >
                  <span>{group.title}</span><ChevronDown size={13} className={"transition-transform " + (expanded[group.title] ? "rotate-180" : "")} />
                </button>
              )}
              {(collapsed || expanded[group.title] || search.trim()) && (
                <div className="space-y-0.5">
                  {group.items.map(({ label, href, icon: Icon }) => (
                    <Link key={href} href={href} title={collapsed ? label : undefined} onClick={() => setMobileOpen(false)} className={linkClass(isActive(href))}>
                      {isActive(href) && <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-brand-400" aria-hidden="true" />}
                      <Icon size={17} className={"shrink-0 transition-colors " + (isActive(href) ? "text-brand-300" : "text-slate-500 group-hover:text-slate-300")} />
                      {!collapsed && <span className="truncate">{label}</span>}
                    </Link>
                  ))}
                </div>
              )}
            </section>
          ))}
          {filteredNavigation.every(group => group.items.length === 0) && !collapsed && <p className="px-3 py-5 text-xs text-slate-500">No matching tools.</p>}
        </nav>

        {!collapsed && (
          <div className="mx-3 mb-3 rounded-2xl border border-white/[0.06] bg-white/[0.03] p-3.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><ShieldCheck size={15} className="text-emerald-400" /> Secure operations</div>
            <p className="mt-2 text-[11px] leading-5 text-slate-500">Server actions are dispatched through authenticated agents and scoped policies.</p>
            <div className="mt-3 flex items-center gap-2 text-[10px] font-medium text-emerald-400"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Control plane status is monitored</div>
          </div>
        )}
        <div className="hidden h-[60px] shrink-0 items-center border-t border-white/[0.06] px-3 lg:flex">
          <button onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} className="flex w-full items-center justify-center gap-2 rounded-xl px-3 py-2 text-xs text-slate-500 transition hover:bg-white/[0.05] hover:text-white">
            {collapsed ? <ArrowRightFromLine size={17} /> : <><ArrowLeftFromLine size={17} /><span>Collapse navigation</span></>}
          </button>
        </div>
      </aside>

      <div className={"min-h-screen transition-[margin] duration-200 " + (collapsed ? "lg:ml-[78px]" : "lg:ml-[272px]")}>
        <header className="sticky top-0 z-30 hidden h-[64px] items-center justify-between border-b border-slate-200/80 bg-white/85 px-7 backdrop-blur-xl lg:flex">
          <div className="flex items-center gap-2.5 text-sm">
            <span className="text-slate-400">Nexora</span><span className="text-slate-300">/</span>
            <span className="font-semibold text-slate-800">{activeLabel}</span>
          </div>
          <div className="flex items-center gap-3">
            <label className="flex w-64 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-slate-400 shadow-sm transition focus-within:border-brand-300 focus-within:ring-4 focus-within:ring-brand-500/10">
              <Search size={15} /><input aria-label="Search hosting tools" value={search} onChange={event => setSearch(event.target.value)} placeholder="Find a hosting tool…" className="w-full bg-transparent text-xs text-slate-700 outline-none placeholder:text-slate-400" />
              {search && <button type="button" aria-label="Clear search" onClick={() => setSearch("")} className="text-xs text-slate-400 hover:text-slate-700">×</button>}
            </label>
            <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1.5 text-[11px] font-semibold text-amber-800">Development environment</span>
          </div>
        </header>
        <div className="sticky top-0 z-30 flex h-[58px] items-center gap-3 border-b border-slate-200/80 bg-white/95 px-4 backdrop-blur-xl lg:hidden">
          <button onClick={() => setMobileOpen(true)} aria-label="Open navigation" className="rounded-xl border border-slate-200 p-2 text-slate-600"><Menu size={18} /></button>
          <span className="flex items-center gap-2 text-sm font-bold tracking-tight"><NexoraMark size={24} /> Nexora <span className="text-brand-600">Control</span></span>
          <span className="ml-auto truncate text-xs text-slate-500">{activeLabel}</span>
        </div>
        {children}
      </div>
    </div>
  );
}

"use client";

import type { ComponentType, ReactNode } from "react";
import { X } from "lucide-react";

// ---------------------------------------------------------------------------
// Nexora design system — shared presentational primitives.
//
// Every service area (dashboard, File Manager, Email, DNS, Backups, Nexora
// Deploy) renders through these primitives so spacing, hierarchy, status
// colors and empty states stay identical across the product. They are pure
// presentation: no data fetching, no API knowledge, no auth decisions.
// ---------------------------------------------------------------------------

export function NexoraMark({ size = 36, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden="true" className={className}>
      <defs>
        <linearGradient id="nexora-mark-bg" x1="4" y1="2" x2="36" y2="38" gradientUnits="userSpaceOnUse">
          <stop stopColor="#4057e4" />
          <stop offset="1" stopColor="#101a3c" />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="36" height="36" rx="11" fill="url(#nexora-mark-bg)" />
      <rect x="2.75" y="2.75" width="34.5" height="34.5" rx="10.25" stroke="white" strokeOpacity="0.18" strokeWidth="1.5" />
      <path d="M13 27.5v-15l14 15v-15" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" fill="none" />
      <circle cx="30.5" cy="9.5" r="2.5" fill="#7dd3fc" />
    </svg>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={"inline-block h-5 w-5 animate-spin rounded-full border-2 border-slate-200 border-t-brand-600 " + className}
    />
  );
}

export function FullPageLoader({ message = "Loading your workspace…" }: { message?: string }) {
  return (
    <main className="grid min-h-screen place-items-center bg-canvas">
      <div className="text-center">
        <Spinner className="mx-auto" />
        <p className="mt-4 text-sm text-slate-500">{message}</p>
      </div>
    </main>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && (
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-brand-600">{eyebrow}</p>
        )}
        <h1 className="mt-1.5 text-2xl font-bold tracking-tight text-slate-950 sm:text-[1.75rem]">{title}</h1>
        {description && <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
}

export function SectionCard({
  title,
  description,
  actions,
  children,
  className = "",
  flush = false,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  flush?: boolean;
}) {
  return (
    <section className={"nx-card " + className}>
      {(title || actions) && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-5 py-4 sm:px-6">
          <div className="min-w-0">
            {title && <h2 className="text-[15px] font-semibold text-slate-900">{title}</h2>}
            {description && <p className="mt-1 text-xs leading-5 text-slate-500">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={flush ? "" : "p-5 sm:p-6"}>{children}</div>
    </section>
  );
}

export function StatCard({
  icon: Icon,
  label,
  value,
  unit,
  hint,
  children,
}: {
  icon?: ComponentType<{ size?: number | string; className?: string }>;
  label: string;
  value: ReactNode;
  unit?: string;
  hint?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="nx-card p-5">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{label}</p>
        {Icon && (
          <span className="grid h-9 w-9 place-items-center rounded-xl bg-brand-50 text-brand-600">
            <Icon size={17} />
          </span>
        )}
      </div>
      <p className="mt-3 text-[1.7rem] font-bold leading-8 tracking-tight text-slate-950">
        {value}
        {unit && <span className="ml-1.5 text-sm font-semibold text-slate-400">{unit}</span>}
      </p>
      {hint && <p className="mt-1.5 text-xs leading-5 text-slate-500">{hint}</p>}
      {children}
    </div>
  );
}

export type BadgeTone = "success" | "info" | "warning" | "danger" | "neutral" | "brand";

const badgeToneClass: Record<BadgeTone, string> = {
  success: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  info: "bg-sky-50 text-sky-700 ring-sky-600/20",
  warning: "bg-amber-50 text-amber-800 ring-amber-600/25",
  danger: "bg-rose-50 text-rose-700 ring-rose-600/20",
  neutral: "bg-slate-100 text-slate-600 ring-slate-500/20",
  brand: "bg-brand-50 text-brand-700 ring-brand-500/20",
};

export function StatusBadge({ tone = "neutral", children, dot = false }: { tone?: BadgeTone; children: ReactNode; dot?: boolean }) {
  return (
    <span className={"inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1 ring-inset " + badgeToneClass[tone]}>
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

// Maps the platform's uppercase lifecycle words onto badge tones so that the
// same status reads the same way everywhere (accounts, jobs, deployments…).
export function statusTone(status: string | null | undefined): BadgeTone {
  const value = (status ?? "").toUpperCase();
  if (["ACTIVE", "ONLINE", "AVAILABLE", "SUCCEEDED", "READY", "CONNECTED", "PROVISIONED", "CONFIGURED"].includes(value)) return "success";
  if (["QUEUED", "RUNNING", "CONFIGURING", "BUILDING", "PUBLISHING", "INSTALLING", "CLONING", "PROVISIONING", "RESTORING", "RESTORE_STAGED", "DELETING"].includes(value)) return "info";
  if (["PENDING", "NOT_CONFIGURED", "WAITING", "AWAITING"].includes(value)) return "warning";
  if (["FAILED", "ERROR", "REJECTED", "OFFLINE", "SUSPENDED"].includes(value)) return "danger";
  return "neutral";
}

export function Meter({ value, tone, className = "" }: { value: number; tone?: "brand" | "success" | "warning" | "danger"; className?: string }) {
  const clamped = Math.max(0, Math.min(100, value));
  const color = tone ?? (clamped >= 90 ? "danger" : clamped >= 75 ? "warning" : "brand");
  const colorClass = color === "danger" ? "bg-rose-500" : color === "warning" ? "bg-amber-500" : color === "success" ? "bg-emerald-500" : "bg-brand-500";
  return (
    <div className={"h-2 w-full overflow-hidden rounded-full bg-slate-100 " + className} role="progressbar" aria-valuenow={Math.round(clamped)} aria-valuemin={0} aria-valuemax={100}>
      <div className={"h-full rounded-full transition-all duration-500 " + colorClass} style={{ width: clamped + "%" }} />
    </div>
  );
}

export function ResourceMeter({
  label,
  used,
  total,
  format = (value: number) => value.toLocaleString(),
  note,
}: {
  label: string;
  used: number | null;
  total: number | null;
  format?: (value: number) => string;
  note?: string;
}) {
  const metered = used !== null && total !== null && total > 0;
  const percent = metered ? (used! / total!) * 100 : 0;
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{label}</span>
        <span className="text-xs font-semibold tabular-nums text-slate-700">
          {metered ? `${format(used!)} / ${format(total!)}` : total !== null ? `Quota ${format(total!)}` : "Not metered"}
        </span>
      </div>
      <Meter value={metered ? percent : 0} className="mt-2" />
      <p className="mt-1.5 text-[11px] leading-4 text-slate-400">
        {metered ? `${percent.toFixed(percent < 10 ? 1 : 0)}% used` : note ?? "Per-resource usage metering is not reported yet."}
      </p>
    </div>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  children,
}: {
  icon: ComponentType<{ size?: number | string; className?: string }>;
  title: string;
  description: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="px-6 py-14 text-center">
      <span className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-slate-200 bg-slate-50 text-slate-400">
        <Icon size={24} />
      </span>
      <h3 className="mt-4 text-[15px] font-semibold text-slate-900">{title}</h3>
      <p className="mx-auto mt-1.5 max-w-md text-sm leading-6 text-slate-500">{description}</p>
      {children && <div className="mt-5 flex flex-wrap items-center justify-center gap-2.5">{children}</div>}
    </div>
  );
}

export type AlertTone = "error" | "success" | "warning" | "info";

const alertToneClass: Record<AlertTone, string> = {
  error: "border-rose-200 bg-rose-50 text-rose-700",
  success: "border-emerald-200 bg-emerald-50 text-emerald-800",
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  info: "border-sky-200 bg-sky-50 text-sky-800",
};

export function InlineAlert({
  tone,
  children,
  onDismiss,
  className = "",
}: {
  tone: AlertTone;
  children: ReactNode;
  onDismiss?: () => void;
  className?: string;
}) {
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={"flex items-start justify-between gap-3 rounded-xl border px-4 py-3 text-sm " + alertToneClass[tone] + " " + className}
    >
      <span className="min-w-0 leading-6">{children}</span>
      {onDismiss && (
        <button type="button" onClick={onDismiss} aria-label="Dismiss message" className="shrink-0 rounded-md p-1 opacity-60 transition hover:opacity-100">
          <X size={15} />
        </button>
      )}
    </div>
  );
}

export function Modal({
  title,
  description,
  onClose,
  children,
  labelledBy,
}: {
  title: string;
  description?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  labelledBy?: string;
}) {
  return (
    <div className="fixed inset-0 z-40 grid place-items-center bg-slate-950/50 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label={labelledBy ?? title}>
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-lift">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h3 className="text-lg font-bold tracking-tight text-slate-950">{title}</h3>
            {description && <p className="mt-1.5 text-xs leading-5 text-slate-500">{description}</p>}
          </div>
          <button type="button" onClick={onClose} aria-label="Close dialog" className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700">
            <X size={17} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function TableFrame({ head, children, minWidth = 720 }: { head: ReactNode; children: ReactNode; minWidth?: number }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm" style={{ minWidth }}>
        <thead className="bg-slate-50/80 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">{head}</thead>
        <tbody className="divide-y divide-slate-100">{children}</tbody>
      </table>
    </div>
  );
}

export function Th({ children, right = false }: { children: ReactNode; right?: boolean }) {
  return <th className={"whitespace-nowrap px-4 py-3 font-semibold " + (right ? "text-right" : "")}>{children}</th>;
}

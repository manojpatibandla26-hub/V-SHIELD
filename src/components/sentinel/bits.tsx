"use client";
/**
 * AI Sentinel — shared UI primitives (severity badges, gauges, formatting, exports).
 * Professional SOC styling: dark zinc surfaces, semantic accent colors.
 */
import { cn } from "@/lib/utils";
import type { EventStatus, Severity } from "@/lib/sentinel/types";

export const SEVERITY_STYLE: Record<
  Severity,
  { chip: string; dot: string; text: string; bar: string; ring: string; border: string }
> = {
  LOW: {
    chip: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    dot: "bg-emerald-400",
    text: "text-emerald-400",
    bar: "bg-emerald-500",
    ring: "stroke-emerald-400",
    border: "border-emerald-500/40",
  },
  MEDIUM: {
    chip: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    dot: "bg-amber-400",
    text: "text-amber-400",
    bar: "bg-amber-500",
    ring: "stroke-amber-400",
    border: "border-amber-500/40",
  },
  HIGH: {
    chip: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    dot: "bg-orange-400",
    text: "text-orange-400",
    bar: "bg-orange-500",
    ring: "stroke-orange-400",
    border: "border-orange-500/40",
  },
  CRITICAL: {
    chip: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    dot: "bg-rose-400",
    text: "text-rose-400",
    bar: "bg-rose-500",
    ring: "stroke-rose-400",
    border: "border-rose-500/50",
  },
};

export const STATUS_STYLE: Record<EventStatus, string> = {
  ACTIVE: "bg-rose-500/10 text-rose-400 border-rose-500/30",
  RESOLVED: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  MITIGATED: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const s = SEVERITY_STYLE[severity] || SEVERITY_STYLE.LOW;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold tracking-wide shadow-sm",
        s.chip,
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", s.dot)} />
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: EventStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase tracking-wider",
        STATUS_STYLE[status] || STATUS_STYLE.ACTIVE,
      )}
    >
      {status}
    </span>
  );
}

export function LivePulse({ active = true, color = "bg-emerald-400" }: { active?: boolean; color?: string }) {
  return (
    <span className="relative flex h-2 w-2">
      {active && (
        <span className={cn("absolute inline-flex h-full w-full animate-ping rounded-full opacity-75", color)} />
      )}
      <span className={cn("relative inline-flex h-2 w-2 rounded-full", color)} />
    </span>
  );
}

export function RiskGauge({
  risk,
  severity,
  size = 120,
}: {
  risk: number;
  severity: Severity;
  size?: number;
}) {
  const s = SEVERITY_STYLE[severity] || SEVERITY_STYLE.LOW;
  const r = size / 2 - 10;
  const circ = Math.PI * r; // semicircle
  const pct = Math.min(100, Math.max(0, risk)) / 100;
  return (
    <div
      className="flex flex-col items-center"
      role="img"
      aria-label={`Risk ${risk} out of 100, severity ${severity}`}
    >
      <svg width={size} height={size / 2 + 14} viewBox={`0 0 ${size} ${size / 2 + 14}`}>
        <path
          d={`M 10 ${size / 2} A ${r} ${r} 0 0 1 ${size - 10} ${size / 2}`}
          fill="none"
          stroke="currentColor"
          className="text-zinc-800/80"
          strokeWidth="8"
          strokeLinecap="round"
        />
        <path
          d={`M 10 ${size / 2} A ${r} ${r} 0 0 1 ${size - 10} ${size / 2}`}
          fill="none"
          strokeWidth="8"
          strokeLinecap="round"
          className={cn("transition-all duration-700 ease-out", s.ring)}
          strokeDasharray={`${circ * pct} ${circ}`}
        />
      </svg>
      <div className="-mt-3 text-center">
        <div className={cn("text-2xl font-bold tabular-nums tracking-tight", s.text)}>
          {risk}
          <span className="text-xs text-zinc-500 font-normal">/100</span>
        </div>
        <div className={cn("text-[11px] font-semibold tracking-wider uppercase", s.text)}>
          {severity}
        </div>
      </div>
    </div>
  );
}

export function fmtNum(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1000) return n.toLocaleString("en-US", { maximumFractionDigits: 0 });
  return `${Math.round(n * 10) / 10}`;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function fmtTimeAgo(tsSeconds: number): string {
  const diff = Math.max(0, Date.now() / 1000 - tsSeconds);
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export function fmtClock(tsMs: number): string {
  const d = new Date(tsMs);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

export function exportAsJson(data: unknown, filename: string): void {
  if (typeof window === "undefined") return;
  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.endsWith(".json") ? filename : `${filename}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportAsCsv(rows: Record<string, unknown>[], filename: string): void {
  if (typeof window === "undefined" || rows.length === 0) return;
  const headers = Object.keys(rows[0]);
  const csvContent = [
    headers.join(","),
    ...rows.map((row) =>
      headers
        .map((header) => {
          const val = row[header];
          if (val === null || val === undefined) return '""';
          const str = typeof val === "object" ? JSON.stringify(val) : String(val);
          return `"${str.replace(/"/g, '""')}"`;
        })
        .join(","),
    ),
  ].join("\n");

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.endsWith(".csv") ? filename : `${filename}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

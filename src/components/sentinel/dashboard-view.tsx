"use client";
/**
 * AI Sentinel — SOC dashboard.
 * Summary cards + real-time traffic chart + threat timeline + detail panel.
 */
import {
  Activity,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Gauge,
  Ban,
} from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { fmtNum, SEVERITY_STYLE } from "./bits";
import { TrafficChart } from "./traffic-chart";
import { ThreatFeed } from "./threat-feed";
import { ThreatDetail } from "./threat-detail";

const STATUS_META = {
  PROTECTED: {
    label: "Protected",
    icon: ShieldCheck,
    cls: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  },
  MONITORING: {
    label: "Monitoring",
    icon: Activity,
    cls: "border-amber-500/30 bg-amber-500/10 text-amber-400",
  },
  UNDER_ATTACK: {
    label: "Under Attack",
    icon: ShieldAlert,
    cls: "border-rose-500/40 bg-rose-500/10 text-rose-400",
  },
} as const;

function SummaryCard({
  label,
  value,
  hint,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string;
  hint?: string;
  icon: React.ComponentType<{ className?: string }>;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
          {label}
        </p>
        <Icon className={cn("h-4 w-4", accent ?? "text-zinc-500")} aria-hidden />
      </div>
      <p className="mt-2 text-2xl font-semibold tabular-nums text-zinc-100">
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-zinc-500">{hint}</p>}
    </div>
  );
}

export function DashboardView() {
  const statistics = useSentinelStore((s) => s.statistics);
  const traffic = useSentinelStore((s) => s.traffic);
  const events = useSentinelStore((s) => s.events);
  const wsStatus = useSentinelStore((s) => s.wsStatus);
  const backendOnline = useSentinelStore((s) => s.backendOnline);

  const status = statistics?.network_status ?? "PROTECTED";
  const meta = STATUS_META[status];
  const currentRisk = statistics?.current_risk ?? 0;
  const riskSev =
    currentRisk >= 75
      ? "CRITICAL"
      : currentRisk >= 50
        ? "HIGH"
        : currentRisk >= 25
          ? "MEDIUM"
          : "LOW";
  const last = traffic.length ? traffic[traffic.length - 1] : null;
  const livePkt = last?.pktRate ?? statistics?.traffic.pkt_rate ?? 0;
  const blocked = statistics?.blocked_sources ?? [];

  const activeEvents = events.filter(
    (e) => e.status === "ACTIVE" && e.attack !== "BENIGN",
  );
  const critical = statistics?.totals.critical_total ?? 0;

  return (
    <div className="space-y-6">
      {/* status banner */}
      <div
        className={cn(
          "flex items-center gap-3 rounded-xl border p-4",
          meta.cls,
        )}
        role="status"
        aria-live="polite"
      >
        <meta.icon className="h-6 w-6" aria-hidden />
        <div>
          <p className="font-semibold">{meta.label}</p>
          <p className="text-sm opacity-80">
            {status === "PROTECTED"
              ? "All traffic matches the learned normal baseline."
              : status === "MONITORING"
                ? "Suspicious activity is being investigated."
                : "Active high-severity threats detected — review the alert panel."}
          </p>
        </div>
        {backendOnline === false && (
          <p className="ml-auto rounded-md bg-rose-500/10 px-2 py-1 text-xs text-rose-300">
            Backend unreachable — retrying
          </p>
        )}
        {wsStatus === "polling" && (
          <p className="ml-auto rounded-md bg-orange-500/10 px-2 py-1 text-xs text-orange-300">
            Live stream unavailable — using periodic refresh
          </p>
        )}
      </div>

      {/* summary cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <SummaryCard
          label="Network Status"
          value={meta.label}
          icon={meta.icon}
          accent="text-emerald-400"
        />
        <SummaryCard
          label="Live Traffic"
          value={`${fmtNum(livePkt)} pkt/s`}
          hint={last ? `${fmtNum(last.byteRate)} B/s · ${last.flows} flows` : undefined}
          icon={Activity}
          accent="text-zinc-300"
        />
        <SummaryCard
          label="Active Threats"
          value={String(activeEvents.length)}
          hint={`${statistics?.totals.threats_total ?? 0} total detected`}
          icon={AlertTriangle}
          accent="text-amber-400"
        />
        <SummaryCard
          label="Critical Events"
          value={String(critical)}
          hint="lifetime"
          icon={ShieldAlert}
          accent="text-rose-400"
        />
        <SummaryCard
          label="Risk Score"
          value={`${currentRisk}`}
          hint={`${riskSev} · current aggregate`}
          icon={Gauge}
          accent={SEVERITY_STYLE[riskSev].text}
        />
        <SummaryCard
          label="Blocked Sources"
          value={String(blocked.length)}
          hint={blocked.length ? blocked[0].source : "simulated blocks only"}
          icon={Ban}
          accent="text-zinc-300"
        />
      </div>

      {/* main grid */}
      <div className="grid gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-2">
          <TrafficChart data={traffic} />
          <ThreatFeed events={events} />
        </div>
        <div className="xl:col-span-1">
          <ThreatDetail />
        </div>
      </div>
    </div>
  );
}

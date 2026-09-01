"use client";
/**
 * AI Sentinel — SOC dashboard.
 * Real-time summary cards + live traffic/risk chart + threat timeline + detailed threat analysis.
 */
import {
  Activity,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Gauge,
  Ban,
  RefreshCw,
  Radio,
  Zap,
  Shield,
  CheckCircle2,
  Lock,
  Flame,
} from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { fmtNum, fmtBytes, SEVERITY_STYLE, LivePulse } from "./bits";
import { TrafficChart } from "./traffic-chart";
import { ThreatFeed } from "./threat-feed";
import { ThreatDetail } from "./threat-detail";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";

const STATUS_META = {
  PROTECTED: {
    label: "Protected",
    icon: ShieldCheck,
    cls: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
    desc: "All traffic matches the learned normal baseline. Zero active severe anomalies.",
    glow: "shadow-[0_0_20px_rgba(16,185,129,0.15)]",
  },
  MONITORING: {
    label: "Monitoring",
    icon: Activity,
    cls: "border-amber-500/30 bg-amber-500/10 text-amber-400",
    desc: "Elevated network deviation detected — real-time analysis in progress.",
    glow: "shadow-[0_0_20px_rgba(245,158,11,0.15)]",
  },
  UNDER_ATTACK: {
    label: "Under Attack",
    icon: ShieldAlert,
    cls: "border-rose-500/40 bg-rose-500/10 text-rose-400",
    desc: "Active high-severity intrusion confirmed — review incident panel and response guidance.",
    glow: "shadow-[0_0_20px_rgba(244,63,94,0.2)]",
  },
} as const;

function SummaryCard({
  label,
  value,
  hint,
  icon: Icon,
  accent,
  loading = false,
  highlight = false,
}: {
  label: string;
  value: string;
  hint?: string;
  icon: React.ComponentType<{ className?: string }>;
  accent?: string;
  loading?: boolean;
  highlight?: boolean;
}) {
  if (loading) {
    return (
      <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/50 p-4 space-y-2.5">
        <div className="flex items-center justify-between">
          <Skeleton className="h-3.5 w-20 bg-zinc-800" />
          <Skeleton className="h-4 w-4 rounded-full bg-zinc-800" />
        </div>
        <Skeleton className="h-7 w-24 bg-zinc-800" />
        <Skeleton className="h-3 w-28 bg-zinc-800" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        "group relative overflow-hidden rounded-xl border p-4 transition-all duration-200",
        "border-zinc-800 bg-zinc-900/60 hover:border-zinc-700 hover:bg-zinc-900/90 hover:shadow-md",
        highlight && "border-amber-500/30 bg-amber-500/5",
      )}
    >
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400">
          {label}
        </p>
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-zinc-800/60 text-zinc-400 group-hover:text-zinc-200 transition-colors">
          <Icon className={cn("h-4 w-4", accent ?? "text-zinc-400")} aria-hidden />
        </div>
      </div>
      <p className="mt-2 text-2xl font-bold tabular-nums tracking-tight text-zinc-100">
        {value}
      </p>
      {hint && (
        <p className="mt-1 text-xs text-zinc-500 truncate font-mono">
          {hint}
        </p>
      )}
    </div>
  );
}

function LiveTrafficKPI({ loading, fallbackPkt }: { loading: boolean; fallbackPkt: number }) {
  const traffic = useSentinelStore((s) => s.traffic);
  const last = traffic.length ? traffic[traffic.length - 1] : null;
  const livePkt = last?.pktRate ?? fallbackPkt;
  return (
    <SummaryCard
      label="Live Traffic"
      value={`${fmtNum(livePkt)} pkt/s`}
      hint={last ? `${fmtBytes(last.byteRate)}/s · ${last.flows} flows` : "baseline telemetry"}
      icon={Activity}
      accent="text-emerald-400"
      loading={loading}
    />
  );
}

export function DashboardView() {
  const statistics = useSentinelStore((s) => s.statistics);
  const events = useSentinelStore((s) => s.events);
  const wsStatus = useSentinelStore((s) => s.wsStatus);
  const backendOnline = useSentinelStore((s) => s.backendOnline);
  const retryConnection = useSentinelStore((s) => s.retryConnection);
  const autoDefense = useSentinelStore((s) => s.autoDefense);
  const toggleAutoDefense = useSentinelStore((s) => s.toggleAutoDefense);
  const mitigateEvent = useSentinelStore((s) => s.mitigateEvent);

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
  const blocked = statistics?.blocked_sources ?? [];

  const activeEvents = events.filter(
    (e) => e.status === "ACTIVE" && e.attack !== "BENIGN",
  );
  const critical = statistics?.totals.critical_total ?? 0;
  const loading = statistics === null;

  return (
    <div className="space-y-5">
      {/* Top Status & Autonomous Defense Control Banner */}
      <div
        className={cn(
          "flex flex-wrap items-center justify-between gap-4 rounded-xl border p-4 transition-all duration-300",
          meta.cls,
          meta.glow,
        )}
        role="status"
        aria-live="polite"
      >
        <div className="flex items-center gap-3.5">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-black/20 backdrop-blur">
            <meta.icon className="h-6 w-6" aria-hidden />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <p className="font-bold tracking-tight text-base">{meta.label}</p>
              <span className="inline-flex items-center gap-1 rounded bg-black/30 px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider font-semibold">
                {status}
              </span>
            </div>
            <p className="text-xs sm:text-sm opacity-90 leading-tight mt-0.5">
              {meta.desc}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          {/* Autonomous AI Shield Toggle */}
          <button
            onClick={toggleAutoDefense}
            className={cn(
              "flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-medium transition-all",
              autoDefense
                ? "border-emerald-500/50 bg-emerald-500/20 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.3)]"
                : "border-zinc-800 bg-zinc-900/80 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
            )}
            title="Auto-Shield: Automatically deploys firewall blocks when attacks are detected"
          >
            <Shield className={cn("h-3.5 w-3.5", autoDefense ? "text-emerald-400 animate-pulse" : "text-zinc-500")} />
            <span>Auto-Shield: {autoDefense ? "ACTIVE (Autonomous IPS)" : "MANUAL (SOC Analyst)"}</span>
          </button>

          {backendOnline === false ? (
            <div className="flex items-center gap-2 rounded-lg bg-rose-950/80 border border-rose-500/30 px-3 py-1.5 text-rose-200">
              <span>Backend Disconnected</span>
              <Button
                size="sm"
                variant="outline"
                onClick={() => void retryConnection()}
                className="h-6 border-rose-500/40 bg-rose-500/20 px-2 text-[11px] text-white hover:bg-rose-500/40"
              >
                <RefreshCw className="mr-1 h-3 w-3" /> Reconnect
              </Button>
            </div>
          ) : (
            <div className="inline-flex items-center gap-2 rounded-lg bg-black/30 px-2.5 py-1.5 text-xs text-zinc-300 font-mono">
              <LivePulse active={wsStatus === "connected"} color="bg-emerald-400" />
              <span>SOC Pipeline Active</span>
            </div>
          )}
        </div>
      </div>

      {/* Emergency Active Threat Defense Bar (When Under Attack) */}
      {activeEvents.length > 0 && (
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 rounded-xl border border-rose-500/60 bg-gradient-to-r from-rose-950/80 via-zinc-900/90 to-zinc-900/90 p-4 shadow-[0_0_20px_rgba(244,63,94,0.25)] animate-pulse">
          <div className="flex items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-rose-500/20 border border-rose-500/40 text-rose-400">
              <Flame className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-rose-200 uppercase tracking-wide">
                  Active Attack in Progress: {activeEvents[0].explanation.classification}
                </span>
                <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-mono text-rose-300">
                  {activeEvents[0].severity} SEVERITY
                </span>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Target: <span className="text-zinc-200 font-mono">{activeEvents[0].target || "Internal Subnet"}</span> · Attacker Source IP: <span className="text-rose-300 font-mono font-bold">{activeEvents[0].source}</span>
              </p>
            </div>
          </div>

          <Button
            onClick={() => void mitigateEvent(activeEvents[0].id)}
            className="shrink-0 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs sm:text-sm px-4 shadow-lg flex items-center gap-2"
          >
            <Shield className="h-4 w-4" />
            Neutralize Threat & Block Attacker
          </Button>
        </div>
      )}

      {/* 6 Key Performance Indicators (KPIs) */}
      <div className="grid grid-cols-2 gap-3.5 sm:gap-4 md:grid-cols-3 xl:grid-cols-6">
        <SummaryCard
          label="Network Status"
          value={meta.label}
          icon={meta.icon}
          accent={meta.cls.split(" ")[2]}
          loading={loading}
        />
        <LiveTrafficKPI loading={loading} fallbackPkt={statistics?.traffic.pkt_rate ?? 0} />
        <SummaryCard
          label="Active Threats"
          value={String(activeEvents.length)}
          hint={`${statistics?.totals.threats_total ?? 0} total detected`}
          icon={AlertTriangle}
          accent={activeEvents.length > 0 ? "text-amber-400" : "text-zinc-400"}
          highlight={activeEvents.length > 0}
          loading={loading}
        />
        <SummaryCard
          label="Critical Events"
          value={String(critical)}
          hint="lifetime incidents"
          icon={ShieldAlert}
          accent={critical > 0 ? "text-rose-400" : "text-zinc-400"}
          loading={loading}
        />
        <SummaryCard
          label="Risk Score"
          value={`${currentRisk}/100`}
          hint={`${riskSev} aggregate`}
          icon={Gauge}
          accent={SEVERITY_STYLE[riskSev].text}
          loading={loading}
        />
        <SummaryCard
          label="Blocked Sources"
          value={String(blocked.length)}
          hint={blocked.length > 0 ? `${blocked[0].source} (active)` : "simulated firewall"}
          icon={Ban}
          accent="text-zinc-300"
          loading={loading}
        />
      </div>

      {/* Active Firewall Rules & Mitigation Status (When Blocked IPs Exist) */}
      {blocked.length > 0 && (
        <div className="rounded-xl border border-emerald-500/30 bg-zinc-900/70 p-4 space-y-3 shadow-md">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <h4 className="text-xs sm:text-sm font-bold text-zinc-100 tracking-wide uppercase">
                Active Dynamic Firewall Defense Rules ({blocked.length} Host{blocked.length > 1 ? "s" : ""} Isolated)
              </h4>
            </div>
            <span className="text-[11px] font-mono text-emerald-400">
              ● Network Shield Active
            </span>
          </div>

          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {blocked.map((b, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950/80 p-3 text-xs"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5 font-mono font-bold text-zinc-200">
                    <Ban className="h-3 w-3 text-rose-400" />
                    <span>{b.source}</span>
                  </div>
                  <p className="text-[11px] font-mono text-zinc-500">
                    Rule: iptables -A INPUT -s {b.source} -j DROP
                  </p>
                </div>
                <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
                  BLOCKED & SECURED
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main SOC Dashboard Grid */}
      <div className="grid gap-6 xl:grid-cols-3">
        {/* Left 2 Columns: Traffic Graph & Threat Feed */}
        <div className="space-y-6 xl:col-span-2">
          <TrafficChart />
          <ThreatFeed />
        </div>

        {/* Right 1 Column: Threat Details Panel */}
        <div className="xl:col-span-1">
          <ThreatDetail />
        </div>
      </div>
    </div>
  );
}

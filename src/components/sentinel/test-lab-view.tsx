"use client";
/**
 * AI Sentinel — Security Test Lab.
 * Safe, synthetic attack scenarios for live demonstration.
 * Progress reflects actual backend WebSocket sim_progress events through ML pipeline.
 */
import { useMemo } from "react";
import {
  Waves,
  Zap,
  Radar,
  KeyRound,
  Ghost,
  ShieldCheck,
  Play,
  RotateCcw,
  LayoutDashboard,
  CheckCircle2,
  AlertCircle,
  FlaskConical,
  Radio,
  Sparkles,
  Ban,
} from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { SeverityBadge, LivePulse } from "./bits";
import { Skeleton } from "@/components/ui/skeleton";
import type { SimState } from "@/lib/sentinel/types";

const SCENARIO_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  syn_flood: Waves,
  dos_ddos: Zap,
  port_scan: Radar,
  brute_force: KeyRound,
  anomaly: Ghost,
};

function ScenarioCard({ type }: { type: string }) {
  const scenarios = useSentinelStore((s) => s.scenarios);
  const sims = useSentinelStore((s) => s.sims);
  const events = useSentinelStore((s) => s.events);
  const runSimulation = useSentinelStore((s) => s.runSimulation);
  const mitigateEvent = useSentinelStore((s) => s.mitigateEvent);
  const setView = useSentinelStore((s) => s.setView);

  const scenario = scenarios.find((s) => s.type === type);
  const Icon = SCENARIO_ICONS[type] ?? Ghost;

  const sim = useMemo<SimState | null>(() => {
    const list = Object.values(sims).filter((s) => s.attack_type === type);
    return list.length ? list[list.length - 1] : null;
  }, [sims, type]);

  if (!scenario) return null;

  const running =
    sim !== null &&
    (sim.phase === "starting" || sim.phase === "running" || sim.phase === "mitigating");
  const pct = sim
    ? Math.round((sim.windows_done / Math.max(sim.windows_total, 1)) * 100)
    : 0;

  // Determine stage status label
  const statusLabel = sim
    ? sim.phase === "starting"
      ? "Simulation Started"
      : sim.phase === "mitigating"
        ? "Mitigation & Recovery In Progress"
        : sim.phase === "running"
          ? `Detection In Progress (${sim.windows_done}/${sim.windows_total} windows)`
          : sim.detected
            ? "Threat Detected & Confirmed"
            : "Simulation Complete"
    : null;

  return (
    <div className="flex flex-col rounded-xl border border-zinc-800 bg-zinc-900/60 p-5 shadow-sm hover:border-zinc-700/80 transition-all">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-zinc-800/80 border border-zinc-700/60 text-emerald-400">
            <Icon className="h-5 w-5" aria-hidden />
          </div>
          <div>
            <h3 className="font-bold text-zinc-100 text-base">{scenario.name}</h3>
            <p className="text-xs text-zinc-400">{scenario.tagline}</p>
          </div>
        </div>

        {running && (
          <div className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-mono font-medium text-amber-300">
            <LivePulse active color="bg-amber-400" /> Live Run
          </div>
        )}
      </div>

      <p className="mt-3.5 flex-1 text-xs sm:text-sm leading-relaxed text-zinc-300">
        {scenario.description}
      </p>

      {/* Expected result box */}
      <div className="mt-3.5 rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-2.5 text-xs text-zinc-400">
        <span className="font-semibold text-zinc-300">Expected Signature:</span>{" "}
        <span className="text-zinc-400">{scenario.expected}</span>
      </div>

      {/* Progress & Live Detection State */}
      {sim && (running || sim.error) && (
        <div className="mt-4 space-y-2 rounded-lg border border-zinc-800 bg-zinc-950/80 p-3">
          {sim.error ? (
            <p className="flex items-center gap-2 text-xs text-rose-300">
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" aria-hidden />
              {sim.error}
            </p>
          ) : (
            <>
              <div className="flex items-center justify-between text-xs text-zinc-300">
                <span className="font-medium flex items-center gap-1.5">
                  <Radio className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
                  {statusLabel}
                </span>
                <span className="font-mono font-bold tabular-nums text-emerald-400">{pct}%</span>
              </div>
              <Progress
                value={pct}
                className="h-2 bg-zinc-800 [&>div]:bg-emerald-500"
                aria-label={`${scenario.name} progress`}
              />
              <div className="flex items-center justify-between text-[11px] text-zinc-500">
                <span>Synthetic feature vector stream</span>
                <span>Window {sim.windows_done} of {sim.windows_total}</span>
              </div>
              {running && sim.phase === "running" && (
                <Button
                  size="sm"
                  onClick={() => {
                    const ev = events.find((e) => (e.sim_id === sim.sim_id || e.source === scenario.source) && e.status === "ACTIVE");
                    if (ev) void mitigateEvent(ev.id);
                  }}
                  className="w-full mt-2 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-md flex items-center justify-center gap-1.5 animate-pulse"
                >
                  <Ban className="h-3.5 w-3.5" />
                  Neutralize & Stop Attack (Deploy Firewall Block)
                </Button>
              )}
            </>
          )}
        </div>
      )}

      {/* Completion Result Card */}
      {sim && !running && !sim.error && (sim.phase === "complete" || sim.phase === "mitigated") && (
        <div className="mt-4 rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3 space-y-2">
          <div className="flex items-center gap-2 text-xs">
            {sim.detected ? (
              <>
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden />
                <span className="text-zinc-200 font-medium">
                  Threat Classified — Final Risk {sim.final_risk}/100
                </span>
                {sim.final_severity && (
                  <SeverityBadge severity={sim.final_severity} />
                )}
              </>
            ) : (
              <span className="text-zinc-400">
                Completed — No threat signature matched baseline deviation threshold.
              </span>
            )}
          </div>
          <Button
            size="sm"
            variant="outline"
            className="w-full border-zinc-700 bg-zinc-900 text-xs text-zinc-200 hover:bg-zinc-800"
            onClick={() => setView("dashboard")}
          >
            <LayoutDashboard className="mr-1.5 h-3.5 w-3.5 text-emerald-400" aria-hidden />
            View Incident on SOC Dashboard
          </Button>
        </div>
      )}

      {/* Trigger Button */}
      <Button
        className={cn(
          "mt-4 w-full text-xs sm:text-sm font-semibold transition-all shadow-sm",
          running
            ? "bg-zinc-800 text-zinc-400 cursor-not-allowed"
            : "bg-emerald-600 text-white hover:bg-emerald-500",
        )}
        disabled={running}
        onClick={() => void runSimulation(type).catch(() => undefined)}
        aria-label={`Run safe synthetic ${scenario.name} test`}
      >
        {running ? (
          "Streaming synthetic windows…"
        ) : sim && !sim.error ? (
          <>
            <RotateCcw className="mr-1.5 h-4 w-4" aria-hidden /> Re-run Safe Test
          </>
        ) : (
          <>
            <Play className="mr-1.5 h-4 w-4" aria-hidden /> Launch Safe Test
          </>
        )}
      </Button>
    </div>
  );
}

export function TestLabView() {
  const scenarios = useSentinelStore((s) => s.scenarios);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Security Test Lab
          </h1>
          <span className="rounded bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 text-xs font-mono font-semibold text-amber-400">
            Safe Mode
          </span>
        </div>
        <p className="mt-1 text-sm text-zinc-400 leading-relaxed">
          Execute controlled synthetic intrusion scenarios to demonstrate real-time AI Sentinel detection, IsolationForest anomaly scoring, and automated alert escalation.
        </p>
      </div>

      {/* Safety Demonstration Environment Banner */}
      <div
        className="flex items-start gap-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 shadow-sm"
        role="note"
      >
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" aria-hidden />
        <div className="text-xs sm:text-sm space-y-1">
          <p className="font-bold text-emerald-400">
            Safe Demonstration Environment — Synthetic Feature Stream
          </p>
          <p className="leading-relaxed text-zinc-300">
            <strong>Simulations generate synthetic traffic patterns and do not attack external systems.</strong> No raw offensive packets leave this process. Each test crafts feature vectors mathematically modeled after documented attack signatures (CIC-IDS2017 profiles) and feeds them through the live Python RandomForest + IsolationForest classification pipeline.
          </p>
        </div>
      </div>

      {/* Scenarios Grid */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {scenarios.map((s) => (
          <ScenarioCard key={s.type} type={s.type} />
        ))}
        {scenarios.length === 0 && (
          <>
            {[1, 2, 3].map((i) => (
              <div key={i} className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-3">
                <Skeleton className="h-6 w-32 bg-zinc-800" />
                <Skeleton className="h-4 w-48 bg-zinc-800" />
                <Skeleton className="h-16 w-full bg-zinc-800" />
                <Skeleton className="h-9 w-full bg-zinc-800" />
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

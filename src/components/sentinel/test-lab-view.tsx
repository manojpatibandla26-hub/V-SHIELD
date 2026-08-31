"use client";
/**
 * AI Sentinel — Security Test Lab.
 * Safe, synthetic attack scenarios. Scenario metadata (names, descriptions)
 * comes from the BACKEND (/api/simulation/types) — not hard-coded copy.
 * Progress reflects actual backend sim_progress events.
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
} from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { SeverityBadge } from "./bits";
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
  const runSimulation = useSentinelStore((s) => s.runSimulation);
  const setView = useSentinelStore((s) => s.setView);

  const scenario = scenarios.find((s) => s.type === type);
  const Icon = SCENARIO_ICONS[type] ?? Ghost;

  // the most recent sim for this scenario type
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

  return (
    <div className="flex flex-col rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-800 text-zinc-300">
          <Icon className="h-5 w-5" aria-hidden />
        </div>
        <div className="min-w-0">
          <h3 className="font-semibold text-zinc-100">{scenario.name}</h3>
          <p className="mt-0.5 text-xs text-zinc-500">{scenario.tagline}</p>
        </div>
      </div>

      <p className="mt-3 flex-1 text-sm leading-relaxed text-zinc-400">
        {scenario.description}
      </p>

      <p className="mt-3 text-xs text-zinc-600">
        <span className="font-medium text-zinc-500">Expected result:</span>{" "}
        {scenario.expected}
      </p>

      {sim && (running || sim.error) && (
        <div className="mt-4 space-y-2">
          {sim.error ? (
            <p className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-300">
              <AlertCircle className="h-4 w-4 shrink-0" aria-hidden />
              {sim.error}
            </p>
          ) : (
            <>
              <Progress
                value={pct}
                className="h-1.5 bg-zinc-800 [&>div]:bg-emerald-500"
                aria-label={`${scenario.name} progress`}
              />
              <div className="flex items-center justify-between text-xs text-zinc-500">
                <span>
                  {sim.phase === "mitigating"
                    ? "Recovering after simulated block…"
                    : `Analyzing window ${sim.windows_done}/${sim.windows_total} through the ML pipeline…`}
                </span>
                <span className="font-mono tabular-nums">{pct}%</span>
              </div>
            </>
          )}
        </div>
      )}

      {sim && !running && !sim.error && (sim.phase === "complete" || sim.phase === "mitigated") && (
        <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
          <div className="flex items-center gap-2 text-xs">
            {sim.detected ? (
              <>
                <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden />
                <span className="text-zinc-300">
                  Threat detected — final risk {sim.final_risk}/100
                </span>
                {sim.final_severity && (
                  <SeverityBadge severity={sim.final_severity} />
                )}
              </>
            ) : (
              <span className="text-zinc-400">
                Completed — no threat signature matched this run.
              </span>
            )}
          </div>
          <Button
            size="sm"
            variant="outline"
            className="mt-2.5 border-zinc-700 bg-transparent text-zinc-300 hover:bg-zinc-800"
            onClick={() => setView("dashboard")}
          >
            <LayoutDashboard className="mr-1.5 h-3.5 w-3.5" aria-hidden />
            View on Dashboard
          </Button>
        </div>
      )}

      <Button
        className={cn(
          "mt-4 w-full",
          running
            ? "bg-zinc-800 text-zinc-400"
            : "bg-emerald-600 text-white hover:bg-emerald-500",
        )}
        disabled={running}
        onClick={() => void runSimulation(type).catch(() => undefined)}
        aria-label={`Run safe ${scenario.name} test`}
      >
        {running ? (
          "Running safe test…"
        ) : sim && !sim.error ? (
          <>
            <RotateCcw className="mr-1.5 h-4 w-4" aria-hidden /> Run Safe Test
          </>
        ) : (
          <>
            <Play className="mr-1.5 h-4 w-4" aria-hidden /> Run Safe Test
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
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Security Test Lab
        </h1>
        <p className="mt-1 text-sm text-zinc-400">
          Run safe synthetic scenarios to demonstrate how AI Sentinel detects
          network threats. Every scenario streams through the real ML
          pipeline — the results you see are live model output.
        </p>
      </div>

      <div
        className="flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4"
        role="note"
      >
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" aria-hidden />
        <div className="text-sm">
          <p className="font-semibold text-emerald-400">
            Safe security simulation
          </p>
          <p className="mt-0.5 leading-relaxed text-zinc-400">
            No real attack tools are used, no packets are sent to any network,
            and no real hosts are targeted. Each scenario generates synthetic
            traffic statistics with the documented characteristics of that
            attack class, then feeds them through the same RandomForest +
            IsolationForest pipeline used for real traffic.
          </p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {scenarios.map((s) => (
          <ScenarioCard key={s.type} type={s.type} />
        ))}
        {scenarios.length === 0 && (
          <div className="col-span-full rounded-xl border border-dashed border-zinc-800 p-8 text-center text-sm text-zinc-500">
            Loading scenarios from backend…
          </div>
        )}
      </div>
    </div>
  );
}

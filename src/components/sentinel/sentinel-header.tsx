"use client";
/**
 * AI Sentinel — header: identity, live system status, model badge, clock,
 * and the global Reset Demo action.
 * All status comes from the backend (health + WS), never hard-coded.
 */
import { useEffect, useState } from "react";
import { ShieldCheck, Radio, Cpu, FlaskConical, RotateCcw } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { ViewTabs } from "./sentinel-app";
import { cn } from "@/lib/utils";
import type { ViewName, WsStatus } from "@/lib/sentinel/types";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

const WS_LABEL: Record<WsStatus, string> = {
  connected: "Live",
  connecting: "Connecting",
  reconnecting: "Reconnecting",
  polling: "Fallback polling",
  offline: "Offline",
};

const WS_COLOR: Record<WsStatus, string> = {
  connected: "bg-emerald-400",
  connecting: "bg-amber-400",
  reconnecting: "bg-amber-400",
  polling: "bg-orange-400",
  offline: "bg-rose-400",
};

export function SentinelHeader({
  nav,
  view,
  onNavigate,
}: {
  nav: { id: ViewName; label: string }[];
  view: ViewName;
  onNavigate: (v: ViewName) => void;
}) {
  const wsStatus = useSentinelStore((s) => s.wsStatus);
  const backendOnline = useSentinelStore((s) => s.backendOnline);
  const modelInfo = useSentinelStore((s) => s.modelInfo);
  const resetDemo = useSentinelStore((s) => s.resetDemo);
  const [clock, setClock] = useState<string>("");
  const [resetOpen, setResetOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  useEffect(() => {
    const tick = () =>
      setClock(new Date().toLocaleTimeString("en-GB", { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const modelOk = modelInfo !== null;

  const doReset = async () => {
    setResetting(true);
    try {
      await resetDemo();
    } finally {
      setResetting(false);
    }
  };

  return (
    <header className="sticky top-0 z-40 border-b border-zinc-800 bg-zinc-950/90 backdrop-blur">
      <div className="mx-auto w-full max-w-7xl px-4 py-3 sm:px-6">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-400">
              <ShieldCheck className="h-6 w-6" aria-hidden />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight tracking-tight">
                AI Sentinel
              </h1>
              <p className="text-xs text-zinc-500">
                AI-Powered Network Intrusion Detection
              </p>
            </div>
          </div>

          <div className="ml-auto flex flex-wrap items-center gap-2 text-xs">
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-medium",
                backendOnline === false
                  ? "border-rose-500/30 bg-rose-500/10 text-rose-400"
                  : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
              )}
              role="status"
              aria-label={`Backend ${backendOnline === false ? "offline" : "online"}`}
            >
              <Radio className="h-3.5 w-3.5" aria-hidden />
              Backend {backendOnline === false ? "offline" : "online"}
            </span>

            <span
              className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-300"
              role="status"
              aria-label="ML engine status"
            >
              <Cpu className="h-3.5 w-3.5 text-emerald-400" aria-hidden />
              {modelOk ? (
                <>
                  ML Engine online · {modelInfo.algorithm}{" "}
                  {modelInfo.model_version}
                </>
              ) : (
                "ML Engine loading…"
              )}
            </span>

            <span
              className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-300"
              role="status"
              aria-label="Data mode"
              title="All traffic in this demo is synthetic"
            >
              <FlaskConical className="h-3.5 w-3.5 text-amber-400" aria-hidden />
              Synthetic data
            </span>

            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1",
                wsStatus === "connected" ? "text-zinc-300" : "text-amber-400",
              )}
              role="status"
              aria-label={`WebSocket ${wsStatus}`}
            >
              <span className={cn("h-2 w-2 animate-pulse rounded-full", WS_COLOR[wsStatus])} />
              {WS_LABEL[wsStatus]}
            </span>

            <span className="rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono tabular-nums text-zinc-400">
              {clock}
            </span>

            {/* Reset Demo — global, clearly visible on every view */}
            <AlertDialog open={resetOpen} onOpenChange={setResetOpen}>
              <AlertDialogTrigger asChild>
                <button
                  type="button"
                  disabled={resetting}
                  aria-label="Reset demo state"
                  title="Reset demo state: clears events, alerts and blocked sources"
                  className={cn(
                    "inline-flex min-h-[32px] items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-semibold transition-colors",
                    "border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20",
                    "disabled:cursor-not-allowed disabled:opacity-60",
                  )}
                >
                  <RotateCcw
                    className={cn("h-3.5 w-3.5", resetting && "animate-spin")}
                    aria-hidden
                  />
                  {resetting ? "Resetting…" : "Reset Demo"}
                </button>
              </AlertDialogTrigger>
              <AlertDialogContent className="border-zinc-800 bg-zinc-950 text-zinc-100">
                <AlertDialogHeader>
                  <AlertDialogTitle>Reset demo state?</AlertDialogTitle>
                  <AlertDialogDescription className="text-zinc-400">
                    This clears all threat events, alerts, blocked sources and
                    running simulations, and returns the dashboard to the clean
                    PROTECTED baseline. The ML models, PCAP files and baseline
                    traffic engine are untouched.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel className="border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100">
                    Cancel
                  </AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => void doReset()}
                    className="bg-amber-600 text-white hover:bg-amber-500"
                  >
                    Reset now
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </div>

        <div className="mt-3">
          <ViewTabs nav={nav} view={view} onNavigate={onNavigate} />
        </div>
      </div>
    </header>
  );
}

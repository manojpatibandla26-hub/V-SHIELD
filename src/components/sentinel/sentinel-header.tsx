"use client";
/**
 * AI Sentinel — header: identity, live system status, model badge, clock,
 * user authentication state, and the global Reset Demo action.
 * All status comes from the backend (health + WS), never hard-coded.
 */
import { useEffect, useState } from "react";
import { ShieldCheck, Radio, Cpu, FlaskConical, RotateCcw, UserCheck, LogOut, RefreshCw, LogIn } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { ViewTabs } from "./sentinel-app";
import { LivePulse } from "./bits";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const WS_LABEL: Record<WsStatus, string> = {
  connected: "Live Stream",
  connecting: "Connecting",
  reconnecting: "Reconnecting",
  polling: "Fallback Polling",
  offline: "Offline",
};

const WS_COLOR: Record<WsStatus, string> = {
  connected: "bg-emerald-400",
  connecting: "bg-amber-400",
  reconnecting: "bg-amber-400",
  polling: "bg-orange-400",
  offline: "bg-rose-400",
};

function HeaderClock() {
  const [clock, setClock] = useState<string>("");
  useEffect(() => {
    const tick = () =>
      setClock(new Date().toLocaleTimeString("en-GB", { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <span className="hidden sm:inline-block rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 font-mono tabular-nums text-zinc-400">
      {clock}
    </span>
  );
}

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
  const retryConnection = useSentinelStore((s) => s.retryConnection);
  const user = useSentinelStore((s) => s.user);
  const setAuthModalOpen = useSentinelStore((s) => s.setAuthModalOpen);
  const logout = useSentinelStore((s) => s.logout);

  const [resetOpen, setResetOpen] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [retrying, setRetrying] = useState(false);

  const modelOk = modelInfo !== null;

  const doReset = async () => {
    setResetting(true);
    try {
      await resetDemo();
    } finally {
      setResetting(false);
    }
  };

  const doRetry = async () => {
    setRetrying(true);
    try {
      await retryConnection();
    } finally {
      setRetrying(false);
    }
  };

  return (
    <header className="sticky top-0 z-40 border-b border-zinc-800 bg-zinc-950/90 backdrop-blur shadow-sm">
      <div className="mx-auto w-full max-w-7xl px-4 py-2.5 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-y-2.5 gap-x-4">
          {/* Logo & Identity */}
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 shadow-inner">
              <ShieldCheck className="h-6 w-6" aria-hidden />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold leading-tight tracking-tight text-zinc-100">
                  AI Sentinel
                </h1>
                <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 text-[10px] font-mono font-semibold text-emerald-400">
                  SOC v1.0
                </span>
              </div>
              <p className="text-xs text-zinc-400">
                AI-Powered Network Intrusion Detection System
              </p>
            </div>
          </div>

          {/* System Status Indicators & Actions */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Backend Status */}
            {backendOnline === false ? (
              <button
                onClick={doRetry}
                disabled={retrying}
                title="Click to retry backend connection"
                className="inline-flex items-center gap-1.5 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 font-medium text-rose-300 hover:bg-rose-500/20 transition-colors"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", retrying && "animate-spin")} />
                Backend offline · Retry
              </button>
            ) : (
              <span
                className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 font-medium text-emerald-400"
                role="status"
                aria-label="Backend online"
              >
                <Radio className="h-3.5 w-3.5" aria-hidden />
                Backend online
              </span>
            )}

            {/* ML Engine Status */}
            <span
              className="hidden sm:inline-flex items-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 text-zinc-300"
              role="status"
              aria-label="ML engine status"
            >
              <Cpu className="h-3.5 w-3.5 text-emerald-400" aria-hidden />
              {modelOk ? (
                <span>
                  ML: {modelInfo.algorithm.replace("Classifier", "")} {modelInfo.model_version}
                </span>
              ) : (
                <span className="text-zinc-500">ML: loading…</span>
              )}
            </span>

            {/* Synthetic Data Badge */}
            <span
              className="hidden md:inline-flex items-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 text-zinc-300"
              role="status"
              aria-label="Data mode"
              title="All traffic in this demo is synthetic / offline PCAP"
            >
              <FlaskConical className="h-3.5 w-3.5 text-amber-400" aria-hidden />
              Synthetic Mode
            </span>

            {/* Live WebSocket Status */}
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-medium",
                wsStatus === "connected"
                  ? "border-zinc-800 bg-zinc-900 text-zinc-300"
                  : "border-amber-500/40 bg-amber-500/10 text-amber-300",
              )}
              role="status"
              aria-label={`WebSocket ${wsStatus}`}
            >
              <LivePulse active={wsStatus === "connected"} color={WS_COLOR[wsStatus]} />
              {WS_LABEL[wsStatus]}
            </span>

            {/* Digital SOC Clock */}
            <HeaderClock />

            {/* User Profile / Auth */}
            {user ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button
                    className="inline-flex items-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1 text-xs text-zinc-200 hover:border-zinc-700 hover:bg-zinc-850 transition-colors"
                    aria-label="User account menu"
                  >
                    <UserCheck className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="max-w-[100px] truncate font-medium">{user.name}</span>
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="border-zinc-800 bg-zinc-950 text-zinc-200">
                  <DropdownMenuLabel className="font-normal text-xs">
                    <div className="font-semibold text-zinc-100">{user.name}</div>
                    <div className="text-zinc-500 truncate">{user.email}</div>
                    <div className="mt-1 inline-block rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-emerald-400 font-mono">
                      {user.role}
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator className="bg-zinc-800" />
                  <DropdownMenuItem
                    onClick={logout}
                    className="text-xs text-rose-400 focus:bg-rose-500/10 focus:text-rose-300 cursor-pointer"
                  >
                    <LogOut className="mr-2 h-3.5 w-3.5" /> Sign Out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : (
              <button
                onClick={() => setAuthModalOpen(true)}
                className="inline-flex items-center gap-1 rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1 text-xs text-zinc-300 hover:bg-zinc-800 transition-colors"
              >
                <LogIn className="h-3.5 w-3.5 text-zinc-400" /> Sign In
              </button>
            )}

            {/* Reset Demo — Global Dialog */}
            <AlertDialog open={resetOpen} onOpenChange={setResetOpen}>
              <AlertDialogTrigger asChild>
                <button
                  type="button"
                  disabled={resetting}
                  aria-label="Reset demo state"
                  title="Reset demo state: clears events, alerts and blocked sources"
                  className={cn(
                    "inline-flex min-h-[30px] items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold transition-colors shadow-sm",
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
                  <AlertDialogTitle className="text-lg font-bold">Reset demo state?</AlertDialogTitle>
                  <AlertDialogDescription className="text-zinc-400 text-sm leading-relaxed">
                    This clears all threat events, alerts, blocked sources, and
                    running simulations, returning the dashboard to the clean
                    <strong> PROTECTED</strong> baseline. The ML models, PCAP files, and baseline
                    traffic engine remain active.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel className="border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100">
                    Cancel
                  </AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => void doReset()}
                    className="bg-amber-600 font-semibold text-white hover:bg-amber-500"
                  >
                    Reset Baseline Now
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </div>

        {/* View Navigation Tabs */}
        <div className="mt-2.5 pt-1 border-t border-zinc-900">
          <ViewTabs nav={nav} view={view} onNavigate={onNavigate} />
        </div>
      </div>
    </header>
  );
}

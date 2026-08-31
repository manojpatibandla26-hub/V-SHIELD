"use client";
/**
 * AI Sentinel — header: identity, live system status, model badge, clock.
 * All status comes from the backend (health + WS), never hard-coded.
 */
import { useEffect, useState } from "react";
import { ShieldCheck, Radio, Cpu, FlaskConical } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { ViewTabs } from "./sentinel-app";
import { cn } from "@/lib/utils";
import type { ViewName, WsStatus } from "@/lib/sentinel/types";

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
  const [clock, setClock] = useState<string>("");

  useEffect(() => {
    const tick = () =>
      setClock(new Date().toLocaleTimeString("en-GB", { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const modelOk = modelInfo !== null;

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
          </div>
        </div>

        <div className="mt-3">
          <ViewTabs nav={nav} view={view} onNavigate={onNavigate} />
        </div>
      </div>
    </header>
  );
}

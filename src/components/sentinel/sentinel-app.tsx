"use client";
/**
 * AI Sentinel — application shell.
 * Single-route SOC application: header + nav + view + sticky footer + auth modal.
 */
import { useEffect } from "react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { useSentinelWebSocket } from "@/hooks/use-sentinel-websocket";
import { DashboardView } from "./dashboard-view";
import { TestLabView } from "./test-lab-view";
import { PcapView } from "./pcap-view";
import { ArchitectureView } from "./architecture-view";
import { ModelView } from "./model-view";
import { AlertToasts } from "./alert-toasts";
import { SentinelHeader } from "./sentinel-header";
import { AuthModal } from "./auth-modal";
import type { ViewName } from "@/lib/sentinel/types";
import { cn } from "@/lib/utils";

const NAV: { id: ViewName; label: string; shortcut: string }[] = [
  { id: "dashboard", label: "Dashboard", shortcut: "1" },
  { id: "lab", label: "Security Test Lab", shortcut: "2" },
  { id: "pcap", label: "PCAP Analysis", shortcut: "3" },
  { id: "architecture", label: "Architecture", shortcut: "4" },
  { id: "model", label: "ML Model", shortcut: "5" },
];

export function SentinelApp() {
  useSentinelWebSocket();
  const view = useSentinelStore((s) => s.view);
  const setView = useSentinelStore((s) => s.setView);
  const initialize = useSentinelStore((s) => s.initialize);

  useEffect(() => {
    void initialize();
    const refresh = setInterval(() => {
      void useSentinelStore.getState().refreshStatistics();
      void useSentinelStore.getState().refreshEvents();
    }, 15000);
    return () => clearInterval(refresh);
  }, []);

  // Keyboard navigation shortcuts (1-5 for views)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if user is typing in an input or textarea
      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA" ||
        document.activeElement?.tagName === "SELECT"
      ) {
        return;
      }

      if (e.key === "1") setView("dashboard");
      else if (e.key === "2") setView("lab");
      else if (e.key === "3") setView("pcap");
      else if (e.key === "4") setView("architecture");
      else if (e.key === "5") setView("model");
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [setView]);

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100 selection:bg-emerald-500/30 selection:text-emerald-200">
      <SentinelHeader nav={NAV} view={view} onNavigate={setView} />

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 pb-12 pt-6 sm:px-6">
        {view === "dashboard" && <DashboardView />}
        {view === "lab" && <TestLabView />}
        {view === "pcap" && <PcapView />}
        {view === "architecture" && <ArchitectureView />}
        {view === "model" && <ModelView />}
      </main>

      <footer className="mt-auto border-t border-zinc-800/80 bg-zinc-950/95 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-2 px-4 py-4 text-xs text-zinc-500 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <p>
            AI Sentinel — Educational NIDS SOC Prototype. All traffic shown is synthetic, simulated, or parsed from offline PCAP captures.
          </p>
          <div className="flex items-center gap-3 shrink-0 text-[11px] font-mono">
            <span>RandomForest v1.0</span>
            <span>·</span>
            <span>IsolationForest</span>
            <span>·</span>
            <span>FastAPI</span>
            <span>·</span>
            <span>Next.js 16</span>
          </div>
        </div>
      </footer>

      <AlertToasts />
      <AuthModal />
    </div>
  );
}

export function ViewTabs({
  nav,
  view,
  onNavigate,
}: {
  nav: { id: ViewName; label: string; shortcut?: string }[];
  view: ViewName;
  onNavigate: (v: ViewName) => void;
}) {
  return (
    <nav aria-label="Application sections" className="flex gap-1 overflow-x-auto soc-scroll pb-1">
      {nav.map((item) => (
        <button
          key={item.id}
          role="tab"
          aria-selected={view === item.id}
          onClick={() => onNavigate(item.id)}
          className={cn(
            "group relative whitespace-nowrap rounded-lg px-3.5 py-1.5 text-xs sm:text-sm font-semibold transition-all flex items-center gap-1.5",
            view === item.id
              ? "bg-zinc-850 text-emerald-400 border border-zinc-700/80 shadow-inner"
              : "text-zinc-400 hover:bg-zinc-900/80 hover:text-zinc-200",
          )}
        >
          {item.label}
          {item.shortcut && (
            <span
              className={cn(
                "hidden md:inline-block rounded px-1 py-0.2 text-[9px] font-mono font-normal opacity-40 group-hover:opacity-70 transition-opacity",
                view === item.id ? "bg-zinc-800 text-emerald-300" : "bg-zinc-900 text-zinc-400",
              )}
            >
              {item.shortcut}
            </span>
          )}
        </button>
      ))}
    </nav>
  );
}

"use client";
/**
 * AI Sentinel — application shell.
 * Single-route SOC application: header + nav + view + sticky footer.
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
import type { ViewName } from "@/lib/sentinel/types";
import { cn } from "@/lib/utils";

const NAV: { id: ViewName; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "lab", label: "Security Test Lab" },
  { id: "pcap", label: "PCAP Analysis" },
  { id: "architecture", label: "Architecture" },
  { id: "model", label: "ML Model" },
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

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      <SentinelHeader nav={NAV} view={view} onNavigate={setView} />

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 pb-10 pt-6 sm:px-6">
        {view === "dashboard" && <DashboardView />}
        {view === "lab" && <TestLabView />}
        {view === "pcap" && <PcapView />}
        {view === "architecture" && <ArchitectureView />}
        {view === "model" && <ModelView />}
      </main>

      <footer className="mt-auto border-t border-zinc-800 bg-zinc-950/95">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-1 px-4 py-4 text-xs text-zinc-500 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <p>
            AI Sentinel — educational prototype. All traffic shown is
            synthetic, simulated, or read from offline PCAP files. No real
            networks are attacked, and &quot;Block Source&quot; is a
            simulation only.
          </p>
          <p className="shrink-0">
            RandomForest v1.0 · IsolationForest · FastAPI · Next.js
          </p>
        </div>
      </footer>

      <AlertToasts />
    </div>
  );
}

export function ViewTabs({
  nav,
  view,
  onNavigate,
}: {
  nav: { id: ViewName; label: string }[];
  view: ViewName;
  onNavigate: (v: ViewName) => void;
}) {
  return (
    <nav aria-label="Application sections" className="flex gap-1 overflow-x-auto">
      {nav.map((item) => (
        <button
          key={item.id}
          role="tab"
          aria-selected={view === item.id}
          onClick={() => onNavigate(item.id)}
          className={cn(
            "whitespace-nowrap rounded-lg px-3 py-1.5 text-sm font-medium transition-colors",
            view === item.id
              ? "bg-zinc-800 text-zinc-100"
              : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200",
          )}
        >
          {item.label}
        </button>
      ))}
    </nav>
  );
}

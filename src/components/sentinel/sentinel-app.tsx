"use client";
/**
 * AI Sentinel — application shell.
 * Single-route SOC application: header + nav + view + sticky footer + auth modal.
 */
import { useEffect } from "react";
import { Loader2, Shield, Lock, LogIn, Sparkles } from "lucide-react";
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
import { Button } from "@/components/ui/button";
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
  const user = useSentinelStore((s) => s.user);
  const authLoading = useSentinelStore((s) => s.authLoading);
  const setAuthModalOpen = useSentinelStore((s) => s.setAuthModalOpen);

  useEffect(() => {
    void initialize();
    const refresh = setInterval(() => {
      void useSentinelStore.getState().refreshStatistics();
      void useSentinelStore.getState().refreshEvents();
    }, 15000);
    return () => clearInterval(refresh);
  }, [initialize]);

  // Keyboard navigation shortcuts (1-5 for views)
  useEffect(() => {
    if (!user) return;
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
  }, [setView, user]);

  // 1. Initial auth loading state — prevents dashboard flash
  if (authLoading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-zinc-950 text-zinc-100 p-4">
        <div className="flex flex-col items-center gap-4 text-center">
          <div className="relative flex h-16 w-16 items-center justify-center rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Shield className="h-8 w-8 animate-pulse" />
          </div>
          <div className="space-y-1">
            <h2 className="text-lg font-bold tracking-tight text-zinc-200">
              V-SHIELD Security Operations Center
            </h2>
            <p className="flex items-center justify-center gap-2 text-xs text-zinc-500 font-mono">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald-400" />
              Verifying Supabase authentication session…
            </p>
          </div>
        </div>
      </div>
    );
  }

  // 2. Unauthenticated Protected View — displays SOC login portal
  if (!user) {
    return (
      <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100 selection:bg-emerald-500/30 selection:text-emerald-200">
        <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur px-6 py-4">
          <div className="mx-auto flex max-w-7xl items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <span className="font-bold text-sm text-zinc-100 tracking-tight">V-SHIELD</span>
                <span className="text-[10px] text-zinc-500 font-mono ml-2">AI-Powered NIDS</span>
              </div>
            </div>
            <Button
              size="sm"
              onClick={() => setAuthModalOpen(true)}
              className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
            >
              <LogIn className="mr-1.5 h-3.5 w-3.5" /> Sign In
            </Button>
          </div>
        </header>

        <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col items-center justify-center px-4 py-16 text-center">
          <div className="max-w-md space-y-6 rounded-2xl border border-zinc-800 bg-zinc-900/60 p-8 shadow-2xl backdrop-blur">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-zinc-800/80 border border-zinc-700 text-amber-400">
              <Lock className="h-7 w-7" />
            </div>

            <div className="space-y-2">
              <h1 className="text-xl font-bold tracking-tight text-zinc-100">
                SOC Authentication Required
              </h1>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Access to live network packet telemetry, intrusion classification models, PCAP traces, and security countermeasures requires an authorized SOC account.
              </p>
            </div>

            <div className="space-y-2.5 pt-2">
              <Button
                onClick={() => setAuthModalOpen(true)}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-sm shadow-md"
              >
                <LogIn className="mr-2 h-4 w-4" /> Sign In / Create Account
              </Button>
            </div>
          </div>
        </main>

        <footer className="border-t border-zinc-800/80 bg-zinc-950/95 py-4 text-center text-xs text-zinc-600">
          V-SHIELD — Advanced AI Network Intrusion Detection System · Protected by Supabase Auth
        </footer>

        <AuthModal />
      </div>
    );
  }

  // 3. Authenticated Dashboard Application
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
            V-SHIELD — AI-Powered Network Intrusion Detection System. Real-time Scapy capture + Random Forest inference.
          </p>
          <div className="flex items-center gap-3 shrink-0 text-[11px] font-mono">
            <span>RandomForest v1.0</span>
            <span>·</span>
            <span>IsolationForest</span>
            <span>·</span>
            <span>FastAPI</span>
            <span>·</span>
            <span>Supabase Auth</span>
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

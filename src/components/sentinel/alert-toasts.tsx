"use client";
/**
 * AI Sentinel — live alert toasts (bottom-right, severity colored).
 * Fired by the backend's severity-aware alert stream; clicking opens the
 * threat on the dashboard.
 */
import { useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Bell, X, ChevronRight, ShieldAlert } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { SEVERITY_STYLE } from "./bits";
import type { AlertToastItem } from "@/lib/sentinel/types";

function Toast({ alert }: { alert: AlertToastItem }) {
  const dismiss = useSentinelStore((s) => s.dismissAlert);
  const selectEvent = useSentinelStore((s) => s.selectEvent);
  const setView = useSentinelStore((s) => s.setView);

  const lifetime = alert.severity === "CRITICAL" ? 14000 : 9000;
  useEffect(() => {
    const t = setTimeout(() => dismiss(alert.key), lifetime);
    return () => clearTimeout(t);
  }, [alert.key, lifetime, dismiss]);

  const sev = SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE.LOW;
  const age = Math.max(0, Date.now() / 1000 - alert.ts);
  const isCritical = alert.severity === "CRITICAL";

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 50, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 50, scale: 0.95 }}
      transition={{ type: "spring", stiffness: 400, damping: 30 }}
      className={cn(
        "pointer-events-auto w-84 cursor-pointer rounded-xl border bg-zinc-950/95 p-3.5 shadow-2xl backdrop-blur transition-all",
        "hover:border-zinc-500",
        isCritical
          ? "border-rose-500/80 shadow-[0_0_25px_rgba(244,63,94,0.25)] ring-1 ring-rose-500/40"
          : alert.severity === "HIGH"
            ? "border-orange-500/60 shadow-[0_0_20px_rgba(249,115,22,0.2)]"
            : alert.severity === "MEDIUM"
              ? "border-amber-500/50"
              : "border-emerald-500/40",
      )}
      onClick={() => {
        selectEvent(alert.event_id);
        setView("dashboard");
        dismiss(alert.key);
      }}
      role="alert"
      aria-live="assertive"
    >
      <div className="flex items-start gap-3">
        <div
          className={cn(
            "mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border shadow-inner",
            sev.chip,
          )}
        >
          {isCritical ? (
            <ShieldAlert className="h-4 w-4 text-rose-400 animate-pulse" aria-hidden />
          ) : (
            <Bell className="h-4 w-4" aria-hidden />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className={cn("text-xs font-bold tracking-wide uppercase", sev.text)}>
              {alert.severity} INTRUSION ALERT
            </p>
            <span className="text-[10px] font-mono text-zinc-500 ml-auto">
              {age < 60 ? `${Math.round(age)}s ago` : "just now"}
            </span>
          </div>
          <p className="mt-0.5 truncate text-sm font-bold text-zinc-100">
            {alert.classification}
          </p>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">
            Risk: <span className="text-zinc-200 font-bold">{alert.risk}/100</span> · Src:{" "}
            <span className="text-zinc-300">{alert.source}</span>
          </p>
        </div>
        <div className="flex items-center gap-1">
          <button
            aria-label="Dismiss alert"
            onClick={(e) => {
              e.stopPropagation();
              dismiss(alert.key);
            }}
            className="rounded p-1 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200 transition-colors"
          >
            <X className="h-3.5 w-3.5" aria-hidden />
          </button>
        </div>
      </div>
    </motion.div>
  );
}

export function AlertToasts() {
  const alerts = useSentinelStore((s) => s.alerts);
  return (
    <div
      aria-label="Active live alerts"
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col-reverse gap-2.5 max-w-sm"
    >
      <AnimatePresence mode="popLayout">
        {alerts.map((a) => (
          <Toast key={a.key} alert={a} />
        ))}
      </AnimatePresence>
    </div>
  );
}

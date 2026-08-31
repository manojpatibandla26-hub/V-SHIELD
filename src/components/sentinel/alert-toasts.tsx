"use client";
/**
 * AI Sentinel — live alert toasts (bottom-right, severity colored).
 * Fired by the backend's severity-aware alert stream; clicking opens the
 * threat on the dashboard.
 */
import { useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Bell, X, ChevronRight } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { SEVERITY_STYLE } from "./bits";
import type { AlertToastItem } from "@/lib/sentinel/types";

function Toast({ alert }: { alert: AlertToastItem }) {
  const dismiss = useSentinelStore((s) => s.dismissAlert);
  const selectEvent = useSentinelStore((s) => s.selectEvent);
  const setView = useSentinelStore((s) => s.setView);

  const lifetime = alert.severity === "CRITICAL" ? 12000 : 8000;
  useEffect(() => {
    const t = setTimeout(() => dismiss(alert.key), lifetime);
    return () => clearTimeout(t);
  }, [alert.key]);

  const sev = SEVERITY_STYLE[alert.severity];
  const age = Math.max(0, Date.now() / 1000 - alert.ts);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 40, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 40, scale: 0.95 }}
      transition={{ type: "spring", stiffness: 400, damping: 30 }}
      className={cn(
        "pointer-events-auto w-80 cursor-pointer rounded-xl border bg-zinc-900/95 p-3 shadow-xl backdrop-blur",
        "hover:border-zinc-600",
        alert.severity === "CRITICAL"
          ? "border-rose-500/50"
          : alert.severity === "HIGH"
            ? "border-orange-500/50"
            : alert.severity === "MEDIUM"
              ? "border-amber-500/40"
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
      <div className="flex items-start gap-2.5">
        <div
          className={cn(
            "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg",
            sev.chip,
          )}
        >
          <Bell className="h-4 w-4" aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className={cn("text-xs font-bold tracking-wide", sev.text)}>
              {alert.severity} ALERT
            </p>
            <span className="text-[11px] text-zinc-500">
              {age < 60 ? `${Math.round(age)}s ago` : "just now"}
            </span>
          </div>
          <p className="mt-0.5 truncate text-sm font-medium text-zinc-100">
            {alert.classification} detected
          </p>
          <p className="text-xs text-zinc-400">
            Risk {alert.risk}/100 · confidence{" "}
            {(alert.confidence * 100).toFixed(0)}% ·{" "}
            <span className="font-mono">{alert.source}</span>
          </p>
        </div>
        <div className="flex items-center gap-1">
          <ChevronRight className="h-4 w-4 text-zinc-600" aria-hidden />
          <button
            aria-label="Dismiss alert"
            onClick={(e) => {
              e.stopPropagation();
              dismiss(alert.key);
            }}
            className="rounded p-0.5 text-zinc-600 hover:text-zinc-300"
          >
            <X className="h-4 w-4" aria-hidden />
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
      aria-label="Active alerts"
      className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col-reverse gap-2"
    >
      <AnimatePresence mode="popLayout">
        {alerts.map((a) => (
          <Toast key={a.key} alert={a} />
        ))}
      </AnimatePresence>
    </div>
  );
}

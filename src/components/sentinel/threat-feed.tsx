"use client";
/**
 * AI Sentinel — live threat timeline / event history.
 */
import { useMemo, useState } from "react";
import { History, Inbox } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { fmtTimeAgo, SeverityBadge, STATUS_STYLE } from "./bits";
import { ATTACK_DISPLAY, type AttackLabel } from "@/lib/sentinel/types";

type Filter = "all" | "active" | "critical";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "active", label: "Active" },
  { id: "critical", label: "Critical" },
];

export function ThreatFeed() {
  const events = useSentinelStore((s) => s.events);
  const selectedEventId = useSentinelStore((s) => s.selectedEventId);
  const selectEvent = useSentinelStore((s) => s.selectEvent);
  const [filter, setFilter] = useState<Filter>("all");

  const filtered = useMemo(() => {
    const threats = events.filter((e) => e.attack !== "BENIGN");
    if (filter === "active")
      return threats.filter((e) => e.status === "ACTIVE");
    if (filter === "critical")
      return threats.filter((e) => e.severity === "CRITICAL");
    return threats;
  }, [events, filter]);

  return (
    <section
      aria-label="Threat timeline"
      className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-zinc-500" aria-hidden />
          <h2 className="text-sm font-semibold text-zinc-200">
            Threat Timeline
          </h2>
          <span className="rounded-md bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">
            {filtered.length}
          </span>
        </div>
        <div className="flex gap-1" role="tablist" aria-label="Filter events">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              role="tab"
              aria-selected={filter === f.id}
              onClick={() => setFilter(f.id)}
              className={cn(
                "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                filter === f.id
                  ? "bg-zinc-800 text-zinc-200"
                  : "text-zinc-500 hover:text-zinc-300",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-3 max-h-[420px] space-y-2 overflow-y-auto pr-1 soc-scroll">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-zinc-800 py-10 text-center">
            <Inbox className="h-8 w-8 text-zinc-700" aria-hidden />
            <p className="text-sm text-zinc-500">No threats detected</p>
            <p className="text-xs text-zinc-600">
              Normal traffic is flowing — the system is protected.
            </p>
          </div>
        ) : (
          filtered.map((ev) => {
            const selected = ev.id === selectedEventId;
            return (
              <button
                key={ev.id}
                onClick={() => selectEvent(ev.id)}
                aria-pressed={selected}
                className={cn(
                  "w-full rounded-lg border p-3 text-left transition-colors",
                  selected
                    ? "border-zinc-600 bg-zinc-800/80"
                    : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700 hover:bg-zinc-800/40",
                )}
              >
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={ev.severity} />
                  <span className="text-sm font-medium text-zinc-200">
                    {ATTACK_DISPLAY[ev.attack as AttackLabel] ?? ev.attack}
                  </span>
                  <span
                    className={cn(
                      "ml-auto rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase",
                      STATUS_STYLE[ev.status],
                    )}
                  >
                    {ev.status}
                  </span>
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-zinc-500">
                  <span className="font-mono">{ev.source}</span>
                  <span>risk {ev.risk}/100</span>
                  <span>conf {(ev.confidence * 100).toFixed(0)}%</span>
                  <span className="ml-auto">{fmtTimeAgo(ev.ts)}</span>
                </div>
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}

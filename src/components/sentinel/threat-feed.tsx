"use client";
/**
 * AI Sentinel — live threat timeline / event history.
 * Filterable, searchable, sortable incident stream with real-time WebSocket updates.
 */
import { useMemo, useState } from "react";
import { History, Inbox, Search, ArrowDownUp, Download, ShieldAlert, Target } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import { fmtTimeAgo, SeverityBadge, STATUS_STYLE, exportAsCsv, exportAsJson } from "./bits";
import { ATTACK_DISPLAY, type AttackLabel, type Severity } from "@/lib/sentinel/types";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

type FilterMode = "all" | "active" | "critical" | "high";
type SortMode = "newest" | "risk_desc" | "confidence_desc";

export function ThreatFeed() {
  const events = useSentinelStore((s) => s.events);
  const selectedEventId = useSentinelStore((s) => s.selectedEventId);
  const selectEvent = useSentinelStore((s) => s.selectEvent);

  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<FilterMode>("all");
  const [sort, setSort] = useState<SortMode>("newest");

  const filtered = useMemo(() => {
    let list = events.filter((e) => e.attack !== "BENIGN");

    // Filter mode
    if (filter === "active") {
      list = list.filter((e) => e.status === "ACTIVE");
    } else if (filter === "critical") {
      list = list.filter((e) => e.severity === "CRITICAL");
    } else if (filter === "high") {
      list = list.filter((e) => e.severity === "HIGH" || e.severity === "CRITICAL");
    }

    // Search query
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((e) => {
        const attackName = (ATTACK_DISPLAY[e.attack as AttackLabel] ?? e.attack).toLowerCase();
        const source = e.source.toLowerCase();
        const target = (e.target || "").toLowerCase();
        const classification = (e.explanation?.classification || "").toLowerCase();
        return attackName.includes(q) || source.includes(q) || target.includes(q) || classification.includes(q);
      });
    }

    // Sort order
    if (sort === "risk_desc") {
      list = [...list].sort((a, b) => b.risk - a.risk);
    } else if (sort === "confidence_desc") {
      list = [...list].sort((a, b) => b.confidence - a.confidence);
    } else {
      list = [...list].sort((a, b) => b.ts - a.ts);
    }

    return list;
  }, [events, filter, search, sort]);

  const handleExportJson = () => {
    exportAsJson(filtered, `ai-sentinel-incidents-${Date.now()}`);
  };

  const handleExportCsv = () => {
    const rows = filtered.map((e) => ({
      id: e.id,
      timestamp: new Date(e.ts * 1000).toISOString(),
      attack: e.attack,
      classification: ATTACK_DISPLAY[e.attack as AttackLabel] ?? e.attack,
      severity: e.severity,
      risk: e.risk,
      confidence: (e.confidence * 100).toFixed(1) + "%",
      status: e.status,
      source: e.source,
      target: e.target,
      anomaly_score: e.anomaly_score,
      model_version: e.model_version,
    }));
    exportAsCsv(rows, `ai-sentinel-incidents-${Date.now()}`);
  };

  return (
    <section
      aria-label="Incident Threat Timeline"
      className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5 shadow-sm space-y-3.5"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-emerald-400" aria-hidden />
          <h2 className="text-sm font-bold text-zinc-100">
            Threat Incident Stream
          </h2>
          <span className="rounded-full bg-zinc-800 border border-zinc-700/60 px-2 py-0.5 text-xs font-mono font-semibold text-zinc-300">
            {filtered.length}
          </span>
        </div>

        {/* Filter Pills & Export Dropdown */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5" role="tablist">
            {(
              [
                { id: "all", label: "All" },
                { id: "active", label: "Active" },
                { id: "high", label: "High+" },
                { id: "critical", label: "Critical" },
              ] as const
            ).map((f) => (
              <button
                key={f.id}
                role="tab"
                aria-selected={filter === f.id}
                onClick={() => setFilter(f.id)}
                className={cn(
                  "rounded-md px-2.5 py-0.5 text-xs font-medium transition-colors",
                  filter === f.id
                    ? "bg-zinc-800 text-zinc-100 shadow-sm"
                    : "text-zinc-500 hover:text-zinc-300",
                )}
              >
                {f.label}
              </button>
            ))}
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                aria-label="Export incident log"
                className="inline-flex items-center gap-1 rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
              >
                <Download className="h-3 w-3" />
                <span className="hidden sm:inline">Export</span>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="border-zinc-800 bg-zinc-950 text-zinc-200 text-xs">
              <DropdownMenuItem onClick={handleExportJson} className="cursor-pointer">
                Export Filtered as JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleExportCsv} className="cursor-pointer">
                Export Filtered as CSV
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Search & Sort Controls */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-zinc-500" />
          <Input
            type="text"
            placeholder="Search by IP, attack class, or target…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-8 border-zinc-800 bg-zinc-950/60 pl-8 text-xs text-zinc-200 placeholder:text-zinc-600 focus-visible:ring-emerald-500"
          />
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              aria-label="Sort options"
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-950/60 px-2.5 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 transition-colors"
            >
              <ArrowDownUp className="h-3 w-3" />
              <span className="hidden md:inline">
                {sort === "newest" ? "Newest" : sort === "risk_desc" ? "Risk (High→Low)" : "Confidence"}
              </span>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="border-zinc-800 bg-zinc-950 text-zinc-200 text-xs">
            <DropdownMenuItem onClick={() => setSort("newest")} className="cursor-pointer">
              Sort by Newest
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setSort("risk_desc")} className="cursor-pointer">
              Sort by Highest Risk Score
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setSort("confidence_desc")} className="cursor-pointer">
              Sort by ML Confidence
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Incident List */}
      <div className="max-h-[440px] space-y-2 overflow-y-auto pr-1 soc-scroll">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center gap-2.5 rounded-xl border border-dashed border-zinc-800/80 bg-zinc-950/20 py-12 text-center">
            <Inbox className="h-8 w-8 text-zinc-700" aria-hidden />
            <p className="text-sm font-medium text-zinc-400">
              {search ? "No matching threat events" : "No active threats detected"}
            </p>
            <p className="text-xs text-zinc-600 max-w-sm">
              {search
                ? "Try clearing the search query or adjusting the severity filter."
                : "Normal baseline traffic flowing — all monitored host-pairs are secure."}
            </p>
          </div>
        ) : (
          filtered.map((ev) => {
            const selected = ev.id === selectedEventId;
            const isCritical = ev.severity === "CRITICAL";
            return (
              <button
                key={ev.id}
                onClick={() => selectEvent(ev.id)}
                aria-pressed={selected}
                className={cn(
                  "w-full rounded-xl border p-3.5 text-left transition-all duration-200 group relative overflow-hidden",
                  selected
                    ? "border-emerald-500/60 bg-zinc-800/90 shadow-md ring-1 ring-emerald-500/30"
                    : isCritical
                      ? "border-rose-500/30 bg-rose-500/5 hover:border-rose-500/50 hover:bg-rose-500/10"
                      : "border-zinc-800/80 bg-zinc-900/40 hover:border-zinc-700 hover:bg-zinc-850/60",
                )}
              >
                {/* Header Row */}
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={ev.severity} />
                  <span className="text-sm font-semibold text-zinc-100 group-hover:text-white transition-colors">
                    {ATTACK_DISPLAY[ev.attack as AttackLabel] ?? ev.attack}
                  </span>
                  <span
                    className={cn(
                      "ml-auto rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider font-mono",
                      STATUS_STYLE[ev.status],
                    )}
                  >
                    {ev.status}
                  </span>
                </div>

                {/* Subtitle / Details */}
                <div className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs text-zinc-400">
                  <div className="flex items-center gap-1 font-mono text-[11px] truncate">
                    <span className="text-zinc-500">Src:</span>
                    <span className="text-zinc-300 truncate">{ev.source}</span>
                  </div>
                  {ev.target && (
                    <div className="flex items-center gap-1 font-mono text-[11px] truncate">
                      <Target className="h-3 w-3 text-zinc-500 shrink-0" />
                      <span className="text-zinc-300 truncate">{ev.target}</span>
                    </div>
                  )}
                  <div className="flex items-center gap-1">
                    <span className="text-zinc-500">Risk:</span>
                    <span className="font-semibold text-zinc-200">{ev.risk}/100</span>
                  </div>
                  <div className="flex items-center justify-end gap-1 text-[11px] text-zinc-500">
                    <span>{fmtTimeAgo(ev.ts)}</span>
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}

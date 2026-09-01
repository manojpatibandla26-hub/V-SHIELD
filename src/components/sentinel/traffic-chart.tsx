"use client";
/**
 * AI Sentinel — real-time traffic chart (recharts).
 * pkt/s, byte/s, flows, syn count area + risk 0-100 line with threshold reference lines.
 * Updates live via WS with configurable series toggles, history windows, and pause control.
 */
import { useMemo, useState } from "react";
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fmtClock, fmtNum, fmtBytes, LivePulse } from "./bits";
import { useSentinelStore } from "@/lib/sentinel/store";
import type { TrafficPoint } from "@/lib/sentinel/types";
import { Button } from "@/components/ui/button";
import { Pause, Play, Check } from "lucide-react";
import { cn } from "@/lib/utils";

type HistoryWindow = "30s" | "1m" | "5m";

export function TrafficChart({ data }: { data?: TrafficPoint[] }) {
  const storeTraffic = useSentinelStore((s) => s.traffic);
  const [showPkt, setShowPkt] = useState(true);
  const [showBytes, setShowBytes] = useState(false);
  const [showFlows, setShowFlows] = useState(false);
  const [showSyn, setShowSyn] = useState(false);
  const [showRisk, setShowRisk] = useState(true);
  const [showThresholds, setShowThresholds] = useState(true);
  const [historyWindow, setHistoryWindow] = useState<HistoryWindow>("1m");
  const [isPaused, setIsPaused] = useState(false);
  const [frozenData, setFrozenData] = useState<TrafficPoint[] | null>(null);

  const activeData = isPaused && frozenData ? frozenData : (data ?? storeTraffic);

  const chartData = useMemo(() => {
    let sliceCount = 60;
    if (historyWindow === "30s") sliceCount = 30;
    if (historyWindow === "5m") sliceCount = 150;

    return activeData.slice(-sliceCount).map((p) => ({
      ...p,
      time: fmtClock(p.t),
      synCountVal: p.synCount ?? 0,
      byteRateKb: p.byteRate ? Math.round(p.byteRate / 1024) : 0,
    }));
  }, [activeData, historyWindow]);

  const togglePause = () => {
    if (!isPaused) {
      setFrozenData([...data]);
      setIsPaused(true);
    } else {
      setIsPaused(false);
      setFrozenData(null);
    }
  };

  return (
    <section
      aria-label="Real-time traffic telemetry"
      className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5 shadow-sm space-y-4"
    >
      {/* Chart Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <LivePulse active={!isPaused} color={isPaused ? "bg-amber-400" : "bg-emerald-400"} />
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-zinc-100">
                Network Telemetry & Risk Stream
              </h2>
              {isPaused && (
                <span className="rounded bg-amber-500/10 border border-amber-500/30 px-1.5 py-0.2 text-[10px] text-amber-300 font-mono">
                  PAUSED
                </span>
              )}
            </div>
            <p className="text-xs text-zinc-400">
              Live packets/s, volume, active flows, and computed risk score over time
            </p>
          </div>
        </div>

        {/* Controls: History Window & Pause/Resume */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <div className="flex rounded-lg border border-zinc-800 bg-zinc-900 p-0.5" role="tablist" aria-label="History window">
            {(["30s", "1m", "5m"] as const).map((w) => (
              <button
                key={w}
                onClick={() => setHistoryWindow(w)}
                className={cn(
                  "rounded-md px-2 py-0.5 text-xs font-medium transition-colors",
                  historyWindow === w
                    ? "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300",
                )}
              >
                {w}
              </button>
            ))}
          </div>

          <Button
            size="sm"
            variant="outline"
            onClick={togglePause}
            className="h-7 border-zinc-800 bg-zinc-900 px-2.5 text-xs text-zinc-300 hover:bg-zinc-800"
          >
            {isPaused ? (
              <>
                <Play className="mr-1 h-3 w-3 text-emerald-400" /> Resume
              </>
            ) : (
              <>
                <Pause className="mr-1 h-3 w-3 text-amber-400" /> Pause
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Metric Toggle Filters */}
      <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-zinc-800/60 text-xs">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 mr-1">
          Metrics:
        </span>

        <button
          onClick={() => setShowPkt(!showPkt)}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
            showPkt
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
              : "border-zinc-800 bg-zinc-900/40 text-zinc-500 hover:text-zinc-300",
          )}
        >
          <span className="h-2 w-2 rounded-full bg-emerald-400" />
          Packets/s
        </button>

        <button
          onClick={() => setShowBytes(!showBytes)}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
            showBytes
              ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-300"
              : "border-zinc-800 bg-zinc-900/40 text-zinc-500 hover:text-zinc-300",
          )}
        >
          <span className="h-2 w-2 rounded-full bg-cyan-400" />
          KB/s
        </button>

        <button
          onClick={() => setShowFlows(!showFlows)}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
            showFlows
              ? "border-purple-500/40 bg-purple-500/10 text-purple-300"
              : "border-zinc-800 bg-zinc-900/40 text-zinc-500 hover:text-zinc-300",
          )}
        >
          <span className="h-2 w-2 rounded-full bg-purple-400" />
          Flows
        </button>

        <button
          onClick={() => setShowSyn(!showSyn)}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
            showSyn
              ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
              : "border-zinc-800 bg-zinc-900/40 text-zinc-500 hover:text-zinc-300",
          )}
        >
          <span className="h-2 w-2 rounded-full bg-amber-400" />
          SYNs
        </button>

        <button
          onClick={() => setShowRisk(!showRisk)}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
            showRisk
              ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
              : "border-zinc-800 bg-zinc-900/40 text-zinc-500 hover:text-zinc-300",
          )}
        >
          <span className="h-2 w-2 rounded-full bg-rose-400" />
          Risk (0-100)
        </button>

        <button
          onClick={() => setShowThresholds(!showThresholds)}
          className={cn(
            "ml-auto text-[11px] font-medium transition-colors",
            showThresholds ? "text-zinc-400 underline decoration-zinc-700" : "text-zinc-600",
          )}
        >
          {showThresholds ? "Hide Risk Thresholds" : "Show Thresholds"}
        </button>
      </div>

      {/* Recharts Canvas */}
      <div className="h-72 w-full pt-2">
        {chartData.length < 2 ? (
          <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-zinc-800 bg-zinc-950/30 text-sm text-zinc-500 font-mono">
            Connecting to telemetry pipeline…
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="pktFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="byteFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: "#71717a", fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: "#3f3f46" }}
                minTickGap={40}
              />
              <YAxis
                yAxisId="traffic"
                tick={{ fill: "#71717a", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                width={55}
                tickFormatter={(v: number) => fmtNum(v)}
              />
              <YAxis
                yAxisId="risk"
                orientation="right"
                domain={[0, 100]}
                ticks={[0, 25, 50, 75, 100]}
                tick={{ fill: "#71717a", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                width={36}
              />

              {showThresholds && (
                <>
                  <ReferenceLine
                    yAxisId="risk"
                    y={50}
                    stroke="#f59e0b"
                    strokeDasharray="3 3"
                    strokeOpacity={0.6}
                    label={{
                      value: "HIGH RISK (50)",
                      position: "insideTopRight",
                      fill: "#f59e0b",
                      fontSize: 9,
                      opacity: 0.8,
                    }}
                  />
                  <ReferenceLine
                    yAxisId="risk"
                    y={75}
                    stroke="#f43f5e"
                    strokeDasharray="3 3"
                    strokeOpacity={0.7}
                    label={{
                      value: "CRITICAL (75)",
                      position: "insideTopRight",
                      fill: "#f43f5e",
                      fontSize: 9,
                      opacity: 0.9,
                    }}
                  />
                </>
              )}

              <Tooltip
                contentStyle={{
                  background: "#09090b",
                  border: "1px solid #3f3f46",
                  borderRadius: 10,
                  fontSize: 12,
                  boxShadow: "0 10px 25px -5px rgba(0,0,0,0.5)",
                }}
                labelStyle={{ color: "#a1a1aa", fontWeight: 600, marginBottom: 4 }}
                formatter={(value: number, name: string) => {
                  if (name === "risk") return [`${value}/100`, "Risk Score"];
                  if (name === "pktRate") return [`${fmtNum(value)} pkt/s`, "Packet Rate"];
                  if (name === "byteRateKb") return [`${fmtNum(value)} KB/s`, "Bandwidth"];
                  if (name === "flows") return [value, "Active Flows"];
                  if (name === "synCountVal") return [value, "SYN Packets"];
                  return [value, name];
                }}
              />

              {showPkt && (
                <Area
                  yAxisId="traffic"
                  type="monotone"
                  dataKey="pktRate"
                  stroke="#10b981"
                  strokeWidth={1.75}
                  fill="url(#pktFill)"
                  isAnimationActive={false}
                  dot={false}
                  activeDot={{ r: 4, fill: "#10b981" }}
                />
              )}

              {showBytes && (
                <Area
                  yAxisId="traffic"
                  type="monotone"
                  dataKey="byteRateKb"
                  stroke="#06b6d4"
                  strokeWidth={1.5}
                  fill="url(#byteFill)"
                  isAnimationActive={false}
                  dot={false}
                />
              )}

              {showFlows && (
                <Line
                  yAxisId="traffic"
                  type="monotone"
                  dataKey="flows"
                  stroke="#c084fc"
                  strokeWidth={1.5}
                  dot={false}
                  isAnimationActive={false}
                />
              )}

              {showSyn && (
                <Line
                  yAxisId="traffic"
                  type="monotone"
                  dataKey="synCountVal"
                  stroke="#fbbf24"
                  strokeWidth={1.5}
                  dot={false}
                  isAnimationActive={false}
                />
              )}

              {showRisk && (
                <Line
                  yAxisId="risk"
                  type="monotone"
                  dataKey="risk"
                  stroke="#fb7185"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                  activeDot={{ r: 4, fill: "#fb7185" }}
                />
              )}
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}

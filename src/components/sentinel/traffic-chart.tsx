"use client";
/**
 * AI Sentinel — real-time traffic chart (recharts).
 * pkt/s area + risk 0-100 line on secondary axis. Updates live via WS.
 */
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fmtClock, fmtNum } from "./bits";
import type { TrafficPoint } from "@/lib/sentinel/types";

export function TrafficChart({ data }: { data: TrafficPoint[] }) {
  const chartData = data.map((p) => ({
    ...p,
    time: fmtClock(p.t),
  }));

  return (
    <section
      aria-label="Real-time traffic chart"
      className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-zinc-200">
            Network Traffic — real time
          </h2>
          <p className="text-xs text-zinc-500">
            Packets per second vs. risk score · live stream from the
            detection pipeline
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs text-zinc-500">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400" /> pkt/s
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-rose-400" /> risk (0-100)
          </span>
        </div>
      </div>

      <div className="mt-4 h-64 w-full">
        {chartData.length < 2 ? (
          <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-zinc-800 text-sm text-zinc-500">
            Waiting for live traffic…
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="pktFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#34d399" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#34d399" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: "#71717a", fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: "#3f3f46" }}
                minTickGap={48}
              />
              <YAxis
                yAxisId="pkt"
                tick={{ fill: "#71717a", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                width={52}
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
                width={34}
              />
              <Tooltip
                contentStyle={{
                  background: "#18181b",
                  border: "1px solid #3f3f46",
                  borderRadius: 8,
                  fontSize: 12,
                }}
                labelStyle={{ color: "#a1a1aa" }}
                formatter={(value: number, name: string) => {
                  if (name === "risk") return [`${value}/100`, "Risk"];
                  return [`${fmtNum(value)} pkt/s`, "Traffic"];
                }}
              />
              <Area
                yAxisId="pkt"
                type="monotone"
                dataKey="pktRate"
                stroke="#34d399"
                strokeWidth={1.5}
                fill="url(#pktFill)"
                isAnimationActive={false}
                dot={false}
                activeDot={{ r: 3, fill: "#34d399" }}
              />
              <Line
                yAxisId="risk"
                type="monotone"
                dataKey="risk"
                stroke="#fb7185"
                strokeWidth={1.5}
                dot={false}
                isAnimationActive={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}

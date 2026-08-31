"use client";
/**
 * AI Sentinel — PCAP upload & offline analysis.
 * Validation, feature extraction and classification all happen in the
 * Python backend; this view renders the results and surfaces the
 * backend-reported limitations honestly.
 */
import { useCallback, useRef, useState } from "react";
import {
  Upload,
  FileSearch,
  FlaskConical,
  AlertTriangle,
  CheckCircle2,
  Loader2,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useSentinelStore } from "@/lib/sentinel/store";
import { uploadPcap, sentinelApi, ApiError } from "@/lib/sentinel/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SeverityBadge, fmtBytes, fmtNum } from "./bits";
import type { PcapResult } from "@/lib/sentinel/types";

function SummaryStat({
  label,
  value,
  hint,
  danger,
}: {
  label: string;
  value: string;
  hint?: string;
  danger?: boolean;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
        {label}
      </p>
      <p
        className={cn(
          "mt-2 text-2xl font-semibold tabular-nums",
          danger ? "text-rose-400" : "text-zinc-100",
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-zinc-500">{hint}</p>}
    </div>
  );
}

export function PcapView() {
  const pcapSamples = useSentinelStore((s) => s.pcapSamples);
  const [result, setResult] = useState<PcapResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const analyze = useCallback(
    async (label: string, fn: () => Promise<PcapResult>) => {
      setBusy(label);
      setError(null);
      setResult(null);
      try {
        const res = await fn();
        setResult(res);
      } catch (e) {
        setError(
          e instanceof ApiError || e instanceof Error
            ? e.message
            : "Analysis failed unexpectedly.",
        );
      } finally {
        setBusy(null);
      }
    },
    [],
  );

  const onFile = useCallback(
    (file: File | undefined) => {
      if (!file) return;
      void analyze(file.name, () => uploadPcap(file));
    },
    [analyze],
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">PCAP Analysis</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Upload a network capture (.pcap / .pcapng) or use a bundled sample.
          Files are parsed offline and read-only — packets are grouped into
          flows, converted to the canonical feature schema, and classified by
          the same ML model as live traffic.
        </p>
      </div>

      {/* upload zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload PCAP file"
        onClick={() => fileInput.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") fileInput.current?.click();
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          onFile(e.dataTransfer.files?.[0]);
        }}
        className={cn(
          "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-8 text-center transition-colors",
          dragOver
            ? "border-emerald-500/50 bg-emerald-500/5"
            : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700",
        )}
      >
        <input
          ref={fileInput}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => onFile(e.target.files?.[0])}
        />
        {busy ? (
          <>
            <Loader2 className="h-8 w-8 animate-spin text-emerald-400" aria-hidden />
            <p className="text-sm text-zinc-300">{busy} — analyzing…</p>
          </>
        ) : (
          <>
            <Upload className="h-8 w-8 text-zinc-600" aria-hidden />
            <p className="text-sm font-medium text-zinc-300">
              Drag &amp; drop a capture file, or click to browse
            </p>
            <p className="text-xs text-zinc-600">
              .pcap / .pcapng · max 25 MB · never leaves this machine
            </p>
          </>
        )}
      </div>

      {/* bundled samples */}
      <div>
        <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-zinc-500">
          <FlaskConical className="h-3.5 w-3.5" aria-hidden />
          Bundled synthetic samples
        </p>
        <div className="mt-2 flex flex-wrap gap-2">
          {pcapSamples.map((s) => (
            <button
              key={s.name}
              disabled={busy !== null || !s.available}
              onClick={() =>
                void analyze(s.filename, () => sentinelApi.analyzeSample(s.name))
              }
              className="group flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2 text-left transition-colors hover:border-zinc-600 disabled:opacity-50"
              title={s.description}
            >
              <FileSearch className="h-4 w-4 shrink-0 text-zinc-500 group-hover:text-emerald-400" aria-hidden />
              <span className="text-sm text-zinc-300">{s.filename}</span>
              <span className="text-xs text-zinc-600">
                {fmtBytes(s.size_bytes)}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* error */}
      {error && (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-300"
        >
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
          <div>
            <p className="font-semibold">Could not analyze this file</p>
            <p className="mt-0.5 leading-relaxed">{error}</p>
          </div>
        </div>
      )}

      {/* results */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <SummaryStat
              label="Total packets"
              value={fmtNum(result.total_packets)}
            />
            <SummaryStat
              label="Flows analyzed"
              value={fmtNum(result.analyzed_windows)}
              hint={`${fmtNum(result.total_flows)} raw flows`}
            />
            <SummaryStat
              label="Benign"
              value={fmtNum(result.benign_flows)}
              hint="host pairs"
            />
            <SummaryStat
              label="Suspicious"
              value={String(result.suspicious_flows)}
              danger={result.suspicious_flows > 0}
              hint={`analyzed in ${result.analysis_ms.toFixed(0)} ms`}
            />
          </div>

          {/* attack types + severity distribution */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h3 className="text-sm font-semibold text-zinc-200">
                Attack types detected
              </h3>
              {Object.keys(result.attack_types).length === 0 ? (
                <p className="mt-3 flex items-center gap-2 text-sm text-emerald-400">
                  <CheckCircle2 className="h-4 w-4" aria-hidden />
                  No attack signatures found in this capture.
                </p>
              ) : (
                <div className="mt-3 flex flex-wrap gap-2">
                  {Object.entries(result.attack_types).map(([atk, n]) => (
                    <span
                      key={atk}
                      className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-sm text-rose-300"
                    >
                      {atk} · {n}
                    </span>
                  ))}
                </div>
              )}
              {result.global_assessment && (
                <p className="mt-3 text-xs text-zinc-500">
                  Whole-capture aggregate:{" "}
                  <span
                    className={cn(
                      "font-medium",
                      result.global_assessment.label === "BENIGN"
                        ? "text-emerald-400"
                        : "text-amber-400",
                    )}
                  >
                    {result.global_assessment.classification}
                  </span>{" "}
                  (risk {result.global_assessment.risk}/100)
                </p>
              )}
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h3 className="text-sm font-semibold text-zinc-200">
                Severity distribution
              </h3>
              <div className="mt-3 space-y-2">
                {(["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).map((sev) => {
                  const n = result.severity_distribution[sev] ?? 0;
                  const total = Math.max(
                    1,
                    Object.values(result.severity_distribution).reduce(
                      (a, b) => a + b,
                      0,
                    ),
                  );
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <span className="w-16 text-xs text-zinc-500">{sev}</span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-zinc-800">
                        <div
                          className={cn(
                            "h-full rounded-full",
                            sev === "LOW"
                              ? "bg-emerald-500"
                              : sev === "MEDIUM"
                                ? "bg-amber-500"
                                : sev === "HIGH"
                                  ? "bg-orange-500"
                                  : "bg-rose-500",
                          )}
                          style={{ width: `${(n / total) * 100}%` }}
                        />
                      </div>
                      <span className="w-6 text-right text-xs tabular-nums text-zinc-400">
                        {n}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* timeline */}
          {result.timeline.length > 1 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
              <h3 className="text-sm font-semibold text-zinc-200">
                Capture timeline — packets per second
              </h3>
              <div className="mt-3 h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={result.timeline}
                    margin={{ top: 4, right: 4, bottom: 0, left: 0 }}
                  >
                    <defs>
                      <linearGradient id="pcapFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#34d399" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#34d399" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="t"
                      tick={{ fill: "#71717a", fontSize: 11 }}
                      tickLine={false}
                      axisLine={{ stroke: "#3f3f46" }}
                      minTickGap={40}
                      tickFormatter={(v: number) => `${v}s`}
                    />
                    <YAxis
                      tick={{ fill: "#71717a", fontSize: 11 }}
                      tickLine={false}
                      axisLine={false}
                      width={52}
                      tickFormatter={(v: number) => fmtNum(v)}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#18181b",
                        border: "1px solid #3f3f46",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                      labelFormatter={(l) => `t=${l}s`}
                      formatter={(v: number) => [fmtNum(v), "packets"]}
                    />
                    <Area
                      type="monotone"
                      dataKey="packets"
                      stroke="#34d399"
                      strokeWidth={1.5}
                      fill="url(#pcapFill)"
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* per-pair results table */}
          <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60">
            <h3 className="border-b border-zinc-800 p-4 text-sm font-semibold text-zinc-200">
              Per host-pair classification
            </h3>
            <div className="max-h-96 overflow-auto soc-scroll">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-zinc-900 text-xs text-zinc-500">
                  <tr>
                    <th className="px-4 py-2 font-medium">Source</th>
                    <th className="px-4 py-2 font-medium">Target</th>
                    <th className="px-4 py-2 font-medium">Classification</th>
                    <th className="px-4 py-2 font-medium">Risk</th>
                    <th className="px-4 py-2 font-medium">Severity</th>
                    <th className="px-4 py-2 font-medium">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {result.results.map((r) => (
                    <tr
                      key={r.event_id}
                      className={cn(
                        "border-t border-zinc-800/60",
                        r.label !== "BENIGN" && "bg-rose-500/5",
                      )}
                    >
                      <td className="px-4 py-2 font-mono text-xs text-zinc-300">
                        {r.source}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-zinc-400">
                        {r.target}
                      </td>
                      <td className="px-4 py-2 text-zinc-200">
                        {r.classification}
                      </td>
                      <td className="px-4 py-2 tabular-nums text-zinc-300">
                        {r.risk}/100
                      </td>
                      <td className="px-4 py-2">
                        {r.label === "BENIGN" ? (
                          <span className="text-xs text-zinc-500">—</span>
                        ) : (
                          <SeverityBadge severity={r.severity} />
                        )}
                      </td>
                      <td className="px-4 py-2 tabular-nums text-zinc-400">
                        {(r.confidence * 100).toFixed(0)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* limitations — surfaced honestly */}
          {result.limitations.length > 0 && (
            <div
              className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4"
              role="note"
            >
              <p className="flex items-center gap-1.5 text-sm font-semibold text-amber-400">
                <AlertTriangle className="h-4 w-4" aria-hidden />
                Analysis limitations (stated honestly)
              </p>
              <ul className="mt-2 space-y-1 text-sm text-zinc-400">
                {result.limitations.map((l, i) => (
                  <li key={i} className="leading-relaxed">
                    · {l}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

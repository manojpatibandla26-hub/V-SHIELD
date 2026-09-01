"use client";
/**
 * AI Sentinel — PCAP upload & offline analysis.
 * Offline network packet parsing and RandomForest + IsolationForest classification.
 * Includes search, filtering, and JSON/CSV export of host-pair flow analysis.
 */
import { useCallback, useRef, useState, useMemo } from "react";
import {
  Upload,
  FileSearch,
  FlaskConical,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Search,
  Download,
  Filter,
  ArrowDownUp,
  FileCode,
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
import { Input } from "@/components/ui/input";
import { SeverityBadge, fmtBytes, fmtNum, exportAsCsv, exportAsJson } from "./bits";
import type { PcapResult, Severity } from "@/lib/sentinel/types";

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
      <p className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
        {label}
      </p>
      <p
        className={cn(
          "mt-2 text-2xl font-bold tabular-nums tracking-tight",
          danger ? "text-rose-400" : "text-zinc-100",
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-zinc-500 font-mono">{hint}</p>}
    </div>
  );
}

export function PcapView() {
  const pcapSamples = useSentinelStore((s) => s.pcapSamples);
  const [result, setResult] = useState<PcapResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [tableSearch, setTableSearch] = useState("");
  const [tableSeverityFilter, setTableSeverityFilter] = useState<string>("ALL");
  const [tableSort, setTableSort] = useState<"risk_desc" | "confidence_desc" | "source">("risk_desc");
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

  const filteredResults = useMemo(() => {
    if (!result) return [];
    let list = result.results;

    if (tableSeverityFilter !== "ALL") {
      if (tableSeverityFilter === "BENIGN") {
        list = list.filter((r) => r.label === "BENIGN");
      } else if (tableSeverityFilter === "THREATS") {
        list = list.filter((r) => r.label !== "BENIGN");
      } else {
        list = list.filter((r) => r.severity === tableSeverityFilter);
      }
    }

    if (tableSearch.trim()) {
      const q = tableSearch.toLowerCase();
      list = list.filter(
        (r) =>
          r.source.toLowerCase().includes(q) ||
          r.target.toLowerCase().includes(q) ||
          r.classification.toLowerCase().includes(q) ||
          r.label.toLowerCase().includes(q),
      );
    }

    if (tableSort === "risk_desc") {
      list = [...list].sort((a, b) => b.risk - a.risk);
    } else if (tableSort === "confidence_desc") {
      list = [...list].sort((a, b) => b.confidence - a.confidence);
    } else if (tableSort === "source") {
      list = [...list].sort((a, b) => a.source.localeCompare(b.source));
    }

    return list;
  }, [result, tableSearch, tableSeverityFilter, tableSort]);

  const handleExportJson = () => {
    if (!result) return;
    exportAsJson(result, `ai-sentinel-pcap-${result.filename.replace(/[^a-zA-Z0-9]/g, "-")}`);
  };

  const handleExportCsv = () => {
    if (!result || filteredResults.length === 0) return;
    const rows = filteredResults.map((r) => ({
      source: r.source,
      target: r.target,
      label: r.label,
      classification: r.classification,
      risk: r.risk,
      severity: r.severity,
      confidence: (r.confidence * 100).toFixed(1) + "%",
      anomaly_score: r.anomaly_score,
      packet_rate: r.observed?.pkt_rate ?? 0,
      flow_count: r.observed?.flow_count ?? 0,
    }));
    exportAsCsv(rows, `ai-sentinel-pcap-${result.filename.replace(/[^a-zA-Z0-9]/g, "-")}`);
  };

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">PCAP Offline Analysis</h1>
          <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-xs font-mono font-semibold text-emerald-400">
            Read-Only
          </span>
        </div>
        <p className="mt-1 text-sm text-zinc-400 leading-relaxed">
          Upload captured network traces (.pcap / .pcapng) or select pre-generated synthetic test captures. Files are parsed offline, grouped into bidirectional host-pair flows, and scored against the same 22-feature RandomForest + IsolationForest model.
        </p>
      </div>

      {/* Upload Zone */}
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
          "flex cursor-pointer flex-col items-center justify-center gap-2.5 rounded-xl border-2 border-dashed p-8 text-center transition-all",
          dragOver
            ? "border-emerald-500 bg-emerald-500/10 shadow-lg"
            : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700 hover:bg-zinc-900/60",
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
          <div className="space-y-2">
            <Loader2 className="mx-auto h-8 w-8 animate-spin text-emerald-400" aria-hidden />
            <p className="text-sm font-semibold text-zinc-200">{busy} — Analyzing…</p>
            <p className="text-xs text-zinc-500 font-mono">Extracting 22 canonical features across flows</p>
          </div>
        ) : (
          <>
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-zinc-800 text-zinc-400">
              <Upload className="h-6 w-6" aria-hidden />
            </div>
            <div>
              <p className="text-sm font-semibold text-zinc-200">
                Drag &amp; drop a capture file, or click to browse
              </p>
              <p className="text-xs text-zinc-500 mt-0.5">
                Standard .pcap / .pcapng · max 25 MB · Secure offline parsing
              </p>
            </div>
          </>
        )}
      </div>

      {/* Bundled Synthetic Samples */}
      <div className="space-y-2">
        <p className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-zinc-400">
          <FlaskConical className="h-3.5 w-3.5 text-amber-400" aria-hidden />
          Pre-packaged Synthetic Sample Traces
        </p>
        <div className="flex flex-wrap gap-2.5">
          {pcapSamples.map((s) => (
            <button
              key={s.name}
              disabled={busy !== null || !s.available}
              onClick={() =>
                void analyze(s.filename, () => sentinelApi.analyzeSample(s.name))
              }
              className="group flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/70 px-3.5 py-2 text-left transition-all hover:border-emerald-500/50 hover:bg-zinc-850 disabled:opacity-50"
              title={s.description}
            >
              <FileSearch className="h-4 w-4 shrink-0 text-zinc-500 group-hover:text-emerald-400 transition-colors" aria-hidden />
              <div>
                <div className="text-xs font-semibold text-zinc-200 group-hover:text-white transition-colors">
                  {s.filename}
                </div>
                <div className="text-[11px] text-zinc-500 font-mono">
                  {fmtBytes(s.size_bytes)} · {s.expected}
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Error Notice */}
      {error && (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300"
        >
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" aria-hidden />
          <div>
            <p className="font-bold">PCAP Parsing Error</p>
            <p className="mt-0.5 text-xs leading-relaxed text-rose-200">{error}</p>
          </div>
        </div>
      )}

      {/* Analysis Results Display */}
      {result && (
        <div className="space-y-6 pt-2 border-t border-zinc-800/80">
          {/* Header & Export Actions */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <FileCode className="h-5 w-5 text-emerald-400" />
                <h2 className="text-lg font-bold text-zinc-100">
                  Analysis Report: <span className="font-mono text-emerald-400">{result.filename}</span>
                </h2>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Completed in {result.analysis_ms.toFixed(0)} ms · {fmtNum(result.total_packets)} packets processed
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={handleExportJson}
                className="border-zinc-800 bg-zinc-900 text-xs text-zinc-300 hover:bg-zinc-800"
              >
                <Download className="mr-1.5 h-3.5 w-3.5" /> Export JSON
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={handleExportCsv}
                className="border-zinc-800 bg-zinc-900 text-xs text-zinc-300 hover:bg-zinc-800"
              >
                <Download className="mr-1.5 h-3.5 w-3.5" /> Export CSV
              </Button>
            </div>
          </div>

          {/* 4 Summary Stat Cards */}
          <div className="grid grid-cols-2 gap-3.5 md:grid-cols-4">
            <SummaryStat
              label="Total Packets"
              value={fmtNum(result.total_packets)}
              hint="raw captured frames"
            />
            <SummaryStat
              label="Host-Pair Flows"
              value={fmtNum(result.analyzed_windows)}
              hint={`${fmtNum(result.total_flows)} bidirectional streams`}
            />
            <SummaryStat
              label="Benign Flows"
              value={fmtNum(result.benign_flows)}
              hint="baseline normal"
            />
            <SummaryStat
              label="Suspicious Flows"
              value={String(result.suspicious_flows)}
              danger={result.suspicious_flows > 0}
              hint={result.suspicious_flows > 0 ? "threat signatures detected" : "all benign"}
            />
          </div>

          {/* Attack Types & Severity Distribution */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
                Attack Signatures Identified
              </h3>
              {Object.keys(result.attack_types).length === 0 ? (
                <p className="flex items-center gap-2 text-xs font-medium text-emerald-400 py-2">
                  <CheckCircle2 className="h-4 w-4" aria-hidden />
                  Zero offensive signatures detected in capture.
                </p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(result.attack_types).map(([atk, n]) => (
                    <span
                      key={atk}
                      className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold text-rose-300"
                    >
                      {atk} · {n} {n === 1 ? "stream" : "streams"}
                    </span>
                  ))}
                </div>
              )}
              {result.global_assessment && (
                <div className="pt-2 border-t border-zinc-800 text-xs text-zinc-400">
                  Global Assessment:{" "}
                  <span
                    className={cn(
                      "font-bold",
                      result.global_assessment.label === "BENIGN"
                        ? "text-emerald-400"
                        : "text-rose-400",
                    )}
                  >
                    {result.global_assessment.classification}
                  </span>{" "}
                  <span className="font-mono text-zinc-500">(aggregate risk: {result.global_assessment.risk}/100)</span>
                </div>
              )}
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
                Severity Distribution
              </h3>
              <div className="space-y-2">
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
                      <span className="w-16 text-xs text-zinc-400 font-mono font-medium">{sev}</span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-zinc-800">
                        <div
                          className={cn(
                            "h-full rounded-full transition-all",
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
                      <span className="w-8 text-right text-xs tabular-nums font-mono font-bold text-zinc-300">
                        {n}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Timeline Chart */}
          {result.timeline.length > 1 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
                Packet Velocity Timeline (Packets/Second across Trace)
              </h3>
              <div className="h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={result.timeline}
                    margin={{ top: 4, right: 8, bottom: 0, left: 0 }}
                  >
                    <defs>
                      <linearGradient id="pcapFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
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
                        background: "#09090b",
                        border: "1px solid #3f3f46",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                      labelFormatter={(l) => `Offset: ${l}s`}
                      formatter={(v: number) => [fmtNum(v), "Packets"]}
                    />
                    <Area
                      type="monotone"
                      dataKey="packets"
                      stroke="#10b981"
                      strokeWidth={1.5}
                      fill="url(#pcapFill)"
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Interactive Host-Pair Classification Table with Search & Filters */}
          <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60 space-y-3 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-zinc-100">
                  Host-Pair Classification Table
                </h3>
                <p className="text-xs text-zinc-400">
                  Showing {filteredResults.length} of {result.results.length} analyzed conversations
                </p>
              </div>

              {/* Table Controls */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative w-48 sm:w-60">
                  <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-500" />
                  <Input
                    type="text"
                    placeholder="Search IP or class…"
                    value={tableSearch}
                    onChange={(e) => setTableSearch(e.target.value)}
                    className="h-7.5 border-zinc-800 bg-zinc-950 pl-8 text-xs text-zinc-200 placeholder:text-zinc-600"
                  />
                </div>

                <select
                  value={tableSeverityFilter}
                  onChange={(e) => setTableSeverityFilter(e.target.value)}
                  className="h-7.5 rounded-md border border-zinc-800 bg-zinc-950 px-2 text-xs text-zinc-300 focus:outline-none"
                >
                  <option value="ALL">All Severities</option>
                  <option value="THREATS">Threats Only</option>
                  <option value="CRITICAL">Critical Only</option>
                  <option value="HIGH">High Only</option>
                  <option value="MEDIUM">Medium Only</option>
                  <option value="BENIGN">Benign Only</option>
                </select>

                <select
                  value={tableSort}
                  onChange={(e) => setTableSort(e.target.value as typeof tableSort)}
                  className="h-7.5 rounded-md border border-zinc-800 bg-zinc-950 px-2 text-xs text-zinc-300 focus:outline-none"
                >
                  <option value="risk_desc">Sort: Risk (High→Low)</option>
                  <option value="confidence_desc">Sort: Confidence</option>
                  <option value="source">Sort: Source IP</option>
                </select>
              </div>
            </div>

            <div className="max-h-96 overflow-auto rounded-lg border border-zinc-800 soc-scroll">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-zinc-950 text-[11px] font-semibold uppercase text-zinc-400 border-b border-zinc-800">
                  <tr>
                    <th className="px-3.5 py-2.5">Source IP</th>
                    <th className="px-3.5 py-2.5">Target IP</th>
                    <th className="px-3.5 py-2.5">Classification</th>
                    <th className="px-3.5 py-2.5">Risk</th>
                    <th className="px-3.5 py-2.5">Severity</th>
                    <th className="px-3.5 py-2.5">ML Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 font-mono">
                  {filteredResults.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-zinc-500 font-sans">
                        No conversations match the search and filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredResults.map((r) => (
                      <tr
                        key={r.event_id}
                        className={cn(
                          "transition-colors",
                          r.label !== "BENIGN"
                            ? "bg-rose-500/5 hover:bg-rose-500/10 text-rose-200"
                            : "hover:bg-zinc-850 text-zinc-300",
                        )}
                      >
                        <td className="px-3.5 py-2 font-medium">{r.source}</td>
                        <td className="px-3.5 py-2 text-zinc-400">{r.target}</td>
                        <td className="px-3.5 py-2 font-sans font-semibold text-zinc-200">
                          {r.classification}
                        </td>
                        <td className="px-3.5 py-2 tabular-nums font-bold text-zinc-200">
                          {r.risk}/100
                        </td>
                        <td className="px-3.5 py-2 font-sans">
                          {r.label === "BENIGN" ? (
                            <span className="text-zinc-500 text-[11px] font-mono">BENIGN</span>
                          ) : (
                            <SeverityBadge severity={r.severity} />
                          )}
                        </td>
                        <td className="px-3.5 py-2 tabular-nums text-zinc-300">
                          {(r.confidence * 100).toFixed(1)}%
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Honest Analysis Limitations */}
          {result.limitations.length > 0 && (
            <div
              className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 space-y-1.5"
              role="note"
            >
              <p className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-amber-400">
                <AlertTriangle className="h-4 w-4" aria-hidden />
                Analysis Limitations &amp; Assumptions
              </p>
              <ul className="space-y-1 text-xs text-zinc-400 leading-relaxed pl-1">
                {result.limitations.map((l, i) => (
                  <li key={i}>• {l}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

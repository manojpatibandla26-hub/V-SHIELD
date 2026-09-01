"use client";
/**
 * AI Sentinel — ML model card view.
 * Live model specifications, evaluation metrics, confusion matrix, and feature importances.
 * Structured for both technical evaluators and general judges.
 */
import {
  Cpu,
  Loader2,
  AlertTriangle,
  Table2,
  BarChart3,
  GitBranch,
  Info,
  CheckCircle2,
  Brain,
  Gauge,
  Sparkles,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useSentinelStore } from "@/lib/sentinel/store";
import { ATTACK_DISPLAY, type AttackLabel } from "@/lib/sentinel/types";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";

export function ModelView() {
  const modelInfo = useSentinelStore((s) => s.modelInfo);
  const error = useSentinelStore((s) => s.modelInfoError);
  const retryConnection = useSentinelStore((s) => s.retryConnection);

  if (error) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-6 space-y-3">
        <p className="flex items-center gap-2 font-bold text-rose-400">
          <AlertTriangle className="h-5 w-5" aria-hidden /> Model Information Unavailable
        </p>
        <p className="text-xs text-rose-200">{error}</p>
        <Button
          size="sm"
          variant="outline"
          onClick={() => void retryConnection()}
          className="border-rose-500/40 bg-rose-500/20 text-xs text-white hover:bg-rose-500/30"
        >
          Retry Fetching Model Specs
        </Button>
      </div>
    );
  }

  if (!modelInfo) {
    return (
      <div className="space-y-6">
        <div>
          <Skeleton className="h-8 w-48 bg-zinc-800" />
          <Skeleton className="h-4 w-96 bg-zinc-800 mt-2" />
        </div>
        <div className="grid gap-4 md:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-24 rounded-xl bg-zinc-800" />
          ))}
        </div>
        <Skeleton className="h-64 rounded-xl bg-zinc-800" />
      </div>
    );
  }

  const m = modelInfo.metrics;
  const importances = modelInfo.feature_importances.slice(0, 10);
  const cm = m.confusion_matrix;

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Machine Learning Intelligence Engine
          </h1>
          <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-xs font-mono font-semibold text-emerald-400">
            RandomForest v1.0
          </span>
        </div>
        <p className="mt-1 text-sm text-zinc-400 leading-relaxed">
          Real-time model specifications, held-out evaluation metrics, confusion matrix, feature importance weights, and mathematical risk formulation.
        </p>
      </div>

      {/* Model Identity Cards */}
      <div className="grid gap-3.5 sm:gap-4 grid-cols-2 md:grid-cols-4">
        {[
          { label: "Core Algorithm", value: modelInfo.algorithm, hint: "220 Decision Trees" },
          { label: "Model Version", value: modelInfo.model_version, hint: "Production Baseline" },
          {
            label: "Training Timestamp",
            value: new Date(modelInfo.trained_at).toLocaleString("en-GB", { dateStyle: "short", timeStyle: "short" }),
            hint: "Verified Checkpoint",
          },
          {
            label: "Dataset Population",
            value: `${modelInfo.train_samples.toLocaleString()} Samples`,
            hint: `+${modelInfo.eval_samples.toLocaleString()} Evaluation Windows`,
          },
        ].map((c) => (
          <div
            key={c.label}
            className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm"
          >
            <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
              {c.label}
            </p>
            <p className="mt-1 text-sm font-bold text-zinc-100 truncate">{c.value}</p>
            <p className="mt-0.5 text-[11px] font-mono text-zinc-500">{c.hint}</p>
          </div>
        ))}
      </div>

      {/* Dataset Honesty & Methodology Box */}
      <div
        className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 shadow-sm"
        role="note"
      >
        <p className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-amber-400">
          <Info className="h-4 w-4" aria-hidden /> Dataset Methodology &amp; Academic Integrity
        </p>
        <p className="mt-1.5 text-xs leading-relaxed text-zinc-300">
          {modelInfo.dataset.honesty_note} The pipeline supports direct retraining on real CIC-IDS2017 raw captures via <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-amber-300">python ml/train_real.py</code>.
        </p>
      </div>

      {/* Evaluation Metrics */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5 shadow-sm space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
              <Cpu className="h-4 w-4 text-emerald-400" aria-hidden /> Held-Out Evaluation Metrics
            </h2>
            <p className="text-xs text-zinc-400 mt-0.5">
              Tested on {m.eval_samples.toLocaleString()} independent held-out evaluation windows
            </p>
          </div>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {[
            { label: "Overall Accuracy", value: m.accuracy, desc: "Correct classifications" },
            { label: "Precision (Macro)", value: m.precision_macro, desc: "Low false alarm rate" },
            { label: "Recall (Macro)", value: m.recall_macro, desc: "High threat catch rate" },
            { label: "F1 Score (Macro)", value: m.f1_macro, desc: "Harmonic balanced mean" },
          ].map((x) => (
            <div key={x.label} className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-3.5">
              <p className="text-xs font-semibold text-zinc-400">{x.label}</p>
              <p className="mt-1 text-2xl font-bold font-mono text-emerald-400 tabular-nums">
                {x.value.toFixed(4)}
              </p>
              <p className="text-[11px] text-zinc-500 mt-0.5">{x.desc}</p>
            </div>
          ))}
        </div>

        {/* Per-Class Metrics Table */}
        <div className="space-y-2 pt-2 border-t border-zinc-800">
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-zinc-400">
            <Table2 className="h-3.5 w-3.5 text-emerald-400" /> Per-Attack Class Performance
          </h3>
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-zinc-950 text-zinc-400 border-b border-zinc-800 text-[11px]">
                <tr>
                  <th className="py-2.5 px-3.5">Attack Class</th>
                  <th className="py-2.5 px-3.5">Precision</th>
                  <th className="py-2.5 px-3.5">Recall</th>
                  <th className="py-2.5 px-3.5">F1-Score</th>
                  <th className="py-2.5 px-3.5">Evaluation Support</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {modelInfo.classes.map((cls) => {
                  const c = m.per_class[cls] ?? {};
                  return (
                    <tr key={cls} className="hover:bg-zinc-850/60 transition-colors">
                      <td className="py-2 px-3.5 font-sans font-semibold text-zinc-200">
                        {ATTACK_DISPLAY[cls as AttackLabel] ?? cls}
                        <span className="ml-2 font-mono text-[10px] text-zinc-500">
                          [{cls}]
                        </span>
                      </td>
                      <td className="py-2 px-3.5 text-emerald-400 font-bold">
                        {(c.precision ?? 0).toFixed(3)}
                      </td>
                      <td className="py-2 px-3.5 text-emerald-400 font-bold">
                        {(c.recall ?? 0).toFixed(3)}
                      </td>
                      <td className="py-2 px-3.5 text-emerald-400 font-bold">
                        {(c.f1 ?? 0).toFixed(3)}
                      </td>
                      <td className="py-2 px-3.5 text-zinc-400">
                        {c.support ?? 0} windows
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Confusion Matrix */}
        <div className="space-y-2 pt-2 border-t border-zinc-800">
          <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
            Multi-Class Confusion Matrix (Rows = True Label, Columns = Predicted)
          </h3>
          <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950/40 p-3">
            <table className="text-xs font-mono mx-auto">
              <thead>
                <tr>
                  <th className="p-2 text-[10px] text-zinc-500 font-sans">Ground Truth ↓ \ Pred →</th>
                  {cm.labels.map((l) => (
                    <th
                      key={l}
                      className="p-2 text-center font-bold text-zinc-300 text-[11px]"
                    >
                      {l.slice(0, 8)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/80">
                {cm.matrix.map((row, i) => (
                  <tr key={i}>
                    <th className="p-2 text-left font-bold text-zinc-300 text-[11px] pr-4">
                      {cm.labels[i]}
                    </th>
                    {row.map((v, j) => {
                      const isDiagonal = i === j;
                      return (
                        <td
                          key={j}
                          className={cn(
                            "p-2 text-center font-bold tabular-nums rounded",
                            isDiagonal && v > 0
                              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                              : v > 0
                                ? "bg-rose-500/20 text-rose-300 font-bold"
                                : "text-zinc-600",
                          )}
                        >
                          {v}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Top Feature Importances */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5 shadow-sm space-y-3">
        <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
          <BarChart3 className="h-4 w-4 text-emerald-400" aria-hidden /> Gini Feature Importance Ranking (Top 10)
        </h2>
        <p className="text-xs text-zinc-400">
          Relative predictive weight of mathematical network features in determining intrusion classes.
        </p>
        <div className="h-64 pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={importances}
              layout="vertical"
              margin={{ top: 0, right: 24, bottom: 0, left: 12 }}
            >
              <CartesianGrid stroke="#27272a" strokeDasharray="3 3" horizontal={false} />
              <XAxis
                type="number"
                tick={{ fill: "#71717a", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                type="category"
                dataKey="feature"
                width={130}
                tick={{ fill: "#d4d4d8", fontSize: 11, fontFamily: "monospace" }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#09090b",
                  border: "1px solid #3f3f46",
                  borderRadius: 8,
                  fontSize: 12,
                }}
                formatter={(v: number) => [v.toFixed(4), "Gini Importance"]}
              />
              <Bar dataKey="importance" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                {importances.map((entry, i) => (
                  <Cell key={i} fill="#10b981" fillOpacity={1 - i * 0.07} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Dual Column: Label Mapping & Risk Formula */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Label Mapping */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5 shadow-sm space-y-3">
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <GitBranch className="h-4 w-4 text-emerald-400" aria-hidden /> CIC-IDS2017 Dataset Mapping
          </h2>
          <div className="rounded-lg border border-zinc-800 overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-zinc-950 text-zinc-500 text-[11px]">
                <tr>
                  <th className="p-2.5">Dataset Raw Signature</th>
                  <th className="p-2.5">Sentinel Target Class</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {modelInfo.label_mapping.map((row, i) => (
                  <tr key={i} className="hover:bg-zinc-850/50">
                    <td className="p-2.5 text-zinc-400">{row.dataset_label}</td>
                    <td className="p-2.5 text-emerald-400 font-bold">{row.app_class}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Risk Formula Breakdown */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5 shadow-sm space-y-3">
          <h2 className="flex items-center gap-2 text-sm font-bold text-zinc-100">
            <Gauge className="h-4 w-4 text-emerald-400" /> Deterministic Risk Scoring Formula
          </h2>
          <div className="space-y-3 text-xs">
            <div className="rounded-lg bg-zinc-950 p-3 border border-zinc-800 font-mono">
              <p className="text-emerald-400 font-bold mb-1">Threat Risk Calculation:</p>
              <p className="text-zinc-300 leading-relaxed">
                Risk = (0.40 × Impact_Eff) + (0.25 × Anomaly × 100) + (0.20 × Confidence × 100) + (0.15 × Deviation × 100)
              </p>
            </div>
            <div className="rounded-lg bg-zinc-950 p-3 border border-zinc-800 font-mono">
              <p className="text-amber-400 font-bold mb-1">Severity Threshold Bands:</p>
              <p className="text-zinc-300">
                {Object.entries(modelInfo.risk_model.severity_bands)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join(" · ")}
              </p>
            </div>
            <div className="rounded-lg bg-zinc-950 p-3 border border-zinc-800 font-mono">
              <p className="text-zinc-400 font-bold mb-1">Base Attack Weights:</p>
              <p className="text-zinc-400 text-[11px]">
                {Object.entries(modelInfo.risk_model.class_impact)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(" · ")}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

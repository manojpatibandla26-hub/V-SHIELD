"use client";
/**
 * AI Sentinel — ML model card view.
 * Every value here is fetched from the backend /api/model-info — including
 * the honest dataset note (never fabricated accuracy).
 */
import {
  Cpu,
  Loader2,
  AlertTriangle,
  Table2,
  BarChart3,
  GitBranch,
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

export function ModelView() {
  const modelInfo = useSentinelStore((s) => s.modelInfo);
  const error = useSentinelStore((s) => s.modelInfoError);

  if (error) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-6">
        <p className="flex items-center gap-2 font-semibold text-rose-400">
          <AlertTriangle className="h-5 w-5" aria-hidden /> Model information
          unavailable
        </p>
        <p className="mt-2 text-sm text-zinc-400">{error}</p>
      </div>
    );
  }

  if (!modelInfo) {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-6 text-sm text-zinc-400">
        <Loader2 className="h-5 w-5 animate-spin text-emerald-400" aria-hidden />
        Loading model information from the backend…
      </div>
    );
  }

  const m = modelInfo.metrics;
  const importances = modelInfo.feature_importances.slice(0, 10);
  const cm = m.confusion_matrix;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">ML Model</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Live model card served by the backend — algorithm, features,
          measured metrics, label mapping, and the risk formula.
        </p>
      </div>

      {/* identity */}
      <div className="grid gap-4 md:grid-cols-4">
        {[
          { label: "Algorithm", value: modelInfo.algorithm },
          { label: "Version", value: modelInfo.model_version },
          {
            label: "Trained",
            value: new Date(modelInfo.trained_at).toLocaleString("en-GB"),
          },
          {
            label: "Training windows",
            value: `${modelInfo.train_samples.toLocaleString()} (+${modelInfo.eval_samples.toLocaleString()} eval)`,
          },
        ].map((c) => (
          <div
            key={c.label}
            className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
          >
            <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
              {c.label}
            </p>
            <p className="mt-1.5 text-sm font-medium text-zinc-200">{c.value}</p>
          </div>
        ))}
      </div>

      {/* honesty note */}
      <div
        className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4"
        role="note"
      >
        <p className="flex items-center gap-1.5 text-sm font-semibold text-amber-400">
          <AlertTriangle className="h-4 w-4" aria-hidden /> Dataset honesty
        </p>
        <p className="mt-1.5 text-sm leading-relaxed text-zinc-400">
          {modelInfo.dataset.honesty_note} Retraining on real data is one
          command: <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs">python ml/train_real.py</code>{" "}
          (see README for dataset placement).
        </p>
      </div>

      {/* metrics */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
          <Cpu className="h-4 w-4 text-emerald-400" aria-hidden /> Evaluation
          metrics (held-out set, {m.eval_samples.toLocaleString()} windows)
        </h2>
        <div className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4">
          {[
            { label: "Accuracy", value: m.accuracy },
            { label: "Precision (macro)", value: m.precision_macro },
            { label: "Recall (macro)", value: m.recall_macro },
            { label: "F1 (macro)", value: m.f1_macro },
          ].map((x) => (
            <div key={x.label} className="rounded-lg bg-zinc-950/60 p-3">
              <p className="text-xs text-zinc-500">{x.label}</p>
              <p className="mt-1 text-xl font-semibold tabular-nums text-zinc-100">
                {x.value.toFixed(4)}
              </p>
            </div>
          ))}
        </div>

        <div className="mt-5 overflow-x-auto">
          <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            <Table2 className="h-3.5 w-3.5" aria-hidden /> Per-class metrics
          </h3>
          <table className="mt-2 w-full min-w-[480px] text-left text-sm">
            <thead className="text-xs text-zinc-500">
              <tr>
                <th className="py-1.5 pr-4 font-medium">Class</th>
                <th className="py-1.5 pr-4 font-medium">Precision</th>
                <th className="py-1.5 pr-4 font-medium">Recall</th>
                <th className="py-1.5 pr-4 font-medium">F1</th>
                <th className="py-1.5 font-medium">Support</th>
              </tr>
            </thead>
            <tbody>
              {modelInfo.classes.map((cls) => {
                const c = m.per_class[cls] ?? {};
                return (
                  <tr key={cls} className="border-t border-zinc-800">
                    <td className="py-1.5 pr-4 text-zinc-200">
                      {ATTACK_DISPLAY[cls as AttackLabel] ?? cls}
                      <span className="ml-2 font-mono text-[10px] text-zinc-600">
                        {cls}
                      </span>
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-zinc-300">
                      {(c.precision ?? 0).toFixed(3)}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-zinc-300">
                      {(c.recall ?? 0).toFixed(3)}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-zinc-300">
                      {(c.f1 ?? 0).toFixed(3)}
                    </td>
                    <td className="py-1.5 tabular-nums text-zinc-500">
                      {c.support ?? 0}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* confusion matrix */}
        <div className="mt-5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
            Confusion matrix (rows = true, columns = predicted)
          </h3>
          <div className="mt-2 overflow-x-auto">
            <table className="text-xs">
              <thead>
                <tr>
                  <th className="p-1.5" />
                  {cm.labels.map((l) => (
                    <th
                      key={l}
                      className="whitespace-nowrap p-1.5 font-medium text-zinc-500"
                    >
                      {l.slice(0, 7)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cm.matrix.map((row, i) => (
                  <tr key={i}>
                    <th className="whitespace-nowrap p-1.5 text-right font-medium text-zinc-500">
                      {cm.labels[i]}
                    </th>
                    {row.map((v, j) => (
                      <td
                        key={j}
                        className="p-1.5 text-center font-mono tabular-nums"
                        style={{
                          background:
                            i === j && v > 0 ? "rgba(52,211,153,0.18)" : undefined,
                          color: i === j && v > 0 ? "#6ee7b7" : "#a1a1aa",
                        }}
                      >
                        {v}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* feature importances */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
          <BarChart3 className="h-4 w-4 text-emerald-400" aria-hidden /> Top
          feature importances (RandomForest)
        </h2>
        <div className="mt-4 h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={importances}
              layout="vertical"
              margin={{ top: 0, right: 16, bottom: 0, left: 8 }}
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
                width={140}
                tick={{ fill: "#a1a1aa", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#18181b",
                  border: "1px solid #3f3f46",
                  borderRadius: 8,
                  fontSize: 12,
                }}
                formatter={(v: number) => [v.toFixed(4), "importance"]}
              />
              <Bar dataKey="importance" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                {importances.map((entry, i) => (
                  <Cell key={i} fill="#34d399" fillOpacity={0.9 - i * 0.05} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* label mapping */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
            <GitBranch className="h-4 w-4 text-emerald-400" aria-hidden /> Label
            mapping (real CIC-IDS2017 → app classes)
          </h2>
          <table className="mt-3 w-full text-left text-sm">
            <tbody>
              {modelInfo.label_mapping.map((row, i) => (
                <tr key={i} className="border-t border-zinc-800/70">
                  <td className="py-1.5 pr-4 text-zinc-400">
                    {row.dataset_label}
                  </td>
                  <td className="py-1.5 font-mono text-xs text-emerald-400">
                    {row.app_class}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* risk formula */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5">
          <h2 className="text-sm font-semibold text-zinc-200">
            Risk engine (documented formula)
          </h2>
          <div className="mt-3 space-y-3 text-sm text-zinc-400">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                Threat windows
              </p>
              <p className="mt-1 font-mono text-xs leading-relaxed text-zinc-300">
                {modelInfo.risk_model.threat}
              </p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                Benign windows
              </p>
              <p className="mt-1 font-mono text-xs text-zinc-300">
                {modelInfo.risk_model.benign}
              </p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                Severity bands
              </p>
              <p className="mt-1 font-mono text-xs text-zinc-300">
                {Object.entries(modelInfo.risk_model.severity_bands)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join(" · ")}
              </p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                Class impact weights
              </p>
              <p className="mt-1 font-mono text-xs text-zinc-300">
                {Object.entries(modelInfo.risk_model.class_impact)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(" · ")}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* anomaly detector */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:p-5">
        <h2 className="text-sm font-semibold text-zinc-200">
          Anomaly detector
        </h2>
        <p className="mt-2 text-sm text-zinc-400">
          {modelInfo.anomaly_detector.algorithm} ·{" "}
          {modelInfo.anomaly_detector.trained_on} · contamination ={" "}
          {modelInfo.anomaly_detector.contamination}. Raw scores are calibrated
          against benign percentiles so 0.2 is &quot;unusual&quot; and 1.0 is
          &quot;extreme outlier&quot;. If the RandomForest votes BENIGN but this
          detector is extremely alarmed, the window is surfaced as an ANOMALY
          (unknown behaviour) instead of being ignored.
        </p>
      </div>
    </div>
  );
}

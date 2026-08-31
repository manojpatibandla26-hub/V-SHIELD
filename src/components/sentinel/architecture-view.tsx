"use client";
/**
 * AI Sentinel — Architecture page.
 * Shows the real pipeline and, for every stage, clearly separates
 * "Implemented now" from "Production integration (future)" — no fake claims.
 */
import {
  ArrowDown,
  CheckCircle2,
  Clock,
  Workflow,
  Network,
  Database,
  MonitorSmartphone,
} from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";

interface Stage {
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  now: string[];
  future: string[];
}

const STAGES: Stage[] = [
  {
    name: "Input — Traffic / PCAP / Safe Simulation",
    icon: Network,
    now: [
      "Background benign traffic generator (synthetic, live stream)",
      "5 safe attack simulations (synthetic feature windows)",
      "Offline PCAP/PCAPNG upload + bundled samples",
      "POST /api/analyze for direct feature vectors",
    ],
    future: [
      "Mirror SPAN/tap port traffic via a capture agent",
      "NetFlow / IPFIX / sFlow collectors from routers",
      "Zeek or nProbe as a live flow exporter",
    ],
  },
  {
    name: "Feature Extraction — canonical 22-feature schema",
    icon: Workflow,
    now: [
      "One schema shared by training, simulation and PCAP parsing",
      "Raw counters -> derived features in a single function (derive)",
      "Bidirectional flow aggregation per host pair",
    ],
    future: [
      "CICFlowMeter-compatible exporters for direct dataset parity",
      "Per-service and per-VLAN feature slices",
    ],
  },
  {
    name: "Preprocessing",
    icon: Database,
    now: [
      "NaN/Inf sanitization and sanity clipping on every input",
      "No scaling needed (tree-based models), documented",
    ],
    future: [
      "Online statistics for drift detection (PSI / KS test)",
      "Feature versioning and schema registry",
    ],
  },
  {
    name: "RandomForest Classifier — 6 classes",
    icon: CheckCircle2,
    now: [
      "220-tree RandomForest (scikit-learn), trained on the documented dataset",
      "Probabilistic output: per-class probabilities + confidence",
      "Model card with real measured metrics and honest dataset note",
    ],
    future: [
      "Retrain on real captures (ml/train_real.py for CIC-IDS2017)",
      "Gradient boosting / deep models comparison, A/B evaluation",
      "Scheduled retraining + champion/challenger deployment",
    ],
  },
  {
    name: "Anomaly Detection — IsolationForest",
    icon: CheckCircle2,
    now: [
      "Unsupervised detector trained on benign windows only",
      "Calibrated 0–1 score against benign percentiles",
      "Overrides BENIGN votes when traffic is a extreme outlier (unknown behaviour)",
    ],
    future: [
      "Autoencoder / variational models for richer reconstruction error",
      "Per-segment baselines (per subnet, per service)",
    ],
  },
  {
    name: "Risk Engine & Severity",
    icon: CheckCircle2,
    now: [
      "Deterministic weighted formula (impact, anomaly, confidence, deviation)",
      "Documented weights; transparent breakdown shown in the UI",
      "LOW / MEDIUM / HIGH / CRITICAL bands from the 0–100 score",
    ],
    future: [
      "Learned risk calibration from analyst feedback",
      "Asset criticality weighting per target",
    ],
  },
  {
    name: "Threat Explanation",
    icon: CheckCircle2,
    now: [
      "Evidence built from the actual observed feature values",
      "Observed vs. benign baseline for every cited feature",
      "Plain-language meaning + recommended response per class",
    ],
    future: [
      "SHAP values for per-prediction attribution (optional add-on)",
      "LLM-generated natural-language summaries (optional)",
    ],
  },
  {
    name: "FastAPI Backend + WebSocket",
    icon: Network,
    now: [
      "All detection decisions made server-side in Python",
      "Native WebSocket broadcasts (traffic, threats, alerts, mitigation)",
      "SQLite event store; REST API for events/statistics/model info",
    ],
    future: [
      "Message queue (Kafka/Redis) for multi-consumer scale-out",
      "Authentication, RBAC, audit log hardening",
    ],
  },
  {
    name: "SOC Dashboard (this app)",
    icon: MonitorSmartphone,
    now: [
      "Real-time charts, escalating alerts, threat detail, PCAP analysis",
      "Polling fallback when the live socket is unavailable",
      "Frontend never decides attack types — it renders backend output",
    ],
    future: [
      "Multi-tenant SOC views, ticketing integration (Jira/ServiceNow)",
      "Automated response playbooks (still simulated until sanctioned)",
    ],
  },
];

function StageCard({ stage, index }: { stage: Stage; index: number }) {
  const Icon = stage.icon;
  return (
    <div className="relative">
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-zinc-800 text-emerald-400">
            <Icon className="h-4.5 w-4.5" aria-hidden />
          </div>
          <h3 className="text-sm font-semibold text-zinc-100">
            <span className="mr-2 font-mono text-xs text-zinc-600">
              {String(index + 1).padStart(2, "0")}
            </span>
            {stage.name}
          </h3>
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div>
            <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-emerald-400">
              <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> Implemented now
            </p>
            <ul className="mt-2 space-y-1.5 text-sm leading-relaxed text-zinc-300">
              {stage.now.map((item, i) => (
                <li key={i} className="flex gap-2">
                  <span className="text-emerald-500">•</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-amber-400">
              <Clock className="h-3.5 w-3.5" aria-hidden /> Production integration (future)
            </p>
            <ul className="mt-2 space-y-1.5 text-sm leading-relaxed text-zinc-500">
              {stage.future.map((item, i) => (
                <li key={i} className="flex gap-2">
                  <span className="text-amber-500/70">•</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      {index < STAGES.length - 1 && (
        <div className="flex justify-center py-1.5" aria-hidden>
          <ArrowDown className="h-4 w-4 text-zinc-700" />
        </div>
      )}
    </div>
  );
}

export function ArchitectureView() {
  const modelInfo = useSentinelStore((s) => s.modelInfo);
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Architecture</h1>
        <p className="mt-1 text-sm text-zinc-400">
          The full detection pipeline, stage by stage. Every stage lists what
          is <span className="text-emerald-400">implemented now</span> versus
          what would be added for{" "}
          <span className="text-amber-400">production integration</span> — this
          prototype never presents future work as done.
        </p>
      </div>

      {modelInfo && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
          <p className="text-sm text-zinc-300">
            <span className="font-semibold text-emerald-400">Live config:</span>{" "}
            {modelInfo.algorithm} {modelInfo.model_version} ·{" "}
            {modelInfo.n_features} canonical features ·{" "}
            {modelInfo.classes.length} classes ·{" "}
            {modelInfo.train_samples.toLocaleString()} training windows ·
            anomaly detector: {modelInfo.anomaly_detector.algorithm}
          </p>
        </div>
      )}

      <div className="space-y-0">
        {STAGES.map((stage, i) => (
          <StageCard key={stage.name} stage={stage} index={i} />
        ))}
      </div>

      <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
        <p className="text-sm font-semibold text-amber-400">
          Honesty statement
        </p>
        <p className="mt-1 text-sm leading-relaxed text-zinc-400">
          This prototype classifies <strong>synthetic</strong> traffic and
          user-supplied PCAP files only. It does not capture live packets from
          any network, does not attack anything, and the &quot;Block Source&quot;
          action is a UI-level simulation. The ML metrics shown in the Model
          tab are measured on the bundled synthetic evaluation set — real-world
          performance requires retraining on real data.
        </p>
      </div>
    </div>
  );
}

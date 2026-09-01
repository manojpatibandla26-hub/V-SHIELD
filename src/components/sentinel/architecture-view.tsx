"use client";
/**
 * AI Sentinel — Architecture & Detection Pipeline.
 * 9-Stage AI Intrusion Detection Pipeline for Hackathon & Technical Evaluation.
 * Clearly separates "Implemented Now" from "Production Integration (Future)".
 */
import {
  ArrowDown,
  CheckCircle2,
  Clock,
  Workflow,
  Network,
  Database,
  MonitorSmartphone,
  Cpu,
  ShieldAlert,
  BellRing,
  Layers,
  Sparkles,
} from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";

interface Stage {
  id: string;
  name: string;
  subtitle: string;
  icon: React.ComponentType<{ className?: string }>;
  now: string[];
  future: string[];
}

const STAGES: Stage[] = [
  {
    id: "stage-1",
    name: "1. Network Traffic Ingestion",
    subtitle: "Synthetic Stream / Offline PCAP / Controlled Simulation",
    icon: Network,
    now: [
      "Continuous background benign traffic generator streaming live telemetry over WebSockets",
      "5 safe attack simulation scenarios (SYN flood, DoS, port scan, brute force, anomalies)",
      "Direct offline PCAP/PCAPNG binary frame parser with magic byte validation",
      "REST endpoint POST /api/analyze for raw telemetry ingestion",
    ],
    future: [
      "Hardware SPAN/TAP mirror port capture agent on edge switches",
      "NetFlow v9 / IPFIX / sFlow collector daemon on core routers",
      "Zeek / Suricata live connection log stream exporter",
    ],
  },
  {
    id: "stage-2",
    name: "2. Flow Aggregation & Capture Parsing",
    subtitle: "Bidirectional Host-Pair Session Assembly",
    icon: Layers,
    now: [
      "Grouping raw packets into bidirectional 5-tuple conversations (Src IP, Dst IP, Protocol, Ports)",
      "Dynamic statistical windowing over time slices",
      "Memory-safe frame parsing with Scapy offline engine",
    ],
    future: [
      "High-throughput eBPF / DPDK kernel bypass flow aggregators",
      "Hardware-accelerated NIC timestamping (PTP/IEEE 1588)",
      "Per-VLAN and per-tenant tenant flow isolation",
    ],
  },
  {
    id: "stage-3",
    name: "3. Canonical Feature Extraction",
    subtitle: "22 Mathematical & Behavioral Network Metrics",
    icon: Workflow,
    now: [
      "Shared derive() feature extractor ensuring 100% schema parity across training, testing, and PCAP",
      "Volume metrics: pkt_rate, byte_rate, avg_pkt_size, duration_s",
      "Flag distributions: syn_ratio, ack_ratio, fin_ratio, rst_ratio, psh_ratio",
      "Connection dynamics: flow_density, half_open_ratio, port_entropy, scan_speed",
    ],
    future: [
      "CICFlowMeter export parity (80+ statistical flow features)",
      "Layer 7 payload entropy and protocol parsing (HTTP/DNS/TLS fingerprinting)",
      "JA3/JA4 TLS client fingerprint extraction",
    ],
  },
  {
    id: "stage-4",
    name: "4. Preprocessing & Data Sanitization",
    subtitle: "Numerical Stability & Outlier Handling",
    icon: Database,
    now: [
      "Automatic NaN, null, and Inf sanitization with bounded clipping",
      "Deterministic normalization (tree-based models require no arbitrary scaling)",
      "Zero-division guard protection across packet ratios",
    ],
    future: [
      "Continuous feature drift detection (Population Stability Index / KS Test)",
      "Online feature versioning and automated schema registry",
      "Dynamic baseline percentile recalibration against network time-of-day",
    ],
  },
  {
    id: "stage-5",
    name: "5. Multi-Model ML Classification Engine",
    subtitle: "Supervised RandomForest + Unsupervised IsolationForest",
    icon: Cpu,
    now: [
      "220-tree RandomForest Classifier trained on balanced synthetic multi-class attack profiles",
      "IsolationForest anomaly detector trained exclusively on benign traffic baseline",
      "Full probabilistic class distribution output across all 6 target classes",
      "Autonomous override: BENIGN predictions with IsolationForest score ≥ 0.90 reclassified as ANOMALY",
    ],
    future: [
      "XGBoost / LightGBM ensemble comparison and champion/challenger deployment",
      "Autoencoder neural network for high-dimensional reconstruction error",
      "Automated pipeline retraining on live labeled enterprise datasets (ml/train_real.py)",
    ],
  },
  {
    id: "stage-6",
    name: "6. Attack Classification & Label Mapping",
    subtitle: "6 High-Fidelity Threat Classes",
    icon: CheckCircle2,
    now: [
      "BENIGN (Normal Enterprise Traffic)",
      "DOS_DDOS (High-volume volumetric packet & bandwidth flood)",
      "SYN_FLOOD (TCP connection state exhaustion attack)",
      "PORT_SCAN (Horizontal and vertical reconnaissance scans)",
      "BRUTE_FORCE (Repeated credential trial bursts)",
      "ANOMALY (Zero-day / unknown statistical behavioral deviation)",
    ],
    future: [
      "MITRE ATT&CK technique mapping matrix (T1046, T1498, T1110, etc.)",
      "Ransomware lateral movement detection",
      "DNS tunneling and covert C2 channel classification",
    ],
  },
  {
    id: "stage-7",
    name: "7. Deterministic Risk Scoring Engine",
    subtitle: "0–100 Weighted Impact & Severity Matrix",
    icon: ShieldAlert,
    now: [
      "Formula: Risk = 0.40·Impact + 0.25·Anomaly + 0.20·Confidence + 0.15·Deviation",
      "Class impact weights: SYN Flood (90), DoS (85), Brute Force (72), Anomaly (50), Port Scan (45)",
      "Severity bands: LOW (0–24), MEDIUM (25–49), HIGH (50–74), CRITICAL (75–100)",
      "Transparent breakdown displayed directly in the analyst UI",
    ],
    future: [
      "Dynamic asset criticality weighting (e.g. Domain Controller = 1.5×, Sandbox = 0.5×)",
      "Analyst feedback loop into risk calibration engine",
      "Threat intelligence feed reputation enrichment (IP/ASN scoring)",
    ],
  },
  {
    id: "stage-8",
    name: "8. Real-Time Alert & Event Dispatcher",
    subtitle: "FastAPI Async Event Bus + Native WebSockets",
    icon: BellRing,
    now: [
      "Sub-millisecond broadcast of traffic_update, threat_detected, and alert frames",
      "SQLite persistent event store for historical review and audit logging",
      "Automatic reconnect with exponential backoff and REST polling fallback",
    ],
    future: [
      "Apache Kafka / Redis Streams broker for distributed microservice scaling",
      "SIEM webhooks (Splunk, Elastic, Microsoft Sentinel, IBM QRadar)",
      "PagerDuty / Slack incident escalation bot integration",
    ],
  },
  {
    id: "stage-9",
    name: "9. SOC Command Console & Automated Mitigation",
    subtitle: "Next.js 16 + React 19 Analyst Interface",
    icon: MonitorSmartphone,
    now: [
      "Real-time Recharts telemetry, threat feed with instant search, and plain-language explainability",
      "Simulate Block response trigger (recovers traffic towards normal baseline)",
      "Offline PCAP inspection with JSON/CSV report export",
      "Zero client-side fake data — pure reflection of backend decisions",
    ],
    future: [
      "SOAR playbook orchestration (automated firewall ACL / BGP blackhole pushes)",
      "Multi-tenant analyst RBAC with hardware security key (WebAuthn)",
      "Automated PDF executive incident report generation",
    ],
  },
];

export function ArchitectureView() {
  const modelInfo = useSentinelStore((s) => s.modelInfo);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            AI Sentinel Architecture
          </h1>
          <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-xs font-mono font-semibold text-emerald-400">
            Pipeline v1.0
          </span>
        </div>
        <p className="mt-1 text-sm text-zinc-400 leading-relaxed">
          The end-to-end intrusion detection pipeline from raw network ingestion to machine learning inference and analyst response. Every stage transparently contrasts what is <span className="text-emerald-400 font-semibold">implemented now</span> versus <span className="text-amber-400 font-semibold">future production integration</span>.
        </p>
      </div>

      {/* Live Pipeline Config Summary */}
      {modelInfo && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-emerald-400 mb-1">
            <Sparkles className="h-3.5 w-3.5" /> Active Pipeline Specifications
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-2 text-xs font-mono">
            <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
              <span className="text-zinc-500 block text-[10px]">Algorithm</span>
              <span className="font-bold text-zinc-200">{modelInfo.algorithm}</span>
            </div>
            <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
              <span className="text-zinc-500 block text-[10px]">Feature Vector</span>
              <span className="font-bold text-emerald-400">{modelInfo.n_features} Canonical Features</span>
            </div>
            <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
              <span className="text-zinc-500 block text-[10px]">Attack Classes</span>
              <span className="font-bold text-zinc-200">{modelInfo.classes.length} Trained Classes</span>
            </div>
            <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
              <span className="text-zinc-500 block text-[10px]">Training Windows</span>
              <span className="font-bold text-zinc-200">{modelInfo.train_samples.toLocaleString()} Samples</span>
            </div>
          </div>
        </div>
      )}

      {/* 9-Stage Pipeline Cards */}
      <div className="space-y-4">
        {STAGES.map((stage, i) => {
          const Icon = stage.icon;
          return (
            <div key={stage.id} className="relative">
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-5 shadow-sm hover:border-zinc-700 transition-all">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-zinc-800 text-emerald-400 border border-zinc-700/60">
                    <Icon className="h-5 w-5" aria-hidden />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-zinc-100">{stage.name}</h3>
                    <p className="text-xs text-zinc-400 font-mono">{stage.subtitle}</p>
                  </div>
                </div>

                <div className="mt-4 grid gap-4 md:grid-cols-2 pt-3 border-t border-zinc-800/80">
                  {/* Implemented Now */}
                  <div className="space-y-2 rounded-lg bg-zinc-950/40 p-3 border border-emerald-500/20">
                    <p className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-emerald-400">
                      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> Implemented Now (Working Demo)
                    </p>
                    <ul className="space-y-1.5 text-xs leading-relaxed text-zinc-300">
                      {stage.now.map((item, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-emerald-400 font-bold shrink-0">•</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Future Production Work */}
                  <div className="space-y-2 rounded-lg bg-zinc-950/40 p-3 border border-amber-500/20">
                    <p className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-amber-400">
                      <Clock className="h-3.5 w-3.5" aria-hidden /> Production Roadmap (Next Steps)
                    </p>
                    <ul className="space-y-1.5 text-xs leading-relaxed text-zinc-400">
                      {stage.future.map((item, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-amber-400/80 font-bold shrink-0">•</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              {i < STAGES.length - 1 && (
                <div className="flex justify-center py-2" aria-hidden>
                  <ArrowDown className="h-4 w-4 text-zinc-700 animate-bounce" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Honesty & Academic Disclaimer */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 shadow-sm">
        <p className="text-xs font-bold uppercase tracking-wider text-amber-400">
          Academic Integrity &amp; Simulation Statement
        </p>
        <p className="mt-1.5 text-xs leading-relaxed text-zinc-300">
          This system was built for educational and hackathon evaluation purposes. All live stream and simulation traffic is generated through synthetic mathematical modeling calibrated against the CIC-IDS2017 intrusion dataset. The &quot;Simulate Block&quot; action demonstrates control plane mitigation at the UI layer without modifying real firewall equipment.
        </p>
      </div>
    </div>
  );
}

/**
 * AI Sentinel — shared TypeScript contracts.
 *
 * These types mirror the Python backend EXACTLY (app/schemas, WS events,
 * API responses). Keep both sides in sync — the consistency of these
 * contracts is what makes the system end-to-end real.
 */

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AttackLabel =
  | "BENIGN"
  | "DOS_DDOS"
  | "PORT_SCAN"
  | "SYN_FLOOD"
  | "BRUTE_FORCE"
  | "ANOMALY";
export type NetworkStatus = "PROTECTED" | "MONITORING" | "UNDER_ATTACK";
export type EventStatus = "ACTIVE" | "RESOLVED" | "MITIGATED";
export type WsStatus =
  | "connecting"
  | "connected"
  | "reconnecting"
  | "polling"
  | "offline";
export type ViewName = "dashboard" | "lab" | "pcap" | "architecture" | "model";

export const ATTACK_DISPLAY: Record<AttackLabel, string> = {
  BENIGN: "Normal Traffic",
  DOS_DDOS: "DoS / DDoS Flood",
  PORT_SCAN: "Port Scan",
  SYN_FLOOD: "SYN Flood",
  BRUTE_FORCE: "Brute Force",
  ANOMALY: "Network Anomaly",
};

// ---------------------------------------------------------------- WS events
export interface TrafficUpdateMsg {
  type: "traffic_update";
  ts: number;
  source: string;
  sim_id?: string | null;
  prediction: AttackLabel;
  confidence: number;
  risk: number;
  severity: Severity;
  pkt_rate: number;
  byte_rate: number;
  flows: number;
  total_packets: number;
  syn_count: number;
  ack_count: number;
  duration_s: number;
  mitigated?: boolean;
}

export interface ExplanationEvidence {
  label: string;
  observed: string;
  baseline: string;
  detail: string;
}

export interface Explanation {
  headline: string;
  classification: string;
  meaning: string;
  evidence: ExplanationEvidence[];
  recommendation: string;
  notes: string[];
}

export interface Observed {
  pkt_rate: number;
  flow_count: number;
  total_packets: number;
  syn_count: number;
  ack_count: number;
  duration_s: number;
  distinct_dst_ports: number;
  avg_pkt_size: number;
}

export interface ThreatDetectedMsg {
  type: "threat_detected";
  ts: number;
  event_id: string;
  sim_id?: string | null;
  attack: AttackLabel;
  classification: string;
  confidence: number;
  risk: number;
  severity: Severity;
  anomaly_score: number;
  source: string;
  target: string;
  explanation: Explanation;
  observed: Observed;
  features: Record<string, number>;
  probabilities: Record<string, number>;
  origin: string;
  model_version: string;
}

export interface AlertMsg {
  type: "alert";
  ts: number;
  event_id: string;
  attack: AttackLabel;
  classification: string;
  severity: Severity;
  risk: number;
  confidence: number;
  source: string;
  message: string;
}

export interface MitigationMsg {
  type: "mitigation";
  ts: number;
  event_id: string;
  action: string;
  target: string;
  before_pkt_rate: number;
  after_pkt_rate: number;
  status: "MITIGATED";
  note: string;
}

export interface SimStartedMsg {
  type: "sim_started";
  ts: number;
  sim_id: string;
  attack_type: string;
  scenario: string;
  windows_total: number;
  message: string;
}

export interface SimProgressMsg {
  type: "sim_progress";
  ts: number;
  sim_id: string;
  attack_type: string;
  phase: "running" | "mitigating" | "complete" | "mitigated";
  windows_done: number;
  windows_total: number;
  intensity?: number;
  current_risk?: number;
}

export interface SimCompleteMsg {
  type: "sim_complete";
  ts: number;
  sim_id: string;
  attack_type: string;
  phase: "complete" | "mitigated";
  detected: boolean;
  final_risk: number;
  final_severity: Severity;
  peak_pkt_rate: number;
  message: string;
}

export interface DemoResetMsg {
  type: "demo_reset";
  ts: number;
  message: string;
}

export type WsMessage =
  | TrafficUpdateMsg
  | ThreatDetectedMsg
  | AlertMsg
  | MitigationMsg
  | SimStartedMsg
  | SimProgressMsg
  | SimCompleteMsg
  | DemoResetMsg
  | { type: "event_resolved"; ts: number; event_id: string; status: string }
  | { type: "hello" | "pong" | "system_status"; [k: string]: unknown };

// ---------------------------------------------------------------- REST types
export interface HealthInfo {
  status: string;
  service: string;
  backend: string;
  model: string;
  model_version: string | null;
  uptime_s: number;
  websocket_clients: number;
}

export interface LabelMappingRow {
  dataset_label: string;
  app_class: string;
  note?: string;
}

export interface ModelInfo {
  algorithm: string;
  model_version: string;
  trained_at: string;
  classes: AttackLabel[];
  features: string[];
  n_features: number;
  train_samples: number;
  eval_samples: number;
  dataset: {
    source: string;
    generator_seed_train: number;
    generator_seed_eval: number;
    honesty_note: string;
  };
  metrics: {
    accuracy: number;
    precision_macro: number;
    recall_macro: number;
    f1_macro: number;
    mean_confidence: number;
    min_confidence: number;
    per_class: Record<
      string,
      { precision: number; recall: number; f1: number; support: number }
    >;
    confusion_matrix: { labels: string[]; matrix: number[][] };
    eval_samples: number;
  };
  feature_importances: { feature: string; importance: number }[];
  label_mapping: LabelMappingRow[];
  anomaly_detector: {
    algorithm: string;
    contamination: number;
    trained_on: string;
  };
  risk_model: {
    benign: string;
    threat: string;
    severity_bands: Record<Severity, string>;
    class_impact: Record<string, number>;
  };
  honesty_notes: string[];
}

export interface ScenarioType {
  type: string;
  name: string;
  tagline: string;
  description: string;
  expected: string;
  safety: string;
}

export interface ThreatEvent {
  id: string;
  ts: number;
  updated_ts: number;
  attack: AttackLabel;
  confidence: number;
  risk: number;
  severity: Severity;
  status: EventStatus;
  source: string;
  target: string;
  sim_id?: string | null;
  origin: string;
  anomaly_score: number;
  model_version: string;
  explanation: Explanation;
  observed: Observed;
  features?: Record<string, number>;
  probabilities: Record<string, number>;
}

export interface StatisticsInfo {
  network_status: NetworkStatus;
  current_risk: number;
  totals: {
    events_total: number;
    threats_total: number;
    critical_total: number;
    active_threats: number;
    mitigated: number;
    resolved: number;
  };
  traffic: {
    pkt_rate: number;
    byte_rate: number;
    flows: number;
    prediction: AttackLabel;
  };
  blocked_sources: { source: string; blocked_at: number; expires_at: number }[];
  uptime_s: number;
  severity_bands: Record<Severity, string>;
}

export interface PcapSampleInfo {
  name: string;
  filename: string;
  description: string;
  expected: string;
  size_bytes: number;
  available: boolean;
}

export interface PcapResultRow {
  event_id: string;
  source: string;
  target: string;
  label: AttackLabel;
  classification: string;
  confidence: number;
  risk: number;
  severity: Severity;
  anomaly_score: number;
  observed: Observed;
  explanation: Explanation;
  features: Record<string, number>;
  ts?: number | null;
}

export interface PcapResult {
  filename: string;
  total_packets: number;
  total_flows: number;
  analyzed_windows: number;
  benign_flows: number;
  suspicious_flows: number;
  attack_types: Record<string, number>;
  severity_distribution: Record<Severity, number>;
  risk_distribution: Record<string, number>;
  results: PcapResultRow[];
  global_assessment: PcapResultRow | null;
  timeline: { t: number; packets: number }[];
  limitations: string[];
  analysis_ms: number;
}

// ---------------------------------------------------------------- UI models
export interface User {
  email: string;
  name: string;
  role: "SOC Analyst" | "Lead Responder" | "Security Lead" | "Guest Evaluator";
}

export interface TrafficPoint {
  t: number;
  pktRate: number;
  byteRate: number;
  flows: number;
  risk: number;
  severity: Severity;
  prediction: AttackLabel;
  synCount?: number;
  ackCount?: number;
  totalPackets?: number;
}

export interface AlertToastItem {
  key: string;
  event_id: string;
  attack: AttackLabel;
  classification: string;
  severity: Severity;
  risk: number;
  confidence: number;
  message: string;
  source: string;
  ts: number;
}

export interface SimState {
  sim_id: string;
  attack_type: string;
  phase: "starting" | "running" | "mitigating" | "complete" | "mitigated";
  windows_done: number;
  windows_total: number;
  started_at: number;
  detected?: boolean;
  final_risk?: number;
  final_severity?: Severity;
  error?: string;
}

export interface CaptureInterface {
  id: string;
  name: string;
  description: string;
  ip: string;
  mac: string;
  is_loopback: boolean;
  is_active: boolean;
}

export interface CaptureStatus {
  status: "CAPTURE_AVAILABLE" | "CAPTURE_RUNNING" | "CAPTURE_STOPPED" | "CAPTURE_ERROR";
  mode: "LIVE" | "SYNTHETIC_BASELINE";
  interface: string | null;
  packets_captured: number;
  duration_s: number;
  error: string | null;
  pcap_provider: boolean;
}



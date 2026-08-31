"use client";
/**
 * AI Sentinel — Zustand store (client state).
 * All real-time state arrives via WebSocket into this store; the UI is a
 * pure function of it. The frontend NEVER decides attack types — it only
 * renders what the Python pipeline classifies.
 */
import { create } from "zustand";
import { sentinelApi } from "./api";
import type {
  AlertToastItem,
  HealthInfo,
  ModelInfo,
  PcapSampleInfo,
  ScenarioType,
  SimState,
  StatisticsInfo,
  ThreatEvent,
  TrafficPoint,
  ViewName,
  WsMessage,
  WsStatus,
} from "./types";

const MAX_TRAFFIC_POINTS = 150;
const MAX_EVENTS = 200;
const MAX_TOASTS = 5;

interface SentinelStore {
  // ---- view
  view: ViewName;
  setView: (v: ViewName) => void;

  // ---- connection / info
  wsStatus: WsStatus;
  setWsStatus: (s: WsStatus) => void;
  backendOnline: boolean | null;
  health: HealthInfo | null;
  modelInfo: ModelInfo | null;
  modelInfoError: string | null;
  scenarios: ScenarioType[];
  pcapSamples: PcapSampleInfo[];
  statistics: StatisticsInfo | null;

  // ---- live data
  traffic: TrafficPoint[];
  livePrediction: ThreatEvent | null; // last window classification chip
  events: ThreatEvent[];
  selectedEventId: string | null;
  alerts: AlertToastItem[];
  sims: Record<string, SimState>;
  simStartView: string | null; // view to auto-open on first threat

  // ---- actions
  initialize: () => Promise<void>;
  handleWsMessage: (msg: WsMessage) => void;
  selectEvent: (id: string | null) => void;
  dismissAlert: (key: string) => void;
  runSimulation: (attackType: string) => Promise<void>;
  resolveEvent: (id: string) => Promise<void>;
  mitigateEvent: (id: string) => Promise<void>;
  refreshEvents: () => Promise<void>;
  refreshStatistics: () => Promise<void>;
}

function upsertEvent(events: ThreatEvent[], ev: ThreatEvent): ThreatEvent[] {
  const idx = events.findIndex((e) => e.id === ev.id);
  if (idx === -1) return [ev, ...events].slice(0, MAX_EVENTS);
  const next = [...events];
  next[idx] = { ...next[idx], ...ev };
  return next;
}

export const useSentinelStore = create<SentinelStore>((set, get) => ({
  view: "dashboard",
  setView: (v) => set({ view: v }),

  wsStatus: "connecting",
  setWsStatus: (s) => set({ wsStatus: s }),
  backendOnline: null,
  health: null,
  modelInfo: null,
  modelInfoError: null,
  scenarios: [],
  pcapSamples: [],
  statistics: null,

  traffic: [],
  livePrediction: null,
  events: [],
  selectedEventId: null,
  alerts: [],
  sims: {},
  simStartView: null,

  initialize: async () => {
    // parallel loads; each failure degrades gracefully
    const tasks = [
      sentinelApi
        .health()
        .then((h) => set({ health: h, backendOnline: true }))
        .catch(() => set({ backendOnline: false })),
      sentinelApi
        .modelInfo()
        .then((m) => set({ modelInfo: m, modelInfoError: null }))
        .catch((e) =>
          set({
            modelInfoError:
              e instanceof Error ? e.message : "Could not load model info",
          }),
        ),
      sentinelApi
        .simulationTypes()
        .then((s) => set({ scenarios: s }))
        .catch(() => set({ scenarios: [] })),
      sentinelApi
        .pcapSamples()
        .then((s) => set({ pcapSamples: s }))
        .catch(() => set({ pcapSamples: [] })),
      get().refreshEvents(),
      get().refreshStatistics(),
    ];
    await Promise.allSettled(tasks);
  },

  refreshEvents: async () => {
    try {
      const { events } = await sentinelApi.events(100);
      set((s) => ({
        events: events.slice(0, MAX_EVENTS),
        selectedEventId:
          s.selectedEventId &&
          events.some((e) => e.id === s.selectedEventId)
            ? s.selectedEventId
            : s.selectedEventId,
      }));
    } catch {
      /* transient; polling fallback will retry */
    }
  },

  refreshStatistics: async () => {
    try {
      const st = await sentinelApi.statistics();
      set({ statistics: st, backendOnline: true });
    } catch {
      set({ backendOnline: false });
    }
  },

  handleWsMessage: (msg) => {
    const state = get();
    switch (msg.type) {
      case "traffic_update": {
        const point: TrafficPoint = {
          t: msg.ts * 1000,
          pktRate: msg.pkt_rate,
          byteRate: msg.byte_rate,
          flows: msg.flows,
          risk: msg.risk,
          severity: msg.severity,
          prediction: msg.prediction,
        };
        set({
          traffic: [...state.traffic, point].slice(-MAX_TRAFFIC_POINTS),
          livePrediction: msg.prediction === "BENIGN" ? null : msg,
        });
        break;
      }
      case "threat_detected": {
        const ev: ThreatEvent = {
          id: msg.event_id,
          ts: msg.ts,
          updated_ts: msg.ts,
          attack: msg.attack,
          confidence: msg.confidence,
          risk: msg.risk,
          severity: msg.severity,
          status: "ACTIVE",
          source: msg.source,
          target: msg.target,
          sim_id: msg.sim_id ?? null,
          origin: msg.origin,
          anomaly_score: msg.anomaly_score,
          model_version: msg.model_version,
          explanation: msg.explanation,
          observed: msg.observed,
          features: msg.features,
          probabilities: msg.probabilities,
        };
        const isNew = !state.events.some((e) => e.id === ev.id);
        set({ events: upsertEvent(state.events, ev) });
        if (isNew) {
          // auto-open the threat (demo flow) when it belongs to a
          // simulation started from the Test Lab
          if (ev.sim_id && state.sims[ev.sim_id]) {
            set({ selectedEventId: ev.id });
            if (state.view === "lab") set({ view: "dashboard" });
          }
        }
        break;
      }
      case "alert": {
        const toast: AlertToastItem = {
          key: `${msg.event_id}-${msg.ts}`,
          event_id: msg.event_id,
          attack: msg.attack,
          classification: msg.classification,
          severity: msg.severity,
          risk: msg.risk,
          confidence: msg.confidence,
          message: msg.message,
          source: msg.source,
          ts: msg.ts,
        };
        set({ alerts: [...state.alerts, toast].slice(-MAX_TOASTS) });
        break;
      }
      case "mitigation": {
        set({
          events: state.events.map((e) =>
            e.id === msg.event_id ? { ...e, status: "MITIGATED" } : e,
          ),
        });
        get().refreshStatistics();
        break;
      }
      case "sim_started": {
        set({
          sims: {
            ...state.sims,
            [msg.sim_id]: {
              sim_id: msg.sim_id,
              attack_type: msg.attack_type,
              phase: "running",
              windows_done: 0,
              windows_total: msg.windows_total,
              started_at: msg.ts,
            },
          },
        });
        break;
      }
      case "sim_progress": {
        const sim = state.sims[msg.sim_id];
        if (sim) {
          set({
            sims: {
              ...state.sims,
              [msg.sim_id]: {
                ...sim,
                phase: msg.phase === "mitigating" ? "mitigating" : "running",
                windows_done: msg.windows_done,
                windows_total: msg.windows_total,
              },
            },
          });
        }
        break;
      }
      case "sim_complete": {
        const sim = state.sims[msg.sim_id];
        if (sim) {
          set({
            sims: {
              ...state.sims,
              [msg.sim_id]: {
                ...sim,
                phase: msg.phase === "mitigated" ? "mitigated" : "complete",
                detected: msg.detected,
                final_risk: msg.final_risk,
                final_severity: msg.final_severity,
              },
            },
          });
        }
        get().refreshStatistics();
        break;
      }
      case "event_resolved": {
        set({
          events: state.events.map((e) =>
            e.id === msg.event_id ? { ...e, status: "RESOLVED" } : e,
          ),
        });
        break;
      }
      default:
        break;
    }
  },

  selectEvent: (id) => set({ selectedEventId: id }),

  dismissAlert: (key) =>
    set((s) => ({ alerts: s.alerts.filter((a) => a.key !== key) })),

  runSimulation: async (attackType) => {
    try {
      const res = await sentinelApi.startSimulation(attackType);
      set((s) => ({
        sims: {
          ...s.sims,
          [res.sim_id]: {
            sim_id: res.sim_id,
            attack_type: attackType,
            phase: "starting",
            windows_done: 0,
            windows_total: res.windows_total,
            started_at: Date.now() / 1000,
          },
        },
      }));
    } catch (e) {
      // attach error to a pseudo sim so the card can show it
      const msg = e instanceof Error ? e.message : "Simulation failed";
      set((s) => {
        const sims = { ...s.sims };
        const existing = Object.values(sims).find(
          (x) => x.attack_type === attackType && x.phase !== "complete",
        );
        if (existing) sims[existing.sim_id] = { ...existing, error: msg };
        return { sims };
      });
      throw e;
    }
  },

  resolveEvent: async (id) => {
    try {
      const res = await sentinelApi.resolveEvent(id);
      set((s) => ({ events: upsertEvent(s.events, res.event) }));
    } catch {
      get().refreshEvents();
    }
  },

  mitigateEvent: async (id) => {
    try {
      const res = await sentinelApi.mitigateEvent(id);
      set((s) => ({ events: upsertEvent(s.events, res.event) }));
      get().refreshStatistics();
    } catch {
      get().refreshEvents();
    }
  },
}));

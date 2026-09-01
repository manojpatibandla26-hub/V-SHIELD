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
  CaptureInterface,
  CaptureStatus,
  HealthInfo,
  ModelInfo,
  PcapSampleInfo,
  ScenarioType,
  SimState,
  StatisticsInfo,
  ThreatEvent,
  TrafficPoint,
  User,
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

  // ---- auth (demo client-side)
  user: User | null;
  authModalOpen: boolean;
  setAuthModalOpen: (open: boolean) => void;
  login: (email: string, pass: string) => Promise<{ success: boolean; error?: string }>;
  signup: (email: string, name: string, pass: string, role?: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;

  // ---- auto defense / active response
  autoDefense: boolean;
  setAutoDefense: (enabled: boolean) => void;
  toggleAutoDefense: () => void;

  // ---- packet capture
  captureStatus: CaptureStatus | null;
  interfaces: CaptureInterface[];
  selectedInterface: string | null;
  setSelectedInterface: (iface: string | null) => void;
  startCapture: (iface?: string) => Promise<void>;
  stopCapture: () => Promise<void>;
  refreshCaptureStatus: () => Promise<void>;

  // ---- actions
  initialize: () => Promise<void>;
  retryConnection: () => Promise<void>;
  handleWsMessage: (msg: WsMessage) => void;
  selectEvent: (id: string | null) => void;
  dismissAlert: (key: string) => void;
  runSimulation: (attackType: string) => Promise<void>;
  resolveEvent: (id: string) => Promise<void>;
  mitigateEvent: (id: string) => Promise<void>;
  resetDemo: () => Promise<void>;
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

function clearedDemoState() {
  return {
    traffic: [] as TrafficPoint[],
    livePrediction: null,
    events: [] as ThreatEvent[],
    selectedEventId: null,
    alerts: [] as AlertToastItem[],
    sims: {} as Record<string, SimState>,
  };
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

  // Auth state
  user: null,
  authModalOpen: false,
  setAuthModalOpen: (open: boolean) => set({ authModalOpen: open }),

  // Auto defense state
  autoDefense: false,
  setAutoDefense: (enabled: boolean) => set({ autoDefense: enabled }),
  toggleAutoDefense: () => set((s) => ({ autoDefense: !s.autoDefense })),

  login: async (email: string, pass: string) => {
    if (!email || !pass) {
      return { success: false, error: "Email and password are required" };
    }
    // Check localStorage accounts
    if (typeof window !== "undefined") {
      try {
        const storedUsers = JSON.parse(localStorage.getItem("sentinel_users") || "[]");
        const found = storedUsers.find((u: { email: string; pass: string }) => u.email.toLowerCase() === email.toLowerCase());
        if (found) {
          if (found.pass === pass) {
            const user: User = { email: found.email, name: found.name, role: found.role || "SOC Analyst" };
            localStorage.setItem("sentinel_current_user", JSON.stringify(user));
            set({ user, authModalOpen: false });
            return { success: true };
          } else {
            return { success: false, error: "Invalid password for this account" };
          }
        } else {
          // Check default demo account
          if (email.toLowerCase() === "analyst@sentinel.soc" && pass === "Sentinel@2026") {
            const user: User = { email: "analyst@sentinel.soc", name: "Alex Chen", role: "SOC Analyst" };
            localStorage.setItem("sentinel_current_user", JSON.stringify(user));
            set({ user, authModalOpen: false });
            return { success: true };
          }
          return { success: false, error: "Account not found. Please sign up." };
        }
      } catch {
        return { success: false, error: "Authentication error" };
      }
    }
    return { success: false, error: "Browser storage unavailable" };
  },

  signup: async (email: string, name: string, pass: string, role?: string) => {
    if (!email || !name || !pass) {
      return { success: false, error: "All fields are required" };
    }
    if (pass.length < 6) {
      return { success: false, error: "Password must be at least 6 characters long" };
    }
    if (!/[A-Z]/.test(pass)) {
      return { success: false, error: "Password must contain at least one uppercase letter" };
    }
    if (typeof window !== "undefined") {
      try {
        const storedUsers = JSON.parse(localStorage.getItem("sentinel_users") || "[]");
        if (storedUsers.some((u: { email: string }) => u.email.toLowerCase() === email.toLowerCase())) {
          return { success: false, error: "An account with this email already exists" };
        }
        const assignedRole = (role as User["role"]) || "SOC Analyst";
        const newUserRecord = { email, name, pass, role: assignedRole };
        storedUsers.push(newUserRecord);
        localStorage.setItem("sentinel_users", JSON.stringify(storedUsers));
        return { success: true };
      } catch {
        return { success: false, error: "Failed to save account" };
      }
    }
    return { success: false, error: "Browser storage unavailable" };
  },

  logout: () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("sentinel_current_user");
    }
    set({ user: null, authModalOpen: true });
  },

  // ---- packet capture
  captureStatus: null,
  interfaces: [],
  selectedInterface: null,
  setSelectedInterface: (iface) => set({ selectedInterface: iface }),

  startCapture: async (iface?: string) => {
    try {
      const res = await sentinelApi.startCapture(iface ?? get().selectedInterface ?? undefined);
      set({ captureStatus: res });
    } catch (e) {
      /* handled gracefully */
    }
  },

  stopCapture: async () => {
    try {
      const res = await sentinelApi.stopCapture();
      set({ captureStatus: res });
    } catch (e) {
      /* handled gracefully */
    }
  },

  refreshCaptureStatus: async () => {
    try {
      const [status, ifaces] = await Promise.all([
        sentinelApi.captureStatus(),
        sentinelApi.captureInterfaces(),
      ]);
      set({
        captureStatus: status,
        interfaces: ifaces.interfaces,
        selectedInterface: ifaces.interfaces.find((i) => i.is_active)?.name || ifaces.interfaces[0]?.name || null,
      });
    } catch {
      /* capture status check */
    }
  },

  initialize: async () => {
    // Restore current user if stored
    if (typeof window !== "undefined") {
      try {
        const stored = localStorage.getItem("sentinel_current_user");
        if (stored) {
          set({ user: JSON.parse(stored) });
        } else {
          set({ user: null, authModalOpen: true });
        }
      } catch {
        /* ignore storage parse error */
      }
    }

    // Set fallback initial statistics to prevent permanent skeleton loading
    if (!get().statistics) {
      set({
        statistics: {
          current_risk: 0,
          network_status: "PROTECTED",
          blocked_sources: [],
          totals: {
            critical_total: 0,
            high_total: 0,
            medium_total: 0,
            low_total: 0,
            mitigated_total: 0,
            resolved_total: 0,
            active_total: 0,
          },
          baseline_pkt_rate: 450,
          traffic_window_s: 2,
        },
      });
    }

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
      get().refreshCaptureStatus(),
    ];
    await Promise.allSettled(tasks);
  },

  retryConnection: async () => {
    set({ backendOnline: null });
    await get().initialize();
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
          synCount: msg.syn_count,
          ackCount: msg.ack_count,
          totalPackets: msg.total_packets,
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
          // Autonomous Active Defense Trigger
          if (get().autoDefense && ev.attack !== "BENIGN" && ev.status === "ACTIVE") {
            setTimeout(() => {
              void get().mitigateEvent(ev.id);
            }, 500);
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
      case "capture_status_change": {
        void get().refreshCaptureStatus();
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
      case "demo_reset": {
        // Backend cleared everything (POST /api/reset): mirror it locally.
        set(clearedDemoState());
        get().refreshStatistics();
        get().refreshEvents();
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

  resetDemo: async () => {
    try {
      await sentinelApi.resetDemo();
      set(clearedDemoState());
      await Promise.allSettled([
        get().refreshStatistics(),
        get().refreshEvents(),
      ]);
    } catch {
      /* backend unreachable — WS reconnect/polling will resync */
    }
  },
}));

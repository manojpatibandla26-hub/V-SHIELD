/**
 * AI Sentinel — API client.
 *
 * Sandbox/gateway mode (default): same-origin requests with the
 * ?XTransformPort=8000 query param — the Caddy gateway routes them to the
 * Python FastAPI mini-service on port 8000. WebSocket: /ws?XTransformPort=8000.
 *
 * Local-laptop mode: set NEXT_PUBLIC_API_BASE=http://localhost:8000 in
 * .env.local and every call (and the WebSocket) goes directly to uvicorn.
 */
import type {
  CaptureInterface,
  CaptureStatus,
  HealthInfo,
  ModelInfo,
  PcapResult,
  PcapSampleInfo,
  ScenarioType,
  StatisticsInfo,
  ThreatEvent,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "";
const SERVICE_PORT = "8000";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

function apiUrl(path: string): string {
  if (API_BASE) return `${API_BASE}${path}`;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}XTransformPort=${SERVICE_PORT}`;
}

export function wsUrl(): string {
  if (API_BASE) return `${API_BASE.replace(/^http/, "ws")}/ws`;
  const proto =
    typeof window !== "undefined" && window.location.protocol === "https:"
      ? "wss"
      : "ws";
  return `${proto}://${window.location.host}/ws?XTransformPort=${SERVICE_PORT}`;
}

async function parseError(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return body.detail;
    if (body?.detail?.message) return body.detail.message;
    return JSON.stringify(body).slice(0, 200);
  } catch {
    return `HTTP ${res.status}`;
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(apiUrl(path), { cache: "no-store" });
  if (!res.ok) throw new ApiError(await parseError(res), res.status);
  return (await res.json()) as T;
}

export async function apiPost<T>(
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(apiUrl(path), {
    method: "POST",
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new ApiError(await parseError(res), res.status);
  return (await res.json()) as T;
}

export async function uploadPcap(file: File): Promise<PcapResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(apiUrl("/api/pcap/upload"), {
    method: "POST",
    body: form,
  });
  if (!res.ok) throw new ApiError(await parseError(res), res.status);
  return (await res.json()) as PcapResult;
}

// ------------------------------------------------------------ typed helpers
export const sentinelApi = {
  health: () => apiGet<HealthInfo>("/api/health"),
  modelInfo: () => apiGet<ModelInfo>("/api/model-info"),
  simulationTypes: () => apiGet<ScenarioType[]>("/api/simulation/types"),
  statistics: () => apiGet<StatisticsInfo>("/api/statistics"),
  events: (limit = 100) =>
    apiGet<{ events: ThreatEvent[] }>(`/api/events?limit=${limit}`),
  pcapSamples: () => apiGet<PcapSampleInfo[]>("/api/pcap/samples"),
  startSimulation: (attackType: string) =>
    apiPost<{ sim_id: string; scenario: string; windows_total: number }>(
      `/api/simulation/${attackType}`,
    ),
  resolveEvent: (eventId: string) =>
    apiPost<{ ok: boolean; event: ThreatEvent }>(
      `/api/events/${eventId}/resolve`,
    ),
  mitigateEvent: (eventId: string) =>
    apiPost<{
      ok: boolean;
      event: ThreatEvent;
      handled_by: string;
      before_pkt_rate?: number;
      after_pkt_rate?: number;
    }>(`/api/events/${eventId}/simulate-mitigation`),
  analyzeSample: (name: string) =>
    apiPost<PcapResult>(`/api/pcap/samples/${name}/analyze`),
  resetDemo: () =>
    apiPost<{
      ok: boolean;
      cleared: { events: number; cancelled_simulations: number };
    }>("/api/reset"),
  captureInterfaces: () =>
    apiGet<{ interfaces: CaptureInterface[] }>("/api/capture/interfaces"),
  captureStatus: () =>
    apiGet<CaptureStatus>("/api/capture/status"),
  startCapture: (iface?: string) =>
    apiPost<CaptureStatus>("/api/capture/start", { interface: iface }),
  stopCapture: () =>
    apiPost<CaptureStatus>("/api/capture/stop"),
};

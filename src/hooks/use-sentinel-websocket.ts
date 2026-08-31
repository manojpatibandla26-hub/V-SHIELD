"use client";
/**
 * AI Sentinel — WebSocket connection hook.
 *
 * Connects to the FastAPI WebSocket (through the Caddy gateway in sandbox
 * mode). Automatic reconnection with backoff; after repeated failures it
 * falls back to REST polling (statistics + events every 4s) while still
 * retrying the socket — the dashboard never silently dies.
 */
import { useEffect, useRef } from "react";
import { wsUrl } from "@/lib/sentinel/api";
import { useSentinelStore } from "@/lib/sentinel/store";
import type { WsMessage } from "@/lib/sentinel/types";

export function useSentinelWebSocket() {
  const effectRan = useRef(false);

  useEffect(() => {
    if (effectRan.current) return; // react 18 strict-mode guard
    effectRan.current = true;

    const store = useSentinelStore.getState();
    let ws: WebSocket | null = null;
    let attempts = 0;
    let closed = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const startPolling = () => {
      if (pollTimer) return;
      useSentinelStore.getState().setWsStatus("polling");
      pollTimer = setInterval(() => {
        void useSentinelStore.getState().refreshStatistics();
        void useSentinelStore.getState().refreshEvents();
      }, 4000);
    };
    const stopPolling = () => {
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const connect = () => {
      if (closed) return;
      useSentinelStore
        .getState()
        .setWsStatus(attempts === 0 ? "connecting" : "reconnecting");
      try {
        ws = new WebSocket(wsUrl());
      } catch {
        scheduleRetry();
        return;
      }

      ws.onopen = () => {
        attempts = 0;
        stopPolling();
        useSentinelStore.getState().setWsStatus("connected");
        void useSentinelStore.getState().refreshStatistics();
      };

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data as string) as WsMessage;
          useSentinelStore.getState().handleWsMessage(msg);
        } catch {
          /* ignore malformed frame */
        }
      };

      ws.onerror = () => {
        ws?.close();
      };

      ws.onclose = () => {
        if (closed) return;
        attempts += 1;
        if (attempts >= 3) startPolling();
        scheduleRetry();
      };
    };

    const scheduleRetry = () => {
      if (closed || retryTimer) return;
      const delay = Math.min(800 * attempts, 5000);
      retryTimer = setTimeout(() => {
        retryTimer = null;
        connect();
      }, delay);
    };

    connect();

    // keepalive (backend replies pong)
    const ping = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send("ping");
      }
    }, 25000);

    return () => {
      closed = true;
      clearInterval(ping);
      stopPolling();
      if (retryTimer) clearTimeout(retryTimer);
      if (ws) {
        ws.onclose = null;
        ws.close();
      }
    };
  }, []);
}

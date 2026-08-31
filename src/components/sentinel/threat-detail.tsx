"use client";
/**
 * AI Sentinel — threat detail panel.
 * Plain language first (what does this mean?), evidence from REAL feature
 * values, observed traffic, recommended response, actions.
 * Technical details expandable in a dialog.
 */
import { useState } from "react";
import {
  ShieldAlert,
  CheckCircle2,
  Ban,
  ChevronDown,
  FileSearch,
  Lightbulb,
  ArrowRight,
} from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import { cn } from "@/lib/utils";
import {
  fmtNum,
  fmtTimeAgo,
  RiskGauge,
  SEVERITY_STYLE,
  SeverityBadge,
  StatusBadge,
} from "./bits";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";

function ObservedStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-zinc-900/70 p-2.5">
      <p className="text-[11px] uppercase tracking-wide text-zinc-500">
        {label}
      </p>
      <p className="mt-0.5 font-mono text-sm tabular-nums text-zinc-200">
        {value}
      </p>
    </div>
  );
}

export function ThreatDetail() {
  const events = useSentinelStore((s) => s.events);
  const selectedEventId = useSentinelStore((s) => s.selectedEventId);
  const selectEvent = useSentinelStore((s) => s.selectEvent);
  const resolveEvent = useSentinelStore((s) => s.resolveEvent);
  const mitigateEvent = useSentinelStore((s) => s.mitigateEvent);
  const [busy, setBusy] = useState(false);
  const [techOpen, setTechOpen] = useState(false);

  const ev = events.find((e) => e.id === selectedEventId) ?? null;

  if (!ev) {
    return (
      <section
        aria-label="Threat details"
        className="flex h-full min-h-[320px] flex-col items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-900/30 p-8 text-center"
      >
        <ShieldAlert className="h-10 w-10 text-zinc-700" aria-hidden />
        <p className="mt-3 text-sm font-medium text-zinc-400">
          No threat selected
        </p>
        <p className="mt-1 max-w-xs text-xs text-zinc-600">
          Select an event in the threat timeline, or run a safe simulation in
          the Security Test Lab — detections will appear here automatically.
        </p>
      </section>
    );
  }

  const sev = SEVERITY_STYLE[ev.severity];
  const exp = ev.explanation;

  const act = async (fn: (id: string) => Promise<void>) => {
    setBusy(true);
    try {
      await fn(ev.id);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section
      aria-label="Threat details"
      className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60"
    >
      {/* header banner */}
      <div className={cn("border-b p-4", sev.chip)}>
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-bold uppercase tracking-widest">
            Threat detected
          </p>
          <StatusBadge status={ev.status} />
        </div>
        <h2 className="mt-1 text-lg font-semibold">{exp.classification}</h2>
        <p className="text-xs opacity-80">
          {exp.headline} · {fmtTimeAgo(ev.ts)} · source{" "}
          <span className="font-mono">{ev.source}</span>
        </p>
      </div>

      <div className="space-y-4 p-4">
        {/* risk + confidence */}
        <div className="flex items-center gap-4">
          <RiskGauge risk={ev.risk} severity={ev.severity} size={130} />
          <div className="min-w-0 flex-1 space-y-3">
            <div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-zinc-500">ML confidence</span>
                <span className="font-mono text-zinc-300">
                  {(ev.confidence * 100).toFixed(1)}%
                </span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-zinc-800">
                <div
                  className={cn("h-full rounded-full transition-all", sev.bar)}
                  style={{ width: `${ev.confidence * 100}%` }}
                />
              </div>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-500">Anomaly score</span>
              <span className="font-mono text-zinc-300">
                {ev.anomaly_score.toFixed(2)}/1.00
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-500">Model</span>
              <span className="font-mono text-zinc-300">
                {ev.model_version}
              </span>
            </div>
          </div>
        </div>

        {/* plain-language meaning */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
            What does this mean?
          </p>
          <p className="mt-1.5 text-sm leading-relaxed text-zinc-300">
            {exp.meaning}
          </p>
        </div>

        {/* evidence from real features */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Why did the system detect this?
          </p>
          <ul className="mt-2 space-y-1.5">
            {exp.evidence.map((evidence, i) => (
              <li
                key={i}
                className="flex items-start gap-2 rounded-lg bg-zinc-900/70 p-2.5 text-sm text-zinc-300"
              >
                <ChevronDown className="mt-0.5 h-3.5 w-3.5 shrink-0 rotate-[-90deg] text-zinc-600" aria-hidden />
                <span>
                  {evidence.detail}{" "}
                  <span className="text-zinc-500">
                    (observed {evidence.observed} · normal {evidence.baseline})
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* observed traffic */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
            Observed traffic
          </p>
          <div className="mt-2 grid grid-cols-3 gap-2">
            <ObservedStat
              label="Packet rate"
              value={`${fmtNum(ev.observed.pkt_rate)}/s`}
            />
            <ObservedStat label="Flows" value={fmtNum(ev.observed.flow_count)} />
            <ObservedStat label="SYN count" value={fmtNum(ev.observed.syn_count)} />
            <ObservedStat label="ACK count" value={fmtNum(ev.observed.ack_count)} />
            <ObservedStat
              label="Duration"
              value={`${ev.observed.duration_s.toFixed(1)}s`}
            />
            <ObservedStat
              label="Ports hit"
              value={fmtNum(ev.observed.distinct_dst_ports)}
            />
          </div>
        </div>

        {/* recommendation */}
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-emerald-400">
            <Lightbulb className="h-3.5 w-3.5" aria-hidden /> Recommended response
          </p>
          <p className="mt-1.5 text-sm leading-relaxed text-zinc-300">
            {exp.recommendation}
          </p>
        </div>

        {ev.status === "MITIGATED" && (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">
            Source was blocked (simulation). Traffic has returned toward the
            normal baseline — this event is marked mitigated.
          </div>
        )}

        {exp.notes.length > 0 && (
          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-200/90">
            {exp.notes.map((note, i) => (
              <p key={i}>{note}</p>
            ))}
          </div>
        )}

        {/* actions */}
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={busy || ev.status === "RESOLVED"}
            onClick={() => act(resolveEvent)}
            className="border-zinc-700 bg-transparent text-zinc-300 hover:bg-zinc-800"
          >
            <CheckCircle2 className="mr-1.5 h-3.5 w-3.5" aria-hidden />
            {ev.status === "RESOLVED" ? "Resolved" : "Mark Resolved"}
          </Button>
          <Button
            size="sm"
            disabled={busy || ev.status === "MITIGATED"}
            onClick={() => act(mitigateEvent)}
            className="bg-emerald-600 text-white hover:bg-emerald-500"
          >
            <Ban className="mr-1.5 h-3.5 w-3.5" aria-hidden />
            {ev.status === "MITIGATED" ? "Mitigated" : "Simulate Block"}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setTechOpen(true)}
            className="border-zinc-700 bg-transparent text-zinc-300 hover:bg-zinc-800"
          >
            <FileSearch className="mr-1.5 h-3.5 w-3.5" aria-hidden />
            View Technical Details
          </Button>
        </div>
      </div>

      {/* technical dialog */}
      <Dialog open={techOpen} onOpenChange={setTechOpen}>
        <DialogContent className="max-h-[85vh] overflow-y-auto border-zinc-800 bg-zinc-950 text-zinc-200 sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Technical details — {exp.classification}
              <SeverityBadge severity={ev.severity} />
            </DialogTitle>
            <DialogDescription>
              Full ML output for event{" "}
              <span className="font-mono text-xs">{ev.id.slice(0, 8)}</span>
            </DialogDescription>
          </DialogHeader>

          <Accordion type="multiple" defaultValue={["probs"]}>
            <AccordionItem value="probs" className="border-zinc-800">
              <AccordionTrigger className="text-sm">
                Class probabilities (RandomForest)
              </AccordionTrigger>
              <AccordionContent className="space-y-2">
                {Object.entries(ev.probabilities)
                  .sort((a, b) => b[1] - a[1])
                  .map(([cls, p]) => (
                    <div key={cls} className="flex items-center gap-3">
                      <span className="w-32 shrink-0 font-mono text-xs text-zinc-400">
                        {cls}
                      </span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-zinc-800">
                        <div
                          className={cn(
                            "h-full rounded-full",
                            cls === ev.attack ? sev.bar : "bg-zinc-600",
                          )}
                          style={{ width: `${p * 100}%` }}
                        />
                      </div>
                      <span className="w-12 text-right font-mono text-xs text-zinc-300">
                        {(p * 100).toFixed(1)}%
                      </span>
                    </div>
                  ))}
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="features" className="border-zinc-800">
              <AccordionTrigger className="text-sm">
                Canonical feature vector (22 features)
              </AccordionTrigger>
              <AccordionContent>
                <table className="w-full text-left font-mono text-xs">
                  <tbody>
                    {Object.entries(ev.features ?? {}).map(([f, v]) => (
                      <tr key={f} className="border-b border-zinc-900">
                        <td className="py-1 pr-4 text-zinc-500">{f}</td>
                        <td className="py-1 text-right text-zinc-300">
                          {Number(v).toLocaleString("en-US", {
                            maximumFractionDigits: 3,
                          })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </AccordionContent>
            </AccordionItem>
          </Accordion>

          <p className="text-xs text-zinc-500">
            These values are the exact model inputs produced by the feature
            extraction stage — identical schema for training data, simulations
            and PCAP analysis.
          </p>
        </DialogContent>
      </Dialog>
    </section>
  );
}

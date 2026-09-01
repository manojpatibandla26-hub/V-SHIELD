"use client";
/**
 * AI Sentinel — threat detail panel.
 * Plain language first (what does this mean?), evidence from REAL feature
 * values, observed traffic, recommended response, actions, and copy incident JSON.
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
  Copy,
  Check,
  Target,
  Server,
  Cpu,
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
    <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-2.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
        {label}
      </p>
      <p className="mt-0.5 font-mono text-sm font-semibold tabular-nums text-zinc-200">
        {value}
      </p>
    </div>
  );
}

export function ThreatDetail() {
  const events = useSentinelStore((s) => s.events);
  const selectedEventId = useSentinelStore((s) => s.selectedEventId);
  const resolveEvent = useSentinelStore((s) => s.resolveEvent);
  const mitigateEvent = useSentinelStore((s) => s.mitigateEvent);

  const [busy, setBusy] = useState(false);
  const [techOpen, setTechOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const ev = events.find((e) => e.id === selectedEventId) ?? null;

  if (!ev) {
    return (
      <section
        aria-label="Threat details"
        className="flex h-full min-h-[380px] flex-col items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-900/30 p-8 text-center"
      >
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-zinc-900 border border-zinc-800 text-zinc-600 mb-3">
          <ShieldAlert className="h-7 w-7" aria-hidden />
        </div>
        <p className="text-sm font-bold text-zinc-300">
          No Threat Selected
        </p>
        <p className="mt-1 max-w-xs text-xs text-zinc-500 leading-relaxed">
          Select an incident from the timeline or trigger a safe attack scenario in the Security Test Lab to inspect real-time feature evidence and response guidance.
        </p>
      </section>
    );
  }

  const sev = SEVERITY_STYLE[ev.severity] || SEVERITY_STYLE.LOW;
  const exp = ev.explanation;

  const handleCopyJson = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* ignore clipboard copy failure */
    }
  };

  const act = async (fn: (id: string) => Promise<void>, feedbackMsg: string) => {
    setBusy(true);
    setActionFeedback(null);
    try {
      await fn(ev.id);
      setActionFeedback(feedbackMsg);
      setTimeout(() => setActionFeedback(null), 3500);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section
      aria-label="Threat details inspection"
      className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60 shadow-lg"
    >
      {/* Header Banner */}
      <div className={cn("border-b p-4 transition-colors", sev.chip)}>
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-bold uppercase tracking-widest">
              Incident Inspection
            </span>
          </div>
          <StatusBadge status={ev.status} />
        </div>
        <h2 className="mt-1 text-lg font-bold text-zinc-100">{exp.classification}</h2>
        <p className="text-xs opacity-90 leading-tight">
          {exp.headline} · {fmtTimeAgo(ev.ts)}
        </p>

        {/* Source & Target Badges */}
        <div className="mt-2.5 flex flex-wrap items-center gap-2 pt-2 border-t border-black/15 text-xs font-mono">
          <div className="inline-flex items-center gap-1 rounded bg-black/30 px-2 py-1 text-[11px] text-zinc-200">
            <Server className="h-3 w-3 text-zinc-400" />
            <span className="text-zinc-500">Src:</span>
            <span>{ev.source}</span>
          </div>
          {ev.target && (
            <div className="inline-flex items-center gap-1 rounded bg-black/30 px-2 py-1 text-[11px] text-zinc-200">
              <Target className="h-3 w-3 text-amber-400" />
              <span className="text-zinc-500">Target:</span>
              <span>{ev.target}</span>
            </div>
          )}
        </div>
      </div>

      <div className="space-y-4 p-4">
        {/* Risk Score & ML Confidence Gauge */}
        <div className="flex items-center gap-4 rounded-xl border border-zinc-800/80 bg-zinc-950/40 p-3.5">
          <RiskGauge risk={ev.risk} severity={ev.severity} size={120} />
          <div className="min-w-0 flex-1 space-y-2.5">
            <div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-zinc-400 font-medium">ML Confidence</span>
                <span className="font-mono font-bold text-zinc-200">
                  {(ev.confidence * 100).toFixed(1)}%
                </span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-zinc-800">
                <div
                  className={cn("h-full rounded-full transition-all duration-500", sev.bar)}
                  style={{ width: `${ev.confidence * 100}%` }}
                />
              </div>
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-400 font-medium">Isolation Forest Anomaly</span>
              <span className="font-mono font-bold text-zinc-200">
                {ev.anomaly_score.toFixed(2)} / 1.00
              </span>
            </div>

            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-400 font-medium">Detection Model</span>
              <span className="font-mono text-zinc-300 text-[11px]">
                {ev.model_version}
              </span>
            </div>
          </div>
        </div>

        {/* Action Confirmation Banner */}
        {actionFeedback && (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-2.5 text-xs text-emerald-300">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{actionFeedback}</span>
          </div>
        )}

        {/* Plain Language Meaning (For Judges) */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5 space-y-1">
          <p className="text-[11px] font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
            <Lightbulb className="h-3.5 w-3.5" /> What does this mean?
          </p>
          <p className="text-xs leading-relaxed text-zinc-300">
            {exp.meaning}
          </p>
        </div>

        {/* Evidence from Real Features */}
        <div className="space-y-1.5">
          <p className="text-[11px] font-bold uppercase tracking-wider text-zinc-400">
            Why did the ML system trigger?
          </p>
          <ul className="space-y-1.5">
            {exp.evidence.map((evidence, i) => (
              <li
                key={i}
                className="flex items-start gap-2 rounded-lg border border-zinc-800/80 bg-zinc-950/40 p-2.5 text-xs text-zinc-300"
              >
                <ChevronDown className="mt-0.5 h-3 w-3 shrink-0 rotate-[-90deg] text-emerald-400" aria-hidden />
                <div>
                  <span className="font-medium text-zinc-200">{evidence.detail}</span>
                  <div className="mt-0.5 text-[11px] text-zinc-500 font-mono">
                    Observed: <span className="text-amber-300">{evidence.observed}</span> · Baseline: {evidence.baseline}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>

        {/* Observed Traffic Counters */}
        <div className="space-y-1.5">
          <p className="text-[11px] font-bold uppercase tracking-wider text-zinc-400">
            Telemetry Snapshot
          </p>
          <div className="grid grid-cols-3 gap-2">
            <ObservedStat label="Packet Rate" value={`${fmtNum(ev.observed.pkt_rate)}/s`} />
            <ObservedStat label="Flows" value={fmtNum(ev.observed.flow_count)} />
            <ObservedStat label="SYN Count" value={fmtNum(ev.observed.syn_count)} />
            <ObservedStat label="ACK Count" value={fmtNum(ev.observed.ack_count)} />
            <ObservedStat label="Duration" value={`${ev.observed.duration_s.toFixed(1)}s`} />
            <ObservedStat label="Ports Hit" value={fmtNum(ev.observed.distinct_dst_ports)} />
          </div>
        </div>

        {/* Recommended Response */}
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
          <p className="text-[11px] font-bold uppercase tracking-wider text-emerald-400">
            Recommended SOC Response
          </p>
          <p className="mt-1 text-xs leading-relaxed text-zinc-300">
            {exp.recommendation}
          </p>
        </div>

        {ev.status === "MITIGATED" && (
          <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-300 leading-relaxed">
            <strong>Source IP Blocked (Simulation):</strong> Incoming traffic from <code className="font-mono bg-emerald-950 px-1 py-0.5 rounded">{ev.source}</code> has been dropped. Network returned to protected baseline.
          </div>
        )}

        {/* Action Controls */}
        <div className="flex flex-wrap gap-2 pt-2 border-t border-zinc-800">
          <Button
            size="sm"
            variant="outline"
            disabled={busy || ev.status === "RESOLVED"}
            onClick={() => act(resolveEvent, "Incident marked as Resolved.")}
            className="border-zinc-700 bg-transparent text-xs text-zinc-300 hover:bg-zinc-800"
          >
            <CheckCircle2 className="mr-1.5 h-3.5 w-3.5 text-zinc-400" />
            {ev.status === "RESOLVED" ? "Resolved" : "Mark Resolved"}
          </Button>

          <Button
            size="sm"
            disabled={busy || ev.status === "MITIGATED"}
            onClick={() => act(mitigateEvent, "Simulated block applied successfully. Traffic recovering.")}
            className="bg-emerald-600 font-semibold text-xs text-white hover:bg-emerald-500"
          >
            <Ban className="mr-1.5 h-3.5 w-3.5" />
            {ev.status === "MITIGATED" ? "Mitigated" : "Simulate Block"}
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={() => setTechOpen(true)}
            className="border-zinc-700 bg-transparent text-xs text-zinc-300 hover:bg-zinc-800"
          >
            <FileSearch className="mr-1.5 h-3.5 w-3.5 text-zinc-400" />
            Technical Vector
          </Button>

          <Button
            size="sm"
            variant="ghost"
            onClick={handleCopyJson}
            className="text-xs text-zinc-400 hover:text-zinc-100 ml-auto"
          >
            {copied ? (
              <>
                <Check className="mr-1 h-3.5 w-3.5 text-emerald-400" /> Copied
              </>
            ) : (
              <>
                <Copy className="mr-1 h-3.5 w-3.5" /> Copy JSON
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Technical Deep Dive Dialog */}
      <Dialog open={techOpen} onOpenChange={setTechOpen}>
        <DialogContent className="max-h-[85vh] overflow-y-auto border-zinc-800 bg-zinc-950 text-zinc-200 sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Technical Details — {exp.classification}
              <SeverityBadge severity={ev.severity} />
            </DialogTitle>
            <DialogDescription className="text-zinc-400 text-xs">
              Complete ML decision tree vector and probability distribution for incident{" "}
              <span className="font-mono text-zinc-300">{ev.id}</span>
            </DialogDescription>
          </DialogHeader>

          <Accordion type="multiple" defaultValue={["probs", "features"]}>
            <AccordionItem value="probs" className="border-zinc-800">
              <AccordionTrigger className="text-sm font-semibold">
                Class Probabilities (RandomForest Classifier)
              </AccordionTrigger>
              <AccordionContent className="space-y-2 pt-1">
                {Object.entries(ev.probabilities || {})
                  .sort((a, b) => b[1] - a[1])
                  .map(([cls, p]) => (
                    <div key={cls} className="flex items-center gap-3">
                      <span className="w-32 shrink-0 font-mono text-xs text-zinc-400 truncate">
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
                      <span className="w-12 text-right font-mono text-xs text-zinc-300 font-semibold">
                        {(p * 100).toFixed(1)}%
                      </span>
                    </div>
                  ))}
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="features" className="border-zinc-800">
              <AccordionTrigger className="text-sm font-semibold">
                Canonical Feature Vector (22 Network Features)
              </AccordionTrigger>
              <AccordionContent className="pt-1">
                <div className="rounded-lg border border-zinc-800 overflow-hidden">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-zinc-900 text-zinc-500 text-[11px]">
                      <tr>
                        <th className="px-3 py-1.5">Feature Name</th>
                        <th className="px-3 py-1.5 text-right">Extracted Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(ev.features ?? {}).map(([f, v], idx) => (
                        <tr key={f} className={cn("border-b border-zinc-900/80", idx % 2 === 0 ? "bg-zinc-950/40" : "bg-zinc-900/20")}>
                          <td className="px-3 py-1 text-zinc-400">{f}</td>
                          <td className="px-3 py-1 text-right text-emerald-400 font-semibold tabular-nums">
                            {Number(v).toLocaleString("en-US", {
                              maximumFractionDigits: 3,
                            })}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>

          <p className="text-xs text-zinc-500 mt-2">
            Canonical feature schema computed directly in Python backend from raw bidirectional flow aggregation.
          </p>
        </DialogContent>
      </Dialog>
    </section>
  );
}

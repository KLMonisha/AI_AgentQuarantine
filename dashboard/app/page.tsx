"use client";

import { useEffect, useMemo, useState } from "react";
import { Room, RoomEvent } from "livekit-client";

type Decision = "ALLOW" | "QUARANTINE" | "BLOCK";
type Risk = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

type SecurityEvent = {
  event_type?: string;

  source?: string;
  email_id?: string;
  subject?: string;

  decision?: Decision;
  risk?: Risk;

  category?: string;
  score?: number;
  latency_ms?: number;
  threat_count?: number;

  agent_directed?: boolean;
  instruction_override?: boolean;
  requests_privileged_action?: boolean;
  sensitive_data_request?: boolean;
  manipulates_agent_behavior?: boolean;
  intent_confidence?: number;

  reason?: string;
  timestamp?: string;
};

const demoEvents: SecurityEvent[] = [
  {
    event_type: "POLICY_DECISION",
    source: "Gmail",
    email_id: "1a0ca9c3108898f6",
    subject: "PO Reconciliation- September",
    decision: "BLOCK",
    risk: "CRITICAL",
    category: "agent_action_hijacking",
    score: 0.9016,
    latency_ms: 34.14,
    threat_count: 5,
    agent_directed: true,
    instruction_override: false,
    requests_privileged_action: true,
    sensitive_data_request: true,
    manipulates_agent_behavior: true,
    intent_confidence: 0.98,
    timestamp: "1:03 AM",
  },
  {
    event_type: "POLICY_DECISION",
    source: "Gmail",
    email_id: "1a0ca9b1079ac8ed",
    subject: "Security Awareness Reminder- Email Handling",
    decision: "QUARANTINE",
    risk: "HIGH",
    category: "email_injection",
    score: 0.9771,
    latency_ms: 26.09,
    threat_count: 5,
    agent_directed: true,
    instruction_override: false,
    requests_privileged_action: false,
    sensitive_data_request: false,
    manipulates_agent_behavior: false,
    intent_confidence: 0.95,
    timestamp: "1:02 AM",
  },
  {
    event_type: "POLICY_DECISION",
    source: "Gmail",
    email_id: "1a0ca99c3b180d85",
    subject: "Q3 Vendor Reconciliation- Updated",
    decision: "BLOCK",
    risk: "CRITICAL",
    category: "email_exfiltration",
    score: 0.9688,
    latency_ms: 37.65,
    threat_count: 5,
    agent_directed: true,
    instruction_override: true,
    requests_privileged_action: true,
    sensitive_data_request: true,
    manipulates_agent_behavior: true,
    intent_confidence: 1.0,
    timestamp: "1:01 AM",
  },
  {
    event_type: "POLICY_DECISION",
    source: "Gmail",
    email_id: "1a0ca98b3ebf9066",
    subject: "Action Required- Invoice Verification",
    decision: "BLOCK",
    risk: "CRITICAL",
    category: "email_exfiltration",
    score: 0.9750,
    latency_ms: 48.70,
    threat_count: 5,
    agent_directed: true,
    instruction_override: true,
    requests_privileged_action: true,
    sensitive_data_request: true,
    manipulates_agent_behavior: true,
    intent_confidence: 1.0,
    timestamp: "1:00 AM",
  },
  {
    event_type: "POLICY_DECISION",
    source: "Gmail",
    email_id: "1a0ca975652378f7",
    subject: "September Invoice- ACME-4821",
    decision: "ALLOW",
    risk: "LOW",
    category: "benign",
    score: 0.9629,
    latency_ms: 17.84,
    threat_count: 5,
    agent_directed: false,
    instruction_override: false,
    requests_privileged_action: false,
    sensitive_data_request: false,
    manipulates_agent_behavior: false,
    intent_confidence: 1.0,
    timestamp: "12:58 AM",
  },
];

export default function Home() {
  const [liveEvents, setLiveEvents] =
    useState<SecurityEvent[]>([]);

  const [liveStatus, setLiveStatus] =
    useState("CONNECTING");

  useEffect(() => {
    let room: Room | null = null;

    async function connectToLiveKit() {
      try {
        const response = await fetch("/api/livekit-token");
        const { token } = await response.json();

        if (!token) {
          throw new Error("No LiveKit token received");
        }

        room = new Room();

        room.on(RoomEvent.DataReceived, (payload) => {
          try {
            const event = JSON.parse(
              new TextDecoder().decode(payload)
            );

            console.log("LiveKit security event:", event);

            setLiveEvents((previous) => [
              event,
              ...previous,
            ]);
          } catch (error) {
            console.error(
              "Failed to parse LiveKit event:",
              error
            );
          }
        });

        await room.connect(
          process.env.NEXT_PUBLIC_LIVEKIT_URL!,
          token
        );

        setLiveStatus("CONNECTED");
      } catch (error) {
        console.error(
          "LiveKit connection failed:",
          error
        );

        setLiveStatus("ERROR");
      }
    }

    connectToLiveKit();

    return () => {
      room?.disconnect();
    };
  }, []);

  const events = useMemo(() => {
    if (liveEvents.length > 0) {
      return liveEvents;
    }

    return demoEvents;
  }, [liveEvents]);

  const blocked = events.filter(
    (event) => event.decision === "BLOCK"
  ).length;

  const quarantined = events.filter(
    (event) => event.decision === "QUARANTINE"
  ).length;

  const threats = events.filter(
    (event) => event.decision !== "ALLOW"
  ).length;

  const latestThreat =
    events.find(
      (event) => event.decision !== "ALLOW"
    ) ?? events[0];

  return (
    <main className="min-h-screen bg-[#08090d] text-white">
      <div className="mx-auto max-w-7xl px-6 py-8">

        {/* HEADER */}
        <header className="mb-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 font-semibold text-red-400">
              AJ
            </div>

            <div>
              <h1 className="text-xl font-semibold">
                Agent Jail
              </h1>

              <p className="text-xs text-zinc-500">
                AI Agent Security Control Center
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/5 px-4 py-2 text-sm text-emerald-400">
            <span
              className={`h-2 w-2 rounded-full ${
                liveStatus === "CONNECTED"
                  ? "bg-emerald-400"
                  : liveStatus === "ERROR"
                    ? "bg-red-400"
                    : "bg-amber-400"
              }`}
            />

            LiveKit {liveStatus}
          </div>
        </header>

        {/* OVERVIEW */}
        <section className="mb-6 grid gap-4 md:grid-cols-4">
          <StatCard
            label="Agent Status"
            value="ACTIVE"
            detail="Groq agent running"
          />

          <StatCard
            label="Security Status"
            value="PROTECTED"
            detail="Agent Jail active"
          />

          <StatCard
            label="Threats Detected"
            value={String(threats)}
            detail="Current execution"
          />

          <StatCard
            label="Blocked"
            value={String(blocked)}
            detail={`${blocked} blocked · ${quarantined} quarantined`}
          />
        </section>

        <div className="grid gap-6 lg:grid-cols-3">

          {/* SECURITY EVENTS */}
          <section className="rounded-2xl border border-white/10 bg-white/[0.03] lg:col-span-2">

            <div className="border-b border-white/10 px-6 py-5">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="font-semibold">
                    Security Events
                  </h2>

                  <p className="mt-1 text-sm text-zinc-500">
                    Real-time events from Agent Jail
                  </p>
                </div>

                <span className="rounded-md border border-white/10 px-2 py-1 text-xs text-zinc-400">
                  {liveEvents.length > 0 ? "LIVE" : "DEMO"}
                </span>
              </div>
            </div>

            <div className="divide-y divide-white/5">
              {events.map((event, index) => (
                <SecurityEventRow
                  key={`${event.email_id ?? "event"}-${index}`}
                  event={event}
                />
              ))}
            </div>
          </section>

          {/* LATEST THREAT */}
          <section className="rounded-2xl border border-white/10 bg-white/[0.03]">

            <div className="border-b border-white/10 px-6 py-5">
              <h2 className="font-semibold">
                Threat Intelligence
              </h2>

              <p className="mt-1 text-sm text-zinc-500">
                Latest Moss + Gemini evidence
              </p>
            </div>

            <div className="space-y-5 p-6">

              <div>
                <p className="text-xs uppercase tracking-wider text-zinc-600">
                  Moss Match
                </p>

                <p className="mt-2 text-lg font-semibold">
                  {latestThreat?.category ??
                    "No threat"}
                </p>

                <p className="mt-1 text-sm text-zinc-500">
                  {latestThreat?.score
                    ? latestThreat.score.toFixed(4)
                    : "—"}
                </p>
              </div>

              <div className="border-t border-white/10 pt-5">
                <p className="text-xs uppercase tracking-wider text-zinc-600">
                  Gemini Intent
                </p>

                <p className="mt-2 text-sm">
                  {latestThreat?.agent_directed
                    ? "Agent-directed"
                    : "Human-directed"}
                </p>

                <p className="mt-1 text-xs text-zinc-500">
                  Confidence:{" "}
                  {latestThreat?.intent_confidence
                    ? (
                        latestThreat.intent_confidence *
                        100
                      ).toFixed(0) + "%"
                    : "—"}
                </p>
              </div>

              <div className="border-t border-white/10 pt-5">
                <p className="text-xs uppercase tracking-wider text-zinc-600">
                  Policy
                </p>

                <p
                  className={`mt-2 font-semibold ${
                    latestThreat?.decision === "BLOCK"
                      ? "text-red-400"
                      : latestThreat?.decision ===
                          "QUARANTINE"
                        ? "text-amber-400"
                        : "text-emerald-400"
                  }`}
                >
                  {latestThreat?.decision ?? "ALLOW"}
                </p>

                <p className="mt-1 text-xs text-zinc-500">
                  {latestThreat?.risk ?? "LOW"} risk
                </p>
              </div>
            </div>
          </section>
        </div>

        {/* METRICS */}
        <section className="mt-6 grid gap-6 md:grid-cols-3">

          <MetricCard
            title="Moss Semantic Lookup"
            value={
              latestThreat?.latency_ms
                ? `${latestThreat.latency_ms.toFixed(2)} ms`
                : "—"
            }
            detail="Latest threat lookup"
          />

          <MetricCard
            title="Agent-directed"
            value={
              latestThreat?.agent_directed
                ? "YES"
                : "NO"
            }
            detail="Gemini intent analysis"
          />

          <MetricCard
            title="Containment"
            value={`${quarantined + blocked} item${
              quarantined + blocked === 1 ? "" : "s"
            }`}
            detail="Removed from active context"
          />
        </section>

        {/* PIPELINE */}
        <section className="mt-6 rounded-2xl border border-white/10 bg-white/[0.03] p-6">

          <h2 className="font-semibold">
            Agent Jail Pipeline
          </h2>

          <div className="mt-5 flex flex-wrap items-center gap-3 text-sm">
            {[
              "External Content",
              "Taint + Provenance",
              "Moss",
              "Gemini",
              "Policy",
              "Quarantine / Block",
              "Agent",
            ].map((stage, index, stages) => (
              <div
                key={stage}
                className="flex items-center gap-3"
              >
                <span className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-zinc-300">
                  {stage}
                </span>

                {index < stages.length - 1 && (
                  <span className="text-zinc-600">
                    →
                  </span>
                )}
              </div>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}

function StatCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
      <p className="text-xs uppercase tracking-wider text-zinc-500">
        {label}
      </p>

      <p className="mt-3 text-2xl font-semibold">
        {value}
      </p>

      <p className="mt-1 text-xs text-zinc-500">
        {detail}
      </p>
    </div>
  );
}

function SecurityEventRow({
  event,
}: {
  event: SecurityEvent;
}) {
  const decision = event.decision ?? "ALLOW";

  const decisionClass = {
    ALLOW: "text-emerald-400",
    QUARANTINE: "text-amber-400",
    BLOCK: "text-red-400",
  }[decision];

  const dotClass = {
    ALLOW: "bg-emerald-400",
    QUARANTINE: "bg-amber-400",
    BLOCK: "bg-red-400",
  }[decision];

  return (
    <div className="flex items-center justify-between gap-4 px-6 py-5">

      <div className="flex min-w-0 items-center gap-4">

        <div
          className={`h-2 w-2 shrink-0 rounded-full ${dotClass}`}
        />

        <div className="min-w-0">
          <p className="truncate text-sm font-medium">
            {event.subject ?? event.email_id ?? "Security Event"}
          </p>

          <p className="mt-1 truncate text-xs text-zinc-500">
            {event.source ?? "Agent Jail"}
            {" · "}
            {event.category ?? event.event_type ?? "event"}
          </p>

          {event.email_id && (
            <p className="mt-1 truncate text-[10px] text-zinc-700">
              {event.email_id}
            </p>
          )}
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-6 text-right">

        <div>
          <p className={`text-xs font-semibold ${decisionClass}`}>
            {decision}
          </p>

          <p className="mt-1 text-xs text-zinc-600">
            {event.risk ?? "LOW"}
          </p>
        </div>

        <div className="hidden sm:block">
          <p className="text-sm text-zinc-300">
            {event.latency_ms !== undefined
              ? `${event.latency_ms.toFixed(2)} ms`
              : "—"}
          </p>

          <p className="mt-1 text-xs text-zinc-600">
            {event.timestamp ?? "LIVE"}
          </p>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  detail,
}: {
  title: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-6">
      <p className="text-sm text-zinc-400">
        {title}
      </p>

      <p className="mt-3 text-3xl font-semibold">
        {value}
      </p>

      <p className="mt-1 text-xs text-zinc-500">
        {detail}
      </p>
    </div>
  );
}
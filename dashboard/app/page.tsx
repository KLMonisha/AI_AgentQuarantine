"use client";

import { useEffect, useState } from "react";
import {
  Room,
  RoomEvent,
} from "livekit-client";

type SecurityEvent = {
  id: string;
  source: string;
  category: string;
  score: number;
  decision: "ALLOW" | "QUARANTINE" | "BLOCK";
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  latency: number;
  timestamp: string;
};

const initialEvents: SecurityEvent[] = [
  {
    id: "email-003",
    source: "Gmail",
    category: "destructive_email_action",
    score: 0.9937,
    decision: "QUARANTINE",
    risk: "HIGH",
    latency: 7.61,
    timestamp: "22:31:04",
  },
  {
    id: "email-002",
    source: "Gmail",
    category: "instruction_override",
    score: 0.8,
    decision: "ALLOW",
    risk: "LOW",
    latency: 7.54,
    timestamp: "22:31:03",
  },
  {
    id: "email-001",
    source: "Gmail",
    category: "instruction_override",
    score: 0.8,
    decision: "ALLOW",
    risk: "LOW",
    latency: 12.61,
    timestamp: "22:31:02",
  },
];

export default function Home() {
  const [events] = useState(initialEvents);

  const [liveEvents, setLiveEvents] = useState<any[]>([]);
  const [liveStatus, setLiveStatus] = useState("CONNECTING");

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

        room.on(
          RoomEvent.DataReceived,
          (payload) => {
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
          }
        );

        await room.connect(
          process.env.NEXT_PUBLIC_LIVEKIT_URL!,
          token
        );

        setLiveStatus("CONNECTED");
      } catch (error) {
        console.error("LiveKit connection failed:", error);
        setLiveStatus("ERROR");
      }
    }

    connectToLiveKit();

    return () => {
      room?.disconnect();
    };
  }, []);

  const quarantined = events.filter(
    (event) => event.decision === "QUARANTINE"
  ).length;

  const threats = events.filter(
    (event) => event.decision !== "ALLOW"
  ).length;

  return (
    <main className="min-h-screen bg-[#08090d] text-white">
      <div className="mx-auto max-w-7xl px-6 py-8">
        {/* Header */}
        <header className="mb-8 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 text-red-400">
                AJ
              </div>

              <div>
                <h1 className="text-xl font-semibold tracking-tight">
                  Agent Jail
                </h1>
                <p className="text-xs text-zinc-500">
                  AI Agent Security Control Center
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/5 px-4 py-2 text-sm text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            System Protected
          </div>
        </header>

        {/* Overview */}
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
            label="Quarantined"
            value={String(quarantined)}
            detail="Isolated from agent"
          />
        </section>

        <div className="grid gap-6 lg:grid-cols-3">
          {/* Security Events */}
          <section className="rounded-2xl border border-white/10 bg-white/[0.03] lg:col-span-2">
            <div className="border-b border-white/10 px-6 py-5">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="font-semibold">Security Events</h2>
                  <p className="mt-1 text-sm text-zinc-500">
                    Recent events from the protected agent
                  </p>
                </div>

                <span className="rounded-md border border-white/10 px-2 py-1 text-xs text-zinc-400">
                <span className="rounded-md border border-emerald-500/20 bg-emerald-500/5 px-2 py-1 text-xs text-emerald-400">
                  LIVEKIT {liveStatus}
                </span>
                  LIVE
                </span>
              </div>
            </div>

            <div className="divide-y divide-white/5">
              {events.map((event) => (
                <SecurityEventRow key={event.id} event={event} />
              ))}
            </div>
          
          {liveEvents.length > 0 && (
            <div className="border-t border-white/10 px-6 py-5">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold">
                    Live Security Event
                  </h3>
                  <p className="mt-1 text-xs text-zinc-500">
                    Received through LiveKit
                  </p>
                </div>

                <span className="rounded-md border border-emerald-500/20 bg-emerald-500/5 px-2 py-1 text-xs text-emerald-400">
                  LIVEKIT
                </span>
              </div>

              <div className="mt-4 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
                <p className="text-sm font-semibold text-amber-400">
                  {liveEvents[0].event_type}
                </p>

                <pre className="mt-3 overflow-x-auto text-xs text-zinc-400">
                  {JSON.stringify(liveEvents[0].data, null, 2)}
                </pre>
              </div>
            </div>
          )}
          </section>

          {/* Threat Intelligence */}
          <section className="rounded-2xl border border-white/10 bg-white/[0.03]">
            <div className="border-b border-white/10 px-6 py-5">
              <h2 className="font-semibold">Threat Intelligence</h2>
              <p className="mt-1 text-sm text-zinc-500">
                Moss semantic matches
              </p>
            </div>

            <div className="space-y-4 p-6">
              <ThreatRow
                id="PI-028"
                category="destructive_email_action"
                score={0.9937}
              />

              <ThreatRow
                id="PI-027"
                category="email_exfiltration"
                score={0.975}
              />

              <ThreatRow
                id="PI-029"
                category="agent_action_hijacking"
                score={0.9147}
              />

              <ThreatRow
                id="PI-026"
                category="email_injection"
                score={0.9118}
              />

              <ThreatRow
                id="PI-001"
                category="instruction_override"
                score={0.8768}
              />
            </div>
          </section>
        </div>

        {/* Metrics */}
        <section className="mt-6 grid gap-6 md:grid-cols-2">
          <MetricCard
            title="Moss Semantic Lookup"
            value="7.61 ms"
            detail="Latest threat lookup"
          />

          <MetricCard
            title="Containment"
            value="1 item"
            detail="Removed from active agent context"
          />
        </section>

        {/* Architecture status */}
        <section className="mt-6 rounded-2xl border border-white/10 bg-white/[0.03] p-6">
          <h2 className="font-semibold">Agent Jail Pipeline</h2>

          <div className="mt-5 flex flex-wrap items-center gap-3 text-sm">
            {[
              "External Content",
              "Taint",
              "Moss",
              "Policy",
              "Quarantine",
              "Agent",
            ].map((stage, index) => (
              <div key={stage} className="flex items-center gap-3">
                <span className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-zinc-300">
                  {stage}
                </span>

                {index < 5 && (
                  <span className="text-zinc-600">→</span>
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

      <p className="mt-3 text-2xl font-semibold">{value}</p>

      <p className="mt-1 text-xs text-zinc-500">{detail}</p>
    </div>
  );
}

function SecurityEventRow({ event }: { event: SecurityEvent }) {
  const decisionClass = {
    ALLOW: "text-emerald-400",
    QUARANTINE: "text-amber-400",
    BLOCK: "text-red-400",
  }[event.decision];

  return (
    <div className="flex items-center justify-between gap-4 px-6 py-5">
      <div className="flex min-w-0 items-center gap-4">
        <div
          className={`h-2 w-2 shrink-0 rounded-full ${
            event.decision === "ALLOW"
              ? "bg-emerald-400"
              : event.decision === "QUARANTINE"
                ? "bg-amber-400"
                : "bg-red-400"
          }`}
        />

        <div className="min-w-0">
          <p className="truncate text-sm font-medium">
            {event.id}
          </p>

          <p className="mt-1 truncate text-xs text-zinc-500">
            {event.source} · {event.category}
          </p>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-6 text-right">
        <div>
          <p className={`text-xs font-semibold ${decisionClass}`}>
            {event.decision}
          </p>

          <p className="mt-1 text-xs text-zinc-600">
            {event.risk}
          </p>
        </div>

        <div className="hidden sm:block">
          <p className="text-sm text-zinc-300">
            {event.latency.toFixed(2)} ms
          </p>

          <p className="mt-1 text-xs text-zinc-600">
            {event.timestamp}
          </p>
        </div>
      </div>
    </div>
  );
}

function ThreatRow({
  id,
  category,
  score,
}: {
  id: string;
  category: string;
  score: number;
}) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-medium text-zinc-300">
          {id}
        </span>

        <span className="text-xs text-zinc-500">
          {score.toFixed(4)}
        </span>
      </div>

      <p className="mt-1 text-xs text-zinc-500">
        {category}
      </p>

      <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/5">
        <div
          className="h-full rounded-full bg-red-400/70"
          style={{ width: `${score * 100}%` }}
        />
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
      <p className="text-sm text-zinc-400">{title}</p>

      <p className="mt-3 text-3xl font-semibold">{value}</p>

      <p className="mt-1 text-xs text-zinc-500">{detail}</p>
    </div>
  );
}

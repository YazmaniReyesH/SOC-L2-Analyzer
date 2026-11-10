import { useMemo, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Server,
  User,
  Globe,
  Crosshair,
  GitBranch,
  Clock,
  ShieldAlert,
} from "lucide-react";
import type { Finding, Incidente, LogEvent } from "../lib/types";
import { Card, Chip } from "./ui/Card";
import { SeverityBadge } from "./ui/SeverityBadge";

function EntidadChips({
  icon,
  valores,
}: {
  icon: React.ReactNode;
  valores: string[];
}) {
  if (!valores.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-muted-foreground">{icon}</span>
      {valores.map((v) => (
        <Chip key={v}>{v}</Chip>
      ))}
    </div>
  );
}

function EvidenciaTabla({
  logIds,
  eventMap,
}: {
  logIds: string[];
  eventMap: Map<string, LogEvent>;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-left text-xs">
        <thead className="bg-muted/50 text-muted-foreground">
          <tr>
            <th className="px-2 py-1.5">Log_ID</th>
            <th className="px-2 py-1.5">Timestamp</th>
            <th className="px-2 py-1.5">Host</th>
            <th className="px-2 py-1.5">Event</th>
            <th className="px-2 py-1.5">Descripción</th>
          </tr>
        </thead>
        <tbody>
          {logIds.map((id) => {
            const e = eventMap.get(id);
            return (
              <tr key={id} className="border-t border-border">
                <td className="px-2 py-1.5 font-mono">{id}</td>
                <td className="whitespace-nowrap px-2 py-1.5">{e?.timestamp_str ?? "—"}</td>
                <td className="px-2 py-1.5">{e?.hostname ?? "—"}</td>
                <td className="px-2 py-1.5 font-mono">{e?.event_id ?? "—"}</td>
                <td className="px-2 py-1.5 text-muted-foreground">
                  {e ? e.event_description + (e.process_commandline ? ` — ${e.process_commandline}` : "") : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function HallazgoCard({
  h,
  eventMap,
}: {
  h: Finding;
  eventMap: Map<string, LogEvent>;
}) {
  const [abierto, setAbierto] = useState(false);
  return (
    <div className="rounded-lg border border-border bg-background">
      <button
        onClick={() => setAbierto((a) => !a)}
        className="flex w-full items-center justify-between gap-3 px-3 py-2.5 text-left"
      >
        <div className="flex items-center gap-2">
          {abierto ? <ChevronDown className="h-4 w-4 shrink-0" /> : <ChevronRight className="h-4 w-4 shrink-0" />}
          <SeverityBadge criticidad={h.criticidad} size="sm" />
          <span className="text-sm font-medium">{h.titulo}</span>
        </div>
        <span className="shrink-0 font-mono text-xs text-muted-foreground">
          {h.regla} · {h.evidencia.length} ev.
        </span>
      </button>
      {abierto && (
        <div className="space-y-3 border-t border-border px-3 py-3 text-sm">
          <p className="text-muted-foreground">{h.justificacion}</p>
          {h.impacto && (
            <p>
              <span className="font-semibold">Impacto: </span>
              <span className="text-muted-foreground">{h.impacto}</span>
            </p>
          )}
          <div className="flex flex-wrap gap-1.5">
            {h.mitre.map((m) => (
              <a
                key={m}
                href={`https://attack.mitre.org/techniques/${m.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer"
                className="rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-xs text-primary hover:bg-primary/20"
              >
                {m}
              </a>
            ))}
          </div>
          <div className="grid gap-1.5">
            <EntidadChips icon={<Server className="h-3.5 w-3.5" />} valores={h.activos} />
            <EntidadChips icon={<User className="h-3.5 w-3.5" />} valores={h.usuarios} />
            <EntidadChips icon={<Globe className="h-3.5 w-3.5" />} valores={h.ips} />
          </div>
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Evidencia (Log_ID)
            </p>
            <EvidenciaTabla logIds={h.evidencia} eventMap={eventMap} />
          </div>
          <div className="grid gap-2 sm:grid-cols-3">
            {(["investigar", "contener", "remediar"] as const).map((fase) =>
              h.acciones[fase].length ? (
                <div key={fase} className="rounded-md border border-border p-2">
                  <p className="mb-1 text-xs font-semibold capitalize">{fase}</p>
                  <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted-foreground">
                    {h.acciones[fase].map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                </div>
              ) : null
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function KillChain({ etapas }: { etapas: string[] }) {
  if (!etapas.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {etapas.map((e, i) => (
        <span key={e} className="flex items-center gap-1.5">
          <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
            {e}
          </span>
          {i < etapas.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
        </span>
      ))}
    </div>
  );
}

function Timeline({ incidente }: { incidente: Incidente }) {
  return (
    <div className="relative ml-2 border-l-2 border-border pl-5">
      {incidente.linea_tiempo.map((t) => (
        <div key={t.log_id} className="relative pb-4 last:pb-0">
          <span className="absolute -left-[26px] top-1 h-3 w-3 rounded-full border-2 border-primary bg-background" />
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Clock className="h-3 w-3 text-muted-foreground" />
            <span className="font-mono text-muted-foreground">{t.timestamp_str}</span>
            <span className="rounded bg-primary/10 px-1.5 py-0.5 text-primary">{t.etapa}</span>
            <span className="font-mono text-muted-foreground">{t.hostname}</span>
            <span className="font-mono text-[11px] text-muted-foreground">({t.log_id})</span>
          </div>
          <p className="mt-0.5 text-sm">{t.descripcion}</p>
        </div>
      ))}
    </div>
  );
}

function IncidenteCard({
  inc,
  findingsById,
  eventMap,
}: {
  inc: Incidente;
  findingsById: Map<string, Finding>;
  eventMap: Map<string, LogEvent>;
}) {
  const [verTimeline, setVerTimeline] = useState(false);
  const hallazgos = inc.hallazgos.map((id) => findingsById.get(id)).filter(Boolean) as Finding[];

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-6 w-6 text-critico" />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm text-muted-foreground">{inc.id}</span>
              <SeverityBadge criticidad={inc.criticidad} />
              {inc.multi_vector && (
                <span className="inline-flex items-center gap-1 rounded-md border border-primary/30 bg-primary/10 px-2 py-0.5 text-xs text-primary">
                  <GitBranch className="h-3 w-3" /> multi-vector
                </span>
              )}
            </div>
            <h3 className="mt-1 text-lg font-bold">{inc.titulo}</h3>
          </div>
        </div>
      </div>

      <p className="mt-3 text-sm text-muted-foreground">{inc.justificacion}</p>

      <div className="mt-4">
        <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Etapas de la kill chain
        </p>
        <KillChain etapas={inc.etapas} />
      </div>

      <div className="mt-4 grid gap-1.5">
        <EntidadChips icon={<Server className="h-3.5 w-3.5" />} valores={inc.activos} />
        <EntidadChips icon={<User className="h-3.5 w-3.5" />} valores={inc.usuarios} />
        <EntidadChips icon={<Globe className="h-3.5 w-3.5" />} valores={inc.ips} />
      </div>

      {inc.multi_vector && (
        <div className="mt-4">
          <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            <GitBranch className="h-3.5 w-3.5" /> Vectores correlacionados
          </p>
          <div className="grid gap-2 sm:grid-cols-2">
            {inc.vectores.map((v) => (
              <div key={v.actor} className="rounded-lg border border-border bg-background p-3">
                <div className="flex items-center gap-1.5 text-sm font-semibold">
                  <Crosshair className="h-3.5 w-3.5 text-alto" /> {v.actor}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{v.resumen}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-4">
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Hallazgos ({hallazgos.length})
        </p>
        <div className="space-y-2">
          {hallazgos.map((h) => (
            <HallazgoCard key={h.id} h={h} eventMap={eventMap} />
          ))}
        </div>
      </div>

      <div className="mt-4">
        <button
          onClick={() => setVerTimeline((v) => !v)}
          className="flex items-center gap-1.5 text-sm font-medium text-primary"
        >
          {verTimeline ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          Línea de tiempo del incidente ({inc.linea_tiempo.length} eventos)
        </button>
        {verTimeline && (
          <div className="mt-3">
            <Timeline incidente={inc} />
          </div>
        )}
      </div>
    </Card>
  );
}

export function IncidentsView({
  incidentes,
  hallazgos,
  eventos,
}: {
  incidentes: Incidente[];
  hallazgos: Finding[];
  eventos: LogEvent[];
}) {
  const findingsById = useMemo(
    () => new Map(hallazgos.map((h) => [h.id, h])),
    [hallazgos]
  );
  const eventMap = useMemo(
    () => new Map(eventos.map((e) => [e.log_id, e])),
    [eventos]
  );

  if (!incidentes.length) {
    return (
      <Card className="p-10 text-center text-muted-foreground">
        No se detectaron incidentes en este dataset.
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {incidentes.map((inc) => (
        <IncidenteCard
          key={inc.id}
          inc={inc}
          findingsById={findingsById}
          eventMap={eventMap}
        />
      ))}
    </div>
  );
}

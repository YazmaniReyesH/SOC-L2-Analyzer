import { useState } from "react";
import {
  FileText,
  Download,
  Sparkles,
  FileCog,
  Loader2,
  AlertCircle,
} from "lucide-react";
import { descargarPdf, generarInforme, mensajeError } from "../lib/api";
import type { AnalyzeResponse, Informe } from "../lib/types";
import { Card } from "./ui/Card";
import { SeverityBadge } from "./ui/SeverityBadge";

function ModoBadge({ informe }: { informe: Informe }) {
  const ia = informe.modo_ia === "ia";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${
        ia
          ? "border-primary/30 bg-primary/10 text-primary"
          : "border-medio/40 bg-medio/15 text-medio"
      }`}
    >
      {ia ? <Sparkles className="h-3.5 w-3.5" /> : <FileCog className="h-3.5 w-3.5" />}
      {ia
        ? `Redactado por IA (${informe.modelo})`
        : "Redactado por plantillas deterministas"}
    </span>
  );
}

function Prosa({ texto }: { texto: string }) {
  return <p className="whitespace-pre-line text-sm leading-relaxed text-foreground/90">{texto}</p>;
}

function Seccion({
  n,
  titulo,
  children,
}: {
  n: string;
  titulo: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="p-6">
      <h2 className="mb-3 border-b border-border pb-2 text-xl font-bold">
        {n}. {titulo}
      </h2>
      {children}
    </Card>
  );
}

function IocTabla({ titulo, valores }: { titulo: string; valores: string[] }) {
  return (
    <tr>
      <th className="w-1/3 border border-border bg-muted/40 px-2 py-1.5 text-left align-top text-xs">
        {titulo}
      </th>
      <td className="border border-border px-2 py-1.5 font-mono text-xs">
        {valores.length ? valores.join(", ") : "—"}
      </td>
    </tr>
  );
}

export function ReportView({ analisis }: { analisis: AnalyzeResponse }) {
  const [informe, setInforme] = useState<Informe | null>(null);
  const [cargando, setCargando] = useState(false);
  const [descargando, setDescargando] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generar = async () => {
    setCargando(true);
    setError(null);
    try {
      setInforme(await generarInforme(analisis));
    } catch (err) {
      setError(mensajeError(err, "No se pudo generar el informe."));
    } finally {
      setCargando(false);
    }
  };

  const exportar = async () => {
    if (!informe) return;
    setDescargando(true);
    setError(null);
    try {
      const blob = await descargarPdf(informe);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "Informe_SOC_L2.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(mensajeError(err, "No se pudo exportar el PDF."));
    } finally {
      setDescargando(false);
    }
  };

  if (!informe) {
    return (
      <Card className="flex flex-col items-center justify-center p-12 text-center">
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-primary">
          <FileText className="h-8 w-8" />
        </div>
        <h3 className="text-lg font-semibold">Genera el informe técnico</h3>
        <p className="mt-1 max-w-md text-sm text-muted-foreground">
          Se redactará a partir de la evidencia detectada. Si hay API key de
          Anthropic se usa IA; si no, plantillas deterministas. La estructura y los
          datos (tablas, Log_ID, IoCs) son siempre deterministas.
        </p>
        <button
          onClick={generar}
          disabled={cargando}
          className="mt-5 flex items-center gap-2 rounded-lg bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground transition hover:opacity-90 disabled:opacity-60"
        >
          {cargando ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
          {cargando ? "Generando…" : "Generar informe"}
        </button>
        {error && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-critico/30 bg-critico/10 p-3 text-sm text-critico">
            <AlertCircle className="h-4 w-4" /> {error}
          </div>
        )}
      </Card>
    );
  }

  const n = informe.narrativa;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <ModoBadge informe={informe} />
        <button
          onClick={exportar}
          disabled={descargando}
          className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition hover:opacity-90 disabled:opacity-60"
        >
          {descargando ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
          Exportar PDF
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-critico/30 bg-critico/10 p-3 text-sm text-critico">
          <AlertCircle className="h-4 w-4" /> {error}
        </div>
      )}

      {/* Portada */}
      <Card className="p-8 text-center">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-critico">
          {informe.clasificacion}
        </p>
        <h1 className="mt-3 text-3xl font-bold">{informe.titulo}</h1>
        <div className="mx-auto mt-2 h-1 w-20 rounded bg-primary" />
        <div className="mt-6 space-y-1 text-sm text-muted-foreground">
          <p>Cliente: <span className="font-medium text-foreground">{informe.cliente}</span></p>
          <p>Analista: <span className="font-medium text-foreground">{informe.analista}</span></p>
          <p>Fecha: {informe.generado}</p>
        </div>
      </Card>

      <Seccion n="1" titulo="Resumen ejecutivo">
        <Prosa texto={n["resumen_ejecutivo"] ?? ""} />
      </Seccion>

      <Seccion n="2" titulo="Alcance y metodología">
        <Prosa texto={n["alcance"] ?? ""} />
      </Seccion>

      <Seccion n="3" titulo="Hallazgos por criticidad">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/50 text-muted-foreground">
              <tr>
                <th className="px-2 py-1.5">ID</th>
                <th className="px-2 py-1.5">Criticidad</th>
                <th className="px-2 py-1.5">Hallazgo</th>
                <th className="px-2 py-1.5">Evidencia</th>
                <th className="px-2 py-1.5">MITRE</th>
              </tr>
            </thead>
            <tbody>
              {informe.hallazgos.map((h) => (
                <tr key={h.id} className="border-t border-border">
                  <td className="px-2 py-1.5 font-mono">{h.id}</td>
                  <td className="px-2 py-1.5"><SeverityBadge criticidad={h.criticidad} size="sm" /></td>
                  <td className="px-2 py-1.5">{h.titulo}</td>
                  <td className="px-2 py-1.5 text-muted-foreground">{h.evidencia.length} ev.</td>
                  <td className="px-2 py-1.5 font-mono text-[11px] text-muted-foreground">{h.mitre.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Seccion>

      <Seccion n="4-6" titulo="Incidentes y clasificación de riesgos">
        <div className="space-y-4">
          {informe.incidentes.map((inc) => (
            <div key={inc.id} className="rounded-lg border border-border p-4">
              <div className="mb-2 flex items-center gap-2">
                <span className="font-mono text-sm text-muted-foreground">{inc.id}</span>
                <SeverityBadge criticidad={inc.criticidad} size="sm" />
                {inc.multi_vector && <span className="text-xs text-primary">multi-vector</span>}
              </div>
              <Prosa texto={n["inc_" + inc.id] ?? inc.justificacion} />
            </div>
          ))}
        </div>
      </Seccion>

      <Seccion n="7" titulo="Impacto en la organización">
        <Prosa texto={n["impacto_organizacion"] ?? ""} />
      </Seccion>

      <Seccion n="9" titulo="Recomendaciones generales de seguridad">
        <Prosa texto={n["recomendaciones"] ?? ""} />
      </Seccion>

      <Seccion n="10" titulo="Anexos — IoCs">
        <table className="w-full border-collapse">
          <tbody>
            <IocTabla titulo="IPs externas de origen" valores={informe.iocs.ips_origen} />
            <IocTabla titulo="IPs externas de destino / exfil" valores={informe.iocs.ips_destino} />
            <IocTabla titulo="Cuentas involucradas" valores={informe.iocs.usuarios} />
            <IocTabla titulo="Hosts afectados" valores={informe.iocs.hosts} />
            <IocTabla titulo="Archivos" valores={informe.iocs.archivos} />
            <IocTabla titulo="Tareas / servicios" valores={informe.iocs.tareas_servicios} />
          </tbody>
        </table>
      </Seccion>
    </div>
  );
}

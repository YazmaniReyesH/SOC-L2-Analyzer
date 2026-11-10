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
      {ia ? `Redactado por IA (${informe.modelo})` : "Redactado por plantillas deterministas"}
    </span>
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
          Se redactará a partir de la evidencia detectada (hallazgos e incidentes).
          Si hay API key de Anthropic se usa IA; si no, plantillas deterministas.
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
        <p className="mt-2 text-muted-foreground">{informe.cliente}</p>
        <div className="mt-6 text-sm text-muted-foreground">
          <p>Analista: <span className="font-medium text-foreground">{informe.analista}</span></p>
          <p>{informe.generado}</p>
        </div>
      </Card>

      {/* Secciones */}
      {informe.secciones.map((s) => (
        <Card key={s.id} className="p-6">
          <h2 className="mb-3 border-b border-border pb-2 text-xl font-bold">{s.titulo}</h2>
          <div className="prose-sm max-w-none space-y-2 text-sm leading-relaxed">
            {s.contenido.split("\n").map((linea, i) =>
              linea.trim() === "" ? (
                <div key={i} className="h-2" />
              ) : (
                <p key={i} className="text-foreground/90">
                  {linea}
                </p>
              )
            )}
          </div>
        </Card>
      ))}
    </div>
  );
}

import { useEffect, useState } from "react";
import {
  ShieldCheck,
  Moon,
  Sun,
  LayoutDashboard,
  Table2,
  Siren,
  FileText,
  RotateCcw,
} from "lucide-react";
import { analizarArchivo, mensajeError } from "./lib/api";
import type { AnalyzeResponse } from "./lib/types";
import { FileUpload } from "./components/FileUpload";
import { Dashboard } from "./components/Dashboard";
import { LogsTable } from "./components/LogsTable";
import { IncidentsView } from "./components/IncidentsView";
import { ReportView } from "./components/ReportView";

type Tab = "dashboard" | "logs" | "incidentes" | "informe";

function useDarkMode() {
  const [dark, setDark] = useState(() => {
    try {
      return localStorage.getItem("soc-theme") !== "light";
    } catch {
      return true;
    }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("soc-theme", dark ? "dark" : "light");
    } catch {
      /* ignora */
    }
  }, [dark]);
  return { dark, setDark };
}

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard className="h-4 w-4" /> },
  { id: "logs", label: "Logs", icon: <Table2 className="h-4 w-4" /> },
  { id: "incidentes", label: "Incidentes", icon: <Siren className="h-4 w-4" /> },
  { id: "informe", label: "Informe", icon: <FileText className="h-4 w-4" /> },
];

function App() {
  const { dark, setDark } = useDarkMode();
  const [analisis, setAnalisis] = useState<AnalyzeResponse | null>(null);
  const [cargando, setCargando] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("dashboard");

  const subir = async (file: File) => {
    setCargando(true);
    setError(null);
    try {
      const data = await analizarArchivo(file);
      setAnalisis(data);
      setTab("dashboard");
    } catch (err) {
      setError(mensajeError(err, "No se pudo analizar el archivo."));
    } finally {
      setCargando(false);
    }
  };

  const reiniciar = () => {
    setAnalisis(null);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-10 border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-lg font-bold leading-tight">SOC L2 Analyzer</h1>
              <p className="text-xs text-muted-foreground">
                Análisis de incidentes asistido por IA · Confidencial
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {analisis && (
              <button
                onClick={reiniciar}
                className="flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-sm text-muted-foreground transition hover:text-foreground"
              >
                <RotateCcw className="h-4 w-4" /> Nuevo análisis
              </button>
            )}
            <button
              onClick={() => setDark((d) => !d)}
              className="rounded-lg border border-border bg-card p-2 text-muted-foreground transition hover:text-foreground"
              aria-label="Cambiar tema"
            >
              {dark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </button>
          </div>
        </div>

        {analisis && (
          <nav className="mx-auto flex max-w-7xl gap-1 px-4">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-1.5 border-b-2 px-3 py-2.5 text-sm font-medium transition ${
                  tab === t.id
                    ? "border-primary text-primary"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                {t.icon}
                {t.label}
              </button>
            ))}
          </nav>
        )}
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        {!analisis ? (
          <div className="py-10">
            <div className="mb-8 text-center">
              <h2 className="text-2xl font-bold">Analiza un export del SIEM</h2>
              <p className="mt-1 text-muted-foreground">
                La detección es 100% determinista. La IA solo redacta el informe a
                partir de la evidencia.
              </p>
            </div>
            <FileUpload onFile={subir} cargando={cargando} error={error} />
          </div>
        ) : (
          <>
            <div className="mb-5 rounded-lg border border-border bg-card p-4 text-sm">
              {analisis.resumen}
            </div>
            {tab === "dashboard" && (
              <Dashboard
                estadisticas={analisis.estadisticas}
                incidentes={analisis.incidentes}
                hallazgos={analisis.hallazgos}
              />
            )}
            {tab === "logs" && <LogsTable eventos={analisis.eventos_preview} />}
            {tab === "incidentes" && (
              <IncidentsView
                incidentes={analisis.incidentes}
                hallazgos={analisis.hallazgos}
                eventos={analisis.eventos_preview}
              />
            )}
            {tab === "informe" && <ReportView analisis={analisis} />}
          </>
        )}
      </main>
    </div>
  );
}

export default App;

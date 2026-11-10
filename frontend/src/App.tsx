import { useEffect, useState } from "react";
import {
  ShieldCheck,
  Moon,
  Sun,
  Activity,
  CheckCircle2,
  XCircle,
  Loader2,
  Cpu,
  FileText,
} from "lucide-react";
import { getHealth, type HealthResponse } from "./lib/api";

type Estado = "cargando" | "ok" | "error";

function App() {
  const [dark, setDark] = useState(true);
  const [estado, setEstado] = useState<Estado>("cargando");
  const [health, setHealth] = useState<HealthResponse | null>(null);

  // Dark mode: alterna la clase en <html>.
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  const comprobar = async () => {
    setEstado("cargando");
    try {
      const data = await getHealth();
      setHealth(data);
      setEstado("ok");
    } catch {
      setHealth(null);
      setEstado("error");
    }
  };

  useEffect(() => {
    comprobar();
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Barra superior */}
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-lg font-bold leading-tight">
                SOC L2 Analyzer
              </h1>
              <p className="text-xs text-muted-foreground">
                Análisis de incidentes asistido por IA
              </p>
            </div>
          </div>
          <button
            onClick={() => setDark((d) => !d)}
            className="rounded-lg border border-border bg-card p-2 text-muted-foreground transition hover:text-foreground"
            aria-label="Cambiar tema"
          >
            {dark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
          </button>
        </div>
      </header>

      {/* Contenido */}
      <main className="mx-auto max-w-5xl px-4 py-10">
        <div className="mb-8">
          <h2 className="text-2xl font-bold">Estado del sistema</h2>
          <p className="text-muted-foreground">
            Módulo 1 — Verificación de conectividad backend ↔ frontend.
          </p>
        </div>

        <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
          <div className="mb-5 flex items-center gap-2 text-sm font-medium text-muted-foreground">
            <Activity className="h-4 w-4" />
            <span>GET /api/health</span>
          </div>

          {estado === "cargando" && (
            <div className="flex items-center gap-3 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin" />
              Comprobando el backend…
            </div>
          )}

          {estado === "error" && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 text-critico">
                <XCircle className="h-5 w-5" />
                <span className="font-medium">
                  No se pudo contactar el backend.
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                Asegúrate de que el backend esté corriendo en el puerto 8000:
                <code className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs">
                  uvicorn app.main:app --reload
                </code>
              </p>
              <button
                onClick={comprobar}
                className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition hover:opacity-90"
              >
                Reintentar
              </button>
            </div>
          )}

          {estado === "ok" && health && (
            <div className="space-y-5">
              <div className="flex items-center gap-3 text-bajo">
                <CheckCircle2 className="h-5 w-5" />
                <span className="font-medium">
                  Backend operativo ({health.service} v{health.version})
                </span>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <InfoCard
                  icon={<Cpu className="h-5 w-5" />}
                  titulo="Modo de redacción"
                  valor={
                    health.modo_ia === "ia"
                      ? "IA (Anthropic)"
                      : "Plantillas deterministas"
                  }
                  nota={
                    health.ia_disponible
                      ? `Modelo: ${health.modelo}`
                      : "Sin API key — fallback activo"
                  }
                />
                <InfoCard
                  icon={<FileText className="h-5 w-5" />}
                  titulo="Próximo paso"
                  valor="Módulo 2"
                  nota="Carga y parseo del .xlsx"
                />
              </div>
            </div>
          )}
        </div>

        <p className="mt-8 text-center text-xs text-muted-foreground">
          Analista: Yazmani Reyes Hernández · Clasificación: Confidencial
        </p>
      </main>
    </div>
  );
}

function InfoCard({
  icon,
  titulo,
  valor,
  nota,
}: {
  icon: React.ReactNode;
  titulo: string;
  valor: string;
  nota: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-background p-4">
      <div className="mb-2 flex items-center gap-2 text-muted-foreground">
        {icon}
        <span className="text-xs font-medium uppercase tracking-wide">
          {titulo}
        </span>
      </div>
      <div className="text-lg font-semibold">{valor}</div>
      <div className="text-xs text-muted-foreground">{nota}</div>
    </div>
  );
}

export default App;

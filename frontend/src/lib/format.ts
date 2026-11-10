import type { Criticidad } from "./types";

// Colores por criticidad (coinciden con tailwind.config y los gráficos).
export const COLOR_CRITICIDAD: Record<Criticidad, string> = {
  "Crítico": "hsl(0 72% 51%)",
  "Alto": "hsl(25 95% 53%)",
  "Medio": "hsl(45 93% 47%)",
  "Bajo": "hsl(142 71% 45%)",
};

export const ORDEN_CRITICIDAD: Criticidad[] = ["Crítico", "Alto", "Medio", "Bajo"];

export const RANGO_CRITICIDAD: Record<Criticidad, number> = {
  "Crítico": 4,
  "Alto": 3,
  "Medio": 2,
  "Bajo": 1,
};

// Clases Tailwind para badges de criticidad (texto + fondo translúcido).
export const CLASES_CRITICIDAD: Record<Criticidad, string> = {
  "Crítico": "bg-critico/15 text-critico border-critico/30",
  "Alto": "bg-alto/15 text-alto border-alto/30",
  "Medio": "bg-medio/15 text-medio border-medio/40",
  "Bajo": "bg-bajo/15 text-bajo border-bajo/30",
};

// Paleta para gráficos categóricos (event types, etc.).
export const PALETA = [
  "hsl(217 91% 60%)",
  "hsl(199 89% 48%)",
  "hsl(160 84% 39%)",
  "hsl(45 93% 47%)",
  "hsl(25 95% 53%)",
  "hsl(0 72% 51%)",
  "hsl(280 65% 60%)",
  "hsl(330 81% 60%)",
  "hsl(142 71% 45%)",
  "hsl(190 90% 50%)",
];

export function horaCorta(ts: string | null): string {
  if (!ts) return "—";
  // ts viene ISO (del backend). Mostramos HH:MM:SS.
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString("es-MX", { hour12: false });
}

export function fechaHora(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString("es-MX", { hour12: false });
}

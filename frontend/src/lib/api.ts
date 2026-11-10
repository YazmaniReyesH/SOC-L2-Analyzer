import axios from "axios";
import type { AnalyzeResponse, Informe } from "./types";

// En desarrollo, Vite hace proxy de /api -> backend (ver vite.config.ts).
// En producción se puede sobreescribir con VITE_API_BASE_URL.
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "",
  timeout: 180000,
});

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  ia_disponible: boolean;
  modo_ia: "ia" | "plantillas";
  modelo: string;
}

export async function getHealth(): Promise<HealthResponse> {
  const { data } = await api.get<HealthResponse>("/api/health");
  return data;
}

/** Extrae el mensaje de error legible del backend (detail) o uno genérico. */
export function mensajeError(err: unknown, fallback = "Ocurrió un error."): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (err.message) return err.message;
  }
  return fallback;
}

export async function analizarArchivo(file: File): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await api.post<AnalyzeResponse>("/api/analyze", form);
  return data;
}

export async function generarInforme(analisis: AnalyzeResponse): Promise<Informe> {
  const { data } = await api.post<Informe>("/api/report", analisis);
  return data;
}

export async function descargarPdf(informe: Informe): Promise<Blob> {
  const { data } = await api.post("/api/report/pdf", informe, {
    responseType: "blob",
  });
  return data as Blob;
}

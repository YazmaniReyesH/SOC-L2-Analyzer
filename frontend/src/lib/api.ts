import axios from "axios";

// En desarrollo, Vite hace proxy de /api -> backend (ver vite.config.ts).
// En producción se puede sobreescribir con VITE_API_BASE_URL.
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "",
  timeout: 120000,
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

// Tipos que reflejan los modelos pydantic del backend (serializados snake_case).

export type Criticidad = "Crítico" | "Alto" | "Medio" | "Bajo";

export interface LogEvent {
  log_id: string;
  timestamp: string;
  timestamp_str: string;
  hostname: string;
  event_id: string;
  user: string;
  source_ip: string;
  destination: string | null;
  log_source: string;
  event_description: string;
  process_commandline: string | null;
  result: string;
  severity: string;
  ip_externa: boolean;
}

export interface Conteo {
  etiqueta: string;
  valor: number;
}

export interface PuntoTiempo {
  hora: string;
  conteo: number;
}

export interface RangoTemporal {
  inicio: string | null;
  fin: string | null;
}

export interface Estadisticas {
  total_eventos: number;
  rango_temporal: RangoTemporal;
  por_severidad: Conteo[];
  por_criticidad_hallazgos: Conteo[];
  por_event_id: Conteo[];
  por_log_source: Conteo[];
  por_hostname: Conteo[];
  por_resultado: Conteo[];
  ips_externas_origen: string[];
  ips_externas_destino: string[];
  ips_externas_unicas: string[];
  top_ips_externas: Conteo[];
  hosts_afectados: string[];
  linea_tiempo: PuntoTiempo[];
}

export interface Acciones {
  investigar: string[];
  contener: string[];
  remediar: string[];
}

export interface Finding {
  id: string;
  regla: string;
  titulo: string;
  categoria: string;
  criticidad: Criticidad;
  justificacion: string;
  evidencia: string[];
  activos: string[];
  ips: string[];
  usuarios: string[];
  mitre: string[];
  impacto: string;
  acciones: Acciones;
  inicio: string | null;
  fin: string | null;
}

export interface EventoTimeline {
  timestamp: string;
  timestamp_str: string;
  log_id: string;
  hostname: string;
  etapa: string;
  descripcion: string;
}

export interface VectorIncidente {
  actor: string;
  usuarios: string[];
  activos: string[];
  ips: string[];
  etapas: string[];
  hallazgos: string[];
  resumen: string;
}

export interface Incidente {
  id: string;
  titulo: string;
  criticidad: Criticidad;
  justificacion: string;
  hallazgos: string[];
  activos: string[];
  ips: string[];
  usuarios: string[];
  mitre: string[];
  etapas: string[];
  vectores: VectorIncidente[];
  multi_vector: boolean;
  impacto: string;
  inicio: string | null;
  fin: string | null;
  linea_tiempo: EventoTimeline[];
}

export interface AnalyzeResponse {
  resumen: string;
  estadisticas: Estadisticas;
  eventos_preview: LogEvent[];
  hallazgos: Finding[];
  incidentes: Incidente[];
}

// --- Informe (Módulo 5) ---
export interface IoCs {
  ips_origen: string[];
  ips_destino: string[];
  usuarios: string[];
  hosts: string[];
  archivos: string[];
  tareas_servicios: string[];
}

export interface Informe {
  modo_ia: "ia" | "plantillas";
  modelo: string | null;
  generado: string;
  titulo: string;
  cliente: string;
  analista: string;
  clasificacion: string;
  resumen: string;
  narrativa: Record<string, string>;
  estadisticas: Estadisticas;
  incidentes: Incidente[];
  hallazgos: Finding[];
  iocs: IoCs;
}

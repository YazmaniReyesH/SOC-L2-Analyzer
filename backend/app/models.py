"""Modelos pydantic v2 compartidos por toda la aplicación.

Incluye el modelo de evento normalizado (`LogEvent`), las estadísticas del
dataset, y los modelos de hallazgos/incidentes que produce el motor de
detección (Módulo 3) y consume la capa de informe (Módulo 5).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Criticidad = Literal["Crítico", "Alto", "Medio", "Bajo"]

# Rango numérico para comparar/ordenar criticidades de forma determinista.
RANGO_CRITICIDAD: dict[str, int] = {"Crítico": 4, "Alto": 3, "Medio": 2, "Bajo": 1}


# --------------------------------------------------------------------------- #
# Evento de log normalizado
# --------------------------------------------------------------------------- #
class LogEvent(BaseModel):
    """Un registro del SIEM, ya normalizado y tipado."""

    log_id: str
    timestamp: datetime
    timestamp_str: str
    hostname: str
    event_id: str
    user: str
    source_ip: str
    destination: str | None = None
    log_source: str
    event_description: str
    process_commandline: str | None = None
    result: str
    severity: str
    # Derivado: la IP de origen no es privada (RFC1918).
    ip_externa: bool = False


# --------------------------------------------------------------------------- #
# Estadísticas del dataset
# --------------------------------------------------------------------------- #
class Conteo(BaseModel):
    etiqueta: str
    valor: int


class RangoTemporal(BaseModel):
    inicio: datetime | None = None
    fin: datetime | None = None


class PuntoTiempo(BaseModel):
    """Eventos agregados por bucket temporal (para la línea de tiempo)."""

    hora: str
    conteo: int


class Estadisticas(BaseModel):
    total_eventos: int
    rango_temporal: RangoTemporal
    por_severidad: list[Conteo] = Field(default_factory=list)
    por_criticidad_hallazgos: list[Conteo] = Field(default_factory=list)
    por_event_id: list[Conteo] = Field(default_factory=list)
    por_log_source: list[Conteo] = Field(default_factory=list)
    por_hostname: list[Conteo] = Field(default_factory=list)
    por_resultado: list[Conteo] = Field(default_factory=list)
    # IPs externas separadas por rol (derivadas de los datos, sin hardcodear).
    ips_externas_origen: list[str] = Field(default_factory=list)
    ips_externas_destino: list[str] = Field(default_factory=list)
    ips_externas_unicas: list[str] = Field(default_factory=list)  # unión (total)
    top_ips_externas: list[Conteo] = Field(default_factory=list)
    hosts_afectados: list[str] = Field(default_factory=list)
    linea_tiempo: list[PuntoTiempo] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Hallazgos e incidentes (motor de detección)
# --------------------------------------------------------------------------- #
class Acciones(BaseModel):
    """Acciones recomendadas, separadas por fase de respuesta."""

    investigar: list[str] = Field(default_factory=list)
    contener: list[str] = Field(default_factory=list)
    remediar: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Hallazgo determinista. TODA conclusión es trazable vía `evidencia`."""

    id: str
    regla: str  # R1..R9
    titulo: str
    categoria: str
    criticidad: Criticidad
    justificacion: str
    evidencia: list[str] = Field(default_factory=list)  # Log_IDs
    activos: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    usuarios: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    impacto: str = ""
    acciones: Acciones = Field(default_factory=Acciones)
    # Rango temporal de la evidencia (para correlación/timeline).
    inicio: datetime | None = None
    fin: datetime | None = None


class EventoTimeline(BaseModel):
    timestamp: datetime
    timestamp_str: str
    log_id: str
    hostname: str
    etapa: str
    descripcion: str


class VectorIncidente(BaseModel):
    """Una 'rama' del incidente: un actor/entidad distinto que converge con otros.

    Permite describir incidentes multi-vía como vectores correlacionados en lugar
    de forzar una única cadena lineal.
    """

    actor: str
    usuarios: list[str] = Field(default_factory=list)
    activos: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    etapas: list[str] = Field(default_factory=list)
    hallazgos: list[str] = Field(default_factory=list)
    resumen: str = ""


class Incidente(BaseModel):
    """Grupo de hallazgos correlacionados por entidades y proximidad temporal."""

    id: str
    titulo: str
    criticidad: Criticidad
    justificacion: str
    hallazgos: list[str] = Field(default_factory=list)  # ids de Finding
    activos: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    usuarios: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    etapas: list[str] = Field(default_factory=list)  # etapas de la kill chain
    vectores: list[VectorIncidente] = Field(default_factory=list)
    multi_vector: bool = False
    impacto: str = ""
    inicio: datetime | None = None
    fin: datetime | None = None
    linea_tiempo: list[EventoTimeline] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Respuesta de /api/analyze
# --------------------------------------------------------------------------- #
class AnalyzeResponse(BaseModel):
    resumen: str
    estadisticas: Estadisticas
    eventos_preview: list[LogEvent] = Field(default_factory=list)
    hallazgos: list[Finding] = Field(default_factory=list)
    incidentes: list[Incidente] = Field(default_factory=list)

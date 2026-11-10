"""Motor de detección: ejecuta las reglas y correlaciona en incidentes."""
from __future__ import annotations

from datetime import datetime

from ..models import RANGO_CRITICIDAD, Finding, Incidente, LogEvent
from .correlation import correlacionar
from .rules import REGLAS, reset_contadores


def ejecutar_deteccion(
    eventos: list[LogEvent],
) -> tuple[list[Finding], list[Incidente]]:
    """Devuelve (hallazgos, incidentes) de forma 100% determinista."""
    reset_contadores()
    hallazgos: list[Finding] = []
    for regla in REGLAS:
        hallazgos.extend(regla(eventos))

    incidentes = correlacionar(hallazgos, eventos)

    hallazgos.sort(
        key=lambda h: (-RANGO_CRITICIDAD[h.criticidad], h.inicio or datetime.max)
    )
    return hallazgos, incidentes

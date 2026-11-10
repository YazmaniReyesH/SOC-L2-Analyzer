"""Orquestación del análisis: parseo -> estadísticas -> detección.

En el Módulo 2 la detección aún no existe (hallazgos/incidentes vacíos).
El Módulo 3 conecta aquí el motor determinista.
"""
from __future__ import annotations

from .models import AnalyzeResponse, Estadisticas, LogEvent
from .stats import calcular_estadisticas

try:
    # Disponible a partir del Módulo 3.
    from .detection import ejecutar_deteccion
except Exception:  # noqa: BLE001
    ejecutar_deteccion = None  # type: ignore[assignment]


def _resumen(est: Estadisticas, n_incidentes: int, n_hallazgos: int) -> str:
    r = est.rango_temporal
    rango = ""
    if r.inicio and r.fin:
        rango = f" en el rango {r.inicio:%Y-%m-%d %H:%M} – {r.fin:%H:%M}"
    return (
        f"Se analizaron {est.total_eventos} eventos{rango}. "
        f"Se identificaron {n_incidentes} incidente(s) y {n_hallazgos} hallazgo(s). "
        f"IPs externas únicas detectadas: {len(est.ips_externas_unicas)}."
    )


def analizar_eventos(eventos: list[LogEvent]) -> AnalyzeResponse:
    estadisticas = calcular_estadisticas(eventos)

    hallazgos = []
    incidentes = []
    if ejecutar_deteccion is not None:
        hallazgos, incidentes = ejecutar_deteccion(eventos)
        # Añade el desglose de criticidad de hallazgos a las estadísticas.
        from collections import Counter

        from .models import Conteo

        c = Counter(h.criticidad for h in hallazgos)
        orden = ["Crítico", "Alto", "Medio", "Bajo"]
        estadisticas.por_criticidad_hallazgos = [
            Conteo(etiqueta=k, valor=c[k]) for k in orden if c[k] > 0
        ]

    return AnalyzeResponse(
        resumen=_resumen(estadisticas, len(incidentes), len(hallazgos)),
        estadisticas=estadisticas,
        eventos_preview=eventos,
        hallazgos=hallazgos,
        incidentes=incidentes,
    )

"""Cálculo de estadísticas del dataset para el dashboard."""
from __future__ import annotations

from collections import Counter

from .models import (
    Conteo,
    Estadisticas,
    LogEvent,
    PuntoTiempo,
    RangoTemporal,
)


def _conteos(valores: list[str], top: int | None = None) -> list[Conteo]:
    c = Counter(v for v in valores if v != "")
    items = c.most_common(top)
    return [Conteo(etiqueta=k, valor=v) for k, v in items]


def calcular_estadisticas(eventos: list[LogEvent]) -> Estadisticas:
    if not eventos:
        return Estadisticas(total_eventos=0, rango_temporal=RangoTemporal())

    ips_externas = sorted({e.source_ip for e in eventos if e.ip_externa})

    # Línea de tiempo: eventos por minuto redondeado a bucket de 5 minutos.
    buckets: Counter[str] = Counter()
    for e in eventos:
        t = e.timestamp
        minuto = (t.minute // 5) * 5
        clave = f"{t:%Y-%m-%d %H}:{minuto:02d}"
        buckets[clave] += 1
    linea = [PuntoTiempo(hora=k, conteo=buckets[k]) for k in sorted(buckets)]

    return Estadisticas(
        total_eventos=len(eventos),
        rango_temporal=RangoTemporal(
            inicio=eventos[0].timestamp, fin=eventos[-1].timestamp
        ),
        por_severidad=_conteos([e.severity for e in eventos]),
        por_event_id=_conteos([e.event_id for e in eventos]),
        por_log_source=_conteos([e.log_source for e in eventos]),
        por_hostname=_conteos([e.hostname for e in eventos]),
        por_resultado=_conteos([e.result for e in eventos]),
        ips_externas_unicas=ips_externas,
        top_ips_externas=_conteos(
            [e.source_ip for e in eventos if e.ip_externa], top=10
        ),
        hosts_afectados=sorted({e.hostname for e in eventos if e.hostname}),
        linea_tiempo=linea,
    )

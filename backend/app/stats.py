"""Cálculo de estadísticas del dataset para el dashboard."""
from __future__ import annotations

import re
from collections import Counter

from .models import (
    Conteo,
    Estadisticas,
    LogEvent,
    PuntoTiempo,
    RangoTemporal,
)
from .parsing import is_external_ip


def _conteos(valores: list[str], top: int | None = None) -> list[Conteo]:
    c = Counter(v for v in valores if v != "")
    items = c.most_common(top)
    return [Conteo(etiqueta=k, valor=v) for k, v in items]


def _ip_de_destino(destination: str | None) -> str | None:
    """Extrae una IP de un campo Destination ('IP:puerto', 'IP', host o UNC).

    Devuelve la IP solo si es una dirección válida (agnóstico: no asume rangos).
    """
    if not destination:
        return None
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", destination)
    return m.group(1) if m else None


def calcular_estadisticas(eventos: list[LogEvent]) -> Estadisticas:
    if not eventos:
        return Estadisticas(total_eventos=0, rango_temporal=RangoTemporal())

    # IPs externas de ORIGEN (Source_IP no RFC1918).
    ips_origen = sorted({e.source_ip for e in eventos if e.ip_externa})

    # IPs externas de DESTINO/EXFIL (derivadas de Destination, p.ej. 5156/PROXY).
    dest_counter: Counter[str] = Counter()
    ips_destino_set: set[str] = set()
    for e in eventos:
        ip = _ip_de_destino(e.destination)
        if ip and is_external_ip(ip):
            ips_destino_set.add(ip)
            dest_counter[ip] += 1
    ips_destino = sorted(ips_destino_set)

    # Unión total y top combinado (origen como fuente + destino como salida).
    ips_union = sorted(set(ips_origen) | ips_destino_set)
    top_counter: Counter[str] = Counter()
    for e in eventos:
        if e.ip_externa:
            top_counter[e.source_ip] += 1
    top_counter.update(dest_counter)
    top_ips = [Conteo(etiqueta=k, valor=v) for k, v in top_counter.most_common(10)]

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
        ips_externas_origen=ips_origen,
        ips_externas_destino=ips_destino,
        ips_externas_unicas=ips_union,
        top_ips_externas=top_ips,
        hosts_afectados=sorted({e.hostname for e in eventos if e.hostname}),
        linea_tiempo=linea,
    )

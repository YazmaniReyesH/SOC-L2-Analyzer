"""Consolidación de IoCs a partir de la evidencia detectada (agnóstico)."""
from __future__ import annotations

import re

from ..models import AnalyzeResponse, IoCs, LogEvent

# Archivos: rutas Windows o nombres con extensiones de interés.
_RE_ARCHIVO = re.compile(
    r"(?:[A-Za-z]:\\[^\s;]+|\\\\[^\s;]+|[\w.\-]+\\[^\s;]+)\.(?:xlsx|xls|docx|doc|zip|7z|rar|csv|pdf|ps1|exe|dll|bat|vbs)",
    re.IGNORECASE,
)
# Nombres de tarea/servicio.
_RE_TAREA = re.compile(r"(?:TaskName|ServiceName)=([^;]+)", re.IGNORECASE)


def consolidar_iocs(analisis: AnalyzeResponse) -> IoCs:
    event_map: dict[str, LogEvent] = {e.log_id: e for e in analisis.eventos_preview}

    usuarios: set[str] = set()
    hosts: set[str] = set()
    archivos: set[str] = set()
    tareas: set[str] = set()

    for h in analisis.hallazgos:
        usuarios.update(u for u in h.usuarios if u and u != "-")
        hosts.update(a for a in h.activos if a)
        for lid in h.evidencia:
            ev = event_map.get(lid)
            if not ev:
                continue
            texto = " ".join(
                filter(None, [ev.process_commandline, ev.event_description, ev.destination])
            )
            archivos.update(m.group(0) for m in _RE_ARCHIVO.finditer(texto))
            tareas.update(m.group(1).strip() for m in _RE_TAREA.finditer(texto))

    return IoCs(
        ips_origen=analisis.estadisticas.ips_externas_origen,
        ips_destino=analisis.estadisticas.ips_externas_destino,
        usuarios=sorted(usuarios),
        hosts=sorted(hosts),
        archivos=sorted(archivos),
        tareas_servicios=sorted(tareas),
    )

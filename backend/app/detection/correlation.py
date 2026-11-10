"""Correlación de hallazgos en incidentes + matriz de riesgo + timeline.

Lógica determinista y documentada:

1. Los hallazgos de anomalía (R9) se agrupan aparte (no contaminan la kill chain).
2. El resto se agrupa por componentes conexos: dos hallazgos se unen si comparten
   al menos una entidad (host/usuario/IP) Y su separación temporal es
   <= CORRELACION_VENTANA_MIN minutos.
3. La criticidad del incidente se deriva con una matriz determinista:
   - Crítico si hay exfiltración, o si se observan >= 4 etapas distintas de la
     kill chain.
   - En otro caso, la criticidad máxima de sus hallazgos.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from .. import constants as C
from ..models import (
    RANGO_CRITICIDAD,
    EventoTimeline,
    Finding,
    Incidente,
    LogEvent,
)

_INV_RANGO = {v: k for k, v in RANGO_CRITICIDAD.items()}


def _entidades(f: Finding) -> set[str]:
    ent = set()
    ent.update(f"H:{h}" for h in f.activos)
    ent.update(f"U:{u}" for u in f.usuarios)
    ent.update(f"I:{i}" for i in f.ips)
    return ent


def _gap_min(a: Finding, b: Finding) -> float:
    if not (a.inicio and a.fin and b.inicio and b.fin):
        return 1e9
    if a.inicio <= b.fin and b.inicio <= a.fin:  # se solapan
        return 0.0
    if a.fin < b.inicio:
        return (b.inicio - a.fin).total_seconds() / 60
    return (a.inicio - b.fin).total_seconds() / 60


def _componentes(findings: list[Finding]) -> list[list[Finding]]:
    """Union-find por entidad compartida + proximidad temporal."""
    padre = list(range(len(findings)))

    def find(x: int) -> int:
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x

    def union(a: int, b: int) -> None:
        padre[find(a)] = find(b)

    ents = [_entidades(f) for f in findings]
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if ents[i] & ents[j] and _gap_min(findings[i], findings[j]) <= C.CORRELACION_VENTANA_MIN:
                union(i, j)

    grupos: dict[int, list[Finding]] = defaultdict(list)
    for idx, f in enumerate(findings):
        grupos[find(idx)].append(f)
    return list(grupos.values())


def criticidad_incidente(findings: list[Finding]) -> str:
    rank = max(RANGO_CRITICIDAD[f.criticidad] for f in findings)
    cats = {f.categoria for f in findings}
    tiene_exfil = "Exfiltración" in cats
    etapas = {c for c in cats if c != "Anomalía"}
    if tiene_exfil or len(etapas) >= 4:
        return "Crítico"
    return _INV_RANGO[rank]


def _titulo(findings: list[Finding]) -> str:
    cats = {f.categoria for f in findings}
    reglas = {f.regla for f in findings}
    hay_beacon = any(f.titulo.startswith("Beaconing") for f in findings)
    if "Exfiltración" in cats and "Acceso inicial" in cats:
        return "Intrusión dirigida con exfiltración de datos (kill chain completa)"
    if hay_beacon:
        return "Actividad de C2 / beaconing con exfiltración"
    if "Exfiltración" in cats:
        return "Exfiltración de datos sensibles"
    if "R2" in reglas:
        return "Campaña de password spraying"
    if "Persistencia" in cats:
        return "Establecimiento de persistencia"
    if "Reconocimiento" in cats:
        return "Escaneo y ataque a aplicación web"
    if cats & {"Movimiento lateral", "Colección"}:
        return "Movimiento lateral y acceso a datos sensibles"
    return "Actividad sospechosa correlacionada"


def _timeline(
    findings: list[Finding], by_id: dict[str, LogEvent]
) -> list[EventoTimeline]:
    etapa_de: dict[str, str] = {}
    for f in findings:
        for lid in f.evidencia:
            etapa_de.setdefault(lid, f.categoria)
    vistos: set[str] = set()
    eventos: list[LogEvent] = []
    for lid in etapa_de:
        if lid in by_id and lid not in vistos:
            vistos.add(lid)
            eventos.append(by_id[lid])
    eventos.sort(key=lambda e: e.timestamp)
    linea = []
    for e in eventos:
        desc = e.event_description
        if e.process_commandline:
            desc += f" — {e.process_commandline}"
        linea.append(
            EventoTimeline(
                timestamp=e.timestamp,
                timestamp_str=e.timestamp_str,
                log_id=e.log_id,
                hostname=e.hostname,
                etapa=etapa_de.get(e.log_id, ""),
                descripcion=desc,
            )
        )
    return linea


def _impacto(findings: list[Finding]) -> str:
    vistos = []
    for f in findings:
        if f.impacto and f.impacto not in vistos:
            vistos.append(f.impacto)
    return " ".join(vistos[:4])


def _construir_incidente(findings: list[Finding], by_id: dict[str, LogEvent]) -> Incidente:
    findings = sorted(findings, key=lambda f: (f.inicio or datetime.min))
    activos = sorted({a for f in findings for a in f.activos})
    ips = sorted({i for f in findings for i in f.ips})
    usuarios = sorted({u for f in findings for u in f.usuarios})
    mitre = sorted({m for f in findings for m in f.mitre})
    etapas = [
        c
        for c in ["Acceso inicial", "Escalamiento de privilegios", "Ejecución",
                  "Movimiento lateral", "Colección", "Persistencia",
                  "Exfiltración", "Reconocimiento", "Anomalía"]
        if c in {f.categoria for f in findings}
    ]
    crit = criticidad_incidente(findings)
    inicios = [f.inicio for f in findings if f.inicio]
    fines = [f.fin for f in findings if f.fin]
    just = (
        f"Incidente conformado por {len(findings)} hallazgo(s) correlacionados por "
        f"entidades compartidas (activos: {', '.join(activos) or 'n/d'}) dentro de una "
        f"ventana temporal de {C.CORRELACION_VENTANA_MIN} min. "
        f"Etapas observadas: {', '.join(etapas)}. "
        + (
            "Se clasifica como Crítico por involucrar exfiltración de datos o una "
            "cadena de ataque de 4+ etapas."
            if crit == "Crítico"
            else f"Criticidad {crit} según la criticidad máxima de sus hallazgos."
        )
    )
    return Incidente(
        id="INC-TMP",
        titulo=_titulo(findings),
        criticidad=crit,  # type: ignore[arg-type]
        justificacion=just,
        hallazgos=[f.id for f in findings],
        activos=activos,
        ips=ips,
        usuarios=usuarios,
        mitre=mitre,
        etapas=etapas,
        impacto=_impacto(findings),
        inicio=min(inicios) if inicios else None,
        fin=max(fines) if fines else None,
        linea_tiempo=_timeline(findings, by_id),
    )


def correlacionar(
    hallazgos: list[Finding], eventos: list[LogEvent]
) -> list[Incidente]:
    by_id = {e.log_id: e for e in eventos}

    anomalias = [f for f in hallazgos if f.categoria == "Anomalía"]
    resto = [f for f in hallazgos if f.categoria != "Anomalía"]

    incidentes: list[Incidente] = []
    for grupo in _componentes(resto):
        incidentes.append(_construir_incidente(grupo, by_id))

    # Las anomalías se consolidan en un único incidente de higiene.
    if anomalias:
        inc = _construir_incidente(anomalias, by_id)
        inc.titulo = "Anomalías e higiene de seguridad"
        incidentes.append(inc)

    # Orden: criticidad desc, luego por inicio asc. Asigna IDs estables.
    incidentes.sort(
        key=lambda i: (
            -RANGO_CRITICIDAD[i.criticidad],
            i.inicio or datetime.max,
        )
    )
    for n, inc in enumerate(incidentes, start=1):
        inc.id = f"INC-{n:02d}"
    return incidentes

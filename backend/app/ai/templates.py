"""Fallback determinista: genera la PROSA del informe sin llamadas externas.

Produce exactamente la misma estructura (mismas claves) que el narrador de IA,
a partir de la misma evidencia. Nunca inventa: todo sale de los hallazgos.
"""
from __future__ import annotations

from ..models import AnalyzeResponse, Finding, Incidente, IoCs


def _by_id(hallazgos: list[Finding]) -> dict[str, Finding]:
    return {h.id: h for h in hallazgos}


def _resumen_ejecutivo(analisis: AnalyzeResponse) -> str:
    inc = analisis.incidentes
    est = analisis.estadisticas
    por_crit: dict[str, int] = {}
    for i in inc:
        por_crit[i.criticidad] = por_crit.get(i.criticidad, 0) + 1
    desglose = ", ".join(f"{v} {k}" for k, v in por_crit.items()) or "ninguno"
    criticos = [i for i in inc if i.criticidad == "Crítico"]

    partes = [
        f"Durante el análisis de {est.total_eventos} eventos del SIEM se "
        f"identificaron {len(inc)} incidente(s) de seguridad y "
        f"{len(analisis.hallazgos)} hallazgo(s) ({desglose}).",
    ]
    if criticos:
        titulos = "; ".join(f"{c.id}: {c.titulo}" for c in criticos)
        partes.append(
            f"Los incidentes de severidad Crítica requieren atención inmediata: {titulos}."
        )
    partes.append(
        f"Se detectaron {len(est.ips_externas_unicas)} direcciones IP externas "
        f"involucradas ({len(est.ips_externas_origen)} de origen y "
        f"{len(est.ips_externas_destino)} de destino/exfiltración)."
    )
    partes.append(
        "Toda conclusión de este informe es trazable a eventos concretos del SIEM "
        "(Log_ID); la detección es determinista y no se derivan hallazgos sin evidencia."
    )
    return "\n".join(partes)


def _alcance(analisis: AnalyzeResponse) -> str:
    est = analisis.estadisticas
    fuentes = ", ".join(c.etiqueta for c in est.por_log_source) or "n/d"
    r = est.rango_temporal
    rango = (
        f"{r.inicio:%Y-%m-%d %H:%M:%S} a {r.fin:%Y-%m-%d %H:%M:%S}"
        if r.inicio and r.fin
        else "n/d"
    )
    return "\n".join(
        [
            f"El análisis abarcó {est.total_eventos} eventos registrados entre "
            f"{rango}, provenientes de {len(est.hosts_afectados)} hosts.",
            f"Fuentes de log analizadas: {fuentes}.",
            "Metodología: los eventos se normalizan y se evalúan con un motor de "
            "detección determinista (reglas R1–R9 sobre patrones, umbrales y "
            "rangos RFC1918). Los hallazgos se correlacionan en incidentes por "
            "entidades compartidas y proximidad temporal. La IA, cuando está "
            "disponible, únicamente redacta la narrativa a partir de la evidencia.",
        ]
    )


def _impacto_organizacion(analisis: AnalyzeResponse) -> str:
    inc = analisis.incidentes
    hay_exfil = any("Exfiltración" in i.etapas for i in inc)
    hay_persist = any("Persistencia" in i.etapas for i in inc)
    hay_cred = any(
        "Acceso inicial" in i.etapas or "Escalamiento de privilegios" in i.etapas
        for i in inc
    )
    partes = []
    if hay_exfil:
        partes.append(
            "Se observa exfiltración de datos hacia infraestructura externa, con "
            "impacto potencial en la confidencialidad de información sensible y "
            "posibles obligaciones de notificación regulatoria."
        )
    if hay_cred:
        partes.append(
            "El compromiso de credenciales y la escalada de privilegios comprometen "
            "la integridad de las cuentas y permiten movimiento dentro de la red."
        )
    if hay_persist:
        partes.append(
            "Los mecanismos de persistencia implican que el atacante puede recuperar "
            "el acceso tras una contención parcial; la erradicación debe ser completa."
        )
    if not partes:
        partes.append(
            "El impacto se limita a actividad de reconocimiento/anomalías sin "
            "compromiso confirmado; aun así debe investigarse para descartar escalada."
        )
    partes.append(
        "La disponibilidad de los servicios afectados y la reputación de la "
        "organización podrían verse comprometidas si los incidentes no se contienen."
    )
    return "\n".join(partes)


def _recomendaciones(analisis: AnalyzeResponse) -> str:
    cats = {e for i in analisis.incidentes for e in i.etapas}
    recs = [
        "Implementar autenticación multifactor (MFA) en todos los accesos, "
        "especialmente administrativos y remotos (RDP).",
        "Restringir y monitorear el acceso RDP/remoto desde Internet (VPN o jump host).",
        "Aplicar el principio de mínimo privilegio y revisar cuentas de servicio.",
        "Habilitar registro avanzado (ScriptBlock Logging, auditoría de procesos) y "
        "alertas sobre creación de tareas/servicios (4698/7045).",
        "Segmentar la red para limitar el movimiento lateral y proteger shares críticos.",
        "Desplegar controles de egreso/DLP para detectar y bloquear exfiltración.",
        "Mantener un inventario de activos consistente (nomenclatura de hosts).",
    ]
    if "Reconocimiento" in cats:
        recs.append("Desplegar/ajustar un WAF y aplicar parches a las aplicaciones web expuestas.")
    return "\n".join(f"- {r}" for r in recs)


def _narr_incidente(inc: Incidente, by_id: dict[str, Finding]) -> str:
    partes = [
        f"Incidente {inc.id} — {inc.titulo} (criticidad {inc.criticidad}). "
        f"{inc.justificacion}"
    ]
    if inc.multi_vector:
        partes.append(
            "Este incidente agrupa múltiples vectores correlacionados (no una única "
            "cadena lineal); cada rama refleja entidades distintas que convergen:"
        )
        for v in inc.vectores:
            partes.append(f"  • Vector «{v.actor}»: {v.resumen}")
    elif inc.etapas:
        partes.append("Secuencia observada (kill chain): " + " → ".join(inc.etapas) + ".")

    partes.append("Hallazgos y evidencia:")
    for hid in inc.hallazgos:
        h = by_id.get(hid)
        if not h:
            continue
        ev = ", ".join(h.evidencia[:10]) + ("…" if len(h.evidencia) > 10 else "")
        partes.append(f"  • [{h.criticidad}] {h.titulo} — Log_ID: {ev}")
    if inc.impacto:
        partes.append(f"Impacto: {inc.impacto}")
    return "\n".join(partes)


def narrativa_determinista(analisis: AnalyzeResponse, _iocs: IoCs) -> dict[str, str]:
    by_id = _by_id(analisis.hallazgos)
    narr = {
        "resumen_ejecutivo": _resumen_ejecutivo(analisis),
        "alcance": _alcance(analisis),
        "impacto_organizacion": _impacto_organizacion(analisis),
        "recomendaciones": _recomendaciones(analisis),
    }
    for inc in analisis.incidentes:
        narr[f"inc_{inc.id}"] = _narr_incidente(inc, by_id)
    return narr

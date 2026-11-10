"""Verificación automática del motor de detección contra el archivo de muestra.

Comprueba los 6 criterios de aceptación con sus IoCs y el principio de rigor:
NINGÚN hallazgo puede existir sin evidencia (Log_IDs reales del dataset).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.detection import ejecutar_deteccion
from app.models import Finding, Incidente
from app.parsing import load_events

SAMPLE = Path(__file__).resolve().parents[1] / "sample" / "SOC_L2_Logs.xlsx"


@pytest.fixture(scope="module")
def resultado():
    assert SAMPLE.exists(), f"Falta el archivo de muestra en {SAMPLE}"
    eventos = load_events(str(SAMPLE))
    hallazgos, incidentes = ejecutar_deteccion(eventos)
    ids_validos = {e.log_id for e in eventos}
    return eventos, hallazgos, incidentes, ids_validos


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _buscar_hallazgo(hallazgos: list[Finding], **criterios) -> Finding | None:
    for h in hallazgos:
        ok = True
        for campo, pred in criterios.items():
            valor = getattr(h, campo)
            if callable(pred):
                ok = ok and pred(valor)
            else:
                ok = ok and valor == pred
        if ok:
            return h
    return None


def _evidencia_incidente(inc: Incidente, hallazgos: list[Finding]) -> set[str]:
    by_id = {h.id: h for h in hallazgos}
    return {e for hid in inc.hallazgos for e in by_id[hid].evidencia}


# --------------------------------------------------------------------------- #
# Principio de rigor: nada sin evidencia
# --------------------------------------------------------------------------- #
def test_no_hay_hallazgos_sin_evidencia(resultado):
    _, hallazgos, _, ids_validos = resultado
    assert hallazgos, "El motor no produjo ningún hallazgo."
    for h in hallazgos:
        assert h.evidencia, f"El hallazgo {h.id} no tiene evidencia (Log_IDs)."
        for lid in h.evidencia:
            assert lid in ids_validos, (
                f"El hallazgo {h.id} cita un Log_ID inexistente: {lid}"
            )


def test_incidentes_solo_referencian_hallazgos_existentes(resultado):
    _, hallazgos, incidentes, _ = resultado
    ids = {h.id for h in hallazgos}
    assert incidentes, "No se generaron incidentes."
    for inc in incidentes:
        assert inc.hallazgos
        for hid in inc.hallazgos:
            assert hid in ids


# --------------------------------------------------------------------------- #
# AC1 — Intrusión dirigida + exfiltración (Crítico)
# --------------------------------------------------------------------------- #
def test_ac1_intrusion_dirigida_exfiltracion(resultado):
    _, hallazgos, incidentes, _ = resultado
    criticos = [
        i
        for i in incidentes
        if i.criticidad == "Crítico"
        and "198.51.100.77" in i.ips
        and "CORP\\admin" in i.usuarios
    ]
    assert criticos, "No se detectó el incidente crítico de intrusión dirigida (admin/198.51.100.77)."
    inc = criticos[0]
    assert {"APP-SRV01", "FS-SRV01"} <= set(inc.activos)
    assert "Exfiltración" in inc.etapas
    assert "203.0.113.88" in inc.ips, "Falta el destino de exfiltración 203.0.113.88."

    ev = _evidencia_incidente(inc, hallazgos)
    # Kill chain: BF RDP exitosa -> staging -> acceso a Budget2027 -> exfil.
    assert "EVT-00188" in ev, "Falta el 4624 exitoso del brute force RDP."
    assert "EVT-00232" in ev, "Falta el evento de staging (tar.exe -> finance.zip)."
    assert "EVT-00231" in ev, "Falta el acceso a Finance\\Budget2027.xlsx."
    assert "EVT-00235" in ev, "Falta la conexión de exfiltración a 203.0.113.88:443."

    # Trazabilidad de IoCs textuales.
    just = " ".join(h.justificacion for h in hallazgos if h.id in inc.hallazgos)
    assert "Budget2027" in just
    assert any("finance.zip" in (h.justificacion + " " + h.impacto) or "C:\\Temp" in h.justificacion
               for h in hallazgos if h.id in inc.hallazgos)


# --------------------------------------------------------------------------- #
# AC2 — Password spraying (Alto)
# --------------------------------------------------------------------------- #
def test_ac2_password_spraying(resultado):
    _, hallazgos, incidentes, _ = resultado
    h = _buscar_hallazgo(
        hallazgos,
        regla="R2",
        ips=lambda v: "203.0.113.74" in v,
    )
    assert h is not None, "No se detectó el password spraying desde 203.0.113.74."
    assert h.criticidad == "Alto"
    # Debe haber atacado >= 5 cuentas distintas.
    assert len(h.usuarios) >= 5, f"Spraying con solo {len(h.usuarios)} cuentas."
    assert "T1110.003" in h.mitre
    # El incidente que lo contiene es de criticidad Alto.
    inc = next(i for i in incidentes if h.id in i.hallazgos)
    assert inc.criticidad == "Alto"


# --------------------------------------------------------------------------- #
# AC3 — Exfiltración / beaconing C2 (Crítico)
# --------------------------------------------------------------------------- #
def test_ac3_beaconing_c2(resultado):
    _, hallazgos, _, _ = resultado
    h = _buscar_hallazgo(
        hallazgos,
        titulo=lambda t: t.startswith("Beaconing"),
        ips=lambda v: "198.51.100.88" in v,
    )
    assert h is not None, "No se detectó el beaconing hacia 198.51.100.88."
    assert h.criticidad == "Crítico"
    assert "CORP\\rrojas" in h.usuarios
    assert "WS-018" in h.activos
    # >= 8 conexiones (el dataset tiene ~22 POST regulares).
    conexiones = [e for e in h.evidencia if e.startswith("EVT")]
    assert len(conexiones) >= 8, f"Solo {len(conexiones)} conexiones en el beacon."
    assert "T1071.001" in h.mitre


# --------------------------------------------------------------------------- #
# AC4 — Persistencia (Alto)
# --------------------------------------------------------------------------- #
def test_ac4_persistencia(resultado):
    _, hallazgos, _, _ = resultado
    h = _buscar_hallazgo(
        hallazgos,
        regla="R7",
        activos=lambda v: "APP-SRV01" in v,
    )
    assert h is not None, "No se detectó la persistencia en APP-SRV01."
    assert h.criticidad == "Alto"
    assert "CORP\\helpdesk" in h.usuarios
    # La evidencia (tarea 4698 + servicio 7045) proviene de los eventos reales.
    assert {"EVT-00523", "EVT-00524"} <= set(h.evidencia)
    assert "T1053.005" in h.mitre and "T1543.003" in h.mitre
    # Masquerading detectado de forma AGNÓSTICA (nombre tipo-sistema + ubicación
    # no confiable), sin codificar los nombres del demo en la regla.
    assert "T1036" in h.mitre
    assert "masquerading" in h.justificacion.lower()


# --------------------------------------------------------------------------- #
# AC5 — Escaneo web (Medio)
# --------------------------------------------------------------------------- #
def test_ac5_escaneo_web(resultado):
    _, hallazgos, incidentes, _ = resultado
    h = _buscar_hallazgo(
        hallazgos,
        regla="R8",
        ips=lambda v: "192.0.2.91" in v,
    )
    assert h is not None, "No se detectó el escaneo web desde 192.0.2.91."
    assert h.criticidad == "Medio"
    assert "WEB-01" in h.activos
    assert "T1190" in h.mitre
    # El incidente que lo contiene debe ser Medio (no elevarse por ruido).
    inc = next(i for i in incidentes if h.id in i.hallazgos)
    assert inc.criticidad == "Medio", f"El incidente web quedó en {inc.criticidad}."


# --------------------------------------------------------------------------- #
# AC6 — Anomalías (Medio/Bajo)
# --------------------------------------------------------------------------- #
def test_ac6_anomalias(resultado):
    _, hallazgos, _, _ = resultado
    # Inconsistencia DC-01 / DC01.
    host = _buscar_hallazgo(
        hallazgos,
        regla="R9",
        activos=lambda v: "DC-01" in v and "DC01" in v,
    )
    assert host is not None, "No se detectó la inconsistencia DC-01/DC01."
    assert host.criticidad in ("Bajo", "Medio")

    # 4672 a cuentas de servicio.
    svc = _buscar_hallazgo(
        hallazgos,
        regla="R9",
        titulo=lambda t: "cuentas de servicio" in t.lower(),
    )
    assert svc is not None, "No se detectó el 4672 a cuentas de servicio."
    assert svc.criticidad in ("Bajo", "Medio")
    assert any("svc" in u.lower() or "backup" in u.lower() for u in svc.usuarios)


# --------------------------------------------------------------------------- #
# Resumen mínimo esperado
# --------------------------------------------------------------------------- #
def test_ips_externas_origen_y_destino(resultado):
    """Las IPs externas deben incluir origen Y destino/exfil (5 en total)."""
    from app.stats import calcular_estadisticas

    eventos, _, _, _ = resultado
    est = calcular_estadisticas(eventos)
    assert set(est.ips_externas_origen) == {"192.0.2.91", "198.51.100.77", "203.0.113.74"}
    assert set(est.ips_externas_destino) == {"198.51.100.88", "203.0.113.88"}
    assert len(est.ips_externas_unicas) == 5


def test_incidente_multivector(resultado):
    """El incidente de intrusión agrupa 2 ramas con entidades distintas."""
    _, _, incidentes, _ = resultado
    inc = next(i for i in incidentes if "198.51.100.77" in i.ips)
    assert inc.multi_vector, "El incidente de intrusión debería ser multi-vector."
    actores = {v.actor for v in inc.vectores}
    assert "CORP\\admin" in actores and "CORP\\backupsvc" in actores


def test_minimo_incidentes_y_criticidades(resultado):
    _, _, incidentes, _ = resultado
    assert len(incidentes) >= 6, f"Se esperaban >= 6 incidentes, hay {len(incidentes)}."
    criticidades = [i.criticidad for i in incidentes]
    assert criticidades.count("Crítico") >= 2
    assert "Alto" in criticidades
    assert "Medio" in criticidades

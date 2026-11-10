"""Pruebas de generalización y robustez (independientes del archivo de demo).

Objetivo: demostrar que las reglas son AGNÓSTICAS al contenido —detectan los
mismos patrones con IPs/usuarios/hosts/nombres completamente distintos— y que
un archivo limpio no produce falsos positivos ni errores.
"""
from __future__ import annotations

import io

import pandas as pd
import pytest

from app.detection import ejecutar_deteccion
from app.parsing import REQUIRED_COLUMNS, ParseError, load_events

# Entidades deliberadamente DISTINTAS a las del demo.
EXT_RDP = "45.76.10.10"       # atacante RDP (externa pública)
EXT_SPRAY = "185.22.33.44"    # atacante spraying
EXT_C2 = "45.76.99.99"        # C2 / beacon
EXT_WEB = "185.99.88.77"      # escáner web


def _fila(lid, ts, host, eid, user, sip, desc, dst="", cmd="",
          res="Success", sev="Informational", logsrc="Security"):
    return {
        "Log_ID": lid,
        "Timestamp": f"2025-01-15 {ts}",
        "Hostname": host,
        "Event_ID": eid,
        "User": user,
        "Source_IP": sip,
        "Destination": dst,
        "Log_Source": logsrc,
        "Event_Description": desc,
        "Process_CommandLine": cmd,
        "Result": res,
        "Severity": sev,
    }


def _xlsx(rows, sheet="SIEM Export", rename=None, extra=None):
    """Construye los bytes de un .xlsx a partir de filas (dicts).

    `rename` renombra columnas DESPUÉS de poblar los datos (para simular
    encabezados con espacios). `extra` agrega columnas irrelevantes.
    """
    df = pd.DataFrame(rows)
    for c in REQUIRED_COLUMNS:
        if c not in df.columns:
            df[c] = ""
    df = df[list(REQUIRED_COLUMNS)]
    if extra:
        for k, v in extra.items():
            df[k] = v
    if rename:
        df = df.rename(columns=rename)
    buf = io.BytesIO()
    df.to_excel(buf, sheet_name=sheet, index=False)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# (1) Archivo sintético que dispara las mismas reglas con otras entidades
# --------------------------------------------------------------------------- #
def _dataset_con_incidentes():
    r = []
    n = [0]

    def nid():
        n[0] += 1
        return f"SYN-{n[0]:04d}"

    # R1: fuerza bruta dirigida EXITOSA vía RDP (jdoe @ RDP-HOST desde EXT_RDP)
    for i, t in enumerate(["09:00:00", "09:01:00", "09:02:00", "09:03:00"]):
        r.append(_fila(nid(), t, "RDP-HOST", "4625", "ACME\\jdoe", EXT_RDP,
                       "An account failed to log on (LogonType=10; RDP)", res="Failure"))
    r.append(_fila(nid(), "09:04:00", "RDP-HOST", "4624", "ACME\\jdoe", EXT_RDP,
                   "An account was successfully logged on (LogonType=10; RDP)"))
    # R3: 4672 desde IP externa
    r.append(_fila(nid(), "09:05:00", "RDP-HOST", "4672", "ACME\\jdoe", EXT_RDP,
                   "Special privileges assigned to new logon"))
    # R4: ejecución sospechosa (PowerShell ofuscado + archivado)
    r.append(_fila(nid(), "09:06:00", "RDP-HOST", "4688", "ACME\\jdoe", EXT_RDP,
                   "New process created", cmd="powershell.exe -NoProfile -EncodedCommand AAbbCC"))
    r.append(_fila(nid(), "09:07:00", "RDP-HOST", "4688", "ACME\\jdoe", EXT_RDP,
                   "New process created", cmd="tar.exe -c -f C:\\Temp\\loot.zip C:\\data"))
    # R5: movimiento lateral (LogonType=3; source=RDP-HOST) a FILE-HOST
    r.append(_fila(nid(), "09:08:00", "FILE-HOST", "4624", "ACME\\jdoe", "10.20.0.9",
                   "An account was successfully logged on (LogonType=3; source=RDP-HOST)"))
    # R5: colección masiva (10 lecturas al mismo objetivo en ráfaga)
    for i in range(10):
        r.append(_fila(nid(), f"09:{10+i:02d}:00", "FILE-HOST", "4663", "ACME\\jdoe",
                       "10.20.0.9", "An attempt was made to access an object",
                       dst="\\\\FILE-HOST\\Projects", cmd=f"File access: Projects\\doc_{i}.docx"))
    # R6: exfiltración post-staging (salida externa tras archivar)
    r.append(_fila(nid(), "09:25:00", "RDP-HOST", "5156", "ACME\\jdoe", "10.20.0.9",
                   "Allowed outbound connection", dst=f"{EXT_C2}:443", cmd="powershell.exe",
                   logsrc="Firewall"))

    # R2: password spraying (EXT_SPRAY contra 6 cuentas en ráfaga)
    for i, u in enumerate(["ana", "beto", "caro", "dani", "eva", "fredo"]):
        r.append(_fila(nid(), f"08:{i:02d}:00", "DC-ACME", "4625", f"ACME\\{u}", EXT_SPRAY,
                       "An account failed to log on - bad password", res="Failure"))

    # R6: beaconing (12 conexiones regulares cada 30s desde WRK a EXT_C2)
    base_min = 30
    for i in range(12):
        mm = base_min + (i * 30) // 60
        ss = (i * 30) % 60
        r.append(_fila(nid(), f"10:{mm:02d}:{ss:02d}", "WRK-ACME", "PROXY_ACCESS",
                       "ACME\\user7", "10.20.5.5", "HTTPS POST outbound",
                       dst=f"{EXT_C2}:8443", res="Allowed", logsrc="Proxy"))

    # R7: persistencia con masquerading genérico (nombre tipo-sistema + ProgramData)
    r.append(_fila(nid(), "11:00:00", "APP-ACME", "4698", "ACME\\it", "10.20.1.2",
                   "A scheduled task was created",
                   cmd="TaskName=\\ACME\\WinHealthCheck; Action=powershell.exe -File C:\\ProgramData\\hc.ps1"))
    r.append(_fila(nid(), "11:01:00", "APP-ACME", "7045", "ACME\\it", "10.20.1.2",
                   "A service was installed in the system",
                   cmd="ServiceName=NetSvcHelper; ImagePath=C:\\ProgramData\\nsh.exe"))

    # R8: escaneo/ataque web (12 peticiones, códigos mixtos)
    for i in range(12):
        code = ["200", "404", "500"][i % 3]
        r.append(_fila(nid(), f"12:{i:02d}:00", "WEB-ACME", "HTTP_ACCESS", "-", EXT_WEB,
                       "HTTP request", dst="WEB-ACME:443", res=code,
                       cmd="/admin/' OR '1'='1", logsrc="IIS"))

    # R9: inconsistencia de hostname (SRV-9 vs SRV9) + 4672 a cuenta de servicio
    r.append(_fila(nid(), "07:30:00", "SRV-9", "7036", "ACME\\user8", "10.20.9.1",
                   "Service entered running state"))
    r.append(_fila(nid(), "07:31:00", "SRV9", "7036", "ACME\\user8", "10.20.9.1",
                   "Service entered running state"))
    r.append(_fila(nid(), "07:32:00", "DB-ACME", "4672", "ACME\\svc_db", "10.20.2.3",
                   "Special privileges assigned to new logon"))
    return r


@pytest.fixture(scope="module")
def sintetico():
    data = _xlsx(_dataset_con_incidentes())
    eventos = load_events(data)
    return ejecutar_deteccion(eventos)


def test_sintetico_dispara_las_mismas_reglas(sintetico):
    hallazgos, incidentes = sintetico
    assert hallazgos, "El dataset sintético no produjo hallazgos."
    reglas = {h.regla for h in hallazgos}
    # Las reglas clave deben dispararse con entidades totalmente distintas.
    for r in ["R1", "R2", "R5", "R6", "R7", "R8", "R9"]:
        assert r in reglas, f"La regla {r} no se disparó en el dataset sintético."


def test_sintetico_detecta_las_entidades_nuevas(sintetico):
    hallazgos, _ = sintetico

    def existe(regla_pred, campo, valor):
        return any(
            regla_pred(h) and valor in getattr(h, campo) for h in hallazgos
        )

    assert existe(lambda h: h.regla == "R1", "ips", EXT_RDP)
    assert existe(lambda h: h.regla == "R2", "ips", EXT_SPRAY)
    assert existe(lambda h: h.titulo.startswith("Beaconing"), "ips", EXT_C2)
    assert existe(lambda h: h.regla == "R8", "ips", EXT_WEB)
    # Persistencia con masquerading detectada por heurística genérica.
    r7 = [h for h in hallazgos if h.regla == "R7"]
    assert r7 and any("T1036" in h.mitre for h in r7)


def test_sintetico_no_filtra_iocs_del_demo(sintetico):
    """Ningún hallazgo debe contener entidades del archivo de demo."""
    hallazgos, _ = sintetico
    prohibido = ["198.51.100", "203.0.113", "192.0.2.91", "CORP\\", "FS-SRV01",
                 "APP-SRV01", "DC-01"]
    for h in hallazgos:
        blob = " ".join(h.ips + h.usuarios + h.activos + [h.titulo, h.justificacion])
        for p in prohibido:
            assert p not in blob, f"Se filtró un IoC del demo ({p}) en {h.id}."


# --------------------------------------------------------------------------- #
# (2) Archivo limpio: cero hallazgos, sin crashear ni inventar
# --------------------------------------------------------------------------- #
def _dataset_limpio():
    r = []
    base = [
        ("07:00:00", "WKS-01", "4624", "ACME\\ana", "10.20.0.11", "An account was successfully logged on"),
        ("07:05:00", "WKS-02", "4634", "ACME\\beto", "10.20.0.12", "An account was logged off"),
        ("07:10:00", "WKS-03", "7036", "ACME\\caro", "10.20.0.13", "Service entered running state"),
        ("07:15:00", "WKS-01", "4688", "ACME\\ana", "10.20.0.11", "A new process has been created"),
        ("07:20:00", "WKS-02", "4624", "ACME\\beto", "10.20.0.12", "An account was successfully logged on"),
        # Un par de fallos AISLADOS (no llegan al umbral de fuerza bruta/spray).
        ("07:25:00", "WKS-03", "4625", "ACME\\caro", "10.20.0.13", "An account failed to log on"),
        ("07:40:00", "WKS-03", "4625", "ACME\\dani", "10.20.0.14", "An account failed to log on"),
    ]
    for i, (ts, host, eid, user, ip, desc) in enumerate(base, 1):
        r.append(_fila(f"OK-{i:03d}", ts, host, eid, user, ip, desc,
                       cmd="explorer.exe" if eid == "4688" else "",
                       res="Failure" if eid == "4625" else "Success"))
    return r


def test_archivo_limpio_cero_hallazgos():
    data = _xlsx(_dataset_limpio())
    eventos = load_events(data)
    hallazgos, incidentes = ejecutar_deteccion(eventos)
    assert hallazgos == [], f"Se inventaron hallazgos en un archivo limpio: {[h.titulo for h in hallazgos]}"
    assert incidentes == []


# --------------------------------------------------------------------------- #
# (3) Robustez del parser
# --------------------------------------------------------------------------- #
def test_parser_columnas_faltantes_error_claro():
    df = pd.DataFrame([{"Log_ID": "1", "Timestamp": "2025-01-15 00:00:00"}])
    buf = io.BytesIO()
    df.to_excel(buf, sheet_name="SIEM Export", index=False)
    with pytest.raises(ParseError) as exc:
        load_events(buf.getvalue())
    assert "Faltan columnas" in str(exc.value)


def test_parser_tolera_columnas_extra_y_encabezados_con_espacios():
    rows = _dataset_limpio()
    # Encabezados con espacios alrededor + columna extra irrelevante.
    data = _xlsx(
        rows,
        rename={"Log_ID": " Log_ID ", "Hostname": "Hostname ", "Event_ID": " Event_ID"},
        extra={"ColumnaExtra": "ignorar"},
    )
    eventos = load_events(data)
    assert len(eventos) == len(rows)
    assert eventos[0].log_id.startswith("OK-")


def test_parser_tolera_celdas_vacias_y_pocas_filas():
    rows = [
        _fila("A-1", "08:00:00", "H1", "4624", "u1", "10.0.0.1",
              "logon", dst="", cmd=""),  # Destination y CommandLine vacíos
    ]
    eventos = load_events(_xlsx(rows))
    assert len(eventos) == 1
    assert eventos[0].destination is None
    assert eventos[0].process_commandline is None


def test_parser_event_id_numerico_y_texto():
    rows = [
        _fila("A-1", "08:00:00", "H1", "4624", "u1", "10.0.0.1", "logon"),
        _fila("A-2", "08:01:00", "H1", "PROXY_ACCESS", "u1", "10.0.0.1", "post", dst="1.2.3.4:443"),
    ]
    eventos = load_events(_xlsx(rows))
    ids = {e.event_id for e in eventos}
    assert "4624" in ids and "PROXY_ACCESS" in ids


def test_parser_detecta_ip_externa_rfc1918():
    rows = [
        _fila("A-1", "08:00:00", "H1", "4624", "u1", "10.20.30.40", "interna"),
        _fila("A-2", "08:01:00", "H1", "4624", "u2", "172.16.5.5", "interna"),
        _fila("A-3", "08:02:00", "H1", "4624", "u3", "192.168.1.1", "interna"),
        _fila("A-4", "08:03:00", "H1", "4624", "u4", "8.8.8.8", "externa"),
    ]
    eventos = load_events(_xlsx(rows))
    por_ip = {e.source_ip: e.ip_externa for e in eventos}
    assert por_ip["10.20.30.40"] is False
    assert por_ip["172.16.5.5"] is False
    assert por_ip["192.168.1.1"] is False
    assert por_ip["8.8.8.8"] is True

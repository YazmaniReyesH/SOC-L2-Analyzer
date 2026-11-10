"""Reglas de detección deterministas R1–R9.

Cada regla recibe la lista de eventos normalizados y devuelve `Finding`s.
TODO hallazgo lleva su `evidencia` (Log_IDs); nunca se afirma nada sin evidencia.
Los umbrales viven en `app.constants`.
"""
from __future__ import annotations

import re
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

from .. import constants as C
from ..models import Acciones, Finding, LogEvent

# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def _texto(e: LogEvent) -> str:
    return " ".join(
        filter(None, [e.event_description, e.process_commandline, e.destination])
    )


def _rango(evs: list[LogEvent]) -> tuple[datetime | None, datetime | None]:
    if not evs:
        return None, None
    ts = [e.timestamp for e in evs]
    return min(ts), max(ts)


def _logon_type(desc: str) -> int | None:
    m = re.search(r"LogonType=(\d+)", desc)
    return int(m.group(1)) if m else None


def _source_host(desc: str) -> str | None:
    m = re.search(r"source=([A-Za-z0-9._\-]+)", desc)
    return m.group(1) if m else None


def _es_cuenta_servicio(user: str) -> bool:
    u = (user or "").lower()
    return any(re.search(p, u) for p in C.PATRONES_CUENTA_SERVICIO)


def _cluster_en_ventana(
    evs: list[LogEvent], ventana_min: int, minimo: int
) -> list[LogEvent]:
    """Devuelve el subconjunto más denso dentro de una ventana temporal."""
    evs = sorted(evs, key=lambda e: e.timestamp)
    mejor: list[LogEvent] = []
    i = 0
    for j in range(len(evs)):
        while evs[j].timestamp - evs[i].timestamp > timedelta(minutes=ventana_min):
            i += 1
        if j - i + 1 > len(mejor):
            mejor = evs[i : j + 1]
    return mejor if len(mejor) >= minimo else []


def _dst_ip_puerto(dest: str | None) -> tuple[str, str] | None:
    if not dest:
        return None
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", dest.strip())
    if m:
        return m.group(1), m.group(2)
    return None


_contador: dict[str, int] = defaultdict(int)


def _nuevo_id(regla: str) -> str:
    _contador[regla] += 1
    return f"{regla}-{_contador[regla]}"


def reset_contadores() -> None:
    _contador.clear()


def _mk(
    regla: str,
    titulo: str,
    categoria: str,
    criticidad: str,
    justificacion: str,
    evidencia: list[LogEvent],
    *,
    mitre: list[str],
    impacto: str,
    acciones: Acciones,
    activos: list[str] | None = None,
    ips: list[str] | None = None,
    usuarios: list[str] | None = None,
) -> Finding:
    ini, fin = _rango(evidencia)
    ev_ids = sorted({e.log_id for e in evidencia})
    act = activos if activos is not None else sorted({e.hostname for e in evidencia if e.hostname})
    ip_set = ips if ips is not None else sorted({e.source_ip for e in evidencia if e.source_ip})
    usr = usuarios if usuarios is not None else sorted({e.user for e in evidencia if e.user and e.user != "-"})
    return Finding(
        id=_nuevo_id(regla),
        regla=regla,
        titulo=titulo,
        categoria=categoria,
        criticidad=criticidad,  # type: ignore[arg-type]
        justificacion=justificacion,
        evidencia=ev_ids,
        activos=act,
        ips=ip_set,
        usuarios=usr,
        mitre=mitre,
        impacto=impacto,
        acciones=acciones,
        inicio=ini,
        fin=fin,
    )


# --------------------------------------------------------------------------- #
# Spray IPs (compartido por R1 y R2)
# --------------------------------------------------------------------------- #
def _spray_burst(evs: list[LogEvent], ventana_min: int) -> tuple[list[LogEvent], int]:
    """Ventana (ráfaga) con el mayor nº de usuarios distintos."""
    evs = sorted(evs, key=lambda e: e.timestamp)
    mejor: list[LogEvent] = []
    mejor_users = 0
    i = 0
    for j in range(len(evs)):
        while evs[j].timestamp - evs[i].timestamp > timedelta(minutes=ventana_min):
            i += 1
        win = evs[i : j + 1]
        u = len({e.user for e in win})
        if u > mejor_users:
            mejor_users = u
            mejor = win
    return mejor, mejor_users


def _ips_spraying(eventos: list[LogEvent]) -> set[str]:
    por_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id == "4625" and e.source_ip:
            por_ip[e.source_ip].append(e)
    spray = set()
    for ip, evs in por_ip.items():
        _, n = _spray_burst(evs, C.SPRAY_VENTANA_MIN)
        if n >= C.SPRAY_MIN_USUARIOS:
            spray.add(ip)
    return spray


# --------------------------------------------------------------------------- #
# R1 — Fuerza bruta dirigida
# --------------------------------------------------------------------------- #
def r1_fuerza_bruta(eventos: list[LogEvent]) -> list[Finding]:
    spray = _ips_spraying(eventos)
    fallidos: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    exitos: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id == "4625" and e.source_ip and e.source_ip not in spray:
            fallidos[(e.user, e.source_ip)].append(e)
        elif e.event_id == "4624":
            exitos[(e.user, e.source_ip)].append(e)

    findings: list[Finding] = []
    for (user, ip), evs in fallidos.items():
        cluster = _cluster_en_ventana(evs, C.BRUTE_FORCE_VENTANA_MIN, C.BRUTE_FORCE_MIN_EVENTOS)
        if not cluster:
            continue
        externa = cluster[0].ip_externa
        rdp = any(_logon_type(e.event_description) == 10 for e in cluster)
        # ¿Hubo un 4624 exitoso durante o justo después del cluster?
        exito_ev = None
        for s in exitos.get((user, ip), []):
            if cluster[0].timestamp <= s.timestamp <= cluster[-1].timestamp + timedelta(
                minutes=C.BRUTE_FORCE_EXITO_VENTANA_MIN
            ):
                exito_ev = s
                break

        evidencia = list(cluster) + ([exito_ev] if exito_ev else [])
        mitre = ["T1110.001"]
        if rdp:
            mitre.append("T1021.001")
        if externa:
            mitre.append("T1133")
        if exito_ev:
            mitre.append("T1078")

        if exito_ev:
            criticidad = "Crítico"
            estado = "EXITOSA"
        else:
            criticidad = "Alto"
            estado = "sin éxito confirmado"

        canal = " vía RDP (LogonType=10)" if rdp else ""
        just = (
            f"Se observaron {len(cluster)} intentos de inicio de sesión fallidos (4625) "
            f"contra la cuenta {user} desde {ip}{canal} dentro de una ventana de "
            f"{C.BRUTE_FORCE_VENTANA_MIN} min."
        )
        if exito_ev:
            just += (
                f" Posteriormente se registró un inicio de sesión EXITOSO (4624, "
                f"{exito_ev.log_id}), confirmando el compromiso de la credencial."
            )
        findings.append(
            _mk(
                "R1",
                f"Fuerza bruta dirigida {estado} contra {user} desde {ip}",
                "Acceso inicial",
                criticidad,
                just,
                evidencia,
                mitre=mitre,
                impacto=(
                    "Compromiso de credenciales y acceso no autorizado al host objetivo."
                    if exito_ev
                    else "Riesgo de compromiso de credenciales por adivinación de contraseñas."
                ),
                acciones=Acciones(
                    investigar=[
                        f"Revisar toda la actividad de {user} y de la IP {ip}.",
                        "Confirmar si el 4624 posterior corresponde al atacante.",
                    ],
                    contener=[
                        f"Bloquear la IP {ip} en el perímetro.",
                        f"Deshabilitar/forzar cambio de contraseña de {user}.",
                    ],
                    remediar=[
                        "Aplicar bloqueo de cuentas y MFA.",
                        "Restringir RDP expuesto a Internet (VPN/jump host).",
                    ],
                ),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# R2 — Password spraying
# --------------------------------------------------------------------------- #
def r2_password_spraying(eventos: list[LogEvent]) -> list[Finding]:
    por_ip_fallos: dict[str, list[LogEvent]] = defaultdict(list)
    por_ip_exitos: dict[str, list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id == "4625" and e.source_ip:
            por_ip_fallos[e.source_ip].append(e)
        elif e.event_id == "4624" and e.source_ip:
            por_ip_exitos[e.source_ip].append(e)

    findings: list[Finding] = []
    for ip, evs in por_ip_fallos.items():
        burst, n_users = _spray_burst(evs, C.SPRAY_VENTANA_MIN)
        if n_users < C.SPRAY_MIN_USUARIOS:
            continue
        usuarios = {e.user for e in burst}
        exitos = [s for s in por_ip_exitos.get(ip, []) if s.user in usuarios]
        # Evidencia: toda la campaña desde esa IP (no solo la ráfaga mínima).
        evidencia = list(evs) + exitos
        mitre = ["T1110.003"]
        just = (
            f"La IP {ip} generó intentos de autenticación fallidos (4625) contra "
            f"{len(usuarios)} cuentas distintas, patrón característico de password spraying."
        )
        impacto = "Posible compromiso de múltiples cuentas mediante contraseñas comunes."
        if exitos:
            mitre.append("T1078")
            cuentas = ", ".join(sorted({s.user for s in exitos}))
            just += f" Se observó al menos un inicio de sesión EXITOSO para: {cuentas}."
            impacto = f"Compromiso confirmado de cuenta(s): {cuentas}."
        findings.append(
            _mk(
                "R2",
                f"Password spraying desde {ip} contra {len(usuarios)} cuentas",
                "Acceso inicial",
                "Alto",
                just,
                evidencia,
                mitre=mitre,
                impacto=impacto,
                acciones=Acciones(
                    investigar=[
                        f"Identificar todas las cuentas objetivo de {ip}.",
                        "Verificar inicios de sesión exitosos subsecuentes.",
                    ],
                    contener=[f"Bloquear la IP {ip}.", "Resetear cuentas comprometidas."],
                    remediar=[
                        "Implementar MFA y políticas de contraseñas robustas.",
                        "Habilitar detección de spraying en el IdP.",
                    ],
                ),
                ips=[ip],
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# R3 — Escalamiento de privilegios
# --------------------------------------------------------------------------- #
def r3_escalamiento(eventos: list[LogEvent]) -> list[Finding]:
    f4672 = [e for e in eventos if e.event_id == "4672"]
    # Index de 4624 por (user, ip) para ligar el logon previo.
    logons: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id == "4624":
            logons[(e.user, e.source_ip)].append(e)

    findings: list[Finding] = []
    for e in f4672:
        # R3 se enfoca en 4672 asociados a logon de IP externa.
        if not e.ip_externa:
            continue
        previo = [
            s for s in logons.get((e.user, e.source_ip), []) if s.timestamp <= e.timestamp
        ]
        evidencia = ([previo[-1]] if previo else []) + [e]
        findings.append(
            _mk(
                "R3",
                f"Escalamiento de privilegios de {e.user} desde IP externa {e.source_ip}",
                "Escalamiento de privilegios",
                "Alto",
                (
                    f"Se asignaron privilegios especiales (4672) a {e.user} en {e.hostname} "
                    f"asociados a un inicio de sesión desde la IP externa {e.source_ip}. "
                    "La asignación de privilegios a un acceso de origen externo es anómala."
                ),
                evidencia,
                mitre=["T1068", "T1078", "T1134"],
                impacto="El atacante obtiene privilegios elevados en el host comprometido.",
                acciones=Acciones(
                    investigar=[
                        f"Revisar las acciones realizadas por {e.user} tras el 4672.",
                        "Determinar qué privilegios se asignaron.",
                    ],
                    contener=[
                        f"Revocar la sesión de {e.user} en {e.hostname}.",
                        f"Bloquear {e.source_ip}.",
                    ],
                    remediar=[
                        "Aplicar principio de mínimo privilegio.",
                        "Monitorear asignaciones de privilegios especiales.",
                    ],
                ),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# R4 — Ejecución sospechosa
# --------------------------------------------------------------------------- #
def r4_ejecucion_sospechosa(eventos: list[LogEvent]) -> list[Finding]:
    patrones = [re.compile(p, re.IGNORECASE) for p in C.PATRONES_EJECUCION_SOSPECHOSA]
    por_entidad: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id not in ("4688", "4104"):
            continue
        # Las ejecuciones en el contexto del worker web (IIS APPPOOL) las cubre R8.
        if e.user.upper().startswith("IIS APPPOOL"):
            continue
        texto = _texto(e)
        if any(p.search(texto) for p in patrones):
            por_entidad[(e.hostname, e.user)].append(e)

    findings: list[Finding] = []
    for (host, user), evs in por_entidad.items():
        muestras = "; ".join(
            sorted({(e.process_commandline or e.event_description)[:80] for e in evs})
        )[:400]
        findings.append(
            _mk(
                "R4",
                f"Ejecución sospechosa en {host} por {user}",
                "Ejecución",
                "Alto",
                (
                    f"Se detectaron {len(evs)} procesos/scripts sospechosos en {host} "
                    f"ejecutados por {user} (PowerShell ofuscado, reconocimiento o "
                    f"herramientas de archivado). Muestras: {muestras}"
                ),
                evs,
                mitre=["T1059.001", "T1027", "T1087", "T1135"],
                impacto="Ejecución de código para reconocimiento, recolección o staging de datos.",
                acciones=Acciones(
                    investigar=[
                        f"Analizar los procesos ejecutados en {host}.",
                        "Decodificar los comandos PowerShell ofuscados.",
                    ],
                    contener=[f"Aislar {host} de la red."],
                    remediar=[
                        "Habilitar ScriptBlock Logging y AMSI.",
                        "Aplicar listas de permitidos de aplicaciones.",
                    ],
                ),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# R5 — Movimiento lateral y colección
# --------------------------------------------------------------------------- #
def r5_movimiento_lateral(eventos: list[LogEvent]) -> list[Finding]:
    hosts = {e.hostname for e in eventos if e.hostname}
    findings: list[Finding] = []

    # --- Parte A: logon LogonType=3 con source= host interno ya involucrado ---
    lateral_por_user: dict[str, list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id not in ("4624", "4625"):
            continue
        src = _source_host(e.event_description)
        if src and src in hosts and _logon_type(e.event_description) == 3:
            lateral_por_user[e.user].append(e)

    for user, evs in lateral_por_user.items():
        destinos = {e.hostname for e in evs}
        # Accesos a shares sensibles por el mismo usuario (5140/5145).
        shares = [
            e
            for e in eventos
            if e.user == user
            and e.event_id in ("5140", "5145")
            and any(s.lower() in _texto(e).lower() for s in C.SHARES_SENSIBLES)
        ]
        evidencia = evs + shares
        archivos = sorted(
            {
                m.group(0)
                for e in shares
                for m in [re.search(r"[A-Za-z]+\\[^\s]+\.(xlsx|docx|zip|7z|csv|pdf)", _texto(e))]
                if m
            }
        )
        det_arch = f" Archivos sensibles accedidos: {', '.join(archivos)}." if archivos else ""
        findings.append(
            _mk(
                "R5",
                f"Movimiento lateral de {user} hacia {', '.join(sorted(destinos))}",
                "Movimiento lateral",
                "Alto",
                (
                    f"La cuenta {user} autenticó con LogonType=3 hacia "
                    f"{', '.join(sorted(destinos))} desde un host interno ya involucrado "
                    f"y accedió a shares sensibles ({', '.join(C.SHARES_SENSIBLES)})." + det_arch
                ),
                evidencia,
                mitre=["T1021.002", "T1039", "T1570"],
                impacto="Propagación dentro de la red y acceso a información sensible.",
                acciones=Acciones(
                    investigar=[
                        f"Trazar la ruta de movimiento de {user}.",
                        "Identificar qué archivos fueron accedidos/copiados.",
                    ],
                    contener=[
                        f"Deshabilitar {user}.",
                        "Aislar los hosts de origen y destino.",
                    ],
                    remediar=[
                        "Segmentar la red y restringir SMB lateral.",
                        "Revisar permisos de los shares sensibles.",
                    ],
                ),
            )
        )

    # --- Parte B: colección masiva de archivos en un share sensible ---
    coleccion: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id in ("4663", "5145") and any(
            s.lower() in _texto(e).lower() for s in C.SHARES_SENSIBLES
        ):
            coleccion[(e.user, e.hostname)].append(e)

    for (user, host), evs in coleccion.items():
        if len(evs) < C.COLECCION_MIN_ACCESOS:
            continue
        findings.append(
            _mk(
                "R5",
                f"Colección masiva de archivos sensibles por {user} en {host}",
                "Colección",
                "Alto",
                (
                    f"Se registraron {len(evs)} accesos a archivos de un share sensible "
                    f"({', '.join(C.SHARES_SENSIBLES)}) por {user} en {host}, consistente "
                    "con recolección de datos previa a exfiltración."
                ),
                evs,
                mitre=["T1039", "T1005", "T1560.001"],
                impacto="Recolección de datos sensibles para su posterior exfiltración.",
                acciones=Acciones(
                    investigar=[f"Determinar el alcance de los datos accedidos por {user}."],
                    contener=[f"Revocar el acceso de {user} a los shares sensibles."],
                    remediar=["Implementar DLP y auditoría de acceso a datos críticos."],
                ),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# R6 — Exfiltración / C2 (beaconing y exfil post-staging)
# --------------------------------------------------------------------------- #
def _es_staging(e: LogEvent) -> bool:
    return e.event_id == "4688" and bool(
        re.search(r"tar\.exe|\.zip|\.7z|archive|staging", _texto(e), re.IGNORECASE)
    )


def r6_exfiltracion(eventos: list[LogEvent]) -> list[Finding]:
    findings: list[Finding] = []

    # Conexiones salientes a IP externa (5156 o PROXY_ACCESS).
    salientes = []
    for e in eventos:
        if e.event_id not in ("5156", "PROXY_ACCESS"):
            continue
        dp = _dst_ip_puerto(e.destination)
        if dp and _dest_externa(dp[0]):
            salientes.append((e, dp))

    # --- Beaconing: >=N conexiones al mismo IP:puerto con intervalos regulares ---
    usados: set[str] = set()
    por_dst: dict[str, list[LogEvent]] = defaultdict(list)
    for e, (ip, puerto) in salientes:
        por_dst[f"{ip}:{puerto}"].append(e)

    for destino, evs in por_dst.items():
        if len(evs) < C.BEACON_MIN_CONEXIONES:
            continue
        evs = sorted(evs, key=lambda x: x.timestamp)
        deltas = [
            (evs[i + 1].timestamp - evs[i].timestamp).total_seconds()
            for i in range(len(evs) - 1)
        ]
        media = statistics.mean(deltas) if deltas else 0
        cv = (statistics.pstdev(deltas) / media) if media > 0 else 1.0
        if cv > C.BEACON_TOLERANCIA_JITTER:
            continue  # intervalos no regulares -> no es beaconing claro
        # Staging previo relacionado (mismo usuario) para enriquecer la evidencia.
        usuarios = {e.user for e in evs}
        staging = [
            s
            for s in eventos
            if _es_staging(s)
            and s.user in usuarios
            and s.timestamp <= evs[0].timestamp
            and evs[0].timestamp - s.timestamp
            <= timedelta(minutes=C.EXFIL_STAGING_VENTANA_MIN)
        ]
        for e in evs:
            usados.add(e.log_id)
        dst_ip = destino.split(":")[0]
        ips_fh = sorted({e.source_ip for e in evs if e.source_ip} | {dst_ip})
        findings.append(
            _mk(
                "R6",
                f"Beaconing/C2 hacia {destino} ({len(evs)} conexiones regulares)",
                "Exfiltración",
                "Crítico",
                (
                    f"Se detectaron {len(evs)} conexiones salientes a {destino} con "
                    f"intervalos regulares (~{media:.0f}s, jitter {cv:.0%}), patrón de "
                    "beaconing hacia infraestructura de comando y control."
                    + (
                        f" Precedido por archivado de datos ({staging[0].log_id})."
                        if staging
                        else ""
                    )
                ),
                evs + staging,
                mitre=["T1071.001", "T1041", "T1567", "T1560.001"],
                impacto="Canal de C2 activo y probable exfiltración de datos recolectados.",
                acciones=Acciones(
                    investigar=[
                        f"Analizar el volumen de datos enviados a {destino}.",
                        "Identificar el proceso/beacon responsable.",
                    ],
                    contener=[
                        f"Bloquear {destino} en el firewall/proxy.",
                        "Aislar el host de origen.",
                    ],
                    remediar=[
                        "Erradicar el malware/beacon.",
                        "Revisar reglas de egreso y DNS.",
                    ],
                ),
                ips=ips_fh,
            )
        )

    # --- Exfil post-staging: salida externa precedida por archivado (no beacon) ---
    por_user: dict[str, list[LogEvent]] = defaultdict(list)
    for e, _dp in salientes:
        if e.log_id in usados:
            continue
        por_user[e.user].append(e)

    for user, evs in por_user.items():
        staging = [
            s
            for s in eventos
            if _es_staging(s)
            and s.user == user
            and any(
                0 <= (out.timestamp - s.timestamp).total_seconds()
                <= C.EXFIL_STAGING_VENTANA_MIN * 60
                for out in evs
            )
        ]
        if not staging:
            continue
        destinos = sorted({e.destination for e in evs if e.destination})
        dst_ips = sorted({d.split(":")[0] for d in destinos})
        ips_fh = sorted({e.source_ip for e in evs if e.source_ip} | set(dst_ips))
        findings.append(
            _mk(
                "R6",
                f"Exfiltración de datos por {user} hacia {', '.join(destinos)}",
                "Exfiltración",
                "Crítico",
                (
                    f"La cuenta {user} realizó conexiones salientes a {', '.join(destinos)} "
                    f"poco después de archivar datos localmente ({staging[0].process_commandline}), "
                    "patrón de exfiltración tras staging."
                ),
                evs + staging,
                mitre=["T1041", "T1567", "T1560.001"],
                impacto="Fuga de información sensible hacia infraestructura controlada por el atacante.",
                acciones=Acciones(
                    investigar=[
                        "Cuantificar los datos exfiltrados.",
                        f"Revisar el archivo de staging creado por {user}.",
                    ],
                    contener=[
                        f"Bloquear los destinos {', '.join(destinos)}.",
                        f"Suspender la cuenta {user}.",
                    ],
                    remediar=[
                        "Notificar a legal/cumplimiento por la fuga de datos.",
                        "Implementar DLP de egreso.",
                    ],
                ),
                ips=ips_fh,
            )
        )
    return findings


def _dest_externa(ip: str) -> bool:
    from ..parsing import is_external_ip

    return is_external_ip(ip)


# --------------------------------------------------------------------------- #
# R7 — Persistencia
# --------------------------------------------------------------------------- #
def r7_persistencia(eventos: list[LogEvent]) -> list[Finding]:
    por_host: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id in ("4698", "7045"):
            por_host[(e.hostname, e.user)].append(e)

    findings: list[Finding] = []
    for (host, user), evs in por_host.items():
        texto = " ".join(_texto(e) for e in evs)
        masquerading = [n for n in C.NOMBRES_MASQUERADING if n.lower() in texto.lower()]
        programdata = "C:\\ProgramData" in texto
        mitre = ["T1053.005", "T1543.003"]
        if masquerading:
            mitre.append("T1036")
        tipos = []
        if any(e.event_id == "4698" for e in evs):
            tipos.append("tarea programada")
        if any(e.event_id == "7045" for e in evs):
            tipos.append("servicio")
        just = (
            f"Se estableció persistencia en {host} por {user} mediante "
            f"{' y '.join(tipos)}."
        )
        if masquerading:
            just += f" Los nombres imitan componentes de Windows ({', '.join(sorted(set(masquerading)))}) — masquerading."
        if programdata:
            just += " Los binarios/scripts residen en C:\\ProgramData (ubicación anómala)."
        findings.append(
            _mk(
                "R7",
                f"Persistencia establecida en {host} por {user}",
                "Persistencia",
                "Alto",
                just,
                evs,
                mitre=mitre,
                impacto="El atacante mantiene acceso persistente al host tras reinicios.",
                acciones=Acciones(
                    investigar=[
                        f"Analizar la tarea/servicio y su binario en {host}.",
                        "Buscar el mismo mecanismo en otros hosts.",
                    ],
                    contener=[
                        "Eliminar la tarea programada y el servicio malicioso.",
                        f"Aislar {host}.",
                    ],
                    remediar=[
                        "Eliminar binarios en C:\\ProgramData.",
                        "Monitorear creación de tareas/servicios (4698/7045).",
                    ],
                ),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# R8 — Escaneo / ataque web
# --------------------------------------------------------------------------- #
def r8_ataque_web(eventos: list[LogEvent]) -> list[Finding]:
    por_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in eventos:
        if e.event_id == "HTTP_ACCESS" and e.ip_externa:
            por_ip[e.source_ip].append(e)

    findings: list[Finding] = []
    for ip, evs in por_ip.items():
        codigos = {e.result for e in evs}
        if len(evs) < C.WEB_SCAN_MIN_PETICIONES or len(codigos) < C.WEB_SCAN_MIN_CODIGOS:
            continue
        objetivos = sorted({e.hostname for e in evs})
        # Posible ejecución vía webshell en el mismo objetivo desde la misma IP.
        webshell = [
            e
            for e in eventos
            if e.event_id == "4688"
            and e.source_ip == ip
            and e.hostname in objetivos
        ]
        rutas = sorted({e.process_commandline for e in evs if e.process_commandline})[:6]
        findings.append(
            _mk(
                "R8",
                f"Escaneo/ataque web desde {ip} contra {', '.join(objetivos)}",
                "Reconocimiento",
                "Medio",
                (
                    f"La IP externa {ip} generó {len(evs)} peticiones HTTP contra "
                    f"{', '.join(objetivos)} con códigos de estado mixtos "
                    f"({', '.join(sorted(codigos))}), consistente con escaneo/fuzzing. "
                    f"Rutas sospechosas: {', '.join(rutas)}."
                    + (
                        f" Se observó ejecución de proceso en el servidor web ({webshell[0].log_id}), posible webshell."
                        if webshell
                        else ""
                    )
                ),
                evs + webshell,
                mitre=["T1595", "T1190"],
                impacto="Reconocimiento de la aplicación web y posible explotación/webshell.",
                acciones=Acciones(
                    investigar=[
                        f"Revisar los logs del servidor web para {ip}.",
                        "Verificar si alguna petición tuvo éxito (200) en rutas sensibles.",
                    ],
                    contener=[f"Bloquear {ip} en el WAF/firewall."],
                    remediar=[
                        "Aplicar parches a la aplicación web.",
                        "Desplegar/ajustar reglas de WAF.",
                    ],
                ),
                ips=[ip],
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# R9 — Anomalías
# --------------------------------------------------------------------------- #
def _normaliza_host(h: str) -> str:
    return re.sub(r"[^a-z0-9]", "", h.lower())


def r9_anomalias(eventos: list[LogEvent]) -> list[Finding]:
    findings: list[Finding] = []

    # --- Inconsistencia de hostnames (p. ej. DC-01 vs DC01) ---
    variantes: dict[str, set[str]] = defaultdict(set)
    for e in eventos:
        if e.hostname:
            variantes[_normaliza_host(e.hostname)].add(e.hostname)
    for norm, raws in variantes.items():
        if len(raws) < 2:
            continue
        evid = []
        for raw in raws:
            ej = next((e for e in eventos if e.hostname == raw), None)
            if ej:
                evid.append(ej)
        findings.append(
            _mk(
                "R9",
                f"Inconsistencia de nomenclatura de host: {' / '.join(sorted(raws))}",
                "Anomalía",
                "Bajo",
                (
                    f"Se observan variantes del mismo host ({' / '.join(sorted(raws))}), "
                    "lo que puede indicar un activo mal inventariado o suplantación de host."
                ),
                evid,
                mitre=["T1036"],
                impacto="Dificulta la atribución y correlación; posible host no autorizado.",
                acciones=Acciones(
                    investigar=["Verificar en el CMDB cuál es el nombre correcto del host."],
                    contener=[],
                    remediar=["Estandarizar la nomenclatura de hosts y el inventario."],
                ),
                activos=sorted(raws),
            )
        )

    # --- Uso anómalo de cuentas de servicio con privilegios (4672) ---
    svc = [e for e in eventos if e.event_id == "4672" and _es_cuenta_servicio(e.user)]
    if svc:
        findings.append(
            _mk(
                "R9",
                "Asignación de privilegios especiales a cuentas de servicio",
                "Anomalía",
                "Medio",
                (
                    f"Se asignaron privilegios especiales (4672) a cuentas de servicio "
                    f"({', '.join(sorted({e.user for e in svc}))}). Las cuentas de servicio "
                    "no deberían requerir privilegios administrativos interactivos."
                ),
                svc,
                mitre=["T1078.004"],
                impacto="Una cuenta de servicio comprometida con privilegios amplía el impacto.",
                acciones=Acciones(
                    investigar=[
                        "Revisar por qué las cuentas de servicio reciben privilegios especiales.",
                    ],
                    contener=[],
                    remediar=[
                        "Aplicar mínimo privilegio a cuentas de servicio.",
                        "Usar gMSA y restringir su logon.",
                    ],
                ),
            )
        )
    return findings


# Orden canónico de ejecución de reglas.
REGLAS = [
    r1_fuerza_bruta,
    r2_password_spraying,
    r3_escalamiento,
    r4_ejecucion_sospechosa,
    r5_movimiento_lateral,
    r6_exfiltracion,
    r7_persistencia,
    r8_ataque_web,
    r9_anomalias,
]

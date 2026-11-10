"""Umbrales y constantes configurables del motor de detección.

Centralizados aquí para poder ajustarlos sin tocar la lógica de las reglas.
"""
from __future__ import annotations

# --- R1: Fuerza bruta dirigida ---
BRUTE_FORCE_MIN_EVENTOS = 3  # nº mínimo de 4625 (mismo User+IP)
BRUTE_FORCE_VENTANA_MIN = 10  # ventana en minutos
BRUTE_FORCE_EXITO_VENTANA_MIN = 15  # ventana para buscar el 4624 posterior

# --- R2: Password spraying ---
SPRAY_MIN_USUARIOS = 5  # nº mínimo de usuarios distintos desde una IP
SPRAY_VENTANA_MIN = 15  # los usuarios distintos deben caer en esta ventana (ráfaga)

# --- R6: Exfiltración / C2 ---
BEACON_MIN_CONEXIONES = 8  # nº mínimo de conexiones al mismo IP:puerto
BEACON_TOLERANCIA_JITTER = 0.35  # coef. de variación máx. de los intervalos
EXFIL_STAGING_VENTANA_MIN = 60  # ventana para ligar archivado -> salida

# --- R8: Escaneo / ataque web ---
WEB_SCAN_MIN_PETICIONES = 8  # ráfaga mínima de peticiones HTTP
WEB_SCAN_MIN_CODIGOS = 2  # nº mínimo de códigos de estado distintos

# --- Colección masiva (R5) ---
COLECCION_MIN_ACCESOS = 8  # accesos a archivos de un share sensible

# --- Correlación de incidentes ---
CORRELACION_VENTANA_MIN = 30  # máx. separación temporal para unir hallazgos

# --- Catálogos ---
SHARES_SENSIBLES = ["Finance", "Legal"]

# Patrones de command line / descripción sospechosos (R4).
PATRONES_EJECUCION_SOSPECHOSA = [
    r"-EncodedCommand",
    r"-NoProfile",
    r"net\.exe\s+view",
    r"tar\.exe",
    r"\b\w+\.(zip|7z)\b",
    r"C:\\Temp\\",
    r"C:\\ProgramData\\[^\s]+\.(ps1|exe)",
    r"Get-LocalGroupMember",
    r"Get-SmbShare",
    r"whoami",
]

# Nombres que imitan componentes de Windows (R7 - Masquerading).
NOMBRES_MASQUERADING = [
    "UpdateCheck",
    "WinUpdateHelper",
    "wuhelper",
    "updatecheck",
    "svchost",
    "WindowsUpdate",
]

# Prefijos/patrones de cuentas de servicio (R3/R9).
PATRONES_CUENTA_SERVICIO = [r"svc[_-]", r"backup", r"service", r"\$$"]

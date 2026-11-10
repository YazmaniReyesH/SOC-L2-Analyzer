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
COLECCION_MIN_ACCESOS = 8  # accesos a archivos del mismo destino por un usuario
COLECCION_VENTANA_MIN = 15  # dentro de esta ventana (ráfaga de lectura)

# --- Correlación de incidentes ---
CORRELACION_VENTANA_MIN = 30  # máx. separación temporal para unir hallazgos

# --- Política de la organización (NO son IoCs del demo) ---
# Nombres de shares considerados sensibles/críticos por la organización.
# Es configuración de política; R5 detecta la colección masiva de forma
# agnóstica (por volumen+ventana) y SOLO usa esta lista para ELEVAR la
# criticidad/justificación si el objetivo coincide. Ajusta a tu entorno.
SHARES_SENSIBLES = ["Finance", "Legal", "HR", "Confidential", "Finanzas", "Legal"]

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

# R7 - Masquerading (AGNÓSTICO, sin nombres del demo).
# Se marca masquerading cuando el nombre de la tarea/servicio USA tokens
# genéricos que imitan componentes del SO *Y* el binario reside en una
# ubicación no confiable. No se codifican nombres concretos.
TOKENS_NOMBRE_SISTEMA = [
    r"update",
    r"win(dows)?",
    r"svc",
    r"host",
    r"micro\w*soft",
    r"defender",
    r"secur",
    r"helper",
    r"service",
    r"system",
    r"driver",
]

# Ubicaciones de disco no confiables (comunes para malware/persistencia).
UBICACIONES_SOSPECHOSAS = [
    r"ProgramData",
    r"\\Temp\\",
    r"\\Tmp\\",
    r"\\Users\\",
    r"\\AppData\\",
    r"\\Public\\",
    r"\\Downloads\\",
]

# Rutas confiables del sistema (si el binario está aquí, NO es masquerading).
UBICACIONES_CONFIABLES = [r"C:\\Windows", r"C:\\Program Files"]

# Prefijos/patrones de cuentas de servicio (R3/R9).
PATRONES_CUENTA_SERVICIO = [r"svc[_-]", r"backup", r"service", r"\$$"]

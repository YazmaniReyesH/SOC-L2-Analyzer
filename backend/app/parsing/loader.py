"""Parseo y normalización del export del SIEM (.xlsx).

Responsabilidades:
- Validar que exista la hoja y las columnas requeridas (error claro si no).
- Normalizar tipos (Event_ID a str, timestamps a datetime, celdas vacías a None).
- Marcar IPs externas (no RFC1918).
- Ordenar los eventos por tiempo.

El parser es tolerante a celdas vacías (Destination y Process_CommandLine
suelen venir vacíos) pero estricto con la estructura.
"""
from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime
from io import BytesIO
from pathlib import Path

import pandas as pd

from ..models import LogEvent

SHEET_NAME = "SIEM Export"

REQUIRED_COLUMNS = [
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Destination",
    "Log_Source",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
]

# Redes privadas RFC1918 (definición de "IP interna" según el enunciado).
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


class ParseError(ValueError):
    """Error de parseo con mensaje apto para mostrar al usuario."""


def is_external_ip(ip: str | None) -> bool:
    """True si `ip` es una IPv4/IPv6 que NO pertenece a RFC1918.

    Cualquier valor no parseable (vacío, '-', host) devuelve False.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return not any(addr in net for net in _PRIVATE_NETS)
    # IPv6: consideramos externas las no privadas/no locales.
    return not (addr.is_private or addr.is_link_local or addr.is_loopback)


def _clean(value: object) -> str | None:
    """Convierte una celda a str limpio o None si está vacía/NaN."""
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    text = str(value).strip()
    if text == "" or text.lower() == "nan":
        return None
    return text


def _norm_event_id(value: object) -> str:
    """Event_ID puede ser numérico (4625) o texto (PROXY_ACCESS)."""
    text = _clean(value) or ""
    # Quita el ".0" que pandas agrega a enteros leídos como float.
    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]
    return text


def _parse_timestamp(value: object) -> datetime:
    text = _clean(value)
    if text is None:
        raise ParseError("Timestamp vacío en una o más filas.")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    # Último recurso: dejar que pandas intente.
    try:
        return pd.to_datetime(text).to_pydatetime()
    except Exception as exc:  # noqa: BLE001
        raise ParseError(f"Timestamp con formato inválido: {text!r}") from exc


def _read_dataframe(source: str | Path | bytes) -> pd.DataFrame:
    """Lee el .xlsx eligiendo la hoja 'SIEM Export' si existe."""
    buffer: str | Path | BytesIO
    buffer = BytesIO(source) if isinstance(source, (bytes, bytearray)) else source
    try:
        xl = pd.ExcelFile(buffer, engine="openpyxl")
    except Exception as exc:  # noqa: BLE001
        raise ParseError(
            "No se pudo abrir el archivo. ¿Es un .xlsx válido exportado del SIEM?"
        ) from exc

    hoja = SHEET_NAME if SHEET_NAME in xl.sheet_names else xl.sheet_names[0]
    df = pd.read_excel(xl, sheet_name=hoja, dtype=str)
    # Normaliza encabezados: quita espacios alrededor y colapsa espacios internos.
    # (tolera "Source_IP ", " Event_ID", etc.). Las columnas extra se conservan
    # pero el parser solo usa las requeridas.
    df.columns = [re.sub(r"\s+", " ", str(c)).strip() for c in df.columns]
    df.attrs["hoja"] = hoja
    return df


def _validate_columns(df: pd.DataFrame) -> None:
    faltantes = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if faltantes:
        raise ParseError(
            "El archivo no tiene la estructura esperada. Faltan columnas: "
            + ", ".join(faltantes)
            + ". Columnas encontradas: "
            + ", ".join(map(str, df.columns))
        )


def load_events(source: str | Path | bytes) -> list[LogEvent]:
    """Carga, valida y normaliza los eventos. Devuelve ordenados por tiempo.

    `source` puede ser una ruta o los bytes del archivo subido.
    Lanza `ParseError` (mensaje claro) si la estructura es inválida.
    """
    df = _read_dataframe(source)
    _validate_columns(df)

    if len(df) == 0:
        raise ParseError("El archivo no contiene filas de eventos.")

    eventos: list[LogEvent] = []
    for _, row in df.iterrows():
        log_id = _clean(row["Log_ID"])
        if log_id is None:
            # Fila sin Log_ID: la ignoramos (tolerancia a filas basura).
            continue
        source_ip = _clean(row["Source_IP"]) or ""
        ts = _parse_timestamp(row["Timestamp"])
        eventos.append(
            LogEvent(
                log_id=log_id,
                timestamp=ts,
                timestamp_str=ts.strftime("%Y-%m-%d %H:%M:%S"),
                hostname=_clean(row["Hostname"]) or "",
                event_id=_norm_event_id(row["Event_ID"]),
                user=_clean(row["User"]) or "",
                source_ip=source_ip,
                destination=_clean(row["Destination"]),
                log_source=_clean(row["Log_Source"]) or "",
                event_description=_clean(row["Event_Description"]) or "",
                process_commandline=_clean(row["Process_CommandLine"]),
                result=_clean(row["Result"]) or "",
                severity=_clean(row["Severity"]) or "",
                ip_externa=is_external_ip(source_ip),
            )
        )

    if not eventos:
        raise ParseError("No se encontraron eventos válidos (con Log_ID) en el archivo.")

    eventos.sort(key=lambda e: e.timestamp)
    return eventos

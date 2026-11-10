"""Ensambla el Informe: estructura/datos deterministas + prosa (IA o plantillas)."""
from __future__ import annotations

import os
from datetime import datetime

from ..ai import narrativa_determinista, redactar_narrativa_ia
from ..config import settings
from ..models import AnalyzeResponse, Informe
from .iocs import consolidar_iocs

TITULO = "Informe de Análisis de Incidentes de Seguridad"
ANALISTA = "Yazmani Reyes Hernández"
CLASIFICACION = "Confidencial"


def construir_informe(analisis: AnalyzeResponse) -> Informe:
    iocs = consolidar_iocs(analisis)

    # La prosa determinista es SIEMPRE la base (garantiza informe completo).
    narrativa = narrativa_determinista(analisis, iocs)
    modo_ia = "plantillas"
    modelo = None

    # Si hay API key, la IA reescribe la prosa (solo las claves que devuelva).
    if settings.anthropic_configured:
        narr_ia = redactar_narrativa_ia(analisis, iocs)
        if narr_ia:
            narrativa = {**narrativa, **narr_ia}
            modo_ia = "ia"
            modelo = settings.anthropic_model

    return Informe(
        modo_ia=modo_ia,
        modelo=modelo,
        generado=datetime.now().strftime("%d/%m/%Y %H:%M"),
        titulo=TITULO,
        cliente=os.getenv("REPORT_CLIENTE", "").strip() or "Organización Evaluada",
        analista=ANALISTA,
        clasificacion=CLASIFICACION,
        resumen=analisis.resumen,
        narrativa=narrativa,
        estadisticas=analisis.estadisticas,
        incidentes=analisis.incidentes,
        hallazgos=analisis.hallazgos,
        iocs=iocs,
    )

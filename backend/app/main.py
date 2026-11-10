"""Punto de entrada de la API FastAPI del analizador SOC N2.

Módulo 1: solo expone CORS + GET /api/health.
Los endpoints de análisis, informe y PDF se agregan en módulos posteriores.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings

app = FastAPI(
    title="SOC L2 Analyzer API",
    description=(
        "API de análisis de incidentes de seguridad. Detección 100% "
        "determinista; la IA solo redacta el informe a partir de la evidencia."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["sistema"])
def health() -> dict:
    """Estado del servicio y disponibilidad de la IA.

    `modo_ia` indica cómo se redactaría el informe ahora mismo:
    - "ia": hay API key configurada.
    - "plantillas": no hay API key -> se usa el fallback determinista.
    """
    return {
        "status": "ok",
        "service": "soc-l2-analyzer",
        "version": app.version,
        "ia_disponible": settings.anthropic_configured,
        "modo_ia": "ia" if settings.anthropic_configured else "plantillas",
        "modelo": settings.anthropic_model,
    }

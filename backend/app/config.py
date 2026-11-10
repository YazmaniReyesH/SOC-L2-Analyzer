"""Configuración central de la aplicación (cargada desde .env).

Toda la configuración sensible/ajustable vive aquí y se lee de variables de
entorno. El valor por defecto de cada una está documentado y es fácil de
editar desde `.env`.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Carga variables de entorno de forma robusta (independiente del CWD):
# 1) backend/.env (junto al código) — para desarrollo local.
# 2) .env en el CWD / raíz — útil si se arranca desde otra ubicación.
# En Docker las variables llegan por el entorno del contenedor y tienen
# prioridad: load_dotenv NO sobreescribe variables ya definidas.
_BACKEND_ENV = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_BACKEND_ENV)  # backend/.env
load_dotenv()  # además, un .env en el CWD si existe


class Settings:
    """Configuración de la app. Instancia única: `settings`."""

    def __init__(self) -> None:
        # --- Anthropic / IA ---
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "").strip()
        # Modelo por defecto documentado y fácilmente editable desde .env.
        # NOTA: el ID definitivo del modelo se valida en el Módulo 5 (capa IA).
        self.anthropic_model: str = (
            os.getenv("ANTHROPIC_MODEL", "").strip() or "claude-sonnet-5"
        )

        # --- CORS ---
        origins = os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        )
        self.cors_origins: list[str] = [
            o.strip() for o in origins.split(",") if o.strip()
        ]

    @property
    def anthropic_configured(self) -> bool:
        """True si hay una API key presente (no valida que sea correcta)."""
        return bool(self.anthropic_api_key)


settings = Settings()

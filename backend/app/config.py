"""Configuración central de la aplicación (cargada desde .env).

Toda la configuración sensible/ajustable vive aquí y se lee de variables de
entorno. El valor por defecto de cada una está documentado y es fácil de
editar desde `.env`.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv

# Carga variables desde backend/.env si existe (no falla si no existe).
load_dotenv()


class Settings:
    """Configuración de la app. Instancia única: `settings`."""

    def __init__(self) -> None:
        # --- Anthropic / IA ---
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "").strip()
        # Modelo por defecto documentado y fácilmente editable desde .env.
        # NOTA: el ID definitivo del modelo se valida en el Módulo 5 (capa IA).
        self.anthropic_model: str = (
            os.getenv("ANTHROPIC_MODEL", "").strip() or "claude-sonnet-4-5"
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

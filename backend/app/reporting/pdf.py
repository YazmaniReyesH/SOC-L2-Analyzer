"""Renderizado del informe a PDF con Jinja2 + WeasyPrint."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Informe

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "xml", "j2"), default=True),
)

# Colores por criticidad (coinciden con la UI).
COLOR_CRITICIDAD = {
    "Crítico": "#e02424",
    "Alto": "#f97316",
    "Medio": "#eab308",
    "Bajo": "#22c55e",
}


def informe_a_pdf(informe: Informe) -> bytes:
    """Renderiza el Informe a PDF. Lanza si WeasyPrint/GTK no está disponible."""
    from weasyprint import HTML  # import perezoso (requiere GTK en el sistema)

    tpl = _env.get_template("report.html.j2")
    html = tpl.render(inf=informe.model_dump(), color=COLOR_CRITICIDAD)
    return HTML(string=html).write_pdf()

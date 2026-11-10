"""Punto de entrada de la API FastAPI del analizador SOC N2.

Endpoints:
- GET  /api/health   -> estado y disponibilidad de IA.
- POST /api/analyze  -> parsea el .xlsx y devuelve estadísticas, preview,
                        hallazgos e incidentes (detección determinista).
"""
from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .models import AnalyzeResponse, Informe
from .parsing import ParseError, load_events
from .reporting import construir_informe, informe_a_pdf
from .service import analizar_eventos

app = FastAPI(
    title="SOC L2 Analyzer API",
    description=(
        "API de análisis de incidentes de seguridad. Detección 100% "
        "determinista; la IA solo redacta el informe a partir de la evidencia."
    ),
    version="0.3.0",
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
    """Estado del servicio y disponibilidad de la IA."""
    return {
        "status": "ok",
        "service": "soc-l2-analyzer",
        "version": app.version,
        "ia_disponible": settings.anthropic_configured,
        "modo_ia": "ia" if settings.anthropic_configured else "plantillas",
        "modelo": settings.anthropic_model,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse, tags=["análisis"])
async def analyze(file: UploadFile = File(...)) -> AnalyzeResponse:
    """Recibe el export .xlsx del SIEM y devuelve el análisis completo."""
    nombre = (file.filename or "").lower()
    if not nombre.endswith((".xlsx", ".xlsm")):
        raise HTTPException(
            status_code=400,
            detail="Formato no soportado. Sube un archivo .xlsx exportado del SIEM.",
        )

    contenido = await file.read()
    if not contenido:
        raise HTTPException(status_code=400, detail="El archivo está vacío.")

    try:
        eventos = load_events(contenido)
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return analizar_eventos(eventos)


@app.post("/api/report", response_model=Informe, tags=["informe"])
def report(analisis: AnalyzeResponse) -> Informe:
    """Construye el informe redactado (IA si hay API key; si no, plantillas)."""
    return construir_informe(analisis)


@app.post("/api/report/pdf", tags=["informe"])
def report_pdf(informe: Informe) -> Response:
    """Renderiza el informe a PDF (WeasyPrint)."""
    try:
        pdf = informe_a_pdf(informe)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=(
                "No se pudo generar el PDF. Verifica que WeasyPrint y sus "
                f"dependencias (GTK) estén instaladas. Detalle: {exc}"
            ),
        ) from exc
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="Informe_SOC_L2.pdf"'},
    )

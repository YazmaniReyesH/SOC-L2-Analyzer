"""Capa de IA (híbrida, grounded): la IA SOLO redacta la narrativa.

- Envía únicamente el JSON de evidencia (incidentes/hallazgos/IoCs/Log_ID).
- System prompt estricto: prohibido inventar hallazgos, IPs, usuarios o
  conclusiones; cita Log_ID; si no está en la evidencia, no se afirma.
- Devuelve un dict {clave_seccion: prosa} o None si falla (la app usa plantillas).
- NUNCA lanza: cualquier error -> None (la app nunca falla por la IA).

Nota de modelo: los modelos Sonnet 5+ rechazan `temperature` (HTTP 400). Por eso
no se envía por defecto; el rigor se garantiza con el system prompt. Se puede
forzar con ANTHROPIC_TEMPERATURE para modelos antiguos que sí la acepten.
"""
from __future__ import annotations

import json
import os

from ..config import settings
from ..models import AnalyzeResponse, IoCs

SYSTEM_PROMPT = (
    "Eres un analista SOC de Nivel 2 redactando un informe de respuesta a "
    "incidentes en ESPAÑOL, para una audiencia ejecutiva y técnica. "
    "Reglas ABSOLUTAS:\n"
    "1. Usa ÚNICAMENTE la evidencia provista en el JSON. \n"
    "2. NO inventes ni infieras hallazgos, incidentes, IPs, usuarios, hosts, "
    "archivos ni conclusiones que no estén explícitamente en la evidencia.\n"
    "3. Cita los Log_ID cuando respalden una afirmación.\n"
    "4. Si un incidente agrupa varios vectores (multi_vector), descríbelos como "
    "vectores correlacionados con sus entidades reales, sin forzar una cadena única.\n"
    "5. Si algo no está en la evidencia, no lo afirmes.\n"
    "6. Tono profesional, claro y accionable. Español neutro.\n"
    "Devuelve EXCLUSIVAMENTE un objeto JSON válido (sin markdown, sin texto "
    "adicional) con las claves solicitadas; cada valor es el texto de esa sección."
)


def _payload_evidencia(analisis: AnalyzeResponse, iocs: IoCs) -> dict:
    est = analisis.estadisticas
    return {
        "estadisticas": {
            "total_eventos": est.total_eventos,
            "rango": [
                est.rango_temporal.inicio.isoformat() if est.rango_temporal.inicio else None,
                est.rango_temporal.fin.isoformat() if est.rango_temporal.fin else None,
            ],
            "ips_externas_origen": est.ips_externas_origen,
            "ips_externas_destino": est.ips_externas_destino,
        },
        "iocs": iocs.model_dump(),
        "incidentes": [
            {
                "id": i.id,
                "titulo": i.titulo,
                "criticidad": i.criticidad,
                "etapas": i.etapas,
                "multi_vector": i.multi_vector,
                "justificacion": i.justificacion,
                "impacto": i.impacto,
                "vectores": [
                    {"actor": v.actor, "resumen": v.resumen, "usuarios": v.usuarios,
                     "activos": v.activos, "ips": v.ips, "etapas": v.etapas}
                    for v in i.vectores
                ],
                "hallazgos": [
                    {
                        "id": h.id, "titulo": h.titulo, "criticidad": h.criticidad,
                        "regla": h.regla, "justificacion": h.justificacion,
                        "evidencia": h.evidencia, "mitre": h.mitre,
                        "activos": h.activos, "usuarios": h.usuarios, "ips": h.ips,
                    }
                    for h in analisis.hallazgos
                    if h.id in i.hallazgos
                ],
            }
            for i in analisis.incidentes
        ],
    }


def _claves(analisis: AnalyzeResponse) -> list[str]:
    base = ["resumen_ejecutivo", "alcance", "impacto_organizacion", "recomendaciones"]
    return base + [f"inc_{i.id}" for i in analisis.incidentes]


def redactar_narrativa_ia(
    analisis: AnalyzeResponse, iocs: IoCs
) -> dict[str, str] | None:
    """Intenta redactar la narrativa con IA. Devuelve dict o None (fallback)."""
    if not settings.anthropic_configured:
        return None
    try:
        from anthropic import Anthropic  # import perezoso: la app no depende de él

        client = Anthropic(api_key=settings.anthropic_api_key)
        claves = _claves(analisis)
        payload = _payload_evidencia(analisis, iocs)
        instrucciones = (
            "Redacta las siguientes secciones del informe. Devuelve un JSON con "
            "EXACTAMENTE estas claves (string cada una):\n"
            + "\n".join(f"- {k}" for k in claves)
            + "\n\nGuía por sección:\n"
            "- resumen_ejecutivo: panorama para dirección (2-4 párrafos).\n"
            "- alcance: alcance y metodología (eventos, rango, fuentes, enfoque determinista).\n"
            "- impacto_organizacion: impacto en confidencialidad/integridad/disponibilidad.\n"
            "- recomendaciones: lista de recomendaciones generales de seguridad.\n"
            "- inc_<ID>: narrativa técnica del incidente, citando Log_ID; si es "
            "multi_vector, describe cada vector.\n\n"
            "EVIDENCIA (única fuente permitida):\n"
            + json.dumps(payload, ensure_ascii=False)
        )

        kwargs = dict(
            model=settings.anthropic_model,
            max_tokens=8000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": instrucciones}],
        )
        # temperature opcional (los modelos recientes la rechazan -> 400).
        temp = os.getenv("ANTHROPIC_TEMPERATURE", "").strip()
        if temp:
            kwargs["temperature"] = float(temp)

        resp = client.messages.create(**kwargs)
        texto = "".join(
            getattr(b, "text", "") for b in resp.content if getattr(b, "type", None) == "text"
        )
        ini, fin = texto.find("{"), texto.rfind("}")
        if ini == -1 or fin == -1:
            return None
        data = json.loads(texto[ini : fin + 1])
        narr = {k: str(v) for k, v in data.items() if isinstance(v, str) and v.strip()}
        # Debe traer al menos el resumen ejecutivo para considerarse válido.
        return narr if "resumen_ejecutivo" in narr else None
    except Exception:  # noqa: BLE001 — la app nunca falla por la IA.
        return None

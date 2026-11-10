# SOC L2 Analyzer

Aplicación web asistida por IA para **análisis de incidentes de seguridad**:
convierte logs exportados de un SIEM (`.xlsx`) en un **informe técnico
profesional exportable a PDF**.

> Laboratorio final — Bootcamp de Analista SOC Nivel 2.
> Analista: **Yazmani Reyes Hernández**.

## Principio innegociable: rigor analítico

- La **detección de incidentes es 100% determinista** (reglas en Python sobre
  los logs reales).
- La **IA solo redacta** el informe a partir de la evidencia ya detectada;
  **no descubre ni agrega hallazgos**.
- Cada conclusión es **trazable a `Log_ID`s** concretos.
- Si no hay API key, la app funciona igual con **plantillas deterministas**.
  La aplicación **nunca falla** por ausencia o error de la IA.

## Stack

- **Backend:** Python 3.11 · FastAPI · Uvicorn · pandas + openpyxl · pydantic v2
  · anthropic · jinja2 + WeasyPrint · python-multipart.
- **Frontend:** React + Vite + TypeScript · TailwindCSS · lucide-react · recharts
  · axios · react-dropzone · @tanstack/react-table. Dark mode.
- **Infra:** Docker por servicio + docker-compose. Config por `.env`.

## Estructura

```
.
├── backend/            # API FastAPI
│   ├── app/            #   código de la aplicación
│   │   ├── main.py     #   endpoints
│   │   └── config.py   #   configuración (.env)
│   ├── sample/         #   coloca aquí SOC_L2_Logs.xlsx
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/           # SPA React + Vite
│   └── src/
├── docker-compose.yml
└── .env.example
```

## Cómo correr

### Opción A — Local

**Backend** (puerto 8000):
```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
# source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # opcional: rellena ANTHROPIC_API_KEY
uvicorn app.main:app --reload
```
> **Windows + WeasyPrint:** la generación de PDF (módulos posteriores) requiere
> las librerías GTK. Si no las tienes, usa Docker para esa parte. El resto de la
> app funciona sin ellas.

**Frontend** (puerto 5173):
```bash
cd frontend
npm install
npm run dev
```
Abre http://localhost:5173 — debe mostrar el backend como *operativo*.

### Opción B — Docker

```bash
cp .env.example .env            # opcional
docker compose up --build
```
- Frontend: http://localhost:5173
- Backend:  http://localhost:8000/api/health

## Variables de entorno

| Variable | Dónde | Descripción | Default |
|----------|-------|-------------|---------|
| `ANTHROPIC_API_KEY` | backend | Clave Anthropic (opcional). Vacía = plantillas. | *(vacía)* |
| `ANTHROPIC_MODEL` | backend | Modelo a usar con IA. | `claude-sonnet-5` |
| `CORS_ORIGINS` | backend | Orígenes permitidos (coma). | `localhost:5173` |
| `VITE_API_TARGET` | frontend | Target del proxy `/api` en dev. | `localhost:8000` |

## Estado del proyecto (por módulos)

- [x] **Módulo 1** — Scaffold + `GET /api/health`.
- [ ] **Módulo 2** — Parseo xlsx + `/api/analyze` (estadísticas + preview).
- [ ] **Módulo 3** — Motor de detección R1–R9 + correlación + tests.
- [ ] **Módulo 4** — Frontend: carga, tabla, dashboard, hallazgos.
- [ ] **Módulo 5** — IA + informe + PDF.
- [ ] **Módulo 6** — Pulido, documentación y E2E.

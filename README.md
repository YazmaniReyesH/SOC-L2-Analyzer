# SOC L2 Analyzer

Aplicación web asistida por IA para **análisis de incidentes de seguridad**:
convierte logs exportados de un SIEM (`.xlsx`) en un **informe técnico
profesional exportable a PDF**.

> Laboratorio final — Bootcamp de Analista SOC Nivel 2.
> Analista: **Yazmani Reyes Hernández** · Clasificación: **Confidencial**.

---

## Principio innegociable: rigor analítico

- La **detección de incidentes es 100% determinista** (reglas en Python sobre
  los logs reales, sin IA).
- La **IA solo redacta** la prosa del informe a partir de la evidencia ya
  detectada; **no descubre ni agrega hallazgos**.
- Cada conclusión es **trazable a `Log_ID`s** concretos.
- Si no hay API key, la app funciona igual con **plantillas deterministas**.
- La aplicación **nunca falla** por ausencia o error de la IA.

Ver la sección [**Cómo se garantiza que no se inventan hallazgos**](#cómo-se-garantiza-que-no-se-inventan-hallazgos).

## Características

- **Carga** `.xlsx` con validación de esquema y errores claros.
- **Tabla de logs** con búsqueda y filtros (Event_ID, Severity, Hostname, User).
- **Dashboard** con KPIs (eventos, incidentes, IPs externas de **origen** y de
  **destino/exfil**) y gráficos (criticidad, línea de tiempo, tipos de evento,
  top IPs, hosts).
- **Motor de detección R1–R9** determinista + correlación en incidentes
  (incluye **incidentes multi-vector**) + línea de tiempo (kill chain) + matriz
  de riesgo.
- **Informe** redactado (IA o plantillas) con **exportación a PDF** profesional.
- **Dark mode**, diseño responsive.

## Stack

- **Backend:** Python 3.11 · FastAPI · Uvicorn · pandas + openpyxl · pydantic v2
  · anthropic · jinja2 + WeasyPrint · python-multipart.
- **Frontend:** React + Vite + TypeScript · TailwindCSS · lucide-react · recharts
  · axios · react-dropzone · @tanstack/react-table.
- **Infra:** Docker por servicio + docker-compose. Config por `.env`.

## Estructura

```
.
├── backend/
│   ├── app/
│   │   ├── main.py            # endpoints FastAPI
│   │   ├── config.py          # configuración (.env)
│   │   ├── models.py          # modelos pydantic
│   │   ├── parsing/loader.py  # parseo/normalización del .xlsx
│   │   ├── stats.py           # estadísticas del dashboard
│   │   ├── detection/         # motor determinista R1–R9 + correlación
│   │   ├── ai/                # narrator.py (IA) + templates.py (fallback)
│   │   └── reporting/         # iocs, builder, pdf + templates/report.html.j2
│   ├── tests/                 # test_detection.py + test_generalizacion.py
│   ├── sample/SOC_L2_Logs.xlsx
│   ├── requirements.txt · Dockerfile
├── frontend/
│   └── src/ (components, lib)  · Dockerfile
├── docker-compose.yml · .env.example · README.md
```

## Cómo correr

### Opción A — Docker (recomendado, incluye PDF)

```bash
cp .env.example .env          # opcional: rellena ANTHROPIC_API_KEY
docker compose up --build
```
- Frontend: http://localhost:5173
- Backend:  http://localhost:8000/api/health

El `Dockerfile` del backend fija **Python 3.11** e instala las librerías GTK que
necesita WeasyPrint, por lo que la **exportación a PDF funciona out-of-the-box**.

### Opción B — Local

**Backend** (puerto 8000):
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate         # Windows   (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env            # opcional
uvicorn app.main:app --reload
```
> **Windows + WeasyPrint:** la generación de PDF requiere las librerías GTK. Si no
> las tienes instaladas, usa Docker para esa parte; el resto de la app (análisis,
> dashboard, informe en pantalla) funciona sin ellas.

**Frontend** (puerto 5173):
```bash
cd frontend
npm install
npm run dev
```

### Tests del motor de detección

```bash
cd backend
pytest tests/ -v     # 20 pruebas (criterios de aceptación + generalización + parser)
```

## Cómo cargar el Excel

1. Abre http://localhost:5173.
2. Arrastra `backend/sample/SOC_L2_Logs.xlsx` (o el tuyo) al área de carga.
3. Explora **Dashboard**, **Logs**, **Incidentes** y genera el **Informe** → **Exportar PDF**.

El Excel debe tener la hoja `SIEM Export` con las columnas: `Log_ID, Timestamp,
Hostname, Event_ID, User, Source_IP, Destination, Log_Source, Event_Description,
Process_CommandLine, Result, Severity`. El parser tolera columnas extra,
encabezados con espacios y celdas vacías; si faltan columnas requeridas, devuelve
un error claro.

## Variables de entorno

| Variable | Dónde | Descripción | Default |
|----------|-------|-------------|---------|
| `ANTHROPIC_API_KEY` | backend | Clave Anthropic (opcional). Vacía = plantillas. | *(vacía)* |
| `ANTHROPIC_MODEL` | backend | Modelo a usar con IA. | `claude-sonnet-5` |
| `ANTHROPIC_TEMPERATURE` | backend | (Opcional) temperatura; los modelos Sonnet 5+ la rechazan, dejar vacío. | *(vacía)* |
| `CORS_ORIGINS` | backend | Orígenes permitidos (coma). | `localhost:5173` |
| `REPORT_CLIENTE` | backend | Nombre del cliente en la portada. | `Organización Evaluada` |
| `VITE_API_TARGET` | frontend | Target del proxy `/api` en dev. | `localhost:8000` |

> **Dónde poner la clave.** Para **local**, en `backend/.env` (`config.py` lo carga
> siempre, sin importar desde dónde ejecutes). Para **Docker**, en `.env` de la raíz
> **o** en `backend/.env` (ambos los lee `docker-compose.yml` vía `env_file`). La
> clave **nunca** se expone al frontend (solo variables `VITE_*`), y los `.env` están
> en `.gitignore`. Con la clave presente, `GET /api/health` reporta `modo_ia: "ia"`.

## Endpoints

- `GET  /api/health` — estado y modo de IA.
- `POST /api/analyze` — (multipart xlsx) → estadísticas, preview, hallazgos, incidentes.
- `POST /api/report` — (análisis) → informe redactado + `modo_ia`.
- `POST /api/report/pdf` — (informe) → PDF (WeasyPrint).

## Modelo de detección (R1–R9)

| Regla | Detección | MITRE |
|-------|-----------|-------|
| R1 | Fuerza bruta dirigida (≥3 `4625` mismo User+IP en ventana; marca EXITOSA si hay `4624`) | T1110.001, T1021.001, T1133, T1078 |
| R2 | Password spraying (1 IP contra ≥5 cuentas en ráfaga) | T1110.003 |
| R3 | Escalamiento de privilegios (`4672` desde IP externa) | T1068, T1078, T1134 |
| R4 | Ejecución sospechosa (`4688`/`4104` con PowerShell ofuscado, recon, archivado) | T1059.001, T1027, T1087, T1135 |
| R5 | Movimiento lateral (LogonType=3 + `source=`) y colección masiva | T1021.002, T1039, T1570, T1005, T1560.001 |
| R6 | Exfiltración / beaconing C2 (`5156`/`PROXY_ACCESS` a IP externa; intervalos regulares) | T1041, T1567, T1071.001, T1560.001 |
| R7 | Persistencia (`4698`/`7045`; masquerading por heurística) | T1053.005, T1543.003, T1036 |
| R8 | Escaneo/ataque web (`HTTP_ACCESS` externo, ráfaga, códigos mixtos) | T1595, T1190 |
| R9 | Anomalías (inconsistencia de hostnames, `4672` a cuentas de servicio) | T1036, T1078.004 |

Umbrales configurables en `backend/app/constants.py`.

## Cómo se garantiza que no se inventan hallazgos

Este es el principio central del laboratorio. Se garantiza por **diseño**, no por
confianza en la IA:

1. **Detección 100% determinista.** Los incidentes y hallazgos los produce
   exclusivamente el motor de reglas en Python (`app/detection/`) sobre los logs
   reales. La IA **no participa** en la detección ni en la correlación.

2. **La IA solo redacta prosa.** `ai/narrator.py` recibe **únicamente** el JSON de
   evidencia ya detectada (incidentes, hallazgos, Log_ID, IoCs) y un *system
   prompt* estricto: «usa SOLO la evidencia provista; no inventes hallazgos, IPs,
   usuarios ni conclusiones; cita los Log_ID». Las **tablas, Log_ID, MITRE, IoCs y
   la línea de tiempo del informe son deterministas** y no dependen de la IA: aun
   si el modelo alucinara, esos datos no cambian.

3. **Trazabilidad total.** Cada hallazgo incluye su lista de `Log_ID`. Un test
   automático (`tests/test_detection.py::test_no_hay_hallazgos_sin_evidencia`)
   **falla** si algún hallazgo no cita Log_ID válidos del dataset.

4. **Reglas agnósticas al contenido.** La lógica no contiene IPs, usuarios,
   hostnames ni nombres de servicio del archivo de demo — solo umbrales, patrones
   de TTP y rangos RFC1918. Hay pruebas de generalización con un dataset sintético
   de entidades distintas y con un archivo limpio (que debe dar **cero** hallazgos).

5. **Fallback determinista.** Sin API key (o si la IA falla), el informe se redacta
   con plantillas deterministas (`ai/templates.py`) desde la misma evidencia. La
   UI indica siempre qué modo se usó.

## Autor

Yazmani Reyes Hernández — Analista SOC Nivel 2.

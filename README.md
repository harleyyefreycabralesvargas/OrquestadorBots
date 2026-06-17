# RPA Orchestrator v3.0 — Cajasan USE TECNOLOGÍA

Sistema de orquestación de robots RPA con arquitectura **Master–Worker**, construido sobre **FastAPI + MongoDB Atlas** (API central en Render.com), **Streamlit** (interfaz Master) y un **agente Python** que se ejecuta en cada máquina worker (Windows).

---

## Arquitectura

```
┌─────────────────┐        HTTPS         ┌──────────────────────┐
│  interfaz.py    │ ───────────────────► │      api.py          │
│  (Streamlit)    │ ◄─────────────────── │  FastAPI + Mongo     │
│  Master UI      │                      │  (Render.com)        │
└─────────────────┘                      └──────────┬───────────┘
                                                    │ polling HTTPS
                                         ┌──────────▼───────────┐
                                         │     worker.py        │
                                         │  Agente en Windows   │
                                         │  clona repo + ejecuta│
                                         └──────────────────────┘
```

- **El worker no abre puertos**: hace *polling* saliente (heartbeat, obtener tarea, logs, finalizar). Funciona detrás de cualquier firewall/NAT.
- Las **credenciales** viajan encriptadas extremo a extremo con **Fernet** (misma clave en API, UI y worker). La API nunca las desencripta: solo las almacena y reenvía.

---

## Novedades v3.0

### Orquestación
- **Dependencias entre tareas (DAG)**: una tarea puede esperar a que otras se completen (`depende_de`). Estado nuevo `esperando`; al completarse las dependencias, se libera automáticamente.
- **Auto-asignación con balanceo de carga**: `POST /api/tareas/auto` elige el worker conectado con menor carga (cola + tarea actual), opcionalmente dentro de un **pool**.
- **Worker Pools**: agrupa workers para reparto automático.
- **Pausa global**: detiene la asignación de nuevas tareas sin perder la cola.
- **Plantillas de lanzamiento**: configuraciones reutilizables (proyecto + prioridad + reintentos + tags + SLA + git_ref) para lanzar en un clic.

### Robots / ejecución
- **Variables de entorno por proyecto** (`env_vars`) inyectadas al `.env` del robot, combinables con un **override por tarea**.
- **Pinning de Git** (`git_ref`): ejecuta una rama, tag o commit específico por proyecto o por tarea.
- **Reintentos automáticos** con *backoff* exponencial (heredado de v2).

### Observabilidad
- **Métricas de salud del worker** (CPU / RAM / disco) reportadas en cada heartbeat y visibles en el dashboard con barras de color.
- **Métricas globales** con serie de tiempo (throughput diario) y exportación CSV.
- **Notificaciones in-app** con severidad (info/success/warning/error).
- **Auditoría completa**: cada acción del Master queda registrada (`/api/audit`).
- **Alertas SLA**: marca y notifica tareas que exceden su tiempo máximo.
- **Búsqueda dentro de logs** (`?buscar=texto`).

### Integraciones
- **Webhooks** por evento + **test de webhook** (ping de prueba).
- **Alertas por correo (SMTP)** configurables por evento.
- **API Keys** (`rpak_…`) para acceso programático desde CI/CD o scripts.

---

## Estructura de archivos

| Archivo | Dónde corre | Descripción |
|---|---|---|
| `api.py` | Render.com | API central FastAPI. **No editar** sin actualizar la UI/worker. |
| `interfaz.py` | PC del Master | Interfaz Streamlit (17 secciones). |
| `worker.py` | Cada PC worker | Agente que ejecuta los robots. |
| `requirements_api.txt` | Render | Dependencias de la API (incluye `croniter`). |
| `requirements_interfaz.txt` | Master | Dependencias de la UI. |
| `requirements_worker.txt` | Worker | Dependencias del agente (incluye `psutil`). |
| `api.env` / `interfaz.env` / `worker.env` | respectivo | Variables de entorno (NO subir a Git). |
| `render.yaml` | raíz repo API | Blueprint de despliegue Render. |
| `tick_scheduler.py` | cron externo | Dispara los schedules cada minuto. |
| `setup_inicial.py` | una vez | Generador de claves/hashes inicial. |
| `*.bat` | Windows | Lanzadores de UI/worker y compilador a `.exe`. |

---

## Puesta en marcha

### 1. API (Render.com)
1. Genere los secretos con `setup_inicial.py` (FERNET_KEY, hash bcrypt del Master, JWT secrets).
2. Configure las variables de `api.env` en Render → *Environment*.
3. Despliegue con `render.yaml`. Healthcheck en `/health`.

### 2. Interfaz Master
```bash
pip install -r requirements_interfaz.txt
# configurar interfaz.env: API_URL, FERNET_KEY
streamlit run interfaz.py      # o ejecutar_interfaz.bat
```

### 3. Worker (cada máquina)
```bash
pip install -r requirements_worker.txt
# configurar worker.env: API_URL, WORKER_USERNAME, WORKER_PASSWORD, FERNET_KEY
python worker.py               # o ejecutar_worker.bat
```
Para varias instancias en una misma máquina, ejecute `worker.py` con distintos `worker.env`.

### 4. Schedules (disparo periódico)
Como el plan *free* de Render no incluye cron jobs, use **`tick_scheduler.py`** desde:
- El **Programador de Tareas de Windows** (cada minuto), o
- Un servicio externo (cron-job.org, EasyCron, UptimeRobot) que haga `POST https://TU-API/api/schedules/tick` con header `Authorization: Bearer rpak_…`.

Genere la API Key en la sección **🔑 API Keys** de la interfaz.

---

## Mapa de la interfaz (17 secciones)

**Operación** — Dashboard · Lanzar Tarea · Plantillas · Historial · Logs en Vivo
**Automatización** — Schedules · Webhooks · Notificaciones
**Analítica** — Métricas · Métricas Globales
**Administración** — Workers · Pools · Proyectos · API Keys · Auditoría · Configuración · Sistema

---

## Compatibilidad

`worker.py` v3.0 es **retrocompatible**: los campos nuevos (`git_ref`, `env_vars`, métricas de salud) son opcionales. Un worker v3 funciona contra la API v3 y degrada con elegancia si un campo no está presente. Los endpoints internos worker↔API mantienen el mismo contrato que v2.

## Estados de tarea

`pendiente` → `ejecutando` → (`completada` | `error` | `cancelada`)
`pausada` (pausa puntual) · `cancelando` (STOP en curso) · `esperando` (dependencias pendientes)

## Seguridad
- Autenticación JWT separada para Master y Worker (+ API Keys para el Master).
- Credenciales encriptadas con Fernet; la API no las descifra.
- Auditoría de todas las acciones del Master.
- `*.env` nunca deben subirse a control de versiones.

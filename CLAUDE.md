# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Qué es esto

RPA Orchestrator (Cajasan / USE TECNOLOGÍA) — sistema de orquestación de robots RPA con arquitectura **Master–Worker**. Tres componentes independientes, cada uno en un único archivo monolítico, que se comunican solo por HTTPS:

- **`api.py`** — API central (FastAPI + MongoDB Atlas vía Motor). Se despliega en Render.com. Es la única pieza con estado (Mongo) y la única que conoce el secreto `FERNET_KEY` para cifrar/descifrar... en realidad ni siquiera lo desencripta, solo lo almacena y reenvía.
- **`interfaz.py`** — Panel Master en Streamlit. Corre en la PC/servidor del administrador. Consume `api.py` por HTTP.
- **`worker.py`** — Agente que corre en cada máquina worker (Windows). Hace *polling* saliente a la API (heartbeat, obtener tarea, enviar logs, finalizar) — nunca abre puertos entrantes, así que funciona detrás de cualquier firewall/NAT. Clona el repo del proyecto y ejecuta el robot como subproceso.
- **`tick_scheduler.py`** — Disparador externo de schedules CRON (el plan free de Render no tiene cron jobs propios; hay que correr esto en algún sitio o usar un servicio externo que llame a `POST /api/schedules/tick`).
- **`setup_inicial.py`** — Script de un solo uso para generar `FERNET_KEY`, `JWT_SECRET_MASTER`, `JWT_SECRET_WORKER` y el hash bcrypt de la contraseña Master.

No hay tests automatizados en el repo.

## Comandos de desarrollo

Cada componente tiene su propio `requirements_*.txt` y `*.env` — no hay un entorno único compartido.

```bash
# API (local)
pip install -r requirements_api.txt
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
# healthcheck: GET /health

# Interfaz Master (Streamlit)
pip install -r requirements_interfaz.txt
streamlit run interfaz.py         # o doble clic en ejecutar_interfaz.bat (crea venv solo la 1a vez)

# Worker
pip install -r requirements_worker.txt
python worker.py                  # o ejecutar_worker.bat
# para varias instancias en la misma máquina: usar distintos worker.env

# Generar secretos (una sola vez, antes de desplegar la API)
python setup_inicial.py

# Scheduler externo de CRON (solo si no hay cron pago en Render)
python tick_scheduler.py
```

Variables de entorno requeridas por componente están en `api.env`, `interfaz.env`, `worker.env` (nunca se suben a Git). La `FERNET_KEY` **debe ser idéntica** en los tres componentes o el cifrado de credenciales se rompe de forma irrecuperable.

Despliegue de la API: `render.yaml` (Blueprint de Render.com). Build: `pip install -r requirements_api.txt`. Start: `uvicorn api:app --host 0.0.0.0 --port $PORT --workers 1`.

## Arquitectura y flujo

```
interfaz.py (Streamlit) ──HTTPS──► api.py (FastAPI+Mongo, Render) ◄──polling HTTPS── worker.py (Windows)
```

- El **worker nunca es contactado directamente**; todo pasa por polling saliente hacia la API (`/api/worker/heartbeat`, `/api/worker/obtener_tarea`, `/api/worker/logs`, `/api/worker/finalizar_tarea`).
- **Autenticación**: JWT separado para Master (`JWT_SECRET_MASTER`) y Worker (`JWT_SECRET_WORKER`), más API Keys (`rpak_…`) para acceso programático (CI/CD, `tick_scheduler.py`).
- **Credenciales de robots** viajan cifradas extremo a extremo con Fernet (misma clave en los 3 componentes). La API solo almacena/reenvía el blob cifrado; nunca lo desencripta.
- **Ciclo de vida de una tarea**: `pendiente → ejecutando → (completada | error | cancelada)`, con estados adicionales `pausada` (pausa puntual), `cancelando` (STOP en curso) y `esperando` (dependencias DAG pendientes vía `depende_de`, se libera automáticamente al completarse).
- **Asignación de tareas**: manual (`POST /api/tareas`, worker elegido explícitamente) o automática con balanceo de carga (`POST /api/tareas/auto`, elige el worker conectado con menor carga, opcionalmente restringido a un **pool**).
- **Ejecución en el worker** (`ejecutar_tarea` en `worker.py`): clona el repo del proyecto (con `git_ref` opcional para pin de rama/tag/commit), inyecta `env_vars` del proyecto + overrides por tarea a un `.env`, desencripta credenciales si las hay, instala `requirements.txt` si está especificado, corre el archivo principal como subproceso, transmite logs por streaming y reporta métricas de salud (CPU/RAM/disco) en cada heartbeat.
- **Compatibilidad hacia atrás intencional**: los campos añadidos en v3 (`git_ref`, `env_vars`, métricas de salud) son opcionales; un worker más antiguo debe seguir funcionando contra la API actual degradando con elegancia.

### `api.py`

Un único archivo FastAPI con todos los endpoints agrupados por tag (`Auth`, `Usuarios`, `API Keys`, `Workers`, `Pools`, `Proyectos`, `Tareas`, `Schedules`, `Webhooks`, `Plantillas`, `Biblioteca`, `Notificaciones`, `Auditoría`, `Config`, `Métricas`, `Worker`, `Sistema`, `Backup`, `Health`). Colecciones de Mongo se acceden vía Motor (`AsyncIOMotorDatabase`) inyectado por dependencia. Cada acción del Master queda registrada en el log de auditoría (`/api/audit`).

### `interfaz.py`

Streamlit de una sola página con navegación por secciones. El registro central está en el diccionario `SECCIONES` (nombre de sección → función `_render_*`), agrupado para el sidebar en `GRUPOS_NAV`. Para añadir una sección nueva: crear la función `_render_xxx`, añadirla a `SECCIONES` y listarla en el grupo correspondiente de `GRUPOS_NAV`. La navegación programática (p. ej. desde resultados de búsqueda global) se hace vía `st.session_state["_goto"]`, resuelta en `main()`.

### `worker.py`

Bucle principal (`bucle_principal`) que hace polling: autentica, pide la siguiente tarea, la ejecuta en un subproceso monitoreado (`ejecutar_tarea`), reporta logs incrementalmente y finaliza. `_thread_heartbeat` corre en paralelo reportando salud/disponibilidad. `aplicar_comando` maneja comandos remotos (pausa, cancelación) recibidos vía el resultado del heartbeat/obtener_tarea.

## Notas importantes

- Los tres componentes deben mantenerse compatibles entre sí en el contrato de endpoints worker↔API; cambiar `api.py` sin considerar `interfaz.py`/`worker.py` puede romper el sistema en producción (según el propio README: "No editar sin actualizar la UI/worker").
- El plan free de Render no incluye cron jobs — los schedules CRON dependen de un disparador externo (`tick_scheduler.py` o un servicio de cron externo) llamando a `POST /api/schedules/tick`.
- Archivos `*.env` nunca deben subirse a control de versiones.

"""
api.py — RPA Orchestration Master API v3.0
FastAPI + MongoDB Atlas — Production Ready
Compatible: Python 3.11+, Windows 10/11, Render.com

═══════════════════════════════════════════════════════════════════
NOVEDADES v3.0 (sobre v2.0)
═══════════════════════════════════════════════════════════════════
  + Dependencias entre tareas (DAG): tarea B espera a que A termine
  + Auto-asignación con balanceo de carga (worker menos cargado)
  + Worker Pools (grupos de workers para reparto automático)
  + Métricas de salud del worker (CPU / RAM / Disco) en heartbeat
  + Variables de entorno por proyecto (env_vars) inyectadas al robot
  + Pinning de rama/commit Git por tarea o proyecto (git_ref)
  + Pausa global del orquestador (detiene asignación de nuevas tareas)
  + Notificaciones in-app con severidad y marcado de leídas
  + Auditoría completa (audit log) de todas las acciones del Master
  + API Keys para acceso programático (CI/CD, scripts)
  + Alertas SLA: marca tareas que exceden su tiempo máximo
  + Alertas por correo (SMTP) además de webhooks
  + Búsqueda dentro de logs (grep)
  + Relanzar tarea con la misma configuración (1 clic)
  + Duplicar proyecto
  + Editar schedules existentes
  + Test de webhook (ping de prueba)
  + Exportación a CSV de tareas y métricas
  + Métricas globales con series de tiempo (throughput diario)
  + Plantillas de lanzamiento reutilizables
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import csv
import hashlib
import io
import logging
import os
import secrets
import smtplib
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from typing import Any, Optional

import bcrypt
import jwt
from bson import ObjectId
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, Security, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pydantic import BaseModel, Field, field_validator
from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("rpa.api")


# ─────────────────────────────────────────────
# CONFIGURACIÓN DE ENTORNO
# ─────────────────────────────────────────────

def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        logger.critical(f"Variable de entorno requerida no definida: {name}")
        raise RuntimeError(f"Variable de entorno requerida no definida: {name}")
    return value


MONGO_URL: str = _require_env("MONGO_URL")
JWT_SECRET_MASTER: str = _require_env("JWT_SECRET_MASTER")
JWT_SECRET_WORKER: str = _require_env("JWT_SECRET_WORKER")
FERNET_KEY: str = _require_env("FERNET_KEY")
MASTER_USERNAME: str = _require_env("MASTER_USERNAME")
MASTER_PASSWORD_HASH: str = _require_env("MASTER_PASSWORD_HASH")
MAX_LOG_SIZE_MB: int = int(os.getenv("MAX_LOG_SIZE_MB", "20"))
WORKER_TIMEOUT_SECONDS: int = int(os.getenv("WORKER_TIMEOUT_SECONDS", "120"))
JWT_EXPIRY_HOURS: int = int(os.getenv("JWT_EXPIRY_HOURS", "24"))
WEBHOOK_TIMEOUT: int = int(os.getenv("WEBHOOK_TIMEOUT", "10"))

# SMTP (opcional — si no se configura, las alertas por correo se omiten)
SMTP_HOST: str = os.getenv("SMTP_HOST", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM: str = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_TLS: bool = os.getenv("SMTP_TLS", "true").lower() == "true"

fernet = Fernet(FERNET_KEY.encode())

# ─────────────────────────────────────────────
# MONGODB
# ─────────────────────────────────────────────

_mongo_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


async def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Base de datos no inicializada")
    return _db


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _mongo_client, _db
    logger.info("Iniciando conexión a MongoDB Atlas...")
    _mongo_client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=10000)
    _db = _mongo_client["rpa_cajasan"]

    # Índices base
    await _db["usuarios_worker"].create_index("username", unique=True)
    await _db["proyectos"].create_index("nombre", unique=True)
    await _db["tareas"].create_index("id_tarea", unique=True)
    await _db["tareas"].create_index([("worker_asignado", ASCENDING), ("estado", ASCENDING)])
    await _db["tareas"].create_index([("estado", ASCENDING), ("fecha_creacion", DESCENDING)])
    await _db["tareas"].create_index([("id_proyecto", ASCENDING), ("estado", ASCENDING)])
    await _db["tareas"].create_index([("fecha_creacion", DESCENDING)])
    await _db["tareas"].create_index([("prioridad", DESCENDING), ("fecha_creacion", ASCENDING)])
    # Índices v3.0
    await _db["schedules"].create_index("id_schedule", unique=True)
    await _db["schedules"].create_index("proxima_ejecucion")
    await _db["webhooks"].create_index("id_webhook", unique=True)
    await _db["metricas_diarias"].create_index([("fecha", ASCENDING), ("id_proyecto", ASCENDING)], unique=True)
    await _db["audit_log"].create_index([("ts", DESCENDING)])
    await _db["notificaciones"].create_index([("ts", DESCENDING)])
    await _db["notificaciones"].create_index("leida")
    await _db["api_keys"].create_index("key_hash", unique=True)
    await _db["pools"].create_index("nombre", unique=True)
    await _db["plantillas"].create_index("nombre", unique=True)
    await _db["config_global"].create_index("_id")
    # v3.5: usuarios master + biblioteca de archivos
    await _db["usuarios_master"].create_index("username", unique=True)
    await _db["biblioteca_archivos"].create_index([("fecha_creacion", DESCENDING)])
    # TTL: auditoría y notificaciones se autolimpian a los 90 días (evita llenar Atlas free)
    try:
        await _db["audit_log"].create_index("ts_dt", expireAfterSeconds=90 * 24 * 3600)
        await _db["notificaciones"].create_index("ts_dt", expireAfterSeconds=90 * 24 * 3600)
    except Exception as _e:
        logger.warning(f"No se pudo crear índice TTL: {_e}")

    # Config global por defecto
    cfg = await _db["config_global"].find_one({"_id": "global"})
    if not cfg:
        await _db["config_global"].insert_one({
            "_id": "global",
            "pausa_global": False,
            "email_alertas": [],
            "email_eventos": ["tarea_error", "worker_desconectado"],
            "sla_global_segundos": 0,
        })

    logger.info("MongoDB Atlas conectado y colecciones indexadas (v3.0).")
    yield
    if _mongo_client:
        _mongo_client.close()
        logger.info("Conexión MongoDB cerrada.")


# ─────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────

app = FastAPI(
    title="RPA Orchestration API",
    version="3.0.0",
    description="Sistema de Orquestación RPA Master-Worker — Cajasan USE TECNOLOGÍA",
    lifespan=lifespan,
)

_origins_env = os.getenv("ALLOWED_ORIGINS", "*").strip()
_allowed_origins = ["*"] if _origins_env == "*" else [o.strip() for o in _origins_env.split(",") if o.strip()]
_allow_creds = _allowed_origins != ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=_allow_creds,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _seguridad_y_roles(request: Request, call_next):
    """Control de roles por método/ruta + cabeceras de seguridad."""
    metodo = request.method
    path = request.url.path
    libres = path in ("/health", "/", "/docs", "/redoc", "/openapi.json") \
        or path.startswith("/api/auth/") or path.startswith("/api/worker/")

    if not libres and metodo in ("POST", "PUT", "PATCH", "DELETE"):
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:]
            if not tok.startswith("rpak_"):
                try:
                    payload = jwt.decode(tok, JWT_SECRET_MASTER, algorithms=["HS256"],
                                         options={"verify_exp": False})
                    rol = payload.get("rol", "admin")
                    if rol == "visor":
                        return JSONResponse(status_code=403,
                                            content={"detail": "Tu rol (visor) es de solo lectura."})
                    if rol != "admin" and path.startswith("/api/usuarios"):
                        return JSONResponse(status_code=403,
                                            content={"detail": "Solo un administrador puede gestionar usuarios."})
                except Exception:
                    pass

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


security = HTTPBearer()


# ─────────────────────────────────────────────
# JWT / AUTH HELPERS
# ─────────────────────────────────────────────

def _create_jwt(payload: dict, secret: str, hours: int = JWT_EXPIRY_HOURS) -> str:
    payload = payload.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=hours)
    payload["iat"] = datetime.now(timezone.utc)
    payload["jti"] = secrets.token_hex(16)  # id único del token (para revocación)
    return jwt.encode(payload, secret, algorithm="HS256")


def _decode_jwt(token: str, secret: str) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Token inválido: {e}")


# ── Revocación de tokens (logout) — en memoria ──
_TOKENS_REVOCADOS: set[str] = set()

# ── Rate limiting / bloqueo por intentos fallidos de login — en memoria ──
_INTENTOS_LOGIN: dict[str, list[float]] = {}        # clave -> timestamps de intentos
_BLOQUEOS_LOGIN: dict[str, float] = {}              # clave -> timestamp hasta el que está bloqueada
RATE_MAX_INTENTOS = int(os.getenv("RATE_MAX_INTENTOS", "5"))      # intentos permitidos
RATE_VENTANA_SEG = int(os.getenv("RATE_VENTANA_SEG", "300"))      # ventana de conteo (5 min)
RATE_BLOQUEO_SEG = int(os.getenv("RATE_BLOQUEO_SEG", "900"))      # duración del bloqueo (15 min)


def _rate_check(clave: str) -> Optional[int]:
    """Devuelve segundos restantes de bloqueo si la clave está bloqueada, o None si puede intentar."""
    import time as _t
    ahora = _t.time()
    hasta = _BLOQUEOS_LOGIN.get(clave)
    if hasta and ahora < hasta:
        return int(hasta - ahora)
    if hasta and ahora >= hasta:
        _BLOQUEOS_LOGIN.pop(clave, None)
        _INTENTOS_LOGIN.pop(clave, None)
    return None


def _rate_fallo(clave: str) -> None:
    """Registra un intento fallido; bloquea si supera el máximo en la ventana."""
    import time as _t
    ahora = _t.time()
    intentos = [t for t in _INTENTOS_LOGIN.get(clave, []) if ahora - t < RATE_VENTANA_SEG]
    intentos.append(ahora)
    _INTENTOS_LOGIN[clave] = intentos
    if len(intentos) >= RATE_MAX_INTENTOS:
        _BLOQUEOS_LOGIN[clave] = ahora + RATE_BLOQUEO_SEG


def _rate_exito(clave: str) -> None:
    """Limpia el contador tras un login exitoso."""
    _INTENTOS_LOGIN.pop(clave, None)
    _BLOQUEOS_LOGIN.pop(clave, None)


async def _verify_master(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """Acepta JWT de master O una API Key válida (prefijo 'rpak_')."""
    token = credentials.credentials
    # API key
    if token.startswith("rpak_"):
        db = await get_db()
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        doc = await db["api_keys"].find_one({"key_hash": key_hash, "activa": True})
        if not doc:
            raise HTTPException(status_code=401, detail="API Key inválida o revocada")
        await db["api_keys"].update_one(
            {"_id": doc["_id"]}, {"$set": {"ultima_uso": _now_iso()}}
        )
        return {"sub": doc.get("nombre", "apikey"), "role": "master", "rol": "admin", "via": "apikey"}
    # JWT
    payload = _decode_jwt(token, JWT_SECRET_MASTER)
    if payload.get("role") != "master":
        raise HTTPException(status_code=403, detail="Acceso restringido a Master")
    if payload.get("jti") in _TOKENS_REVOCADOS:
        raise HTTPException(status_code=401, detail="Sesión cerrada. Vuelve a iniciar sesión.")
    payload.setdefault("rol", "admin")  # compat: tokens viejos sin rol = admin
    return payload


async def _verify_admin(payload: dict = Depends(_verify_master)) -> dict:
    """Restringe a usuarios con rol 'admin'."""
    if payload.get("rol") != "admin":
        raise HTTPException(status_code=403, detail="Acción reservada a administradores")
    return payload


def _verify_worker(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    payload = _decode_jwt(credentials.credentials, JWT_SECRET_WORKER)
    if payload.get("role") != "worker":
        raise HTTPException(status_code=403, detail="Acceso restringido a Worker")
    return payload


# ─────────────────────────────────────────────
# HELPERS INTERNOS
# ─────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _bytes_from_entries(entries: list[dict]) -> int:
    return sum(len(str(e).encode("utf-8")) for e in entries)


def _truncar_logs_fifo(logs: list[dict], max_bytes: int) -> list[dict]:
    while logs and _bytes_from_entries(logs) > max_bytes:
        logs.pop(0)
    return logs


async def _audit(db: AsyncIOMotorDatabase, usuario: str, accion: str, recurso: str, detalle: str = "") -> None:
    """Registra una acción en el log de auditoría."""
    try:
        await db["audit_log"].insert_one({
            "ts": _now_iso(), "ts_dt": _now_dt(), "usuario": usuario,
            "accion": accion, "recurso": recurso, "detalle": detalle,
        })
    except Exception as e:
        logger.warning(f"No se pudo registrar auditoría: {e}")


async def _notificar(db: AsyncIOMotorDatabase, tipo: str, mensaje: str, severidad: str = "info") -> None:
    """Crea una notificación in-app. Severidad: info | warning | error | success."""
    try:
        await db["notificaciones"].insert_one({
            "id_notif": str(uuid.uuid4()),
            "ts": _now_iso(), "ts_dt": _now_dt(), "tipo": tipo,
            "mensaje": mensaje, "severidad": severidad, "leida": False,
        })
    except Exception as e:
        logger.warning(f"No se pudo crear notificación: {e}")


async def _config_global(db: AsyncIOMotorDatabase) -> dict:
    cfg = await db["config_global"].find_one({"_id": "global"})
    return cfg or {}


def _enviar_email(destinatarios: list[str], asunto: str, cuerpo: str) -> bool:
    """Envía un correo vía SMTP si está configurado. Retorna True si se envió."""
    if not SMTP_HOST or not destinatarios:
        return False
    try:
        msg = MIMEText(cuerpo, "plain", "utf-8")
        msg["Subject"] = asunto
        msg["From"] = SMTP_FROM or SMTP_USER
        msg["To"] = ", ".join(destinatarios)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM or SMTP_USER, destinatarios, msg.as_string())
        logger.info(f"Correo enviado a {destinatarios}: {asunto}")
        return True
    except Exception as e:
        logger.warning(f"Fallo al enviar correo: {e}")
        return False


async def _disparar_webhooks(db: AsyncIOMotorDatabase, evento: str, payload: dict) -> None:
    """Dispara webhooks (con firma HMAC opcional y reintentos acotados) + correos."""
    import httpx
    import hmac as _hmac
    import hashlib as _hashlib
    cursor = db["webhooks"].find({"activo": True, "eventos": evento})
    async for wh in cursor:
        url = wh.get("url", "")
        cuerpo = {"evento": evento, "data": payload, "ts": _now_iso()}
        cuerpo_bytes = json.dumps(cuerpo, ensure_ascii=False).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "RPA-Orchestrator-Webhook"}
        # Firma HMAC-SHA256 si el webhook tiene secreto
        secreto = wh.get("secreto")
        if secreto:
            firma = _hmac.new(secreto.encode(), cuerpo_bytes, _hashlib.sha256).hexdigest()
            headers["X-RPA-Signature"] = f"sha256={firma}"
        # Hasta 3 intentos con espera breve (ligero, sin proceso en segundo plano)
        enviado = False
        for intento in range(3):
            try:
                async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
                    resp = await client.post(url, content=cuerpo_bytes, headers=headers)
                if resp.status_code < 500:
                    enviado = True
                    logger.info(f"Webhook disparado: {evento} → {url} ({resp.status_code})")
                    break
            except Exception as e:
                logger.warning(f"Webhook intento {intento+1} falló ({url}): {e}")
            if intento < 2:
                await asyncio.sleep(1.5 * (intento + 1))
        if not enviado:
            # Registrar fallo (acotado) para diagnóstico, sin reintentar en segundo plano
            await db["webhooks"].update_one(
                {"id_webhook": wh["id_webhook"]},
                {"$set": {"ultimo_fallo": _now_iso()}, "$inc": {"fallos_totales": 1}})

    # Correo
    cfg = await _config_global(db)
    if evento in cfg.get("email_eventos", []) and cfg.get("email_alertas"):
        asunto = f"[RPA Orchestrator] {evento}"
        cuerpo_mail = f"Evento: {evento}\n\n" + "\n".join(f"{k}: {v}" for k, v in payload.items())
        _enviar_email(cfg["email_alertas"], asunto, cuerpo_mail)


async def _registrar_metrica(db: AsyncIOMotorDatabase, id_proyecto: str, estado_final: str, duracion_seg: float) -> None:
    hoy = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    inc: dict[str, Any] = {"total": 1}
    if estado_final == "completada":
        inc["completadas"] = 1
        inc["duracion_total_seg"] = duracion_seg
    elif estado_final == "error":
        inc["errores"] = 1
    elif estado_final == "cancelada":
        inc["canceladas"] = 1
    await db["metricas_diarias"].update_one(
        {"fecha": hoy, "id_proyecto": id_proyecto},
        {"$inc": inc, "$setOnInsert": {"fecha": hoy, "id_proyecto": id_proyecto}},
        upsert=True,
    )


async def _carga_worker(db: AsyncIOMotorDatabase, worker_id: str) -> int:
    """Devuelve la 'carga' de un worker = tareas en cola + (1 si ocupado)."""
    w = await db["usuarios_worker"].find_one({"_id": ObjectId(worker_id)})
    if not w:
        return 9999
    carga = len(w.get("cola_tareas", []))
    if w.get("tarea_actual"):
        carga += 1
    return carga


async def _mejor_worker(db: AsyncIOMotorDatabase, candidatos_ids: Optional[list[str]] = None) -> Optional[dict]:
    """Selecciona el worker conectado con menor carga. Si candidatos_ids se da, restringe a ese conjunto."""
    filtro: dict[str, Any] = {"estado": {"$in": ["disponible", "ocupado"]},
                              "en_mantenimiento": {"$ne": True}}  # excluir en mantenimiento
    if candidatos_ids:
        filtro["_id"] = {"$in": [ObjectId(x) for x in candidatos_ids]}
    mejor = None
    mejor_carga = 10**9
    async for w in db["usuarios_worker"].find(filtro):
        carga = len(w.get("cola_tareas", []))
        if w.get("tarea_actual"):
            carga += 1
        # preferir disponibles
        if w["estado"] == "disponible":
            carga -= 0.5
        if carga < mejor_carga:
            mejor_carga = carga
            mejor = w
    return mejor


async def _procesar_siguiente_tarea(db: AsyncIOMotorDatabase, worker_id: str) -> None:
    # Respetar pausa global
    cfg = await _config_global(db)
    if cfg.get("pausa_global"):
        return

    worker = await db["usuarios_worker"].find_one({"_id": ObjectId(worker_id)})
    if not worker:
        return
    cola: list[str] = worker.get("cola_tareas", [])
    if not cola:
        await db["usuarios_worker"].update_one(
            {"_id": ObjectId(worker_id)},
            {"$set": {"estado": "disponible", "tarea_actual": None}},
        )
        return

    siguiente_id = cola[0]
    tarea = await db["tareas"].find_one({"id_tarea": siguiente_id})
    if not tarea or tarea.get("estado") not in ("pendiente", "esperando"):
        await db["usuarios_worker"].update_one(
            {"_id": ObjectId(worker_id)}, {"$pull": {"cola_tareas": siguiente_id}},
        )
        await _procesar_siguiente_tarea(db, worker_id)
        return

    # Verificar dependencias
    deps = tarea.get("depende_de", [])
    if deps and not await _dependencias_satisfechas(db, deps):
        # dejar en espera y pasar a la siguiente
        await db["tareas"].update_one(
            {"id_tarea": siguiente_id}, {"$set": {"estado": "esperando"}}
        )
        # rotar la cola para no bloquear
        await db["usuarios_worker"].update_one(
            {"_id": ObjectId(worker_id)},
            {"$pull": {"cola_tareas": siguiente_id}},
        )
        await db["usuarios_worker"].update_one(
            {"_id": ObjectId(worker_id)},
            {"$push": {"cola_tareas": siguiente_id}},
        )
        # intentar siguiente solo si quedan otras
        cola_restante = [x for x in cola if x != siguiente_id]
        if cola_restante:
            await _procesar_siguiente_tarea(db, worker_id)
        return

    # Límite de concurrencia por proyecto: si el proyecto ya tiene el máximo ejecutándose, esperar
    proy = await db["proyectos"].find_one({"_id": ObjectId(tarea["id_proyecto"])}, {"max_concurrencia": 1})
    max_conc = (proy or {}).get("max_concurrencia", 0)
    if max_conc and max_conc > 0:
        en_curso = await db["tareas"].count_documents(
            {"id_proyecto": tarea["id_proyecto"], "estado": "ejecutando"})
        if en_curso >= max_conc:
            # rotar la cola: dejar esta para después y probar la siguiente
            cola_restante = [x for x in cola if x != siguiente_id]
            if cola_restante:
                await db["usuarios_worker"].update_one(
                    {"_id": ObjectId(worker_id)}, {"$pull": {"cola_tareas": siguiente_id}})
                await db["usuarios_worker"].update_one(
                    {"_id": ObjectId(worker_id)}, {"$push": {"cola_tareas": siguiente_id}})
                await _procesar_siguiente_tarea(db, worker_id)
            else:
                await db["usuarios_worker"].update_one(
                    {"_id": ObjectId(worker_id)}, {"$set": {"estado": "disponible", "tarea_actual": None}})
            return

    ahora = _now_iso()
    await db["tareas"].update_one(
        {"id_tarea": siguiente_id},
        {"$set": {"estado": "ejecutando", "fecha_inicio": ahora, "comando_pendiente": "NONE"}},
    )
    await db["usuarios_worker"].update_one(
        {"_id": ObjectId(worker_id)},
        {"$set": {"estado": "ocupado", "tarea_actual": siguiente_id}, "$pull": {"cola_tareas": siguiente_id}},
    )
    logger.info(f"Siguiente tarea asignada: {siguiente_id} → Worker {worker_id}")


async def _dependencias_satisfechas(db: AsyncIOMotorDatabase, deps: list[str]) -> bool:
    """True si todas las tareas de las que depende terminaron en 'completada'."""
    for dep_id in deps:
        t = await db["tareas"].find_one({"id_tarea": dep_id}, {"estado": 1})
        if not t or t.get("estado") != "completada":
            return False
    return True


async def _resolver_dependientes(db: AsyncIOMotorDatabase, tarea_completada_id: str) -> int:
    """Tras completar una tarea, libera las que dependían de ella si ya no tienen pendientes."""
    liberadas = 0
    cursor = db["tareas"].find({"estado": "esperando", "depende_de": tarea_completada_id})
    async for t in cursor:
        if await _dependencias_satisfechas(db, t.get("depende_de", [])):
            await db["tareas"].update_one(
                {"id_tarea": t["id_tarea"]}, {"$set": {"estado": "pendiente"}}
            )
            liberadas += 1
            logger.info(f"Tarea {t['id_tarea']} liberada (dependencias satisfechas)")
    return liberadas


async def _manejar_reintento(db: AsyncIOMotorDatabase, tarea: dict, estado_final: str) -> None:
    max_reintentos = tarea.get("max_reintentos", 0)
    reintento_actual = tarea.get("reintento_num", 0)
    if estado_final != "error" or reintento_actual >= max_reintentos:
        return

    siguiente_reintento = reintento_actual + 1
    espera_seg = min(60 * (2 ** reintento_actual), 3600)
    nueva_tarea_id = str(uuid.uuid4())
    ahora = _now_iso()
    doc_tarea = {
        "id_tarea": nueva_tarea_id, "id_proyecto": tarea["id_proyecto"],
        "worker_asignado": tarea["worker_asignado"], "estado": "pendiente",
        "credenciales_encriptadas": tarea.get("credenciales_encriptadas"),
        "fecha_creacion": ahora, "fecha_inicio": None, "fecha_fin": None,
        "logs": [{"ts": ahora, "stream": "system",
                  "msg": f"[REINTENTO {siguiente_reintento}/{max_reintentos}] Espera: {espera_seg}s. Original: {tarea['id_tarea']}"}],
        "log_size_bytes": 0, "ultima_actualizacion_log": None, "comando_pendiente": "NONE",
        "prioridad": tarea.get("prioridad", 0), "tags": tarea.get("tags", []),
        "notas": tarea.get("notas", ""), "max_reintentos": max_reintentos,
        "reintento_num": siguiente_reintento,
        "tarea_padre_id": tarea.get("tarea_padre_id") or tarea["id_tarea"],
        "programada_para": (datetime.now(timezone.utc) + timedelta(seconds=espera_seg)).isoformat(),
        "depende_de": tarea.get("depende_de", []), "git_ref": tarea.get("git_ref"),
        "env_override": tarea.get("env_override", {}), "sla_segundos": tarea.get("sla_segundos", 0),
    }
    await db["tareas"].insert_one(doc_tarea)
    await db["usuarios_worker"].update_one(
        {"_id": ObjectId(tarea["worker_asignado"])}, {"$push": {"cola_tareas": nueva_tarea_id}},
    )
    logger.info(f"Reintento {siguiente_reintento} programado: {nueva_tarea_id} (espera {espera_seg}s)")


async def _ejecutar_limpieza_interna(db: AsyncIOMotorDatabase) -> tuple[int, int]:
    workers_col = db["usuarios_worker"]
    tareas_col = db["tareas"]
    desconectados = 0
    errores = 0

    cursor = workers_col.find({"estado": {"$in": ["disponible", "ocupado"]}})
    async for worker in cursor:
        ultima = worker.get("ultima_conexion")
        if not ultima:
            continue
        if isinstance(ultima, str):
            try:
                ultima_dt = datetime.fromisoformat(ultima)
                if ultima_dt.tzinfo is None:
                    ultima_dt = ultima_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        else:
            ultima_dt = ultima

        if _now_dt() - ultima_dt > timedelta(seconds=WORKER_TIMEOUT_SECONDS):
            worker_id = str(worker["_id"])
            tarea_id = worker.get("tarea_actual")
            await workers_col.update_one(
                {"_id": worker["_id"]},
                {"$set": {"estado": "desconectado", "tarea_actual": None, "cola_tareas": []}},
            )
            desconectados += 1
            logger.warning(f"Worker desconectado: {worker_id}")
            await _notificar(db, "worker_desconectado",
                             f"Worker {worker.get('username', worker_id)} sin heartbeat (>{WORKER_TIMEOUT_SECONDS}s)",
                             "warning")
            await _disparar_webhooks(db, "worker_desconectado",
                                     {"worker_id": worker_id, "username": worker.get("username")})

            if tarea_id:
                tarea = await tareas_col.find_one({"id_tarea": tarea_id})
                resultado = await tareas_col.update_one(
                    {"id_tarea": tarea_id, "estado": {"$in": ["ejecutando", "pausada", "cancelando"]}},
                    {"$set": {"estado": "error", "fecha_fin": _now_iso()},
                     "$push": {"logs": {"ts": _now_iso(), "stream": "system",
                                        "msg": f"Worker {worker_id} desconectado. Tarea marcada como error."}}},
                )
                if resultado.modified_count > 0:
                    errores += 1
                    if tarea:
                        await _manejar_reintento(db, tarea, "error")

    return desconectados, errores


async def _chequear_sla(db: AsyncIOMotorDatabase) -> int:
    """Marca alerta en tareas en ejecución que superaron su SLA. Retorna número de alertas."""
    cfg = await _config_global(db)
    sla_global = cfg.get("sla_global_segundos", 0)
    alertas = 0
    cursor = db["tareas"].find({"estado": "ejecutando", "sla_alertado": {"$ne": True}})
    async for t in cursor:
        sla = t.get("sla_segundos", 0) or sla_global
        if sla <= 0:
            continue
        inicio = t.get("fecha_inicio")
        if not inicio:
            continue
        try:
            dt_i = datetime.fromisoformat(inicio)
            if dt_i.tzinfo is None:
                dt_i = dt_i.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        transcurrido = (_now_dt() - dt_i).total_seconds()
        if transcurrido > sla:
            await db["tareas"].update_one({"id_tarea": t["id_tarea"]}, {"$set": {"sla_alertado": True}})
            await _notificar(db, "sla_excedido",
                             f"Tarea {t['id_tarea'][:8]} excedió su SLA ({sla}s, lleva {int(transcurrido)}s)",
                             "error")
            alertas += 1
    return alertas


# ─────────────────────────────────────────────
# MODELOS PYDANTIC
# ─────────────────────────────────────────────

class MasterLoginRequest(BaseModel):
    username: str
    password: str

class MasterLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class WorkerLoginRequest(BaseModel):
    username: str
    password: str

class WorkerLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    worker_id: str

class CrearWorkerRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    etiqueta: Optional[str] = None
    pool: Optional[str] = None

class ActualizarWorkerRequest(BaseModel):
    en_mantenimiento: Optional[bool] = None
    etiqueta: Optional[str] = None
    pool: Optional[str] = None

class CambiarPasswordWorkerRequest(BaseModel):
    nueva_password: str = Field(..., min_length=8)

class WorkerInfo(BaseModel):
    en_mantenimiento: bool = False  # se rellena vía .get en el serializador
    id: str
    username: str
    estado: str
    etiqueta: Optional[str] = None
    pool: Optional[str] = None
    ultima_conexion: Optional[str] = None
    tarea_actual: Optional[str] = None
    cola_tareas: list[str] = []
    fecha_creacion: str
    tareas_completadas: int = 0
    tareas_error: int = 0
    cpu_percent: Optional[float] = None
    ram_percent: Optional[float] = None
    disk_percent: Optional[float] = None

class ArchivoAdjunto(BaseModel):
    """Archivo de configuración inyectado en el repo del robot antes de ejecutar.
    Permite que el robot reciba config.json, settings.yaml, cuentas.txt, etc.,
    con el nombre y la ruta que necesite, sin pasar por GitHub."""
    nombre_archivo: str = Field(..., min_length=1, max_length=200,
                                description="Nombre exacto que tendrá en el repo, ej. config.json")
    contenido: str = Field(default="", description="Contenido (texto o base64). Cifrado si 'encriptado'=True")
    encriptado: bool = Field(default=False, description="Si True, 'contenido' viene cifrado con Fernet")
    es_binario: bool = Field(default=False, description="Si True, 'contenido' es base64 de un binario")
    subcarpeta: str = Field(default="", max_length=200,
                            description="Subcarpeta dentro del repo, ej. config/ (opcional)")

    @field_validator("nombre_archivo")
    @classmethod
    def _val_nombre(cls, v: str) -> str:
        v = v.strip().replace("\\", "/")
        if v.startswith("/") or ".." in v:
            raise ValueError("Nombre de archivo inválido (sin rutas absolutas ni '..')")
        return v

    @field_validator("subcarpeta")
    @classmethod
    def _val_sub(cls, v: str) -> str:
        v = (v or "").strip().replace("\\", "/").strip("/")
        if ".." in v:
            raise ValueError("Subcarpeta inválida")
        return v


class CrearProyectoRequest(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=100)
    descripcion: str = Field(..., min_length=5)
    git_url: str
    archivo_principal: str = Field(..., min_length=1)
    archivo_requirements: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    env_vars: dict[str, str] = Field(default_factory=dict)
    git_ref: Optional[str] = Field(default=None, description="Rama, tag o commit por defecto")
    archivos_adjuntos: list[ArchivoAdjunto] = Field(default_factory=list)
    max_concurrencia: int = Field(default=0, ge=0, le=50, description="Máx. tareas simultáneas del proyecto (0 = sin límite)")

    @field_validator("git_url")
    @classmethod
    def validar_git_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://github.com/"):
            raise ValueError("Solo repositorios públicos de GitHub (https://github.com/...)")
        return v

class ActualizarProyectoRequest(BaseModel):
    descripcion: Optional[str] = None
    git_url: Optional[str] = None
    archivo_principal: Optional[str] = None
    archivo_requirements: Optional[str] = None
    tags: Optional[list[str]] = None
    env_vars: Optional[dict[str, str]] = None
    git_ref: Optional[str] = None
    archivos_adjuntos: Optional[list[ArchivoAdjunto]] = None
    max_concurrencia: Optional[int] = Field(default=None, ge=0, le=50)
    favorito: Optional[bool] = None

    @field_validator("git_url")
    @classmethod
    def validar_git_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v.startswith("https://github.com/"):
                raise ValueError("Solo repositorios públicos de GitHub")
        return v

class ProyectoInfo(BaseModel):
    id: str
    nombre: str
    descripcion: str
    git_url: str
    archivo_principal: str
    archivo_requirements: str
    tags: list[str] = []
    env_vars: dict[str, str] = {}
    git_ref: Optional[str] = None
    archivos_adjuntos: list[ArchivoAdjunto] = []
    max_concurrencia: int = 0
    favorito: bool = False
    fecha_creacion: str

class LanzarTareaRequest(BaseModel):
    id_proyecto: str
    worker_id: str
    credenciales_encriptadas: Optional[str] = None
    prioridad: int = Field(default=0, ge=0, le=10)
    tags: list[str] = Field(default_factory=list)
    notas: Optional[str] = Field(default=None, max_length=2000)
    max_reintentos: int = Field(default=0, ge=0, le=5)
    depende_de: list[str] = Field(default_factory=list, description="IDs de tareas que deben completarse antes")
    git_ref: Optional[str] = None
    env_override: dict[str, str] = Field(default_factory=dict)
    sla_segundos: int = Field(default=0, ge=0, description="0 = sin límite")
    timeout_segundos: int = Field(default=0, ge=0, le=86400, description="Máx. ejecución (0 = usa default worker)")
    archivos_adjuntos: list[ArchivoAdjunto] = Field(default_factory=list)

class LanzarAutoRequest(BaseModel):
    id_proyecto: str
    pool: Optional[str] = Field(default=None, description="Restringir a workers de este pool")
    credenciales_encriptadas: Optional[str] = None
    prioridad: int = Field(default=0, ge=0, le=10)
    tags: list[str] = Field(default_factory=list)
    notas: Optional[str] = None
    max_reintentos: int = Field(default=0, ge=0, le=5)
    git_ref: Optional[str] = None
    env_override: dict[str, str] = Field(default_factory=dict)
    sla_segundos: int = Field(default=0, ge=0)
    timeout_segundos: int = Field(default=0, ge=0, le=86400)
    archivos_adjuntos: list[ArchivoAdjunto] = Field(default_factory=list)

class TareaInfo(BaseModel):
    id_tarea: str
    id_proyecto: str
    nombre_proyecto: Optional[str] = None
    worker_asignado: str
    worker_username: Optional[str] = None
    estado: str
    prioridad: int = 0
    tags: list[str] = []
    notas: Optional[str] = None
    max_reintentos: int = 0
    reintento_num: int = 0
    tarea_padre_id: Optional[str] = None
    depende_de: list[str] = []
    git_ref: Optional[str] = None
    sla_segundos: int = 0
    timeout_segundos: int = 0
    num_archivos_adjuntos: int = 0
    fecha_creacion: str
    fecha_inicio: Optional[str] = None
    fecha_fin: Optional[str] = None
    log_size_bytes: int = 0
    ultima_actualizacion_log: Optional[str] = None
    programada_para: Optional[str] = None

class AgregarNotaRequest(BaseModel):
    nota: str = Field(..., min_length=1, max_length=2000)

class HeartbeatRequest(BaseModel):
    worker_id: str
    estado: str
    logs: list[dict] = Field(default_factory=list)
    cpu_percent: Optional[float] = None
    ram_percent: Optional[float] = None
    disk_percent: Optional[float] = None

class HeartbeatResponse(BaseModel):
    comando: str = "NONE"
    tarea_id: Optional[str] = None

class ObtenerTareaResponse(BaseModel):
    tiene_tarea: bool
    tarea_id: Optional[str] = None
    id_proyecto: Optional[str] = None
    git_url: Optional[str] = None
    git_ref: Optional[str] = None
    archivo_principal: Optional[str] = None
    archivo_requirements: Optional[str] = None
    credenciales_encriptadas: Optional[str] = None
    env_vars: dict[str, str] = {}
    archivos_adjuntos: list[ArchivoAdjunto] = []
    timeout_segundos: int = 0

class ComandoTareaRequest(BaseModel):
    comando: str

class LogsRequest(BaseModel):
    id_tarea: str
    worker_id: str
    entries: list[dict]

class LogsResponse(BaseModel):
    id_tarea: str
    logs: list[dict]
    total_bytes: int

class FinalizarTareaRequest(BaseModel):
    id_tarea: str
    estado_final: str
    worker_id: str

# Schedules
class CrearScheduleRequest(BaseModel):
    id_proyecto: str
    worker_id: Optional[str] = Field(default=None, description="None = auto-asignar al mejor worker")
    pool: Optional[str] = None
    cron_expr: str
    credenciales_encriptadas: Optional[str] = None
    max_reintentos: int = Field(default=0, ge=0, le=5)
    prioridad: int = Field(default=0, ge=0, le=10)
    tags: list[str] = Field(default_factory=list)
    activo: bool = True
    descripcion: Optional[str] = None

class ActualizarScheduleRequest(BaseModel):
    cron_expr: Optional[str] = None
    descripcion: Optional[str] = None
    prioridad: Optional[int] = Field(default=None, ge=0, le=10)
    max_reintentos: Optional[int] = Field(default=None, ge=0, le=5)
    tags: Optional[list[str]] = None

class ScheduleInfo(BaseModel):
    id_schedule: str
    id_proyecto: str
    nombre_proyecto: Optional[str] = None
    worker_id: Optional[str] = None
    pool: Optional[str] = None
    cron_expr: str
    descripcion: Optional[str] = None
    activo: bool
    proxima_ejecucion: Optional[str] = None
    ultima_ejecucion: Optional[str] = None
    max_reintentos: int = 0
    prioridad: int = 0
    tags: list[str] = []
    fecha_creacion: str

# Webhooks
class CrearWebhookRequest(BaseModel):
    url: str
    eventos: list[str]
    descripcion: Optional[str] = None
    activo: bool = True
    secreto: Optional[str] = Field(default=None, max_length=200,
                                   description="Si se define, los envíos se firman con HMAC-SHA256 (cabecera X-RPA-Signature)")

    @field_validator("url")
    @classmethod
    def validar_url(cls, v: str) -> str:
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("URL debe comenzar con http:// o https://")
        return v

    @field_validator("eventos")
    @classmethod
    def validar_eventos(cls, v: list[str]) -> list[str]:
        validos = {"tarea_completada", "tarea_error", "tarea_cancelada", "worker_desconectado", "tarea_iniciada"}
        invalidos = set(v) - validos
        if invalidos:
            raise ValueError(f"Eventos inválidos: {invalidos}")
        return v

class WebhookInfo(BaseModel):
    id_webhook: str
    url: str
    eventos: list[str]
    descripcion: Optional[str] = None
    activo: bool
    fecha_creacion: str

class CancelarMasivaRequest(BaseModel):
    estado: Optional[str] = None
    worker_id: Optional[str] = None
    id_proyecto: Optional[str] = None

# Pools
class CrearPoolRequest(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=50)
    descripcion: Optional[str] = None
    worker_ids: list[str] = Field(default_factory=list)

class ActualizarPoolRequest(BaseModel):
    descripcion: Optional[str] = None
    worker_ids: Optional[list[str]] = None

class PoolInfo(BaseModel):
    id: str
    nombre: str
    descripcion: Optional[str] = None
    worker_ids: list[str] = []
    fecha_creacion: str

# API Keys
class CrearApiKeyRequest(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=50)

class ApiKeyCreada(BaseModel):
    id: str
    nombre: str
    api_key: str  # solo se muestra una vez
    fecha_creacion: str

class ApiKeyInfo(BaseModel):
    id: str
    nombre: str
    activa: bool
    ultima_uso: Optional[str] = None
    fecha_creacion: str

# Notificaciones
class NotificacionInfo(BaseModel):
    id_notif: str
    ts: str
    tipo: str
    mensaje: str
    severidad: str
    leida: bool

# Config
class ActualizarConfigRequest(BaseModel):
    pausa_global: Optional[bool] = None
    email_alertas: Optional[list[str]] = None
    email_eventos: Optional[list[str]] = None
    sla_global_segundos: Optional[int] = Field(default=None, ge=0)

# Plantillas
class CrearPlantillaRequest(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=60)
    id_proyecto: str
    pool: Optional[str] = None
    prioridad: int = Field(default=0, ge=0, le=10)
    max_reintentos: int = Field(default=0, ge=0, le=5)
    tags: list[str] = Field(default_factory=list)
    git_ref: Optional[str] = None
    sla_segundos: int = Field(default=0, ge=0)
    notas: Optional[str] = None
    archivos_adjuntos: list[ArchivoAdjunto] = Field(default_factory=list)

class PlantillaInfo(BaseModel):
    id: str
    nombre: str
    id_proyecto: str
    nombre_proyecto: Optional[str] = None
    pool: Optional[str] = None
    prioridad: int = 0
    max_reintentos: int = 0
    tags: list[str] = []
    git_ref: Optional[str] = None
    sla_segundos: int = 0
    notas: Optional[str] = None
    archivos_adjuntos: list[ArchivoAdjunto] = []
    fecha_creacion: str


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────

@app.post("/api/auth/master", response_model=MasterLoginResponse, tags=["Auth"])
async def login_master(body: MasterLoginRequest, request: Request,
                       db: AsyncIOMotorDatabase = Depends(get_db)) -> MasterLoginResponse:
    # Rate limiting / bloqueo por intentos fallidos (por IP + usuario)
    ip = request.client.host if request.client else "?"
    clave = f"{ip}:{body.username}"
    bloqueo = _rate_check(clave)
    if bloqueo is not None:
        raise HTTPException(status_code=429,
                            detail=f"Demasiados intentos fallidos. Intenta de nuevo en {bloqueo // 60 + 1} min.")

    nombre = body.username
    rol = "admin"
    autenticado = False

    # 1) Superadmin de variables de entorno (bootstrap, siempre rol admin)
    if body.username == MASTER_USERNAME and bcrypt.checkpw(body.password.encode(), MASTER_PASSWORD_HASH.encode()):
        autenticado = True
        rol = "admin"
        nombre = MASTER_USERNAME
    else:
        # 2) Usuarios de la colección usuarios_master
        u = await db["usuarios_master"].find_one({"username": body.username, "activo": True})
        if u and bcrypt.checkpw(body.password.encode(), u["password_hash"].encode()):
            autenticado = True
            rol = u.get("rol", "operador")
            nombre = u.get("nombre_completo") or u["username"]
            await db["usuarios_master"].update_one({"_id": u["_id"]}, {"$set": {"ultimo_acceso": _now_iso()}})

    if not autenticado:
        _rate_fallo(clave)
        await _audit(db, body.username, "login_fallido", "auth", f"Intento fallido desde {ip}")
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    _rate_exito(clave)
    token = _create_jwt({"sub": body.username, "role": "master", "rol": rol, "nombre": nombre}, JWT_SECRET_MASTER)
    await _audit(db, body.username, "login", "auth", f"Inicio de sesión ({rol})")
    return MasterLoginResponse(access_token=token)


@app.get("/api/auth/me", tags=["Auth"])
async def auth_me(payload: dict = Depends(_verify_master)) -> dict[str, Any]:
    """Devuelve la identidad y permisos del usuario autenticado."""
    rol = payload.get("rol", "admin")
    return {
        "username": payload.get("sub"),
        "nombre": payload.get("nombre") or payload.get("sub"),
        "rol": rol,
        "puede_escribir": rol in ("admin", "operador"),
        "es_admin": rol == "admin",
        "via": payload.get("via", "jwt"),
    }


@app.post("/api/auth/logout", tags=["Auth"])
async def logout(payload: dict = Depends(_verify_master)) -> dict[str, str]:
    """Revoca el token actual (cierre de sesión seguro)."""
    jti = payload.get("jti")
    if jti:
        _TOKENS_REVOCADOS.add(jti)
        # Evitar crecimiento ilimitado del set
        if len(_TOKENS_REVOCADOS) > 10000:
            _TOKENS_REVOCADOS.clear()
    return {"mensaje": "Sesión cerrada correctamente"}


@app.post("/api/auth/worker", response_model=WorkerLoginResponse, tags=["Auth"])
async def login_worker(body: WorkerLoginRequest, db: AsyncIOMotorDatabase = Depends(get_db)) -> WorkerLoginResponse:
    worker = await db["usuarios_worker"].find_one({"username": body.username})
    if not worker:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    if not bcrypt.checkpw(body.password.encode(), worker["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    await db["usuarios_worker"].update_one({"_id": worker["_id"]}, {"$set": {"ultima_conexion": _now_iso()}})
    worker_id = str(worker["_id"])
    token = _create_jwt({"sub": body.username, "role": "worker", "worker_id": worker_id}, JWT_SECRET_WORKER)
    return WorkerLoginResponse(access_token=token, worker_id=worker_id)


# ─────────────────────────────────────────────
# GESTIÓN DE USUARIOS (multiusuario con roles)
# ─────────────────────────────────────────────

ROLES_VALIDOS = ["admin", "operador", "visor"]


class CrearUsuarioRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=200)
    nombre_completo: Optional[str] = Field(default=None, max_length=120)
    rol: str = Field(default="operador")

    @field_validator("username")
    @classmethod
    def _val_user(cls, v: str) -> str:
        v = v.strip().lower()
        if not v.replace("_", "").replace(".", "").isalnum():
            raise ValueError("El usuario solo admite letras, números, '_' y '.'")
        return v

    @field_validator("rol")
    @classmethod
    def _val_rol(cls, v: str) -> str:
        if v not in ROLES_VALIDOS:
            raise ValueError(f"Rol inválido. Debe ser uno de: {', '.join(ROLES_VALIDOS)}")
        return v


class ActualizarUsuarioRequest(BaseModel):
    nombre_completo: Optional[str] = None
    rol: Optional[str] = None
    activo: Optional[bool] = None

    @field_validator("rol")
    @classmethod
    def _val_rol(cls, v):
        if v is not None and v not in ROLES_VALIDOS:
            raise ValueError(f"Rol inválido. Debe ser uno de: {', '.join(ROLES_VALIDOS)}")
        return v


class CambiarPasswordUsuarioRequest(BaseModel):
    nueva_password: str = Field(..., min_length=8, max_length=200)


class UsuarioInfo(BaseModel):
    id: str
    username: str
    nombre_completo: Optional[str] = None
    rol: str
    activo: bool
    fecha_creacion: str
    ultimo_acceso: Optional[str] = None


def _usuario_info(u: dict) -> UsuarioInfo:
    return UsuarioInfo(
        id=str(u["_id"]), username=u["username"], nombre_completo=u.get("nombre_completo"),
        rol=u.get("rol", "operador"), activo=u.get("activo", True),
        fecha_creacion=u["fecha_creacion"], ultimo_acceso=u.get("ultimo_acceso"),
    )


@app.post("/api/usuarios", response_model=UsuarioInfo, tags=["Usuarios"])
async def crear_usuario(body: CrearUsuarioRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                        admin: dict = Depends(_verify_admin)) -> UsuarioInfo:
    if body.username == MASTER_USERNAME:
        raise HTTPException(status_code=400, detail="Ese usuario está reservado al superadmin")
    existe = await db["usuarios_master"].find_one({"username": body.username})
    if existe:
        raise HTTPException(status_code=409, detail="Ya existe un usuario con ese nombre")
    ahora = _now_iso()
    pwd_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    doc = {
        "_id": ObjectId(), "username": body.username, "password_hash": pwd_hash,
        "nombre_completo": body.nombre_completo, "rol": body.rol, "activo": True,
        "fecha_creacion": ahora, "ultimo_acceso": None,
    }
    await db["usuarios_master"].insert_one(doc)
    await _audit(db, admin.get("sub", "?"), "crear_usuario", body.username, f"Rol: {body.rol}")
    return _usuario_info(doc)


@app.get("/api/usuarios", tags=["Usuarios"])
async def listar_usuarios(db: AsyncIOMotorDatabase = Depends(get_db),
                          admin: dict = Depends(_verify_admin)) -> list[dict]:
    out = []
    # Incluir el superadmin de entorno como entrada virtual (no editable)
    out.append({
        "id": "__env__", "username": MASTER_USERNAME, "nombre_completo": "Superadministrador (variables de entorno)",
        "rol": "admin", "activo": True, "fecha_creacion": "—", "ultimo_acceso": None, "protegido": True,
    })
    async for u in db["usuarios_master"].find().sort("fecha_creacion", DESCENDING):
        d = _usuario_info(u).model_dump()
        d["protegido"] = False
        out.append(d)
    return out


@app.patch("/api/usuarios/{usuario_id}", response_model=UsuarioInfo, tags=["Usuarios"])
async def actualizar_usuario(usuario_id: str, body: ActualizarUsuarioRequest,
                             db: AsyncIOMotorDatabase = Depends(get_db),
                             admin: dict = Depends(_verify_admin)) -> UsuarioInfo:
    try:
        oid = ObjectId(usuario_id)
    except Exception:
        raise HTTPException(status_code=400, detail="usuario_id inválido")
    campos = {f: getattr(body, f) for f in ["nombre_completo", "rol", "activo"] if getattr(body, f) is not None}
    if not campos:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    u = await db["usuarios_master"].find_one_and_update(
        {"_id": oid}, {"$set": campos}, return_document=ReturnDocument.AFTER)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    await _audit(db, admin.get("sub", "?"), "actualizar_usuario", u["username"], str(campos))
    return _usuario_info(u)


@app.post("/api/usuarios/{usuario_id}/password", tags=["Usuarios"])
async def cambiar_password_usuario(usuario_id: str, body: CambiarPasswordUsuarioRequest,
                                   db: AsyncIOMotorDatabase = Depends(get_db),
                                   admin: dict = Depends(_verify_admin)) -> dict[str, str]:
    try:
        oid = ObjectId(usuario_id)
    except Exception:
        raise HTTPException(status_code=400, detail="usuario_id inválido")
    pwd_hash = bcrypt.hashpw(body.nueva_password.encode(), bcrypt.gensalt()).decode()
    r = await db["usuarios_master"].update_one({"_id": oid}, {"$set": {"password_hash": pwd_hash}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    await _audit(db, admin.get("sub", "?"), "cambiar_password_usuario", usuario_id)
    return {"mensaje": "Contraseña actualizada"}


@app.delete("/api/usuarios/{usuario_id}", tags=["Usuarios"])
async def eliminar_usuario(usuario_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                           admin: dict = Depends(_verify_admin)) -> dict[str, str]:
    try:
        oid = ObjectId(usuario_id)
    except Exception:
        raise HTTPException(status_code=400, detail="usuario_id inválido")
    u = await db["usuarios_master"].find_one({"_id": oid})
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    await db["usuarios_master"].delete_one({"_id": oid})
    await _audit(db, admin.get("sub", "?"), "eliminar_usuario", u["username"])
    return {"mensaje": "Usuario eliminado"}


# ─────────────────────────────────────────────
# API KEYS
# ─────────────────────────────────────────────

@app.post("/api/apikeys", response_model=ApiKeyCreada, tags=["API Keys"])
async def crear_apikey(body: CrearApiKeyRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                       user: dict = Depends(_verify_master)) -> ApiKeyCreada:
    raw = "rpak_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    oid = ObjectId()
    ahora = _now_iso()
    await db["api_keys"].insert_one({
        "_id": oid, "nombre": body.nombre, "key_hash": key_hash,
        "activa": True, "ultima_uso": None, "fecha_creacion": ahora,
    })
    await _audit(db, user.get("sub", "?"), "crear_apikey", str(oid), body.nombre)
    return ApiKeyCreada(id=str(oid), nombre=body.nombre, api_key=raw, fecha_creacion=ahora)


@app.get("/api/apikeys", response_model=list[ApiKeyInfo], tags=["API Keys"])
async def listar_apikeys(db: AsyncIOMotorDatabase = Depends(get_db), _: dict = Depends(_verify_master)) -> list[ApiKeyInfo]:
    out = []
    async for k in db["api_keys"].find().sort("fecha_creacion", DESCENDING):
        out.append(ApiKeyInfo(id=str(k["_id"]), nombre=k["nombre"], activa=k["activa"],
                              ultima_uso=k.get("ultima_uso"), fecha_creacion=k["fecha_creacion"]))
    return out


@app.delete("/api/apikeys/{key_id}", tags=["API Keys"])
async def revocar_apikey(key_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                         user: dict = Depends(_verify_master)) -> dict[str, str]:
    try:
        oid = ObjectId(key_id)
    except Exception:
        raise HTTPException(status_code=400, detail="key_id inválido")
    r = await db["api_keys"].delete_one({"_id": oid})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="API Key no encontrada")
    await _audit(db, user.get("sub", "?"), "revocar_apikey", key_id)
    return {"mensaje": "API Key revocada"}


# ─────────────────────────────────────────────
# WORKERS
# ─────────────────────────────────────────────

def _worker_info(w: dict) -> WorkerInfo:
    m = w.get("metricas", {})
    return WorkerInfo(
        id=str(w["_id"]), username=w["username"], estado=w["estado"],
        etiqueta=w.get("etiqueta"), pool=w.get("pool"),
        ultima_conexion=w.get("ultima_conexion"), tarea_actual=w.get("tarea_actual"),
        cola_tareas=w.get("cola_tareas", []), fecha_creacion=w["fecha_creacion"],
        tareas_completadas=w.get("tareas_completadas", 0), tareas_error=w.get("tareas_error", 0),
        cpu_percent=m.get("cpu_percent"), ram_percent=m.get("ram_percent"),
        disk_percent=m.get("disk_percent"),
        en_mantenimiento=w.get("en_mantenimiento", False),
    )


@app.post("/api/workers", response_model=WorkerInfo, tags=["Workers"])
async def crear_worker(body: CrearWorkerRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                       user: dict = Depends(_verify_master)) -> WorkerInfo:
    if await db["usuarios_worker"].find_one({"username": body.username}):
        raise HTTPException(status_code=409, detail="Username ya existe")
    oid = ObjectId()
    password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    ahora = _now_iso()
    doc = {
        "_id": oid, "username": body.username, "password_hash": password_hash,
        "etiqueta": body.etiqueta, "pool": body.pool, "estado": "desconectado",
        "ultima_conexion": None, "tarea_actual": None, "cola_tareas": [],
        "fecha_creacion": ahora, "tareas_completadas": 0, "tareas_error": 0, "metricas": {},
    }
    await db["usuarios_worker"].insert_one(doc)
    await _audit(db, user.get("sub", "?"), "crear_worker", str(oid), body.username)
    return _worker_info(doc)


@app.get("/api/workers", response_model=list[WorkerInfo], tags=["Workers"])
async def listar_workers(pool: Optional[str] = Query(default=None),
                         db: AsyncIOMotorDatabase = Depends(get_db),
                         _: dict = Depends(_verify_master)) -> list[WorkerInfo]:
    filtro: dict = {}
    if pool:
        filtro["pool"] = pool
    out = []
    async for w in db["usuarios_worker"].find(filtro).sort("fecha_creacion", DESCENDING):
        out.append(_worker_info(w))
    return out


@app.get("/api/workers/{worker_id}", response_model=WorkerInfo, tags=["Workers"])
async def detalle_worker(worker_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                         _: dict = Depends(_verify_master)) -> WorkerInfo:
    try:
        oid = ObjectId(worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")
    w = await db["usuarios_worker"].find_one({"_id": oid})
    if not w:
        raise HTTPException(status_code=404, detail="Worker no encontrado")
    return _worker_info(w)


@app.patch("/api/workers/{worker_id}", response_model=WorkerInfo, tags=["Workers"])
async def actualizar_worker(worker_id: str, body: ActualizarWorkerRequest,
                            db: AsyncIOMotorDatabase = Depends(get_db),
                            user: dict = Depends(_verify_master)) -> WorkerInfo:
    try:
        oid = ObjectId(worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")
    campos: dict[str, Any] = {}
    if body.etiqueta is not None:
        campos["etiqueta"] = body.etiqueta
    if body.pool is not None:
        campos["pool"] = body.pool or None
    if body.en_mantenimiento is not None:
        campos["en_mantenimiento"] = body.en_mantenimiento
    if not campos:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    w = await db["usuarios_worker"].find_one_and_update(
        {"_id": oid}, {"$set": campos}, return_document=ReturnDocument.AFTER)
    if not w:
        raise HTTPException(status_code=404, detail="Worker no encontrado")
    await _audit(db, user.get("sub", "?"), "editar_worker", worker_id, str(campos))
    return _worker_info(w)


@app.post("/api/workers/{worker_id}/password", tags=["Workers"])
async def cambiar_password_worker(worker_id: str, body: CambiarPasswordWorkerRequest,
                                  db: AsyncIOMotorDatabase = Depends(get_db),
                                  user: dict = Depends(_verify_master)) -> dict[str, str]:
    try:
        oid = ObjectId(worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")
    nuevo_hash = bcrypt.hashpw(body.nueva_password.encode(), bcrypt.gensalt()).decode()
    r = await db["usuarios_worker"].update_one({"_id": oid}, {"$set": {"password_hash": nuevo_hash}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Worker no encontrado")
    await _audit(db, user.get("sub", "?"), "cambiar_password_worker", worker_id)
    return {"mensaje": "Contraseña actualizada"}


@app.delete("/api/workers/{worker_id}", tags=["Workers"])
async def eliminar_worker(worker_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                          user: dict = Depends(_verify_master)) -> dict[str, str]:
    try:
        oid = ObjectId(worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")
    worker = await db["usuarios_worker"].find_one({"_id": oid})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker no encontrado")
    if worker.get("estado") == "ocupado":
        raise HTTPException(status_code=409, detail="No se puede eliminar un Worker ocupado")
    await db["usuarios_worker"].delete_one({"_id": oid})
    await _audit(db, user.get("sub", "?"), "eliminar_worker", worker_id, worker.get("username", ""))
    return {"mensaje": "Worker eliminado"}


# ─────────────────────────────────────────────
# POOLS
# ─────────────────────────────────────────────

@app.post("/api/pools", response_model=PoolInfo, tags=["Pools"])
async def crear_pool(body: CrearPoolRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                     user: dict = Depends(_verify_master)) -> PoolInfo:
    oid = ObjectId()
    ahora = _now_iso()
    doc = {"_id": oid, "nombre": body.nombre, "descripcion": body.descripcion,
           "worker_ids": body.worker_ids, "fecha_creacion": ahora}
    try:
        await db["pools"].insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Ya existe un pool con ese nombre")
    # marcar pool en cada worker
    for wid in body.worker_ids:
        try:
            await db["usuarios_worker"].update_one({"_id": ObjectId(wid)}, {"$set": {"pool": body.nombre}})
        except Exception:
            pass
    await _audit(db, user.get("sub", "?"), "crear_pool", str(oid), body.nombre)
    return PoolInfo(id=str(oid), nombre=body.nombre, descripcion=body.descripcion,
                    worker_ids=body.worker_ids, fecha_creacion=ahora)


@app.get("/api/pools", response_model=list[PoolInfo], tags=["Pools"])
async def listar_pools(db: AsyncIOMotorDatabase = Depends(get_db), _: dict = Depends(_verify_master)) -> list[PoolInfo]:
    out = []
    async for p in db["pools"].find().sort("fecha_creacion", DESCENDING):
        out.append(PoolInfo(id=str(p["_id"]), nombre=p["nombre"], descripcion=p.get("descripcion"),
                            worker_ids=p.get("worker_ids", []), fecha_creacion=p["fecha_creacion"]))
    return out


@app.patch("/api/pools/{pool_id}", response_model=PoolInfo, tags=["Pools"])
async def actualizar_pool(pool_id: str, body: ActualizarPoolRequest,
                          db: AsyncIOMotorDatabase = Depends(get_db),
                          user: dict = Depends(_verify_master)) -> PoolInfo:
    try:
        oid = ObjectId(pool_id)
    except Exception:
        raise HTTPException(status_code=400, detail="pool_id inválido")
    campos: dict[str, Any] = {}
    if body.descripcion is not None:
        campos["descripcion"] = body.descripcion
    if body.worker_ids is not None:
        campos["worker_ids"] = body.worker_ids
    if not campos:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    p = await db["pools"].find_one_and_update({"_id": oid}, {"$set": campos}, return_document=ReturnDocument.AFTER)
    if not p:
        raise HTTPException(status_code=404, detail="Pool no encontrado")
    if body.worker_ids is not None:
        # re-sincronizar campo pool en workers
        await db["usuarios_worker"].update_many({"pool": p["nombre"]}, {"$set": {"pool": None}})
        for wid in body.worker_ids:
            try:
                await db["usuarios_worker"].update_one({"_id": ObjectId(wid)}, {"$set": {"pool": p["nombre"]}})
            except Exception:
                pass
    await _audit(db, user.get("sub", "?"), "editar_pool", pool_id)
    return PoolInfo(id=str(p["_id"]), nombre=p["nombre"], descripcion=p.get("descripcion"),
                    worker_ids=p.get("worker_ids", []), fecha_creacion=p["fecha_creacion"])


@app.delete("/api/pools/{pool_id}", tags=["Pools"])
async def eliminar_pool(pool_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                        user: dict = Depends(_verify_master)) -> dict[str, str]:
    try:
        oid = ObjectId(pool_id)
    except Exception:
        raise HTTPException(status_code=400, detail="pool_id inválido")
    p = await db["pools"].find_one({"_id": oid})
    if not p:
        raise HTTPException(status_code=404, detail="Pool no encontrado")
    await db["usuarios_worker"].update_many({"pool": p["nombre"]}, {"$set": {"pool": None}})
    await db["pools"].delete_one({"_id": oid})
    await _audit(db, user.get("sub", "?"), "eliminar_pool", pool_id, p["nombre"])
    return {"mensaje": "Pool eliminado"}


# ─────────────────────────────────────────────
# PROYECTOS
# ─────────────────────────────────────────────

def _proyecto_info(p: dict) -> ProyectoInfo:
    return ProyectoInfo(
        id=str(p["_id"]), nombre=p["nombre"], descripcion=p["descripcion"],
        git_url=p["git_url"], archivo_principal=p["archivo_principal"],
        archivo_requirements=p["archivo_requirements"], tags=p.get("tags", []),
        env_vars=p.get("env_vars", {}), git_ref=p.get("git_ref"),
        archivos_adjuntos=p.get("archivos_adjuntos", []),
        max_concurrencia=p.get("max_concurrencia", 0), favorito=p.get("favorito", False),
        fecha_creacion=p["fecha_creacion"],
    )


@app.post("/api/proyectos", response_model=ProyectoInfo, tags=["Proyectos"])
async def crear_proyecto(body: CrearProyectoRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                         user: dict = Depends(_verify_master)) -> ProyectoInfo:
    oid = ObjectId()
    ahora = _now_iso()
    doc = {
        "_id": oid, "nombre": body.nombre, "descripcion": body.descripcion,
        "git_url": body.git_url, "archivo_principal": body.archivo_principal,
        "archivo_requirements": body.archivo_requirements, "tags": body.tags,
        "env_vars": body.env_vars, "git_ref": body.git_ref, "fecha_creacion": ahora,
        "archivos_adjuntos": [a.model_dump() for a in body.archivos_adjuntos],
        "max_concurrencia": body.max_concurrencia, "favorito": False,
    }
    try:
        await db["proyectos"].insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Ya existe un proyecto con ese nombre")
    await _audit(db, user.get("sub", "?"), "crear_proyecto", str(oid), body.nombre)
    return _proyecto_info(doc)


@app.get("/api/proyectos", response_model=list[ProyectoInfo], tags=["Proyectos"])
async def listar_proyectos(tag: Optional[str] = Query(default=None),
                           db: AsyncIOMotorDatabase = Depends(get_db),
                           _: dict = Depends(_verify_master)) -> list[ProyectoInfo]:
    filtro: dict = {}
    if tag:
        filtro["tags"] = tag
    out = []
    async for p in db["proyectos"].find(filtro).sort("fecha_creacion", DESCENDING):
        out.append(_proyecto_info(p))
    return out


@app.get("/api/proyectos/{proyecto_id}", response_model=ProyectoInfo, tags=["Proyectos"])
async def detalle_proyecto(proyecto_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                           _: dict = Depends(_verify_master)) -> ProyectoInfo:
    try:
        oid = ObjectId(proyecto_id)
    except Exception:
        raise HTTPException(status_code=400, detail="proyecto_id inválido")
    p = await db["proyectos"].find_one({"_id": oid})
    if not p:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    return _proyecto_info(p)


@app.patch("/api/proyectos/{proyecto_id}", response_model=ProyectoInfo, tags=["Proyectos"])
async def actualizar_proyecto(proyecto_id: str, body: ActualizarProyectoRequest,
                              db: AsyncIOMotorDatabase = Depends(get_db),
                              user: dict = Depends(_verify_master)) -> ProyectoInfo:
    try:
        oid = ObjectId(proyecto_id)
    except Exception:
        raise HTTPException(status_code=400, detail="proyecto_id inválido")
    campos: dict[str, Any] = {}
    for field in ["descripcion", "git_url", "archivo_principal", "archivo_requirements", "tags", "env_vars", "git_ref", "archivos_adjuntos", "max_concurrencia", "favorito"]:
        val = getattr(body, field, None)
        if val is not None:
            if field == "archivos_adjuntos":
                campos[field] = [a.model_dump() if hasattr(a, "model_dump") else a for a in val]
            else:
                campos[field] = val
    if not campos:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    p = await db["proyectos"].find_one_and_update({"_id": oid}, {"$set": campos}, return_document=ReturnDocument.AFTER)
    if not p:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    await _audit(db, user.get("sub", "?"), "editar_proyecto", proyecto_id, str(list(campos.keys())))
    return _proyecto_info(p)


@app.post("/api/proyectos/{proyecto_id}/duplicar", response_model=ProyectoInfo, tags=["Proyectos"])
async def duplicar_proyecto(proyecto_id: str, nuevo_nombre: str = Query(...),
                            db: AsyncIOMotorDatabase = Depends(get_db),
                            user: dict = Depends(_verify_master)) -> ProyectoInfo:
    try:
        oid = ObjectId(proyecto_id)
    except Exception:
        raise HTTPException(status_code=400, detail="proyecto_id inválido")
    orig = await db["proyectos"].find_one({"_id": oid})
    if not orig:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    nuevo_oid = ObjectId()
    ahora = _now_iso()
    doc = {
        "_id": nuevo_oid, "nombre": nuevo_nombre, "descripcion": orig["descripcion"],
        "git_url": orig["git_url"], "archivo_principal": orig["archivo_principal"],
        "archivo_requirements": orig["archivo_requirements"], "tags": orig.get("tags", []),
        "env_vars": orig.get("env_vars", {}), "git_ref": orig.get("git_ref"), "fecha_creacion": ahora,
    }
    try:
        await db["proyectos"].insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Ya existe un proyecto con ese nombre")
    await _audit(db, user.get("sub", "?"), "duplicar_proyecto", str(nuevo_oid), nuevo_nombre)
    return _proyecto_info(doc)


@app.delete("/api/proyectos/{proyecto_id}", tags=["Proyectos"])
async def eliminar_proyecto(proyecto_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                            user: dict = Depends(_verify_master)) -> dict[str, str]:
    try:
        oid = ObjectId(proyecto_id)
    except Exception:
        raise HTTPException(status_code=400, detail="proyecto_id inválido")
    r = await db["proyectos"].delete_one({"_id": oid})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    await _audit(db, user.get("sub", "?"), "eliminar_proyecto", proyecto_id)
    return {"mensaje": "Proyecto eliminado"}


# ─────────────────────────────────────────────
# TAREAS
# ─────────────────────────────────────────────

def _tarea_info(t: dict, nombre_proyecto: Optional[str] = None, worker_username: Optional[str] = None) -> TareaInfo:
    return TareaInfo(
        id_tarea=t["id_tarea"], id_proyecto=t["id_proyecto"], nombre_proyecto=nombre_proyecto,
        worker_asignado=t["worker_asignado"], worker_username=worker_username,
        estado=t["estado"], prioridad=t.get("prioridad", 0), tags=t.get("tags", []),
        notas=t.get("notas"), max_reintentos=t.get("max_reintentos", 0),
        reintento_num=t.get("reintento_num", 0), tarea_padre_id=t.get("tarea_padre_id"),
        depende_de=t.get("depende_de", []), git_ref=t.get("git_ref"),
        sla_segundos=t.get("sla_segundos", 0),
        timeout_segundos=t.get("timeout_segundos", 0),
        num_archivos_adjuntos=len(t.get("archivos_adjuntos", [])),
        fecha_creacion=t["fecha_creacion"], fecha_inicio=t.get("fecha_inicio"),
        fecha_fin=t.get("fecha_fin"), log_size_bytes=t.get("log_size_bytes", 0),
        ultima_actualizacion_log=t.get("ultima_actualizacion_log"),
        programada_para=t.get("programada_para"),
    )


def _combinar_archivos(archivos_proyecto: list, archivos_tarea: list) -> list:
    """Combina archivos del proyecto + de la tarea. La tarea sobrescribe por (subcarpeta, nombre)."""
    def _clave(a: dict) -> tuple:
        return (a.get("subcarpeta", ""), a.get("nombre_archivo", ""))
    combinado: dict[tuple, dict] = {}
    for a in (archivos_proyecto or []):
        d = a if isinstance(a, dict) else a.model_dump()
        combinado[_clave(d)] = d
    for a in (archivos_tarea or []):
        d = a if isinstance(a, dict) else a.model_dump()
        combinado[_clave(d)] = d  # la tarea pisa al proyecto
    return list(combinado.values())


async def _crear_tarea_doc(db, id_proyecto, worker_id, proyecto, worker, body_dict) -> dict:
    """Lógica común de creación de tarea. Decide estado según dependencias y disponibilidad."""
    id_tarea = str(uuid.uuid4())
    ahora = _now_iso()
    deps = body_dict.get("depende_de", [])

    # Si tiene dependencias no satisfechas → esperando, encolar
    if deps and not await _dependencias_satisfechas(db, deps):
        estado_tarea = "esperando"
        fecha_inicio = None
        await db["usuarios_worker"].update_one({"_id": worker["_id"]}, {"$push": {"cola_tareas": id_tarea}})
    else:
        cfg = await _config_global(db)
        if cfg.get("pausa_global"):
            estado_tarea = "pendiente"
            fecha_inicio = None
            await db["usuarios_worker"].update_one({"_id": worker["_id"]}, {"$push": {"cola_tareas": id_tarea}})
        elif worker["estado"] == "disponible":
            estado_tarea = "ejecutando"
            fecha_inicio = ahora
            await db["usuarios_worker"].update_one(
                {"_id": worker["_id"]}, {"$set": {"estado": "ocupado", "tarea_actual": id_tarea}})
        else:
            estado_tarea = "pendiente"
            fecha_inicio = None
            await db["usuarios_worker"].update_one({"_id": worker["_id"]}, {"$push": {"cola_tareas": id_tarea}})

    doc = {
        "id_tarea": id_tarea, "id_proyecto": str(id_proyecto), "worker_asignado": str(worker_id),
        "estado": estado_tarea, "credenciales_encriptadas": body_dict.get("credenciales_encriptadas"),
        "fecha_creacion": ahora, "fecha_inicio": fecha_inicio, "fecha_fin": None,
        "logs": [], "log_size_bytes": 0, "ultima_actualizacion_log": None, "comando_pendiente": "NONE",
        "prioridad": body_dict.get("prioridad", 0), "tags": body_dict.get("tags", []),
        "notas": body_dict.get("notas") or "", "max_reintentos": body_dict.get("max_reintentos", 0),
        "reintento_num": 0, "tarea_padre_id": None, "programada_para": None,
        "depende_de": deps, "git_ref": body_dict.get("git_ref"),
        "env_override": body_dict.get("env_override", {}), "sla_segundos": body_dict.get("sla_segundos", 0),
        "sla_alertado": False,
        "timeout_segundos": body_dict.get("timeout_segundos", 0),
        "archivos_adjuntos": _combinar_archivos(proyecto.get("archivos_adjuntos", []),
                                                body_dict.get("archivos_adjuntos", [])),
    }
    await db["tareas"].insert_one(doc)
    if estado_tarea == "ejecutando":
        await _disparar_webhooks(db, "tarea_iniciada",
                                 {"id_tarea": id_tarea, "id_proyecto": str(id_proyecto), "worker_id": str(worker_id)})
    return doc


@app.post("/api/tareas", response_model=TareaInfo, tags=["Tareas"])
async def lanzar_tarea(body: LanzarTareaRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                       user: dict = Depends(_verify_master)) -> TareaInfo:
    try:
        pid = ObjectId(body.id_proyecto)
    except Exception:
        raise HTTPException(status_code=400, detail="id_proyecto inválido")
    proyecto = await db["proyectos"].find_one({"_id": pid})
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    try:
        wid = ObjectId(body.worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")
    worker = await db["usuarios_worker"].find_one({"_id": wid})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker no encontrado")
    if worker["estado"] == "desconectado":
        raise HTTPException(status_code=409, detail="Worker desconectado")

    doc = await _crear_tarea_doc(db, pid, wid, proyecto, worker, body.model_dump())
    await _audit(db, user.get("sub", "?"), "lanzar_tarea", doc["id_tarea"], proyecto["nombre"])
    return _tarea_info(doc, proyecto.get("nombre"), worker.get("username"))


@app.post("/api/tareas/auto", response_model=TareaInfo, tags=["Tareas"])
async def lanzar_tarea_auto(body: LanzarAutoRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                            user: dict = Depends(_verify_master)) -> TareaInfo:
    """Auto-asigna la tarea al worker conectado con menor carga (opcionalmente dentro de un pool)."""
    try:
        pid = ObjectId(body.id_proyecto)
    except Exception:
        raise HTTPException(status_code=400, detail="id_proyecto inválido")
    proyecto = await db["proyectos"].find_one({"_id": pid})
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    candidatos_ids: Optional[list[str]] = None
    if body.pool:
        pool = await db["pools"].find_one({"nombre": body.pool})
        if not pool:
            raise HTTPException(status_code=404, detail="Pool no encontrado")
        candidatos_ids = pool.get("worker_ids", [])
        if not candidatos_ids:
            raise HTTPException(status_code=409, detail="El pool no tiene workers")

    worker = await _mejor_worker(db, candidatos_ids)
    if not worker:
        raise HTTPException(status_code=409, detail="No hay workers conectados disponibles")

    body_dict = {
        "credenciales_encriptadas": body.credenciales_encriptadas, "prioridad": body.prioridad,
        "tags": body.tags, "notas": body.notas, "max_reintentos": body.max_reintentos,
        "depende_de": [], "git_ref": body.git_ref, "env_override": body.env_override,
        "sla_segundos": body.sla_segundos,
    }
    doc = await _crear_tarea_doc(db, pid, worker["_id"], proyecto, worker, body_dict)
    await _audit(db, user.get("sub", "?"), "lanzar_tarea_auto", doc["id_tarea"],
                 f"{proyecto['nombre']} → {worker['username']}")
    return _tarea_info(doc, proyecto.get("nombre"), worker.get("username"))


@app.post("/api/tareas/{id_tarea}/relanzar", response_model=TareaInfo, tags=["Tareas"])
async def relanzar_tarea(id_tarea: str, db: AsyncIOMotorDatabase = Depends(get_db),
                         user: dict = Depends(_verify_master)) -> TareaInfo:
    """Crea una nueva tarea con la misma configuración de una existente."""
    orig = await db["tareas"].find_one({"id_tarea": id_tarea})
    if not orig:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    proyecto = await db["proyectos"].find_one({"_id": ObjectId(orig["id_proyecto"])})
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto de la tarea ya no existe")
    worker = await db["usuarios_worker"].find_one({"_id": ObjectId(orig["worker_asignado"])})
    if not worker or worker["estado"] == "desconectado":
        # auto-reasignar
        worker = await _mejor_worker(db)
        if not worker:
            raise HTTPException(status_code=409, detail="No hay workers disponibles para relanzar")
    body_dict = {
        "credenciales_encriptadas": orig.get("credenciales_encriptadas"),
        "prioridad": orig.get("prioridad", 0), "tags": orig.get("tags", []),
        "notas": orig.get("notas"), "max_reintentos": orig.get("max_reintentos", 0),
        "depende_de": [], "git_ref": orig.get("git_ref"),
        "env_override": orig.get("env_override", {}), "sla_segundos": orig.get("sla_segundos", 0),
    }
    doc = await _crear_tarea_doc(db, ObjectId(orig["id_proyecto"]), worker["_id"], proyecto, worker, body_dict)
    await _audit(db, user.get("sub", "?"), "relanzar_tarea", doc["id_tarea"], f"desde {id_tarea}")
    return _tarea_info(doc, proyecto.get("nombre"), worker.get("username"))


@app.get("/api/tareas", response_model=list[TareaInfo], tags=["Tareas"])
async def listar_tareas(
    estado: Optional[str] = Query(default=None),
    worker_id: Optional[str] = Query(default=None),
    id_proyecto: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
    fecha_desde: Optional[str] = Query(default=None),
    fecha_hasta: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    skip: int = Query(default=0, ge=0),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> list[TareaInfo]:
    filtro: dict[str, Any] = {}
    if estado:
        filtro["estado"] = estado
    if worker_id:
        filtro["worker_asignado"] = worker_id
    if id_proyecto:
        filtro["id_proyecto"] = id_proyecto
    if tag:
        filtro["tags"] = tag
    if fecha_desde or fecha_hasta:
        filtro["fecha_creacion"] = {}
        if fecha_desde:
            filtro["fecha_creacion"]["$gte"] = fecha_desde
        if fecha_hasta:
            filtro["fecha_creacion"]["$lte"] = fecha_hasta

    proyectos_map = {str(p["_id"]): p["nombre"] async for p in db["proyectos"].find({}, {"nombre": 1})}
    workers_map = {str(w["_id"]): w["username"] async for w in db["usuarios_worker"].find({}, {"username": 1})}

    out = []
    cursor = db["tareas"].find(filtro).sort("fecha_creacion", DESCENDING).skip(skip).limit(limit)
    async for t in cursor:
        out.append(_tarea_info(t, proyectos_map.get(t["id_proyecto"]), workers_map.get(t["worker_asignado"])))
    return out


@app.get("/api/tareas/export/csv", tags=["Tareas"])
async def exportar_tareas_csv(
    estado: Optional[str] = Query(default=None),
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
):
    """Exporta tareas a CSV descargable."""
    filtro: dict[str, Any] = {}
    if estado:
        filtro["estado"] = estado
    proyectos_map = {str(p["_id"]): p["nombre"] async for p in db["proyectos"].find({}, {"nombre": 1})}
    workers_map = {str(w["_id"]): w["username"] async for w in db["usuarios_worker"].find({}, {"username": 1})}

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id_tarea", "proyecto", "worker", "estado", "prioridad",
                     "fecha_creacion", "fecha_inicio", "fecha_fin", "reintentos", "tags"])
    async for t in db["tareas"].find(filtro).sort("fecha_creacion", DESCENDING).limit(5000):
        writer.writerow([
            t["id_tarea"], proyectos_map.get(t["id_proyecto"], t["id_proyecto"]),
            workers_map.get(t["worker_asignado"], t["worker_asignado"]), t["estado"],
            t.get("prioridad", 0), t.get("fecha_creacion", ""), t.get("fecha_inicio", ""),
            t.get("fecha_fin", ""), f"{t.get('reintento_num',0)}/{t.get('max_reintentos',0)}",
            ";".join(t.get("tags", [])),
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=tareas.csv"},
    )


@app.get("/api/tareas/{id_tarea}", response_model=TareaInfo, tags=["Tareas"])
async def obtener_tarea(id_tarea: str, db: AsyncIOMotorDatabase = Depends(get_db),
                        _: dict = Depends(_verify_master)) -> TareaInfo:
    t = await db["tareas"].find_one({"id_tarea": id_tarea})
    if not t:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    proyecto = await db["proyectos"].find_one({"_id": ObjectId(t["id_proyecto"])}, {"nombre": 1})
    worker = await db["usuarios_worker"].find_one({"_id": ObjectId(t["worker_asignado"])}, {"username": 1})
    return _tarea_info(t, proyecto.get("nombre") if proyecto else None,
                       worker.get("username") if worker else None)


@app.post("/api/tareas/{id_tarea}/comando", tags=["Tareas"])
async def enviar_comando_tarea(id_tarea: str, body: ComandoTareaRequest,
                               db: AsyncIOMotorDatabase = Depends(get_db),
                               user: dict = Depends(_verify_master)) -> dict[str, str]:
    comandos_validos = {"PAUSE", "RESUME", "STOP"}
    if body.comando not in comandos_validos:
        raise HTTPException(status_code=400, detail=f"Comando inválido. Válidos: {comandos_validos}")
    tarea = await db["tareas"].find_one({"id_tarea": id_tarea})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    estados_permitidos = {"PAUSE": ["ejecutando"], "RESUME": ["pausada"],
                          "STOP": ["ejecutando", "pausada", "pendiente"]}
    if tarea["estado"] not in estados_permitidos[body.comando]:
        raise HTTPException(status_code=409, detail=f"No se puede {body.comando} en estado '{tarea['estado']}'")
    nuevo_estado = "cancelando" if body.comando == "STOP" else tarea["estado"]
    await db["tareas"].update_one({"id_tarea": id_tarea},
                                  {"$set": {"comando_pendiente": body.comando, "estado": nuevo_estado}})
    await _audit(db, user.get("sub", "?"), f"comando_{body.comando}", id_tarea)
    return {"mensaje": f"Comando {body.comando} registrado"}


@app.post("/api/tareas/{id_tarea}/nota", tags=["Tareas"])
async def agregar_nota_tarea(id_tarea: str, body: AgregarNotaRequest,
                             db: AsyncIOMotorDatabase = Depends(get_db),
                             _: dict = Depends(_verify_master)) -> dict[str, str]:
    r = await db["tareas"].update_one({"id_tarea": id_tarea}, {"$set": {"notas": body.nota}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    return {"mensaje": "Nota actualizada"}


@app.get("/api/tareas/{id_tarea}/logs", response_model=LogsResponse, tags=["Tareas"])
async def obtener_logs_tarea(id_tarea: str,
                             stream: Optional[str] = Query(default=None),
                             buscar: Optional[str] = Query(default=None, description="Filtra líneas que contengan este texto"),
                             limit: int = Query(default=500, ge=1, le=5000),
                             db: AsyncIOMotorDatabase = Depends(get_db),
                             _: dict = Depends(_verify_master)) -> LogsResponse:
    tarea = await db["tareas"].find_one({"id_tarea": id_tarea}, {"logs": 1, "log_size_bytes": 1})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    logs = tarea.get("logs", [])
    if stream:
        logs = [l for l in logs if l.get("stream") == stream]
    if buscar:
        bl = buscar.lower()
        logs = [l for l in logs if bl in str(l.get("msg", "")).lower()]
    logs = logs[-limit:]
    return LogsResponse(id_tarea=id_tarea, logs=logs, total_bytes=tarea.get("log_size_bytes", 0))


@app.get("/api/tareas/{id_tarea}/logs/export", response_class=PlainTextResponse, tags=["Tareas"])
async def exportar_logs_texto(id_tarea: str, db: AsyncIOMotorDatabase = Depends(get_db),
                              _: dict = Depends(_verify_master)) -> str:
    tarea = await db["tareas"].find_one({"id_tarea": id_tarea}, {"logs": 1})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    return "\n".join(
        f"[{e.get('ts','')}] [{e.get('stream','').upper()}] {e.get('msg','')}"
        for e in tarea.get("logs", [])
    )


@app.delete("/api/tareas/{id_tarea}/logs", tags=["Tareas"])
async def eliminar_logs_tarea(id_tarea: str, db: AsyncIOMotorDatabase = Depends(get_db),
                              _: dict = Depends(_verify_master)) -> dict[str, str]:
    tarea = await db["tareas"].find_one({"id_tarea": id_tarea}, {"estado": 1})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    if tarea["estado"] not in {"completada", "cancelada", "error"}:
        raise HTTPException(status_code=409, detail="Solo se eliminan logs de tareas finalizadas")
    await db["tareas"].update_one({"id_tarea": id_tarea}, {"$set": {"logs": [], "log_size_bytes": 0}})
    return {"mensaje": "Logs eliminados"}


@app.post("/api/tareas/cancelar_masiva", tags=["Tareas"])
async def cancelar_tareas_masiva(body: CancelarMasivaRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                                 user: dict = Depends(_verify_master)) -> dict[str, Any]:
    filtro: dict[str, Any] = {"estado": {"$in": ["pendiente", "ejecutando", "pausada", "esperando"]}}
    if body.estado:
        filtro["estado"] = body.estado
    if body.worker_id:
        filtro["worker_asignado"] = body.worker_id
    if body.id_proyecto:
        filtro["id_proyecto"] = body.id_proyecto
    r = await db["tareas"].update_many(filtro, {"$set": {"estado": "cancelando", "comando_pendiente": "STOP"}})
    await _audit(db, user.get("sub", "?"), "cancelar_masiva", "tareas", f"{r.modified_count} afectadas")
    return {"tareas_afectadas": r.modified_count, "mensaje": "STOP enviado a las tareas activas"}


# ─────────────────────────────────────────────
# SCHEDULES
# ─────────────────────────────────────────────

def _cron_proxima(cron_expr: str) -> Optional[str]:
    try:
        from croniter import croniter
        return croniter(cron_expr, _now_dt()).get_next(datetime).isoformat()
    except Exception:
        return None


@app.post("/api/schedules", response_model=ScheduleInfo, tags=["Schedules"])
async def crear_schedule(body: CrearScheduleRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                         user: dict = Depends(_verify_master)) -> ScheduleInfo:
    try:
        pid = ObjectId(body.id_proyecto)
    except Exception:
        raise HTTPException(status_code=400, detail="id_proyecto inválido")
    proyecto = await db["proyectos"].find_one({"_id": pid})
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    worker_id_str: Optional[str] = None
    if body.worker_id:
        try:
            wid = ObjectId(body.worker_id)
        except Exception:
            raise HTTPException(status_code=400, detail="worker_id inválido")
        if not await db["usuarios_worker"].find_one({"_id": wid}):
            raise HTTPException(status_code=404, detail="Worker no encontrado")
        worker_id_str = str(wid)

    if not _cron_proxima(body.cron_expr):
        raise HTTPException(status_code=400, detail="Expresión CRON inválida")

    proxima = _cron_proxima(body.cron_expr)
    id_schedule = str(uuid.uuid4())
    ahora = _now_iso()
    doc = {
        "id_schedule": id_schedule, "id_proyecto": str(pid), "worker_id": worker_id_str,
        "pool": body.pool, "cron_expr": body.cron_expr, "descripcion": body.descripcion,
        "activo": body.activo, "proxima_ejecucion": proxima, "ultima_ejecucion": None,
        "credenciales_encriptadas": body.credenciales_encriptadas, "max_reintentos": body.max_reintentos,
        "prioridad": body.prioridad, "tags": body.tags, "fecha_creacion": ahora,
    }
    await db["schedules"].insert_one(doc)
    await _audit(db, user.get("sub", "?"), "crear_schedule", id_schedule, body.cron_expr)
    return ScheduleInfo(id_schedule=id_schedule, id_proyecto=str(pid), nombre_proyecto=proyecto.get("nombre"),
                        worker_id=worker_id_str, pool=body.pool, cron_expr=body.cron_expr,
                        descripcion=body.descripcion, activo=body.activo, proxima_ejecucion=proxima,
                        ultima_ejecucion=None, max_reintentos=body.max_reintentos, prioridad=body.prioridad,
                        tags=body.tags, fecha_creacion=ahora)


@app.get("/api/schedules", response_model=list[ScheduleInfo], tags=["Schedules"])
async def listar_schedules(activo: Optional[bool] = Query(default=None),
                           db: AsyncIOMotorDatabase = Depends(get_db),
                           _: dict = Depends(_verify_master)) -> list[ScheduleInfo]:
    filtro: dict = {}
    if activo is not None:
        filtro["activo"] = activo
    proyectos_map = {str(p["_id"]): p["nombre"] async for p in db["proyectos"].find({}, {"nombre": 1})}
    out = []
    async for s in db["schedules"].find(filtro).sort("fecha_creacion", DESCENDING):
        out.append(ScheduleInfo(
            id_schedule=s["id_schedule"], id_proyecto=s["id_proyecto"],
            nombre_proyecto=proyectos_map.get(s["id_proyecto"]), worker_id=s.get("worker_id"),
            pool=s.get("pool"), cron_expr=s["cron_expr"], descripcion=s.get("descripcion"),
            activo=s["activo"], proxima_ejecucion=s.get("proxima_ejecucion"),
            ultima_ejecucion=s.get("ultima_ejecucion"), max_reintentos=s.get("max_reintentos", 0),
            prioridad=s.get("prioridad", 0), tags=s.get("tags", []), fecha_creacion=s["fecha_creacion"]))
    return out


@app.patch("/api/schedules/{id_schedule}", tags=["Schedules"])
async def editar_schedule(id_schedule: str, body: ActualizarScheduleRequest,
                          db: AsyncIOMotorDatabase = Depends(get_db),
                          user: dict = Depends(_verify_master)) -> dict[str, Any]:
    campos: dict[str, Any] = {}
    if body.cron_expr is not None:
        if not _cron_proxima(body.cron_expr):
            raise HTTPException(status_code=400, detail="Expresión CRON inválida")
        campos["cron_expr"] = body.cron_expr
        campos["proxima_ejecucion"] = _cron_proxima(body.cron_expr)
    for f in ["descripcion", "prioridad", "max_reintentos", "tags"]:
        v = getattr(body, f, None)
        if v is not None:
            campos[f] = v
    if not campos:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    r = await db["schedules"].update_one({"id_schedule": id_schedule}, {"$set": campos})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Schedule no encontrado")
    await _audit(db, user.get("sub", "?"), "editar_schedule", id_schedule)
    return {"mensaje": "Schedule actualizado", "proxima_ejecucion": campos.get("proxima_ejecucion")}


@app.patch("/api/schedules/{id_schedule}/toggle", tags=["Schedules"])
async def toggle_schedule(id_schedule: str, db: AsyncIOMotorDatabase = Depends(get_db),
                          _: dict = Depends(_verify_master)) -> dict[str, Any]:
    s = await db["schedules"].find_one({"id_schedule": id_schedule})
    if not s:
        raise HTTPException(status_code=404, detail="Schedule no encontrado")
    nuevo = not s["activo"]
    await db["schedules"].update_one({"id_schedule": id_schedule}, {"$set": {"activo": nuevo}})
    return {"activo": nuevo, "mensaje": f"Schedule {'activado' if nuevo else 'desactivado'}"}


@app.delete("/api/schedules/{id_schedule}", tags=["Schedules"])
async def eliminar_schedule(id_schedule: str, db: AsyncIOMotorDatabase = Depends(get_db),
                            user: dict = Depends(_verify_master)) -> dict[str, str]:
    r = await db["schedules"].delete_one({"id_schedule": id_schedule})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Schedule no encontrado")
    await _audit(db, user.get("sub", "?"), "eliminar_schedule", id_schedule)
    return {"mensaje": "Schedule eliminado"}


@app.post("/api/schedules/tick", tags=["Schedules"])
async def ejecutar_schedules_pendientes(db: AsyncIOMotorDatabase = Depends(get_db),
                                        _: dict = Depends(_verify_master)) -> dict[str, Any]:
    """Ejecuta schedules vencidos. Llamar desde un Render Cron Job cada minuto."""
    ahora_iso = _now_iso()
    lanzadas = 0
    errores_lista = []
    cursor = db["schedules"].find({"activo": True, "proxima_ejecucion": {"$lte": ahora_iso}})
    async for s in cursor:
        try:
            # Elegir worker: explícito, por pool, o auto
            if s.get("worker_id"):
                worker = await db["usuarios_worker"].find_one({"_id": ObjectId(s["worker_id"])})
            elif s.get("pool"):
                pool = await db["pools"].find_one({"nombre": s["pool"]})
                worker = await _mejor_worker(db, pool.get("worker_ids", []) if pool else None)
            else:
                worker = await _mejor_worker(db)

            if not worker or worker["estado"] == "desconectado":
                errores_lista.append(f"{s['id_schedule']}: sin worker disponible")
                continue
            proyecto = await db["proyectos"].find_one({"_id": ObjectId(s["id_proyecto"])})
            if not proyecto:
                errores_lista.append(f"{s['id_schedule']}: proyecto inexistente")
                continue

            body_dict = {
                "credenciales_encriptadas": s.get("credenciales_encriptadas"),
                "prioridad": s.get("prioridad", 0), "tags": s.get("tags", []),
                "notas": f"Lanzada por schedule {s['id_schedule']}",
                "max_reintentos": s.get("max_reintentos", 0), "depende_de": [],
                "git_ref": None, "env_override": {}, "sla_segundos": 0,
            }
            await _crear_tarea_doc(db, ObjectId(s["id_proyecto"]), worker["_id"], proyecto, worker, body_dict)
            proxima = _cron_proxima(s["cron_expr"])
            await db["schedules"].update_one({"id_schedule": s["id_schedule"]},
                                             {"$set": {"ultima_ejecucion": ahora_iso, "proxima_ejecucion": proxima}})
            lanzadas += 1
        except Exception as e:
            errores_lista.append(f"{s['id_schedule']}: {e}")
            logger.error(f"Error en schedule {s['id_schedule']}: {e}")
    return {"tareas_lanzadas": lanzadas, "errores": errores_lista, "timestamp": ahora_iso}


# ─────────────────────────────────────────────
# WEBHOOKS
# ─────────────────────────────────────────────

@app.post("/api/webhooks", response_model=WebhookInfo, tags=["Webhooks"])
async def crear_webhook(body: CrearWebhookRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                        user: dict = Depends(_verify_master)) -> WebhookInfo:
    id_webhook = str(uuid.uuid4())
    ahora = _now_iso()
    await db["webhooks"].insert_one({
        "id_webhook": id_webhook, "url": body.url, "eventos": body.eventos,
        "descripcion": body.descripcion, "activo": body.activo, "secreto": body.secreto,
        "fallos_totales": 0, "ultimo_fallo": None, "fecha_creacion": ahora})
    await _audit(db, user.get("sub", "?"), "crear_webhook", id_webhook, body.url)
    return WebhookInfo(id_webhook=id_webhook, url=body.url, eventos=body.eventos,
                       descripcion=body.descripcion, activo=body.activo, fecha_creacion=ahora)


@app.get("/api/webhooks", response_model=list[WebhookInfo], tags=["Webhooks"])
async def listar_webhooks(db: AsyncIOMotorDatabase = Depends(get_db),
                          _: dict = Depends(_verify_master)) -> list[WebhookInfo]:
    out = []
    async for w in db["webhooks"].find().sort("fecha_creacion", DESCENDING):
        out.append(WebhookInfo(id_webhook=w["id_webhook"], url=w["url"], eventos=w["eventos"],
                               descripcion=w.get("descripcion"), activo=w["activo"],
                               fecha_creacion=w["fecha_creacion"]))
    return out


@app.post("/api/webhooks/{id_webhook}/test", tags=["Webhooks"])
async def probar_webhook(id_webhook: str, db: AsyncIOMotorDatabase = Depends(get_db),
                         _: dict = Depends(_verify_master)) -> dict[str, Any]:
    import httpx
    wh = await db["webhooks"].find_one({"id_webhook": id_webhook})
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook no encontrado")
    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            r = await client.post(wh["url"], json={"evento": "test", "data": {"mensaje": "Ping de prueba"}, "ts": _now_iso()})
        return {"ok": True, "status_code": r.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.delete("/api/webhooks/{id_webhook}", tags=["Webhooks"])
async def eliminar_webhook(id_webhook: str, db: AsyncIOMotorDatabase = Depends(get_db),
                           user: dict = Depends(_verify_master)) -> dict[str, str]:
    r = await db["webhooks"].delete_one({"id_webhook": id_webhook})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Webhook no encontrado")
    await _audit(db, user.get("sub", "?"), "eliminar_webhook", id_webhook)
    return {"mensaje": "Webhook eliminado"}


# ─────────────────────────────────────────────
# PLANTILLAS DE LANZAMIENTO
# ─────────────────────────────────────────────

@app.post("/api/plantillas", response_model=PlantillaInfo, tags=["Plantillas"])
async def crear_plantilla(body: CrearPlantillaRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                          user: dict = Depends(_verify_master)) -> PlantillaInfo:
    try:
        pid = ObjectId(body.id_proyecto)
    except Exception:
        raise HTTPException(status_code=400, detail="id_proyecto inválido")
    proyecto = await db["proyectos"].find_one({"_id": pid})
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    oid = ObjectId()
    ahora = _now_iso()
    doc = {"_id": oid, "nombre": body.nombre, "id_proyecto": str(pid), "pool": body.pool,
           "prioridad": body.prioridad, "max_reintentos": body.max_reintentos, "tags": body.tags,
           "git_ref": body.git_ref, "sla_segundos": body.sla_segundos, "notas": body.notas,
           "archivos_adjuntos": [a.model_dump() for a in body.archivos_adjuntos],
           "fecha_creacion": ahora}
    try:
        await db["plantillas"].insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Ya existe una plantilla con ese nombre")
    await _audit(db, user.get("sub", "?"), "crear_plantilla", str(oid), body.nombre)
    return PlantillaInfo(id=str(oid), nombre=body.nombre, id_proyecto=str(pid),
                         nombre_proyecto=proyecto.get("nombre"), pool=body.pool, prioridad=body.prioridad,
                         max_reintentos=body.max_reintentos, tags=body.tags, git_ref=body.git_ref,
                         sla_segundos=body.sla_segundos, notas=body.notas,
                         archivos_adjuntos=body.archivos_adjuntos, fecha_creacion=ahora)


@app.get("/api/plantillas", response_model=list[PlantillaInfo], tags=["Plantillas"])
async def listar_plantillas(db: AsyncIOMotorDatabase = Depends(get_db),
                            _: dict = Depends(_verify_master)) -> list[PlantillaInfo]:
    proyectos_map = {str(p["_id"]): p["nombre"] async for p in db["proyectos"].find({}, {"nombre": 1})}
    out = []
    async for t in db["plantillas"].find().sort("fecha_creacion", DESCENDING):
        out.append(PlantillaInfo(id=str(t["_id"]), nombre=t["nombre"], id_proyecto=t["id_proyecto"],
                                 nombre_proyecto=proyectos_map.get(t["id_proyecto"]), pool=t.get("pool"),
                                 prioridad=t.get("prioridad", 0), max_reintentos=t.get("max_reintentos", 0),
                                 tags=t.get("tags", []), git_ref=t.get("git_ref"),
                                 sla_segundos=t.get("sla_segundos", 0), notas=t.get("notas"),
                                 archivos_adjuntos=t.get("archivos_adjuntos", []),
                                 fecha_creacion=t["fecha_creacion"]))
    return out


@app.delete("/api/plantillas/{plantilla_id}", tags=["Plantillas"])
async def eliminar_plantilla(plantilla_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                             user: dict = Depends(_verify_master)) -> dict[str, str]:
    try:
        oid = ObjectId(plantilla_id)
    except Exception:
        raise HTTPException(status_code=400, detail="plantilla_id inválido")
    r = await db["plantillas"].delete_one({"_id": oid})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Plantilla no encontrada")
    await _audit(db, user.get("sub", "?"), "eliminar_plantilla", plantilla_id)
    return {"mensaje": "Plantilla eliminada"}


# ─────────────────────────────────────────────
# BIBLIOTECA DE ARCHIVOS (configs reutilizables)
# ─────────────────────────────────────────────

class GuardarArchivoRequest(BaseModel):
    nombre_logico: str = Field(..., min_length=1, max_length=100, description="Nombre para identificarlo, ej. 'Config prod SIMAT'")
    nombre_archivo: str = Field(..., min_length=1, max_length=200, description="Nombre del archivo, ej. config.json")
    contenido: str = Field(default="")
    encriptado: bool = False
    es_binario: bool = False
    subcarpeta: str = Field(default="", max_length=200)
    descripcion: Optional[str] = Field(default=None, max_length=500)
    tags: list[str] = Field(default_factory=list)


class ActualizarArchivoRequest(BaseModel):
    nombre_logico: Optional[str] = None
    nombre_archivo: Optional[str] = None
    contenido: Optional[str] = None
    encriptado: Optional[bool] = None
    es_binario: Optional[bool] = None
    subcarpeta: Optional[str] = None
    descripcion: Optional[str] = None
    tags: Optional[list[str]] = None


class ArchivoBibliotecaInfo(BaseModel):
    id: str
    nombre_logico: str
    nombre_archivo: str
    encriptado: bool
    es_binario: bool
    subcarpeta: str
    descripcion: Optional[str] = None
    tags: list[str] = []
    tamano_bytes: int = 0
    fecha_creacion: str
    fecha_modificacion: Optional[str] = None


def _archivo_info(a: dict, incluir_contenido: bool = False) -> dict:
    base = {
        "id": str(a["_id"]), "nombre_logico": a["nombre_logico"], "nombre_archivo": a["nombre_archivo"],
        "encriptado": a.get("encriptado", False), "es_binario": a.get("es_binario", False),
        "subcarpeta": a.get("subcarpeta", ""), "descripcion": a.get("descripcion"),
        "tags": a.get("tags", []), "tamano_bytes": len(a.get("contenido", "") or ""),
        "fecha_creacion": a["fecha_creacion"], "fecha_modificacion": a.get("fecha_modificacion"),
    }
    if incluir_contenido:
        base["contenido"] = a.get("contenido", "")
    return base


@app.post("/api/archivos", tags=["Biblioteca"])
async def guardar_archivo(body: GuardarArchivoRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                          user: dict = Depends(_verify_master)) -> dict[str, Any]:
    oid = ObjectId()
    ahora = _now_iso()
    doc = {
        "_id": oid, "nombre_logico": body.nombre_logico, "nombre_archivo": body.nombre_archivo,
        "contenido": body.contenido, "encriptado": body.encriptado, "es_binario": body.es_binario,
        "subcarpeta": body.subcarpeta, "descripcion": body.descripcion, "tags": body.tags,
        "fecha_creacion": ahora, "fecha_modificacion": None,
    }
    await db["biblioteca_archivos"].insert_one(doc)
    await _audit(db, user.get("sub", "?"), "guardar_archivo", str(oid), body.nombre_logico)
    return _archivo_info(doc)


@app.get("/api/archivos", tags=["Biblioteca"])
async def listar_archivos(tag: Optional[str] = Query(default=None),
                          db: AsyncIOMotorDatabase = Depends(get_db),
                          _: dict = Depends(_verify_master)) -> list[dict]:
    filtro: dict = {}
    if tag:
        filtro["tags"] = tag
    out = []
    async for a in db["biblioteca_archivos"].find(filtro).sort("fecha_creacion", DESCENDING):
        out.append(_archivo_info(a, incluir_contenido=False))
    return out


@app.get("/api/archivos/{archivo_id}", tags=["Biblioteca"])
async def detalle_archivo(archivo_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                          _: dict = Depends(_verify_master)) -> dict:
    try:
        oid = ObjectId(archivo_id)
    except Exception:
        raise HTTPException(status_code=400, detail="archivo_id inválido")
    a = await db["biblioteca_archivos"].find_one({"_id": oid})
    if not a:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    return _archivo_info(a, incluir_contenido=True)


@app.patch("/api/archivos/{archivo_id}", tags=["Biblioteca"])
async def actualizar_archivo(archivo_id: str, body: ActualizarArchivoRequest,
                             db: AsyncIOMotorDatabase = Depends(get_db),
                             user: dict = Depends(_verify_master)) -> dict:
    try:
        oid = ObjectId(archivo_id)
    except Exception:
        raise HTTPException(status_code=400, detail="archivo_id inválido")
    campos: dict = {}
    for f in ["nombre_logico", "nombre_archivo", "contenido", "encriptado", "es_binario",
              "subcarpeta", "descripcion", "tags"]:
        v = getattr(body, f, None)
        if v is not None:
            campos[f] = v
    if not campos:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    campos["fecha_modificacion"] = _now_iso()
    a = await db["biblioteca_archivos"].find_one_and_update(
        {"_id": oid}, {"$set": campos}, return_document=ReturnDocument.AFTER)
    if not a:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    await _audit(db, user.get("sub", "?"), "actualizar_archivo", archivo_id)
    return _archivo_info(a, incluir_contenido=True)


@app.delete("/api/archivos/{archivo_id}", tags=["Biblioteca"])
async def eliminar_archivo(archivo_id: str, db: AsyncIOMotorDatabase = Depends(get_db),
                           user: dict = Depends(_verify_master)) -> dict[str, str]:
    try:
        oid = ObjectId(archivo_id)
    except Exception:
        raise HTTPException(status_code=400, detail="archivo_id inválido")
    r = await db["biblioteca_archivos"].delete_one({"_id": oid})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    await _audit(db, user.get("sub", "?"), "eliminar_archivo", archivo_id)
    return {"mensaje": "Archivo eliminado"}


# ─────────────────────────────────────────────
# NOTIFICACIONES
# ─────────────────────────────────────────────

@app.get("/api/notificaciones", response_model=list[NotificacionInfo], tags=["Notificaciones"])
async def listar_notificaciones(solo_no_leidas: bool = Query(default=False),
                                limit: int = Query(default=50, ge=1, le=200),
                                db: AsyncIOMotorDatabase = Depends(get_db),
                                _: dict = Depends(_verify_master)) -> list[NotificacionInfo]:
    filtro: dict = {}
    if solo_no_leidas:
        filtro["leida"] = False
    out = []
    async for n in db["notificaciones"].find(filtro).sort("ts", DESCENDING).limit(limit):
        out.append(NotificacionInfo(id_notif=n["id_notif"], ts=n["ts"], tipo=n["tipo"],
                                    mensaje=n["mensaje"], severidad=n.get("severidad", "info"),
                                    leida=n.get("leida", False)))
    return out


@app.get("/api/notificaciones/contador", tags=["Notificaciones"])
async def contador_notificaciones(db: AsyncIOMotorDatabase = Depends(get_db),
                                  _: dict = Depends(_verify_master)) -> dict[str, int]:
    no_leidas = await db["notificaciones"].count_documents({"leida": False})
    return {"no_leidas": no_leidas}


@app.post("/api/notificaciones/{id_notif}/leer", tags=["Notificaciones"])
async def marcar_leida(id_notif: str, db: AsyncIOMotorDatabase = Depends(get_db),
                       _: dict = Depends(_verify_master)) -> dict[str, str]:
    await db["notificaciones"].update_one({"id_notif": id_notif}, {"$set": {"leida": True}})
    return {"mensaje": "Marcada como leída"}


@app.post("/api/notificaciones/leer_todas", tags=["Notificaciones"])
async def marcar_todas_leidas(db: AsyncIOMotorDatabase = Depends(get_db),
                              _: dict = Depends(_verify_master)) -> dict[str, int]:
    r = await db["notificaciones"].update_many({"leida": False}, {"$set": {"leida": True}})
    return {"marcadas": r.modified_count}


@app.delete("/api/notificaciones", tags=["Notificaciones"])
async def limpiar_notificaciones(solo_leidas: bool = Query(default=True),
                                 db: AsyncIOMotorDatabase = Depends(get_db),
                                 _: dict = Depends(_verify_master)) -> dict[str, int]:
    filtro = {"leida": True} if solo_leidas else {}
    r = await db["notificaciones"].delete_many(filtro)
    return {"eliminadas": r.deleted_count}


# ─────────────────────────────────────────────
# AUDITORÍA
# ─────────────────────────────────────────────

@app.get("/api/audit", tags=["Auditoría"])
async def listar_auditoria(accion: Optional[str] = Query(default=None),
                           limit: int = Query(default=100, ge=1, le=500),
                           db: AsyncIOMotorDatabase = Depends(get_db),
                           _: dict = Depends(_verify_master)) -> list[dict]:
    filtro: dict = {}
    if accion:
        filtro["accion"] = accion
    out = []
    async for a in db["audit_log"].find(filtro).sort("ts", DESCENDING).limit(limit):
        out.append({"ts": a["ts"], "usuario": a.get("usuario", "?"), "accion": a.get("accion", ""),
                    "recurso": a.get("recurso", ""), "detalle": a.get("detalle", "")})
    return out


# ─────────────────────────────────────────────
# CONFIG GLOBAL
# ─────────────────────────────────────────────

@app.get("/api/config", tags=["Config"])
async def obtener_config(db: AsyncIOMotorDatabase = Depends(get_db),
                         _: dict = Depends(_verify_master)) -> dict[str, Any]:
    cfg = await _config_global(db)
    cfg.pop("_id", None)
    cfg["smtp_configurado"] = bool(SMTP_HOST)
    return cfg


@app.patch("/api/config", tags=["Config"])
async def actualizar_config(body: ActualizarConfigRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                            user: dict = Depends(_verify_master)) -> dict[str, Any]:
    campos: dict[str, Any] = {}
    for f in ["pausa_global", "email_alertas", "email_eventos", "sla_global_segundos"]:
        v = getattr(body, f, None)
        if v is not None:
            campos[f] = v
    if not campos:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    await db["config_global"].update_one({"_id": "global"}, {"$set": campos}, upsert=True)
    await _audit(db, user.get("sub", "?"), "editar_config", "global", str(list(campos.keys())))
    if "pausa_global" in campos:
        await _notificar(db, "config",
                         "Orquestador PAUSADO" if campos["pausa_global"] else "Orquestador REANUDADO",
                         "warning" if campos["pausa_global"] else "success")
    return {"mensaje": "Configuración actualizada", "config": campos}


@app.post("/api/sistema/pausa", tags=["Config"])
async def toggle_pausa_global(db: AsyncIOMotorDatabase = Depends(get_db),
                              user: dict = Depends(_verify_master)) -> dict[str, Any]:
    cfg = await _config_global(db)
    nuevo = not cfg.get("pausa_global", False)
    await db["config_global"].update_one({"_id": "global"}, {"$set": {"pausa_global": nuevo}}, upsert=True)
    await _audit(db, user.get("sub", "?"), "toggle_pausa", "global", str(nuevo))
    await _notificar(db, "config", "Orquestador PAUSADO" if nuevo else "Orquestador REANUDADO",
                     "warning" if nuevo else "success")
    return {"pausa_global": nuevo, "mensaje": "Pausado" if nuevo else "Reanudado"}


# ─────────────────────────────────────────────
# MÉTRICAS
# ─────────────────────────────────────────────

@app.get("/api/metricas/proyecto/{id_proyecto}", tags=["Métricas"])
async def metricas_proyecto(id_proyecto: str, dias: int = Query(default=30, ge=1, le=365),
                            db: AsyncIOMotorDatabase = Depends(get_db),
                            _: dict = Depends(_verify_master)) -> dict[str, Any]:
    desde = (datetime.now(timezone.utc) - timedelta(days=dias)).strftime("%Y-%m-%d")
    cursor = db["metricas_diarias"].find({"id_proyecto": id_proyecto, "fecha": {"$gte": desde}}).sort("fecha", ASCENDING)
    dias_data = []
    total = completadas = errores = canceladas = duracion_total = 0
    async for d in cursor:
        dias_data.append({
            "fecha": d["fecha"], "total": d.get("total", 0), "completadas": d.get("completadas", 0),
            "errores": d.get("errores", 0), "canceladas": d.get("canceladas", 0),
            "duracion_promedio_seg": round(d.get("duracion_total_seg", 0) / d.get("completadas", 1), 1)
                if d.get("completadas", 0) > 0 else None,
        })
        total += d.get("total", 0); completadas += d.get("completadas", 0)
        errores += d.get("errores", 0); canceladas += d.get("canceladas", 0)
        duracion_total += d.get("duracion_total_seg", 0)
    return {
        "id_proyecto": id_proyecto, "periodo_dias": dias,
        "resumen": {"total": total, "completadas": completadas, "errores": errores, "canceladas": canceladas,
                    "tasa_exito": round(completadas / total * 100, 1) if total > 0 else None,
                    "duracion_promedio_seg": round(duracion_total / completadas, 1) if completadas > 0 else None},
        "por_dia": dias_data,
    }


@app.get("/api/metricas/worker/{worker_id}", tags=["Métricas"])
async def metricas_worker(worker_id: str, dias: int = Query(default=30, ge=1, le=365),
                          db: AsyncIOMotorDatabase = Depends(get_db),
                          _: dict = Depends(_verify_master)) -> dict[str, Any]:
    desde = (datetime.now(timezone.utc) - timedelta(days=dias)).isoformat()
    pipeline = [{"$match": {"worker_asignado": worker_id, "fecha_creacion": {"$gte": desde}}},
                {"$group": {"_id": "$estado", "count": {"$sum": 1}}}]
    resultados = {}
    async for r in db["tareas"].aggregate(pipeline):
        resultados[r["_id"]] = r["count"]
    total = sum(resultados.values())
    return {"worker_id": worker_id, "periodo_dias": dias, "por_estado": resultados, "total": total,
            "tasa_exito": round(resultados.get("completada", 0) / total * 100, 1) if total > 0 else None}


@app.get("/api/metricas/global", tags=["Métricas"])
async def metricas_global(dias: int = Query(default=30, ge=1, le=365),
                          db: AsyncIOMotorDatabase = Depends(get_db),
                          _: dict = Depends(_verify_master)) -> dict[str, Any]:
    """Serie de tiempo agregada de todos los proyectos (throughput diario)."""
    desde = (datetime.now(timezone.utc) - timedelta(days=dias)).strftime("%Y-%m-%d")
    pipeline = [
        {"$match": {"fecha": {"$gte": desde}}},
        {"$group": {"_id": "$fecha", "total": {"$sum": "$total"}, "completadas": {"$sum": "$completadas"},
                    "errores": {"$sum": "$errores"}, "canceladas": {"$sum": "$canceladas"},
                    "duracion_total": {"$sum": "$duracion_total_seg"}}},
        {"$sort": {"_id": 1}},
    ]
    por_dia = []
    tot = comp = err = canc = dur = 0
    async for d in db["metricas_diarias"].aggregate(pipeline):
        por_dia.append({"fecha": d["_id"], "total": d["total"], "completadas": d["completadas"],
                        "errores": d["errores"], "canceladas": d["canceladas"]})
        tot += d["total"]; comp += d["completadas"]; err += d["errores"]; canc += d["canceladas"]
        dur += d.get("duracion_total", 0)
    return {"periodo_dias": dias, "por_dia": por_dia,
            "resumen": {"total": tot, "completadas": comp, "errores": err, "canceladas": canc,
                        "tasa_exito": round(comp / tot * 100, 1) if tot > 0 else None,
                        "duracion_promedio_seg": round(dur / comp, 1) if comp > 0 else None}}


@app.get("/api/metricas/export/csv", tags=["Métricas"])
async def exportar_metricas_csv(dias: int = Query(default=90, ge=1, le=365),
                                db: AsyncIOMotorDatabase = Depends(get_db),
                                _: dict = Depends(_verify_master)):
    desde = (datetime.now(timezone.utc) - timedelta(days=dias)).strftime("%Y-%m-%d")
    proyectos_map = {str(p["_id"]): p["nombre"] async for p in db["proyectos"].find({}, {"nombre": 1})}
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["fecha", "proyecto", "total", "completadas", "errores", "canceladas", "duracion_total_seg"])
    async for d in db["metricas_diarias"].find({"fecha": {"$gte": desde}}).sort("fecha", ASCENDING):
        writer.writerow([d["fecha"], proyectos_map.get(d["id_proyecto"], d["id_proyecto"]),
                         d.get("total", 0), d.get("completadas", 0), d.get("errores", 0),
                         d.get("canceladas", 0), round(d.get("duracion_total_seg", 0), 1)])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=metricas.csv"})


# ─────────────────────────────────────────────
# ENDPOINTS WORKER (interno)
# ─────────────────────────────────────────────

@app.post("/api/worker/heartbeat", response_model=HeartbeatResponse, tags=["Worker"])
async def worker_heartbeat(body: HeartbeatRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                           token_data: dict = Depends(_verify_worker)) -> HeartbeatResponse:
    if token_data.get("worker_id") != body.worker_id:
        raise HTTPException(status_code=403, detail="worker_id no coincide con el token")
    try:
        wid = ObjectId(body.worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")
    worker = await db["usuarios_worker"].find_one({"_id": wid})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker no encontrado")

    ahora = _now_iso()
    update_set: dict[str, Any] = {"ultima_conexion": ahora, "estado": body.estado}
    # Métricas de salud (opcionales, backward-compatible)
    if body.cpu_percent is not None or body.ram_percent is not None or body.disk_percent is not None:
        update_set["metricas"] = {
            "cpu_percent": body.cpu_percent, "ram_percent": body.ram_percent,
            "disk_percent": body.disk_percent, "ts": ahora,
        }
    await db["usuarios_worker"].update_one({"_id": wid}, {"$set": update_set})

    # Logs
    if body.logs:
        tarea_id = worker.get("tarea_actual")
        if tarea_id:
            tarea = await db["tareas"].find_one({"id_tarea": tarea_id}, {"logs": 1, "log_size_bytes": 1})
            if tarea:
                logs_actuales: list[dict] = tarea.get("logs", [])
                logs_actuales.extend(body.logs)
                max_bytes = MAX_LOG_SIZE_MB * 1024 * 1024
                logs_actuales = _truncar_logs_fifo(logs_actuales, max_bytes)
                await db["tareas"].update_one({"id_tarea": tarea_id},
                    {"$set": {"logs": logs_actuales, "log_size_bytes": _bytes_from_entries(logs_actuales),
                              "ultima_actualizacion_log": ahora}})

    # Comando pendiente
    tarea_id = worker.get("tarea_actual")
    if tarea_id:
        tarea = await db["tareas"].find_one({"id_tarea": tarea_id}, {"comando_pendiente": 1})
        if tarea:
            comando = tarea.get("comando_pendiente", "NONE")
            if comando != "NONE":
                await db["tareas"].update_one({"id_tarea": tarea_id}, {"$set": {"comando_pendiente": "NONE"}})
                return HeartbeatResponse(comando=comando, tarea_id=tarea_id)

    try:
        await _ejecutar_limpieza_interna(db)
        await _chequear_sla(db)
    except Exception as exc:
        logger.warning(f"Mantenimiento en heartbeat falló: {exc}")

    return HeartbeatResponse(comando="NONE", tarea_id=tarea_id)


@app.post("/api/worker/obtener_tarea", response_model=ObtenerTareaResponse, tags=["Worker"])
async def worker_obtener_tarea(db: AsyncIOMotorDatabase = Depends(get_db),
                               token_data: dict = Depends(_verify_worker)) -> ObtenerTareaResponse:
    try:
        wid = ObjectId(token_data.get("worker_id"))
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido en token")
    worker = await db["usuarios_worker"].find_one({"_id": wid})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker no encontrado")

    tarea_id = worker.get("tarea_actual")
    if not tarea_id:
        return ObtenerTareaResponse(tiene_tarea=False)
    tarea = await db["tareas"].find_one({"id_tarea": tarea_id, "estado": "ejecutando"})
    if not tarea:
        return ObtenerTareaResponse(tiene_tarea=False)

    # Respetar reintento con espera
    programada_para = tarea.get("programada_para")
    if programada_para and programada_para > _now_iso():
        return ObtenerTareaResponse(tiene_tarea=False)

    proyecto = await db["proyectos"].find_one({"_id": ObjectId(tarea["id_proyecto"])})
    if not proyecto:
        return ObtenerTareaResponse(tiene_tarea=False)

    # env_vars del proyecto + override de la tarea
    env_vars = dict(proyecto.get("env_vars", {}))
    env_vars.update(tarea.get("env_override", {}))
    # git_ref de la tarea o del proyecto
    git_ref = tarea.get("git_ref") or proyecto.get("git_ref")

    return ObtenerTareaResponse(
        tiene_tarea=True, tarea_id=tarea_id, id_proyecto=tarea["id_proyecto"],
        git_url=proyecto["git_url"], git_ref=git_ref,
        archivo_principal=proyecto["archivo_principal"],
        archivo_requirements=proyecto["archivo_requirements"],
        credenciales_encriptadas=tarea.get("credenciales_encriptadas"),
        env_vars=env_vars,
        archivos_adjuntos=tarea.get("archivos_adjuntos", []),
        timeout_segundos=tarea.get("timeout_segundos", 0),
    )


@app.post("/api/worker/logs", tags=["Worker"])
async def worker_enviar_logs(body: LogsRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                             token_data: dict = Depends(_verify_worker)) -> dict[str, Any]:
    if token_data.get("worker_id") != body.worker_id:
        raise HTTPException(status_code=403, detail="worker_id no coincide con el token")
    tarea = await db["tareas"].find_one({"id_tarea": body.id_tarea}, {"logs": 1, "log_size_bytes": 1})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    logs_actuales: list[dict] = tarea.get("logs", [])
    logs_actuales.extend(body.entries)
    max_bytes = MAX_LOG_SIZE_MB * 1024 * 1024
    logs_actuales = _truncar_logs_fifo(logs_actuales, max_bytes)
    nuevo_size = _bytes_from_entries(logs_actuales)
    await db["tareas"].update_one({"id_tarea": body.id_tarea},
        {"$set": {"logs": logs_actuales, "log_size_bytes": nuevo_size, "ultima_actualizacion_log": _now_iso()}})
    return {"mensaje": "Logs recibidos", "total_bytes": nuevo_size}


@app.post("/api/worker/finalizar_tarea", tags=["Worker"])
async def worker_finalizar_tarea(body: FinalizarTareaRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                                 token_data: dict = Depends(_verify_worker)) -> dict[str, str]:
    if token_data.get("worker_id") != body.worker_id:
        raise HTTPException(status_code=403, detail="worker_id no coincide con el token")
    if body.estado_final not in {"completada", "cancelada", "error"}:
        raise HTTPException(status_code=400, detail="estado_final inválido")
    tarea = await db["tareas"].find_one({"id_tarea": body.id_tarea})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")

    ahora = _now_iso()
    await db["tareas"].update_one({"id_tarea": body.id_tarea},
        {"$set": {"estado": body.estado_final, "fecha_fin": ahora, "comando_pendiente": "NONE"}})

    # Duración + métricas
    duracion_seg = 0.0
    if tarea.get("fecha_inicio"):
        try:
            duracion_seg = (datetime.fromisoformat(ahora) - datetime.fromisoformat(tarea["fecha_inicio"])).total_seconds()
        except Exception:
            pass
    await _registrar_metrica(db, tarea["id_proyecto"], body.estado_final, duracion_seg)

    # Contadores worker
    inc = {}
    if body.estado_final == "completada":
        inc = {"tareas_completadas": 1}
    elif body.estado_final == "error":
        inc = {"tareas_error": 1}
    update = {"$set": {"tarea_actual": None}}
    if inc:
        update["$inc"] = inc
    await db["usuarios_worker"].update_one({"_id": ObjectId(body.worker_id)}, update)

    # Reintentos
    await _manejar_reintento(db, tarea, body.estado_final)

    # Resolver dependientes si completó
    if body.estado_final == "completada":
        liberadas = await _resolver_dependientes(db, body.id_tarea)
        if liberadas:
            await _notificar(db, "dependencias",
                             f"{liberadas} tarea(s) liberada(s) tras completar {body.id_tarea[:8]}", "info")

    # Notificación + webhooks
    sev = {"completada": "success", "error": "error", "cancelada": "info"}.get(body.estado_final, "info")
    await _notificar(db, f"tarea_{body.estado_final}",
                     f"Tarea {body.id_tarea[:8]} finalizó: {body.estado_final} ({duracion_seg:.0f}s)", sev)
    evento_map = {"completada": "tarea_completada", "error": "tarea_error", "cancelada": "tarea_cancelada"}
    if evento_map.get(body.estado_final):
        await _disparar_webhooks(db, evento_map[body.estado_final],
            {"id_tarea": body.id_tarea, "id_proyecto": tarea["id_proyecto"],
             "worker_id": body.worker_id, "estado_final": body.estado_final, "duracion_seg": duracion_seg})

    await _procesar_siguiente_tarea(db, body.worker_id)
    return {"mensaje": f"Tarea finalizada: {body.estado_final}"}


# ─────────────────────────────────────────────
# SISTEMA
# ─────────────────────────────────────────────

@app.post("/api/sistema/limpieza", tags=["Sistema"])
async def ejecutar_limpieza(db: AsyncIOMotorDatabase = Depends(get_db),
                            _: dict = Depends(_verify_master)) -> dict[str, Any]:
    desconectados, errores = await _ejecutar_limpieza_interna(db)
    return {"workers_desconectados": desconectados, "tareas_marcadas_error": errores}


@app.post("/api/sistema/sla_check", tags=["Sistema"])
async def ejecutar_sla_check(db: AsyncIOMotorDatabase = Depends(get_db),
                             _: dict = Depends(_verify_master)) -> dict[str, int]:
    alertas = await _chequear_sla(db)
    return {"alertas_generadas": alertas}


@app.get("/api/sistema/estado", tags=["Sistema"])
async def estado_sistema(db: AsyncIOMotorDatabase = Depends(get_db),
                         _: dict = Depends(_verify_master)) -> dict[str, Any]:
    cfg = await _config_global(db)
    return {
        "workers": {
            "total": await db["usuarios_worker"].count_documents({}),
            "disponibles": await db["usuarios_worker"].count_documents({"estado": "disponible"}),
            "ocupados": await db["usuarios_worker"].count_documents({"estado": "ocupado"}),
            "desconectados": await db["usuarios_worker"].count_documents({"estado": "desconectado"}),
        },
        "tareas": {
            "total": await db["tareas"].count_documents({}),
            "ejecutando": await db["tareas"].count_documents({"estado": "ejecutando"}),
            "pendientes": await db["tareas"].count_documents({"estado": "pendiente"}),
            "esperando": await db["tareas"].count_documents({"estado": "esperando"}),
            "completadas": await db["tareas"].count_documents({"estado": "completada"}),
            "errores": await db["tareas"].count_documents({"estado": "error"}),
        },
        "schedules_activos": await db["schedules"].count_documents({"activo": True}),
        "webhooks_activos": await db["webhooks"].count_documents({"activo": True}),
        "pools": await db["pools"].count_documents({}),
        "notificaciones_no_leidas": await db["notificaciones"].count_documents({"leida": False}),
        "pausa_global": cfg.get("pausa_global", False),
        "timestamp": _now_iso(),
    }


@app.get("/api/sugerencias", tags=["Sistema"])
async def sugerencias(db: AsyncIOMotorDatabase = Depends(get_db),
                      _: dict = Depends(_verify_master)) -> dict[str, list]:
    """Devuelve valores ya usados en la base de datos para autocompletar campos.
    Ligero: usa distinct() sobre campos indexables, bajo demanda."""
    def _limpiar(vals, limite=40):
        out = sorted({str(v).strip() for v in vals if v and str(v).strip()})
        return out[:limite]

    # Tags de proyectos, tareas y plantillas (unificados)
    tags = set()
    for col in ("proyectos", "tareas", "plantillas", "biblioteca_archivos"):
        try:
            for t in await db[col].distinct("tags"):
                if t and str(t).strip():
                    tags.add(str(t).strip())
        except Exception:
            pass

    # Archivos principales y requirements usados en proyectos
    archivos_principales = await db["proyectos"].distinct("archivo_principal")
    requirements = await db["proyectos"].distinct("archivo_requirements")
    git_refs = await db["proyectos"].distinct("git_ref")

    # Nombres de archivos usados (biblioteca + adjuntos de proyectos)
    nombres_archivos = set(await db["biblioteca_archivos"].distinct("nombre_archivo"))
    try:
        async for p in db["proyectos"].find({}, {"archivos_adjuntos.nombre_archivo": 1}):
            for a in p.get("archivos_adjuntos", []):
                if a.get("nombre_archivo"):
                    nombres_archivos.add(a["nombre_archivo"])
    except Exception:
        pass

    # Subcarpetas usadas
    subcarpetas = set()
    try:
        for sc in await db["biblioteca_archivos"].distinct("subcarpeta"):
            if sc and str(sc).strip():
                subcarpetas.add(str(sc).strip())
    except Exception:
        pass

    return {
        "tags": _limpiar(tags),
        "archivos_principales": _limpiar(archivos_principales) or ["main.py"],
        "requirements": _limpiar(requirements) or ["requirements.txt"],
        "git_refs": _limpiar(git_refs),
        "nombres_archivos": _limpiar(nombres_archivos),
        "subcarpetas": _limpiar(subcarpetas),
    }


@app.get("/api/sistema/resumen", tags=["Sistema"])
async def resumen_ejecutivo(db: AsyncIOMotorDatabase = Depends(get_db),
                            _: dict = Depends(_verify_master)) -> dict[str, Any]:
    cfg = await _config_global(db)
    desde_30d = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    pipeline = [{"$match": {"fecha": {"$gte": desde_30d}}},
                {"$group": {"_id": None, "total": {"$sum": "$total"}, "completadas": {"$sum": "$completadas"},
                            "duracion_total": {"$sum": "$duracion_total_seg"}}}]
    tasa = tprom = None
    async for r in db["metricas_diarias"].aggregate(pipeline):
        if r.get("total", 0) > 0:
            tasa = round(r.get("completadas", 0) / r["total"] * 100, 1)
        if r.get("completadas", 0) > 0:
            tprom = round(r.get("duracion_total", 0) / r["completadas"], 1)
    return {
        "workers": {
            "total": await db["usuarios_worker"].count_documents({}),
            "disponibles": await db["usuarios_worker"].count_documents({"estado": "disponible"}),
            "ocupados": await db["usuarios_worker"].count_documents({"estado": "ocupado"}),
            "desconectados": await db["usuarios_worker"].count_documents({"estado": "desconectado"}),
        },
        "tareas": {
            "total": await db["tareas"].count_documents({}),
            "ejecutando": await db["tareas"].count_documents({"estado": "ejecutando"}),
            "pendientes": await db["tareas"].count_documents({"estado": "pendiente"}),
            "completadas": await db["tareas"].count_documents({"estado": "completada"}),
            "errores": await db["tareas"].count_documents({"estado": "error"}),
        },
        "proyectos_activos": await db["proyectos"].count_documents({}),
        "tasa_exito_30d": tasa,
        "tiempo_promedio_ejecucion_seg": tprom,
        "pausa_global": cfg.get("pausa_global", False),
        "notificaciones_no_leidas": await db["notificaciones"].count_documents({"leida": False}),
        "timestamp": _now_iso(),
    }


# ─────────────────────────────────────────────
# COPIA DE SEGURIDAD (export / import de configuración)
# ─────────────────────────────────────────────

# Colecciones que forman parte de la configuración (NO incluimos tareas/logs/métricas: son históricos pesados)
_COLECCIONES_BACKUP = ["proyectos", "usuarios_worker", "pools", "plantillas",
                       "schedules", "webhooks", "biblioteca_archivos", "config_global", "usuarios_master"]


def _limpiar_doc(d: dict) -> dict:
    """Convierte ObjectId a str y deja el documento serializable a JSON."""
    out = {}
    for k, v in d.items():
        if k == "_id":
            out["_id"] = str(v)
        elif isinstance(v, ObjectId):
            out[k] = str(v)
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


@app.get("/api/backup/exportar", tags=["Backup"])
async def exportar_backup(db: AsyncIOMotorDatabase = Depends(get_db),
                          admin: dict = Depends(_verify_admin)) -> dict[str, Any]:
    """Exporta toda la configuración a un JSON descargable (sin tareas/logs/métricas)."""
    data: dict[str, Any] = {
        "_meta": {"version": "3.7.0", "exportado": _now_iso(),
                  "por": admin.get("sub", "?"), "colecciones": _COLECCIONES_BACKUP},
        "datos": {},
    }
    total = 0
    for col in _COLECCIONES_BACKUP:
        docs = []
        async for d in db[col].find():
            docs.append(_limpiar_doc(d))
        data["datos"][col] = docs
        total += len(docs)
    data["_meta"]["total_documentos"] = total
    await _audit(db, admin.get("sub", "?"), "exportar_backup", "backup", f"{total} documentos")
    return data


class ImportarBackupRequest(BaseModel):
    datos: dict[str, list]
    modo: str = Field(default="combinar", description="'combinar' (no borra) o 'reemplazar' (vacía antes)")
    incluir_usuarios: bool = Field(default=False, description="Si True, también restaura usuarios_master")


@app.post("/api/backup/importar", tags=["Backup"])
async def importar_backup(body: ImportarBackupRequest, db: AsyncIOMotorDatabase = Depends(get_db),
                          admin: dict = Depends(_verify_admin)) -> dict[str, Any]:
    """Restaura configuración desde un backup. Modo 'combinar' (upsert) o 'reemplazar'."""
    if body.modo not in ("combinar", "reemplazar"):
        raise HTTPException(status_code=400, detail="modo debe ser 'combinar' o 'reemplazar'")
    resumen: dict[str, int] = {}
    for col, docs in body.datos.items():
        if col not in _COLECCIONES_BACKUP:
            continue
        if col == "usuarios_master" and not body.incluir_usuarios:
            continue
        if not isinstance(docs, list):
            continue
        if body.modo == "reemplazar":
            await db[col].delete_many({})
        n = 0
        for d in docs:
            d = dict(d)
            _id = d.pop("_id", None)
            try:
                oid = ObjectId(_id) if _id else ObjectId()
            except Exception:
                oid = ObjectId()
            try:
                await db[col].update_one({"_id": oid}, {"$set": d}, upsert=True)
                n += 1
            except Exception as e:
                logger.warning(f"Backup import: no se pudo restaurar doc en {col}: {e}")
        resumen[col] = n
    total = sum(resumen.values())
    await _audit(db, admin.get("sub", "?"), "importar_backup", "backup", f"modo={body.modo}, {total} docs")
    return {"mensaje": "Backup restaurado", "modo": body.modo, "restaurado": resumen, "total": total}


# ─────────────────────────────────────────────
# VALIDACIÓN PREVIA DE PROYECTO (pre-flight)
# ─────────────────────────────────────────────

class PreflightRequest(BaseModel):
    git_url: str
    archivo_principal: str = "main.py"
    archivo_requirements: Optional[str] = None
    git_ref: Optional[str] = None


@app.post("/api/proyectos/validar", tags=["Proyectos"])
async def validar_proyecto(body: PreflightRequest, user: dict = Depends(_verify_master)) -> dict[str, Any]:
    """Verifica (vía GitHub) que el repo existe y que el archivo principal está presente.
    Ligero: hasta 2 peticiones HTTP, sin clonar nada."""
    import httpx
    import re as _re
    m = _re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", body.git_url.strip())
    checks: list[dict[str, Any]] = []
    if not m:
        return {"ok": False, "checks": [{"item": "URL de GitHub", "ok": False,
                "detalle": "El formato debe ser https://github.com/usuario/repo"}]}
    owner, repo = m.group(1), m.group(2)
    rama = body.git_ref or None

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        # 1) El repositorio existe y es accesible
        repo_ok = False
        rama_def = "main"
        try:
            r = await client.get(f"https://api.github.com/repos/{owner}/{repo}",
                                 headers={"Accept": "application/vnd.github+json"})
            if r.status_code == 200:
                repo_ok = True
                rama_def = r.json().get("default_branch", "main")
                checks.append({"item": "Repositorio", "ok": True, "detalle": f"{owner}/{repo} accesible"})
            elif r.status_code == 404:
                checks.append({"item": "Repositorio", "ok": False,
                               "detalle": "No existe o es privado (debe ser público)"})
            elif r.status_code == 403:
                # límite de rate de GitHub: no podemos verificar, pero no es error del usuario
                checks.append({"item": "Repositorio", "ok": True,
                               "detalle": "No verificable ahora (límite de GitHub), se asume válido"})
                repo_ok = True
            else:
                checks.append({"item": "Repositorio", "ok": False, "detalle": f"HTTP {r.status_code}"})
        except Exception as e:
            checks.append({"item": "Repositorio", "ok": False, "detalle": f"Error de red: {str(e)[:60]}"})

        rama_usar = rama or rama_def
        # 2) El archivo principal existe en la rama
        if repo_ok:
            for archivo, etiqueta, obligatorio in [
                (body.archivo_principal, "Archivo principal", True),
                (body.archivo_requirements, "Requirements", False),
            ]:
                if not archivo:
                    continue
                try:
                    raw = await client.get(f"https://raw.githubusercontent.com/{owner}/{repo}/{rama_usar}/{archivo}")
                    if raw.status_code == 200:
                        checks.append({"item": etiqueta, "ok": True, "detalle": f"{archivo} encontrado"})
                    else:
                        checks.append({"item": etiqueta, "ok": (not obligatorio),
                                       "detalle": f"{archivo} no encontrado en la rama {rama_usar}"
                                       + ("" if obligatorio else " (opcional)")})
                except Exception as e:
                    checks.append({"item": etiqueta, "ok": not obligatorio, "detalle": f"Error: {str(e)[:50]}"})

    ok_global = all(c["ok"] for c in checks)
    return {"ok": ok_global, "repo": f"{owner}/{repo}", "checks": checks}


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, Any]:
    """Verifica que el proceso vive Y que MongoDB responde."""
    db_ok = False
    db_error = None
    try:
        db = await get_db()
        await db.command("ping")
        db_ok = True
    except Exception as e:
        db_error = str(e)[:120]
    estado = "ok" if db_ok else "degraded"
    resp: dict[str, Any] = {"status": estado, "version": "3.5.0", "timestamp": _now_iso(),
                            "database": "ok" if db_ok else "unreachable"}
    if db_error:
        resp["db_error"] = db_error
    return resp

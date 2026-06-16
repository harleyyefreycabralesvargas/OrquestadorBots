"""
api.py — RPA Orchestration Master API
FastAPI + MongoDB Atlas — Production Ready
Compatible: Python 3.11+, Windows 10/11, Render.com
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
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
WORKER_TIMEOUT_SECONDS: int = 120
JWT_EXPIRY_HOURS: int = 24

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

    # Índices
    await _db["usuarios_worker"].create_index("username", unique=True)
    await _db["proyectos"].create_index("nombre", unique=True)
    await _db["tareas"].create_index("id_tarea", unique=True)
    await _db["tareas"].create_index([("worker_asignado", ASCENDING), ("estado", ASCENDING)])
    await _db["tareas"].create_index([("estado", ASCENDING), ("fecha_creacion", DESCENDING)])

    logger.info("MongoDB Atlas conectado y colecciones indexadas.")
    yield
    if _mongo_client:
        _mongo_client.close()
        logger.info("Conexión MongoDB cerrada.")


# ─────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────

app = FastAPI(
    title="RPA Orchestration API",
    version="1.0.0",
    description="Sistema de Orquestación RPA Master-Worker",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# ─────────────────────────────────────────────
# JWT HELPERS
# ─────────────────────────────────────────────

def _create_jwt(payload: dict, secret: str, hours: int = JWT_EXPIRY_HOURS) -> str:
    payload = payload.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=hours)
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, secret, algorithm="HS256")


def _decode_jwt(token: str, secret: str) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Token inválido: {e}")


def _verify_master(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    payload = _decode_jwt(credentials.credentials, JWT_SECRET_MASTER)
    if payload.get("role") != "master":
        raise HTTPException(status_code=403, detail="Acceso restringido a Master")
    return payload


def _verify_worker(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    payload = _decode_jwt(credentials.credentials, JWT_SECRET_WORKER)
    if payload.get("role") != "worker":
        raise HTTPException(status_code=403, detail="Acceso restringido a Worker")
    return payload


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


class WorkerInfo(BaseModel):
    id: str
    username: str
    estado: str
    ultima_conexion: Optional[str]
    tarea_actual: Optional[str]
    cola_tareas: list[str]
    fecha_creacion: str


class CrearProyectoRequest(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=100)
    descripcion: str = Field(..., min_length=5)
    git_url: str
    archivo_principal: str = Field(..., min_length=1)
    archivo_requirements: str = Field(default="requirements.txt")

    @field_validator("git_url")
    @classmethod
    def validar_git_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://github.com/"):
            raise ValueError("Solo se permiten repositorios públicos de GitHub (https://github.com/...)")
        return v


class ProyectoInfo(BaseModel):
    id: str
    nombre: str
    descripcion: str
    git_url: str
    archivo_principal: str
    archivo_requirements: str
    fecha_creacion: str


class LanzarTareaRequest(BaseModel):
    id_proyecto: str
    worker_id: str
    credenciales_encriptadas: Optional[str] = None


class TareaInfo(BaseModel):
    id_tarea: str
    id_proyecto: str
    nombre_proyecto: Optional[str]
    worker_asignado: str
    estado: str
    fecha_creacion: str
    fecha_inicio: Optional[str]
    fecha_fin: Optional[str]
    log_size_bytes: int
    ultima_actualizacion_log: Optional[str]


class HeartbeatRequest(BaseModel):
    worker_id: str
    estado: str
    logs: list[dict] = Field(default_factory=list)


class HeartbeatResponse(BaseModel):
    comando: str = "NONE"
    tarea_id: Optional[str] = None


class ObtenerTareaResponse(BaseModel):
    tiene_tarea: bool
    tarea_id: Optional[str] = None
    id_proyecto: Optional[str] = None
    git_url: Optional[str] = None
    archivo_principal: Optional[str] = None
    archivo_requirements: Optional[str] = None
    credenciales_encriptadas: Optional[str] = None


class ComandoTareaRequest(BaseModel):
    comando: str  # PAUSE | RESUME | STOP


class EliminarLogsRequest(BaseModel):
    id_tarea: str


class LogsRequest(BaseModel):
    id_tarea: str
    worker_id: str
    entries: list[dict]


class LogsResponse(BaseModel):
    id_tarea: str
    logs: list[dict]
    total_bytes: int


class LimpiezaResponse(BaseModel):
    workers_desconectados: int
    tareas_marcadas_error: int


class FinalizarTareaRequest(BaseModel):
    id_tarea: str
    estado_final: str  # completada | cancelada | error
    worker_id: str


# ─────────────────────────────────────────────
# HELPERS INTERNOS
# ─────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _bytes_from_entries(entries: list[dict]) -> int:
    total = 0
    for e in entries:
        total += len(str(e).encode("utf-8"))
    return total


def _truncar_logs_fifo(logs: list[dict], max_bytes: int) -> list[dict]:
    """Elimina entradas antiguas hasta que el tamaño esté bajo el límite."""
    while logs and _bytes_from_entries(logs) > max_bytes:
        logs.pop(0)
    return logs


async def _procesar_siguiente_tarea(db: AsyncIOMotorDatabase, worker_id: str) -> None:
    """Toma la siguiente tarea de la cola del worker y la pone en ejecutando."""
    worker = await db["usuarios_worker"].find_one({"_id": worker_id})
    if not worker:
        return
    cola: list[str] = worker.get("cola_tareas", [])
    if not cola:
        await db["usuarios_worker"].update_one(
            {"_id": worker_id},
            {"$set": {"estado": "disponible", "tarea_actual": None}},
        )
        return

    siguiente_id = cola[0]
    tarea = await db["tareas"].find_one({"id_tarea": siguiente_id})
    if not tarea or tarea.get("estado") not in ("pendiente",):
        # Eliminar de cola y recursivo
        await db["usuarios_worker"].update_one(
            {"_id": worker_id},
            {"$pull": {"cola_tareas": siguiente_id}},
        )
        await _procesar_siguiente_tarea(db, worker_id)
        return

    ahora = _now_iso()
    await db["tareas"].update_one(
        {"id_tarea": siguiente_id},
        {"$set": {"estado": "ejecutando", "fecha_inicio": ahora, "comando_pendiente": "NONE"}},
    )
    await db["usuarios_worker"].update_one(
        {"_id": worker_id},
        {
            "$set": {"estado": "ocupado", "tarea_actual": siguiente_id},
            "$pull": {"cola_tareas": siguiente_id},
        },
    )
    logger.info(f"Siguiente tarea asignada: {siguiente_id} → Worker {worker_id}")


async def _ejecutar_limpieza_interna(db: AsyncIOMotorDatabase) -> tuple[int, int]:
    """Detecta workers desconectados y marca tareas huérfanas como error."""
    limite = _now_dt() - timedelta(seconds=WORKER_TIMEOUT_SECONDS)
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
            await workers_col.update_one(
                {"_id": worker["_id"]},
                {"$set": {"estado": "desconectado", "tarea_actual": None, "cola_tareas": []}},
            )
            desconectados += 1
            logger.warning(f"Worker desconectado detectado: {worker_id}")

            # Marcar tarea activa como error
            tarea_id = worker.get("tarea_actual")
            if tarea_id:
                resultado = await tareas_col.update_one(
                    {"id_tarea": tarea_id, "estado": {"$in": ["ejecutando", "pausada", "cancelando"]}},
                    {
                        "$set": {
                            "estado": "error",
                            "fecha_fin": _now_iso(),
                        },
                        "$push": {
                            "logs": {
                                "ts": _now_iso(),
                                "stream": "system",
                                "msg": f"Worker {worker_id} desconectado. Tarea marcada como error.",
                            }
                        },
                    },
                )
                if resultado.modified_count > 0:
                    errores += 1
                    logger.warning(f"Tarea {tarea_id} marcada como error por desconexión.")

    return desconectados, errores


# ─────────────────────────────────────────────
# ENDPOINTS AUTH
# ─────────────────────────────────────────────

@app.post("/api/auth/master", response_model=MasterLoginResponse, tags=["Auth"])
async def login_master(body: MasterLoginRequest) -> MasterLoginResponse:
    if body.username != MASTER_USERNAME:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    if not bcrypt.checkpw(body.password.encode(), MASTER_PASSWORD_HASH.encode()):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token = _create_jwt({"sub": body.username, "role": "master"}, JWT_SECRET_MASTER)
    logger.info(f"Master autenticado: {body.username}")
    return MasterLoginResponse(access_token=token)


@app.post("/api/auth/worker", response_model=WorkerLoginResponse, tags=["Auth"])
async def login_worker(body: WorkerLoginRequest, db: AsyncIOMotorDatabase = Depends(get_db)) -> WorkerLoginResponse:
    worker = await db["usuarios_worker"].find_one({"username": body.username})
    if not worker:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    if not bcrypt.checkpw(body.password.encode(), worker["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    await db["usuarios_worker"].update_one(
        {"_id": worker["_id"]},
        {"$set": {"ultima_conexion": _now_iso()}},
    )
    worker_id = str(worker["_id"])
    token = _create_jwt({"sub": body.username, "role": "worker", "worker_id": worker_id}, JWT_SECRET_WORKER)
    logger.info(f"Worker autenticado: {body.username} ({worker_id})")
    return WorkerLoginResponse(access_token=token, worker_id=worker_id)


# ─────────────────────────────────────────────
# ENDPOINTS WORKERS (MASTER)
# ─────────────────────────────────────────────

@app.post("/api/workers", response_model=WorkerInfo, tags=["Workers"])
async def crear_worker(
    body: CrearWorkerRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> WorkerInfo:
    existente = await db["usuarios_worker"].find_one({"username": body.username})
    if existente:
        raise HTTPException(status_code=409, detail="Username ya existe")

    from bson import ObjectId
    oid = ObjectId()
    password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    ahora = _now_iso()
    doc = {
        "_id": oid,
        "username": body.username,
        "password_hash": password_hash,
        "estado": "desconectado",
        "ultima_conexion": None,
        "tarea_actual": None,
        "cola_tareas": [],
        "fecha_creacion": ahora,
    }
    await db["usuarios_worker"].insert_one(doc)
    logger.info(f"Worker creado: {body.username} ({str(oid)})")
    return WorkerInfo(
        id=str(oid),
        username=body.username,
        estado="desconectado",
        ultima_conexion=None,
        tarea_actual=None,
        cola_tareas=[],
        fecha_creacion=ahora,
    )


@app.get("/api/workers", response_model=list[WorkerInfo], tags=["Workers"])
async def listar_workers(
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> list[WorkerInfo]:
    workers = []
    async for w in db["usuarios_worker"].find().sort("fecha_creacion", DESCENDING):
        workers.append(WorkerInfo(
            id=str(w["_id"]),
            username=w["username"],
            estado=w["estado"],
            ultima_conexion=w.get("ultima_conexion"),
            tarea_actual=w.get("tarea_actual"),
            cola_tareas=w.get("cola_tareas", []),
            fecha_creacion=w["fecha_creacion"],
        ))
    return workers


@app.delete("/api/workers/{worker_id}", tags=["Workers"])
async def eliminar_worker(
    worker_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> dict[str, str]:
    from bson import ObjectId
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
    logger.info(f"Worker eliminado: {worker_id}")
    return {"mensaje": "Worker eliminado correctamente"}


# ─────────────────────────────────────────────
# ENDPOINTS PROYECTOS (MASTER)
# ─────────────────────────────────────────────

@app.post("/api/proyectos", response_model=ProyectoInfo, tags=["Proyectos"])
async def crear_proyecto(
    body: CrearProyectoRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> ProyectoInfo:
    from bson import ObjectId
    oid = ObjectId()
    ahora = _now_iso()
    doc = {
        "_id": oid,
        "nombre": body.nombre,
        "descripcion": body.descripcion,
        "git_url": body.git_url,
        "archivo_principal": body.archivo_principal,
        "archivo_requirements": body.archivo_requirements,
        "fecha_creacion": ahora,
    }
    try:
        await db["proyectos"].insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Ya existe un proyecto con ese nombre")

    logger.info(f"Proyecto creado: {body.nombre} ({str(oid)})")
    return ProyectoInfo(
        id=str(oid),
        nombre=body.nombre,
        descripcion=body.descripcion,
        git_url=body.git_url,
        archivo_principal=body.archivo_principal,
        archivo_requirements=body.archivo_requirements,
        fecha_creacion=ahora,
    )


@app.get("/api/proyectos", response_model=list[ProyectoInfo], tags=["Proyectos"])
async def listar_proyectos(
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> list[ProyectoInfo]:
    proyectos = []
    async for p in db["proyectos"].find().sort("fecha_creacion", DESCENDING):
        proyectos.append(ProyectoInfo(
            id=str(p["_id"]),
            nombre=p["nombre"],
            descripcion=p["descripcion"],
            git_url=p["git_url"],
            archivo_principal=p["archivo_principal"],
            archivo_requirements=p["archivo_requirements"],
            fecha_creacion=p["fecha_creacion"],
        ))
    return proyectos


@app.delete("/api/proyectos/{proyecto_id}", tags=["Proyectos"])
async def eliminar_proyecto(
    proyecto_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> dict[str, str]:
    from bson import ObjectId
    try:
        oid = ObjectId(proyecto_id)
    except Exception:
        raise HTTPException(status_code=400, detail="proyecto_id inválido")

    resultado = await db["proyectos"].delete_one({"_id": oid})
    if resultado.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    logger.info(f"Proyecto eliminado: {proyecto_id}")
    return {"mensaje": "Proyecto eliminado correctamente"}


# ─────────────────────────────────────────────
# ENDPOINTS TAREAS (MASTER)
# ─────────────────────────────────────────────

@app.post("/api/tareas", response_model=TareaInfo, tags=["Tareas"])
async def lanzar_tarea(
    body: LanzarTareaRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> TareaInfo:
    from bson import ObjectId
    import uuid

    # Validar proyecto
    try:
        pid = ObjectId(body.id_proyecto)
    except Exception:
        raise HTTPException(status_code=400, detail="id_proyecto inválido")
    proyecto = await db["proyectos"].find_one({"_id": pid})
    if not proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    # Validar worker
    try:
        wid = ObjectId(body.worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")
    worker = await db["usuarios_worker"].find_one({"_id": wid})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker no encontrado")
    if worker["estado"] == "desconectado":
        raise HTTPException(status_code=409, detail="Worker desconectado")

    id_tarea = str(uuid.uuid4())
    ahora = _now_iso()
    worker_estado = worker["estado"]

    if worker_estado == "disponible":
        estado_tarea = "ejecutando"
        fecha_inicio: Optional[str] = ahora
        await db["usuarios_worker"].update_one(
            {"_id": wid},
            {"$set": {"estado": "ocupado", "tarea_actual": id_tarea}},
        )
    else:
        estado_tarea = "pendiente"
        fecha_inicio = None
        await db["usuarios_worker"].update_one(
            {"_id": wid},
            {"$push": {"cola_tareas": id_tarea}},
        )

    doc_tarea = {
        "id_tarea": id_tarea,
        "id_proyecto": str(pid),
        "worker_asignado": str(wid),
        "estado": estado_tarea,
        "credenciales_encriptadas": body.credenciales_encriptadas,
        "fecha_creacion": ahora,
        "fecha_inicio": fecha_inicio,
        "fecha_fin": None,
        "logs": [],
        "log_size_bytes": 0,
        "ultima_actualizacion_log": None,
        "comando_pendiente": "NONE",
    }
    await db["tareas"].insert_one(doc_tarea)
    logger.info(f"Tarea lanzada: {id_tarea} → Worker {body.worker_id} (estado={estado_tarea})")

    return TareaInfo(
        id_tarea=id_tarea,
        id_proyecto=str(pid),
        nombre_proyecto=proyecto.get("nombre"),
        worker_asignado=str(wid),
        estado=estado_tarea,
        fecha_creacion=ahora,
        fecha_inicio=fecha_inicio,
        fecha_fin=None,
        log_size_bytes=0,
        ultima_actualizacion_log=None,
    )


@app.get("/api/tareas", response_model=list[TareaInfo], tags=["Tareas"])
async def listar_tareas(
    estado: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> list[TareaInfo]:
    filtro: dict[str, Any] = {}
    if estado:
        filtro["estado"] = estado

    proyectos_map: dict[str, str] = {}
    async for p in db["proyectos"].find({}, {"nombre": 1}):
        proyectos_map[str(p["_id"])] = p["nombre"]

    tareas = []
    async for t in db["tareas"].find(filtro).sort("fecha_creacion", DESCENDING).limit(200):
        tareas.append(TareaInfo(
            id_tarea=t["id_tarea"],
            id_proyecto=t["id_proyecto"],
            nombre_proyecto=proyectos_map.get(t["id_proyecto"]),
            worker_asignado=t["worker_asignado"],
            estado=t["estado"],
            fecha_creacion=t["fecha_creacion"],
            fecha_inicio=t.get("fecha_inicio"),
            fecha_fin=t.get("fecha_fin"),
            log_size_bytes=t.get("log_size_bytes", 0),
            ultima_actualizacion_log=t.get("ultima_actualizacion_log"),
        ))
    return tareas


@app.post("/api/tareas/{id_tarea}/comando", tags=["Tareas"])
async def enviar_comando_tarea(
    id_tarea: str,
    body: ComandoTareaRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> dict[str, str]:
    comandos_validos = {"PAUSE", "RESUME", "STOP"}
    if body.comando not in comandos_validos:
        raise HTTPException(status_code=400, detail=f"Comando inválido. Válidos: {comandos_validos}")

    tarea = await db["tareas"].find_one({"id_tarea": id_tarea})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")

    estados_permitidos = {
        "PAUSE": ["ejecutando"],
        "RESUME": ["pausada"],
        "STOP": ["ejecutando", "pausada", "pendiente"],
    }
    if tarea["estado"] not in estados_permitidos[body.comando]:
        raise HTTPException(
            status_code=409,
            detail=f"No se puede aplicar {body.comando} a tarea en estado '{tarea['estado']}'",
        )

    nuevo_estado = tarea["estado"]
    if body.comando == "STOP":
        nuevo_estado = "cancelando"

    await db["tareas"].update_one(
        {"id_tarea": id_tarea},
        {"$set": {"comando_pendiente": body.comando, "estado": nuevo_estado}},
    )
    logger.info(f"Comando {body.comando} enviado a tarea {id_tarea}")
    return {"mensaje": f"Comando {body.comando} registrado"}


@app.get("/api/tareas/{id_tarea}/logs", response_model=LogsResponse, tags=["Tareas"])
async def obtener_logs_tarea(
    id_tarea: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> LogsResponse:
    tarea = await db["tareas"].find_one({"id_tarea": id_tarea}, {"logs": 1, "log_size_bytes": 1})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")
    return LogsResponse(
        id_tarea=id_tarea,
        logs=tarea.get("logs", []),
        total_bytes=tarea.get("log_size_bytes", 0),
    )


@app.delete("/api/tareas/{id_tarea}/logs", tags=["Tareas"])
async def eliminar_logs_tarea(
    id_tarea: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> dict[str, str]:
    tarea = await db["tareas"].find_one({"id_tarea": id_tarea}, {"estado": 1})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")

    estados_permitidos = {"completada", "cancelada", "error"}
    if tarea["estado"] not in estados_permitidos:
        raise HTTPException(
            status_code=409,
            detail=f"Solo se pueden eliminar logs de tareas en estado: {estados_permitidos}",
        )

    await db["tareas"].update_one(
        {"id_tarea": id_tarea},
        {"$set": {"logs": [], "log_size_bytes": 0}},
    )
    logger.info(f"Logs eliminados para tarea {id_tarea}")
    return {"mensaje": "Logs eliminados correctamente"}


# ─────────────────────────────────────────────
# ENDPOINTS WORKER
# ─────────────────────────────────────────────

@app.post("/api/worker/heartbeat", response_model=HeartbeatResponse, tags=["Worker"])
async def worker_heartbeat(
    body: HeartbeatRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    token_data: dict = Depends(_verify_worker),
) -> HeartbeatResponse:
    worker_id_token = token_data.get("worker_id")
    if worker_id_token != body.worker_id:
        raise HTTPException(status_code=403, detail="worker_id no coincide con el token")

    from bson import ObjectId
    try:
        wid = ObjectId(body.worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")

    worker = await db["usuarios_worker"].find_one({"_id": wid})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker no encontrado")

    ahora = _now_iso()
    await db["usuarios_worker"].update_one(
        {"_id": wid},
        {"$set": {"ultima_conexion": ahora, "estado": body.estado}},
    )

    # Procesar logs recibidos
    if body.logs:
        tarea_id = worker.get("tarea_actual")
        if tarea_id:
            tarea = await db["tareas"].find_one({"id_tarea": tarea_id}, {"logs": 1, "log_size_bytes": 1})
            if tarea:
                logs_actuales: list[dict] = tarea.get("logs", [])
                logs_actuales.extend(body.logs)
                max_bytes = MAX_LOG_SIZE_MB * 1024 * 1024
                logs_actuales = _truncar_logs_fifo(logs_actuales, max_bytes)
                nuevo_size = _bytes_from_entries(logs_actuales)
                await db["tareas"].update_one(
                    {"id_tarea": tarea_id},
                    {
                        "$set": {
                            "logs": logs_actuales,
                            "log_size_bytes": nuevo_size,
                            "ultima_actualizacion_log": ahora,
                        }
                    },
                )

    # Obtener comando pendiente
    tarea_id = worker.get("tarea_actual")
    if tarea_id:
        tarea = await db["tareas"].find_one({"id_tarea": tarea_id}, {"comando_pendiente": 1})
        if tarea:
            comando = tarea.get("comando_pendiente", "NONE")
            if comando != "NONE":
                # Limpiar comando después de entregarlo
                await db["tareas"].update_one(
                    {"id_tarea": tarea_id},
                    {"$set": {"comando_pendiente": "NONE"}},
                )
                return HeartbeatResponse(comando=comando, tarea_id=tarea_id)

    # Limpieza rápida en background (sin overhead pesado)
    try:
        await _ejecutar_limpieza_interna(db)
    except Exception as exc:
        logger.warning(f"Limpieza automática falló silenciosamente: {exc}")

    return HeartbeatResponse(comando="NONE", tarea_id=tarea_id)


@app.post("/api/worker/obtener_tarea", response_model=ObtenerTareaResponse, tags=["Worker"])
async def worker_obtener_tarea(
    db: AsyncIOMotorDatabase = Depends(get_db),
    token_data: dict = Depends(_verify_worker),
) -> ObtenerTareaResponse:
    from bson import ObjectId
    worker_id = token_data.get("worker_id")
    try:
        wid = ObjectId(worker_id)
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

    proyecto = await db["proyectos"].find_one({"_id": ObjectId(tarea["id_proyecto"])})
    if not proyecto:
        return ObtenerTareaResponse(tiene_tarea=False)

    return ObtenerTareaResponse(
        tiene_tarea=True,
        tarea_id=tarea_id,
        id_proyecto=tarea["id_proyecto"],
        git_url=proyecto["git_url"],
        archivo_principal=proyecto["archivo_principal"],
        archivo_requirements=proyecto["archivo_requirements"],
        credenciales_encriptadas=tarea.get("credenciales_encriptadas"),
    )


@app.post("/api/worker/logs", tags=["Worker"])
async def worker_enviar_logs(
    body: LogsRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    token_data: dict = Depends(_verify_worker),
) -> dict[str, Any]:
    worker_id_token = token_data.get("worker_id")
    if worker_id_token != body.worker_id:
        raise HTTPException(status_code=403, detail="worker_id no coincide con el token")

    tarea = await db["tareas"].find_one({"id_tarea": body.id_tarea}, {"logs": 1, "log_size_bytes": 1})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")

    logs_actuales: list[dict] = tarea.get("logs", [])
    logs_actuales.extend(body.entries)
    max_bytes = MAX_LOG_SIZE_MB * 1024 * 1024
    logs_actuales = _truncar_logs_fifo(logs_actuales, max_bytes)
    nuevo_size = _bytes_from_entries(logs_actuales)

    await db["tareas"].update_one(
        {"id_tarea": body.id_tarea},
        {
            "$set": {
                "logs": logs_actuales,
                "log_size_bytes": nuevo_size,
                "ultima_actualizacion_log": _now_iso(),
            }
        },
    )
    return {"mensaje": "Logs recibidos", "total_bytes": nuevo_size}


@app.post("/api/worker/finalizar_tarea", tags=["Worker"])
async def worker_finalizar_tarea(
    body: FinalizarTareaRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    token_data: dict = Depends(_verify_worker),
) -> dict[str, str]:
    worker_id_token = token_data.get("worker_id")
    if worker_id_token != body.worker_id:
        raise HTTPException(status_code=403, detail="worker_id no coincide con el token")

    estados_validos = {"completada", "cancelada", "error"}
    if body.estado_final not in estados_validos:
        raise HTTPException(status_code=400, detail=f"estado_final inválido. Válidos: {estados_validos}")

    tarea = await db["tareas"].find_one({"id_tarea": body.id_tarea})
    if not tarea:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")

    await db["tareas"].update_one(
        {"id_tarea": body.id_tarea},
        {"$set": {"estado": body.estado_final, "fecha_fin": _now_iso(), "comando_pendiente": "NONE"}},
    )

    from bson import ObjectId
    try:
        wid = ObjectId(body.worker_id)
    except Exception:
        raise HTTPException(status_code=400, detail="worker_id inválido")

    await db["usuarios_worker"].update_one(
        {"_id": wid},
        {"$set": {"tarea_actual": None}},
    )

    await _procesar_siguiente_tarea(db, body.worker_id)
    logger.info(f"Tarea {body.id_tarea} finalizada con estado: {body.estado_final}")
    return {"mensaje": f"Tarea finalizada: {body.estado_final}"}


# ─────────────────────────────────────────────
# SISTEMA
# ─────────────────────────────────────────────

@app.post("/api/sistema/limpieza", response_model=LimpiezaResponse, tags=["Sistema"])
async def ejecutar_limpieza(
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> LimpiezaResponse:
    desconectados, errores = await _ejecutar_limpieza_interna(db)
    logger.info(f"Limpieza manual: {desconectados} workers desconectados, {errores} tareas marcadas error")
    return LimpiezaResponse(workers_desconectados=desconectados, tareas_marcadas_error=errores)


@app.get("/api/sistema/estado", tags=["Sistema"])
async def estado_sistema(
    db: AsyncIOMotorDatabase = Depends(get_db),
    _: dict = Depends(_verify_master),
) -> dict[str, Any]:
    total_workers = await db["usuarios_worker"].count_documents({})
    disponibles = await db["usuarios_worker"].count_documents({"estado": "disponible"})
    ocupados = await db["usuarios_worker"].count_documents({"estado": "ocupado"})
    desconectados = await db["usuarios_worker"].count_documents({"estado": "desconectado"})
    total_tareas = await db["tareas"].count_documents({})
    ejecutando = await db["tareas"].count_documents({"estado": "ejecutando"})
    pendientes = await db["tareas"].count_documents({"estado": "pendiente"})
    return {
        "workers": {
            "total": total_workers,
            "disponibles": disponibles,
            "ocupados": ocupados,
            "desconectados": desconectados,
        },
        "tareas": {
            "total": total_tareas,
            "ejecutando": ejecutando,
            "pendientes": pendientes,
        },
        "timestamp": _now_iso(),
    }


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "timestamp": _now_iso()}

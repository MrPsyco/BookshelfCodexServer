"""CodexServer - FastAPI entrypoint (v0.3: manual OAuth/token handoff for cloud backends).

OAuth model: rclone v1.60 has no true Device-Code-Flow (no google.com/device + user_code).
Instead we surface rclone's own `rclone authorize <backend>` instructions and let the user
paste the resulting JSON token back. Works for every rclone OAuth backend without us
shipping or leaking our own client secret.

Endpoints:
  GET  /health                              (public)
  POST /upload                             (auth) multipart EPUB -> metadata pipeline -> storage
  GET  /api/books                          (auth)
  GET/POST/DELETE /api/storage             (auth) StorageConfig CRUD
  GET/PUT/POST/DELETE /api/metadata        (auth) MetadataConfig CRUD
  POST /sync/syncs                         (auth) KOReader progress push
  GET  /sync/progress/<user>/<doc>         (auth) KOReader progress pull
  POST /api/storage/{id}/mount             (auth) trigger rclone FUSE mount
  POST /api/storage/{id}/unmount           (auth) unmount
  POST /api/storage/{id}/auth_start        (auth) emit OAuth instructions (manual flow)
  GET  /api/storage/{id}/auth_status       (auth) poll auth flow state
  POST /api/storage/{id}/auth_complete     (auth) ingest pasted token, mount
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import signal
import subprocess
import threading
from base64 import b64decode
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Form, Request, status
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

import epub_washer
from database import get_db, init_db, SessionLocal
from models import Book, MetadataConfig, Progress, StorageConfig, User

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("codexserver")

BOOKS_ROOT = os.environ.get("BOOKS_ROOT", "/books")
STATIC_DIR = Path(__file__).parent / "static"
CLOUD_MOUNT_ROOT = Path(os.environ.get("CLOUD_MOUNT_ROOT", "/mnt/cloud"))
RCLONE_CONFIG = Path("/root/.config/rclone/rclone.conf")
RCLONE_LOG_DIR = Path("/var/log/codex-rclone")
RCLONE_LOG_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="CodexServer", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================================== AUTH ===

_admin_lock = threading.Lock()
_ADMIN_USER: str = ""
_ADMIN_PASS: str = ""


def _ensure_admin_credentials() -> tuple[str, str]:
    global _ADMIN_USER, _ADMIN_PASS
    with _admin_lock:
        if _ADMIN_USER and _ADMIN_PASS:
            return _ADMIN_USER, _ADMIN_PASS
        u = os.environ.get("CODEX_ADMIN_USER", "").strip()
        p = os.environ.get("CODEX_ADMIN_PASSWORD", "").strip()
        if not u:
            u = "admin"
        if not p:
            p = secrets.token_urlsafe(18)
            log.warning("=================================================================")
            log.warning("  No CODEX_ADMIN_PASSWORD set. Generated single-use admin password:")
            log.warning("  user: %s", u)
            log.warning("  pass: %s", p)
            log.warning("  Save this NOW. Restart the container to rotate.")
            log.warning("=================================================================")
        _ADMIN_USER = u
        _ADMIN_PASS = p
        return u, p


def _check_basic_auth(auth_header: Optional[str]) -> bool:
    if not auth_header or not auth_header.lower().startswith("basic "):
        return False
    try:
        raw = b64decode(auth_header.split(None, 1)[1]).decode("utf-8", errors="strict")
        user, _, password = raw.partition(":")
    except Exception:
        return False
    u, p = _ensure_admin_credentials()
    return hmac.compare_digest(user, u) and hmac.compare_digest(password, p)


def require_auth(request: Request) -> None:
    if not _check_basic_auth(request.headers.get("authorization")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="codexserver"'},
        )


# ======================================================= RCLONE MOUNT MGR ===

_mounts: dict[int, dict] = {}
_mounts_lock = threading.Lock()


def _slugify(s: str) -> str:
    import re
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", s).strip("_")
    return (s or "remote")[:60]


# OAuth-supporting backends in rclone v1.60.
# Each entry: (config_key_for_token, human_backend_aliases)
_OAUTH_BACKENDS = {
    "gdrive":   {"token_key": "token",  "drive_type": "drive"},
    "onedrive": {"token_key": "token",  "drive_type": "onedrive"},
    "dropbox":  {"token_key": "token",  "drive_type": "dropbox"},
    "box":      {"token_key": "token",  "drive_type": "box"},
    "pcloud":   {"token_key": "token",  "drive_type": "pcloud"},
}


def _rclone_remote_section(cfg: StorageConfig) -> str:
    creds = {}
    if cfg.credentials_json:
        try:
            creds = json.loads(cfg.credentials_json)
        except ValueError:
            log.warning("storage id=%s credentials_json is not valid JSON, ignored", cfg.id)

    if cfg.backend == "gdrive":
        return f"[{cfg.remote_name}]\ntype = drive\nscope = drive\n" + "".join(f"{k} = {v}\n" for k, v in creds.items())
    if cfg.backend == "onedrive":
        return f"[{cfg.remote_name}]\ntype = onedrive\n" + "".join(f"{k} = {v}\n" for k, v in creds.items())
    if cfg.backend == "dropbox":
        return f"[{cfg.remote_name}]\ntype = dropbox\n" + "".join(f"{k} = {v}\n" for k, v in creds.items())
    if cfg.backend == "webdav":
        url = creds.get("url", "")
        user = creds.get("user", "")
        pw = creds.get("pass", "")
        return (
            f"[{cfg.remote_name}]\ntype = webdav\nurl = {url}\nvendor = nextcloud\n"
            f"user = {user}\npass = {pw}\n"
        )
    if cfg.backend == "s3":
        return (
            f"[{cfg.remote_name}]\ntype = s3\nprovider = {creds.get('provider','Other')}\n"
            f"access_key_id = {creds.get('access_key_id','')}\n"
            f"secret_access_key = {creds.get('secret_access_key','')}\n"
            f"region = {creds.get('region','')}\n"
            f"endpoint = {creds.get('endpoint','')}\n"
        )
    raise ValueError(f"unsupported backend: {cfg.backend}")


def _ensure_rclone_config(db: Session) -> None:
    RCLONE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    sections = []
    for cfg in db.query(StorageConfig).filter(StorageConfig.is_active.is_(True)).all():
        if cfg.backend == "local" or not cfg.remote_name:
            continue
        try:
            sections.append(_rclone_remote_section(cfg))
        except Exception as e:  # noqa: BLE001
            log.warning("skipping storage id=%s: %s", cfg.id, e)
    RCLONE_CONFIG.write_text("\n".join(sections) + ("\n" if sections else ""))
    log.info("rclone config written with %d remote(s)", len(sections))


def mount_storage(cfg: StorageConfig) -> dict:
    with _mounts_lock:
        existing = _mounts.get(cfg.id)
        if existing and existing["proc"].poll() is None:
            return {"status": "already-mounted", "mountpoint": str(existing["mountpoint"])}

    if cfg.backend == "local":
        return {"status": "local-noop", "mountpoint": BOOKS_ROOT}

    if not cfg.remote_name:
        raise ValueError("remote_name is required for non-local backends")

    mountpoint = CLOUD_MOUNT_ROOT / _slugify(f"{cfg.backend}_{cfg.remote_name}")
    mountpoint.mkdir(parents=True, exist_ok=True)

    remote_path = (cfg.remote_path or "/").lstrip("/")
    remote_spec = f"{cfg.remote_name}:{remote_path}" if remote_path else f"{cfg.remote_name}:"

    log_path = RCLONE_LOG_DIR / f"{cfg.id}.log"
    log_file = open(log_path, "ab", buffering=0)

    cmd = [
        "rclone", "mount",
        remote_spec, str(mountpoint),
        "--config", str(RCLONE_CONFIG),
        "--vfs-cache-mode", "full",
        "--vfs-read-chunk-size", "64M",
        "--vfs-cache-max-age", "168h",
        "--allow-other",
        "--daemon",
    ]

    log.info("starting rclone mount: %s -> %s", remote_spec, mountpoint)
    proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file)

    with _mounts_lock:
        _mounts[cfg.id] = {"proc": proc, "mountpoint": mountpoint, "log": log_path}

    import time
    time.sleep(0.5)
    return {"status": "mount-started", "mountpoint": str(mountpoint), "log": str(log_path)}


def unmount_storage(cfg_id: int) -> dict:
    with _mounts_lock:
        m = _mounts.pop(cfg_id, None)
    if not m:
        return {"status": "not-mounted"}
    proc: subprocess.Popen = m["proc"]
    mountpoint: Path = m["mountpoint"]
    try:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        if mountpoint.exists():
            subprocess.run(["fusermount", "-u", str(mountpoint)],
                           capture_output=True, check=False)
    return {"status": "unmounted", "mountpoint": str(mountpoint)}


def remount_all(db: Session) -> None:
    _ensure_rclone_config(db)
    for cfg in db.query(StorageConfig).filter(StorageConfig.is_active.is_(True)).all():
        if cfg.backend == "local":
            continue
        try:
            mount_storage(cfg)
        except Exception as e:  # noqa: BLE001
            log.error("remount failed for storage id=%s: %s", cfg.id, e)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    Path(BOOKS_ROOT).mkdir(parents=True, exist_ok=True)
    CLOUD_MOUNT_ROOT.mkdir(parents=True, exist_ok=True)
    _ensure_admin_credentials()
    def _worker():
        with SessionLocal() as db:
            remount_all(db)
    threading.Thread(target=_worker, daemon=True, name="remount-all").start()
    log.info("CodexServer up. BOOKS_ROOT=%s CLOUD_MOUNT_ROOT=%s", BOOKS_ROOT, CLOUD_MOUNT_ROOT)


# ==================================================================== health

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "codexserver",
        "books_root": BOOKS_ROOT,
        "cloud_mount_root": str(CLOUD_MOUNT_ROOT),
        "active_mounts": [sid for sid, m in _mounts.items() if m["proc"].poll() is None],
    }


# ==================================================================== books

@app.get("/api/books", dependencies=[Depends(require_auth)])
def list_books(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(Book).order_by(Book.added_at.desc()).all()
    return [
        {
            "id": b.id, "title": b.title, "author": b.author,
            "storage_path": b.storage_path, "storage_backend": b.storage_backend,
            "file_size": b.file_size, "added_at": b.added_at.isoformat(),
        }
        for b in rows
    ]


@app.post("/upload", dependencies=[Depends(require_auth)])
async def upload_epub(
    file: UploadFile = File(...),
    backend: str = Form("local"),
    db: Session = Depends(get_db),
) -> JSONResponse:
    if not file.filename or not file.filename.lower().endswith(".epub"):
        raise HTTPException(400, "Only .epub uploads are accepted")

    blob = await file.read()
    if not blob:
        raise HTTPException(400, "Empty upload")

    active = (
        db.query(MetadataConfig)
        .filter(MetadataConfig.is_active.is_(True))
        .order_by(MetadataConfig.priority.asc())
        .all()
    )
    title, author = epub_washer.enrich(blob, active)
    if not title:
        title = Path(file.filename).stem
    if not author:
        author = "Unknown Author"

    chosen_root = BOOKS_ROOT
    chosen_label = backend
    if backend != "local":
        with _mounts_lock:
            for sid, m in _mounts.items():
                cfg = db.get(StorageConfig, sid)
                if cfg and cfg.backend == backend and m["proc"].poll() is None:
                    chosen_root = str(m["mountpoint"])
                    chosen_label = cfg.label
                    break

    dest = epub_washer.safe_storage_path(chosen_root, author, title, file.filename)
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(blob)

    book = Book(
        title=title, author=author, storage_path=dest,
        storage_backend=chosen_label, file_size=len(blob),
    )
    db.add(book)
    db.commit()
    db.refresh(book)

    return JSONResponse(
        {
            "id": book.id, "title": title, "author": author,
            "saved_to": dest, "providers_used": [c.provider_name for c in active],
        },
        status_code=201,
    )


# =============================================================== storage ===

class StorageIn(BaseModel):
    label: str
    backend: str
    remote_name: Optional[str] = None
    remote_path: Optional[str] = None
    credentials_json: Optional[str] = None
    is_active: bool = True


SUPPORTED_BACKENDS = {"local", "gdrive", "onedrive", "dropbox", "webdav", "s3"}


def _auth_status_dict(s: StorageConfig) -> dict:
    """Parse s.auth_status (JSON text) into a dict; default to idle."""
    if not s.auth_status:
        return {"state": "idle"}
    try:
        return json.loads(s.auth_status)
    except ValueError:
        return {"state": "error", "error": "corrupt auth_status JSON"}


def _set_auth_status(s: StorageConfig, **fields) -> dict:
    """Merge new fields into s.auth_status and return the result."""
    current = _auth_status_dict(s)
    current.update(fields)
    s.auth_status = json.dumps(current)
    return current


@app.get("/api/storage", dependencies=[Depends(require_auth)])
def list_storage(db: Session = Depends(get_db)) -> list[dict]:
    out = []
    for s in db.query(StorageConfig).all():
        mounted = s.id in _mounts and _mounts[s.id]["proc"].poll() is None
        out.append({
            "id": s.id, "label": s.label, "backend": s.backend,
            "remote_name": s.remote_name, "remote_path": s.remote_path,
            "is_active": s.is_active, "created_at": s.created_at.isoformat(),
            "mounted": mounted,
            "auth": _auth_status_dict(s),
        })
    return out


@app.post("/api/storage", dependencies=[Depends(require_auth)])
def create_storage(payload: StorageIn, db: Session = Depends(get_db)) -> dict:
    if payload.backend not in SUPPORTED_BACKENDS:
        raise HTTPException(400, f"backend must be one of {sorted(SUPPORTED_BACKENDS)}")
    if payload.backend != "local" and not payload.remote_name:
        raise HTTPException(400, "remote_name is required for non-local backends")

    s = StorageConfig(**payload.model_dump())
    db.add(s)
    db.commit()
    db.refresh(s)

    if s.backend != "local" and s.is_active:
        _ensure_rclone_config(db)
        try:
            mount_storage(s)
        except Exception as e:
            log.exception("mount failed for storage id=%s", s.id)
            return {"id": s.id, "label": s.label, "backend": s.backend,
                    "stub": False, "mount_error": str(e)}
    return {"id": s.id, "label": s.label, "backend": s.backend, "stub": False}


@app.delete("/api/storage/{sid}", dependencies=[Depends(require_auth)])
def delete_storage(sid: int, db: Session = Depends(get_db)) -> dict:
    if sid in _mounts:
        unmount_storage(sid)
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    db.delete(s)
    db.commit()
    return {"deleted": sid}


@app.post("/api/storage/{sid}/mount", dependencies=[Depends(require_auth)])
def api_mount(sid: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    _ensure_rclone_config(db)
    return mount_storage(s)


@app.post("/api/storage/{sid}/unmount", dependencies=[Depends(require_auth)])
def api_unmount(sid: int) -> dict:
    return unmount_storage(sid)


# ========================================================== OAuth flow ===

class AuthCompleteIn(BaseModel):
    token_blob: str
    # Optional: how to merge the token blob into rclone.conf.
    # "auto" (default): if backend is OAuth, merge {token: <blob>} into the [remote_name] section.
    # "raw":            replace credentials_json verbatim and let rclone.conf inherit it.
    mode: str = "auto"


_OAUTH_INSTRUCTIONS = {
    "gdrive": (
        "1. On a machine with rclone installed and a browser, run:\n"
        "     rclone authorize \"drive\"\n"
        "2. A browser window opens (or you copy the URL). Sign in to the Google account.\n"
        "3. rclone prints a single line of JSON that starts with\n"
        '   {"access_token":... or {"token":"...  — copy that ENTIRE line.\n'
        "4. Paste it into the field below and click 'Complete connection'.\n"
        "\n"
        "The container has no browser; we cannot do step 1 here."
    ),
    "onedrive": (
        "1. On a machine with rclone + browser, run:\n"
        "     rclone authorize \"onedrive\"\n"
        "2. Sign in to your Microsoft account, grant the requested scopes.\n"
        "3. rclone prints a JSON token line — copy the entire line.\n"
        "4. Paste it below and click 'Complete connection'."
    ),
    "dropbox": (
        "1. On a machine with rclone + browser, run:\n"
        "     rclone authorize \"dropbox\"\n"
        "2. Sign in to Dropbox, allow rclone access.\n"
        "3. rclone prints a JSON token line — copy the entire line.\n"
        "4. Paste it below and click 'Complete connection'."
    ),
    "box": (
        "1. On a machine with rclone + browser, run:\n"
        "     rclone authorize \"box\"\n"
        "2. Sign in to Box, allow rclone access.\n"
        "3. rclone prints a JSON token line — copy the entire line.\n"
        "4. Paste it below and click 'Complete connection'."
    ),
}


@app.post("/api/storage/{sid}/auth_start", dependencies=[Depends(require_auth)])
def api_auth_start(sid: int, db: Session = Depends(get_db)) -> dict:
    """Emit OAuth instructions for the given storage config.

    Does NOT start a subprocess — rclone v1.60 has no real Device-Code-Flow.
    The user must run `rclone authorize <backend>` on a machine with a browser
    and paste the resulting JSON token into /auth_complete.
    """
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    if s.backend == "local":
        raise HTTPException(400, "local backend needs no auth")
    if s.backend not in _OAUTH_INSTRUCTIONS:
        raise HTTPException(400, f"backend {s.backend!r} uses non-OAuth credentials; "
                                 "fill the credentials_json field directly.")

    instructions = _OAUTH_INSTRUCTIONS[s.backend]
    _set_auth_status(
        s, state="pending", backend=s.backend,
        instructions=instructions, error=None,
    )
    db.commit()
    return {
        "storage_id": sid,
        "backend": s.backend,
        "remote_name": s.remote_name,
        "state": "pending",
        "instructions": instructions,
        "note": ("rclone v1.60 has no true Device-Code-Flow. We surface rclone's own "
                 "`rclone authorize` instructions and accept the pasted token blob. "
                 "No client secret is shipped or required."),
    }


@app.get("/api/storage/{sid}/auth_status", dependencies=[Depends(require_auth)])
def api_auth_status(sid: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    return {"storage_id": sid, **_auth_status_dict(s)}


@app.post("/api/storage/{sid}/auth_complete", dependencies=[Depends(require_auth)])
def api_auth_complete(sid: int, payload: AuthCompleteIn, db: Session = Depends(get_db)) -> dict:
    """Ingest a pasted token blob and mount the storage."""
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")

    blob = payload.token_blob.strip()
    if not blob:
        raise HTTPException(400, "token_blob is empty")

    # Parse to validate it's JSON. rclone authorize prints a JSON object, possibly
    # wrapped in {"access_token": ...} or {"token": "..."}.
    try:
        parsed = json.loads(blob)
    except ValueError:
        _set_auth_status(s, state="error", error="pasted blob is not valid JSON")
        db.commit()
        raise HTTPException(400, "pasted blob is not valid JSON")

    if not isinstance(parsed, dict):
        _set_auth_status(s, state="error", error="pasted JSON must be an object")
        db.commit()
        raise HTTPException(400, "pasted JSON must be an object (got " + type(parsed).__name__ + ")")

    # Build credentials_json for the rclone.conf section.
    # rclone's OAuth backends want {"token": "<json-string>"} - i.e. the entire
    # JSON object gets re-stringified into a single config value.
    if payload.mode == "raw":
        creds = parsed
    else:
        # Auto-wrap: serialize the entire blob into a single "token" value.
        creds = {"token": json.dumps(parsed)}

    s.credentials_json = json.dumps(creds)
    _set_auth_status(s, state="complete", error=None)
    db.commit()

    # Rebuild rclone.conf + mount.
    _ensure_rclone_config(db)
    try:
        m = mount_storage(s)
        return {"storage_id": sid, "auth": "complete", "mount": m}
    except Exception as e:  # noqa: BLE001
        log.exception("mount after auth_complete failed for storage id=%s", s.id)
        _set_auth_status(s, state="error", error=f"auth ok but mount failed: {e}")
        db.commit()
        raise HTTPException(500, f"auth ok but mount failed: {e}")


# ============================================================== metadata ===

class MetadataIn(BaseModel):
    provider_name: str
    is_active: bool = True
    priority: int = 100
    api_key_or_url: Optional[str] = None


@app.get("/api/metadata", dependencies=[Depends(require_auth)])
def list_metadata(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(MetadataConfig).order_by(MetadataConfig.priority.asc()).all()
    return [
        {
            "id": m.id, "provider_name": m.provider_name, "is_active": m.is_active,
            "priority": m.priority, "api_key_or_url": m.api_key_or_url,
        }
        for m in rows
    ]


@app.post("/api/metadata", dependencies=[Depends(require_auth)])
def create_metadata(payload: MetadataIn, db: Session = Depends(get_db)) -> dict:
    if payload.provider_name not in epub_washer.PROVIDERS:
        raise HTTPException(400, f"unknown provider, supported: {sorted(epub_washer.PROVIDERS)}")
    m = MetadataConfig(**payload.model_dump())
    db.add(m)
    db.commit()
    db.refresh(m)
    return {"id": m.id, "provider_name": m.provider_name, "priority": m.priority}


@app.put("/api/metadata/{mid}", dependencies=[Depends(require_auth)])
def update_metadata(mid: int, payload: MetadataIn, db: Session = Depends(get_db)) -> dict:
    m = db.get(MetadataConfig, mid)
    if not m:
        raise HTTPException(404, "metadata config not found")
    m.provider_name = payload.provider_name
    m.is_active = payload.is_active
    m.priority = payload.priority
    m.api_key_or_url = payload.api_key_or_url
    db.commit()
    return {"id": m.id, "updated": True}


@app.delete("/api/metadata/{mid}", dependencies=[Depends(require_auth)])
def delete_metadata(mid: int, db: Session = Depends(get_db)) -> dict:
    m = db.get(MetadataConfig, mid)
    if not m:
        raise HTTPException(404, "metadata config not found")
    db.delete(m)
    db.commit()
    return {"deleted": mid}


# ============================================================ KOReader sync

class SyncBody(BaseModel):
    username: str
    password: str
    document: str
    progress: str
    percentage: Optional[float] = None
    device: Optional[str] = None


@app.post("/sync/syncs", dependencies=[Depends(require_auth)])
def koreader_push(body: SyncBody, db: Session = Depends(get_db)) -> dict:
    user = db.query(User).filter(User.username == body.username).first()
    if user is None:
        user = User(username=body.username)
        db.add(user)
        db.commit()
        db.refresh(user)

    book = db.query(Book).filter(Book.storage_path.like(f"%{body.document}%")).first()
    if book is None:
        book = Book(title=f"[unmatched:{body.document[:12]}]", author="Unknown Author",
                    storage_path=body.document, storage_backend="sync")
        db.add(book)
        db.commit()
        db.refresh(book)

    p = (
        db.query(Progress)
        .filter(Progress.user_id == user.id, Progress.book_id == book.id)
        .first()
    )
    if p is None:
        p = Progress(user_id=user.id, book_id=book.id, progress_percent=body.progress,
                     device=body.device)
        db.add(p)
    else:
        p.progress_percent = body.progress
        p.device = body.device
    db.commit()
    return {"status": "ok"}


@app.get("/sync/progress/{username}/{document}", dependencies=[Depends(require_auth)])
def koreader_pull(username: str, document: str, db: Session = Depends(get_db)) -> dict:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(404, "unknown user")
    book = db.query(Book).filter(Book.storage_path == document).first()
    if book is None:
        raise HTTPException(404, "unknown document")
    p = (
        db.query(Progress)
        .filter(Progress.user_id == user.id, Progress.book_id == book.id)
        .first()
    )
    if p is None:
        raise HTTPException(404, "no progress recorded")
    return {
        "username": username, "document": document,
        "progress": p.progress_percent,
        "device": p.device,
        "timestamp": int(p.updated_at.timestamp()),
    }


# ============================================================== static ===

@app.get("/", response_class=HTMLResponse)
def root() -> FileResponse:
    index = STATIC_DIR / "index.html"
    if not index.exists():
        return HTMLResponse("<h1>CodexServer</h1><p>UI not built.</p>", status_code=500)
    return FileResponse(index, media_type="text/html")


@app.get("/favicon.ico")
def favicon() -> JSONResponse:
    return JSONResponse({}, status_code=204)


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    log.warning("static/ directory missing at %s - assets will 404", STATIC_DIR)

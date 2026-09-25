"""CodexServer - FastAPI entrypoint (v0.4: split auth, first-run setup, cookie sessions).

AUTH MODEL (v0.4)
-----------------
Two completely separate authentication mechanisms, because they have two
completely different clients:

  * Web UI   -> cookie session. `POST /api/auth/login` sets an HttpOnly
                `codex_session` cookie (SameSite=Strict). Protected routes read
                the cookie. On failure we return 401 **without** a
                `WWW-Authenticate` header, so the browser NEVER pops its native
                basic-auth dialog (that dialog is triggered by the header per
                RFC 7617, not by the 401 status itself).
  * KOReader -> HTTP Basic on `/sync/*` only. KOReader is an API client, it
                handles the WWW-Authenticate challenge correctly. The header is
                deliberately kept on these routes.

FIRST-RUN SETUP
---------------
If the `users` table contains no row with role='admin', the UI routes to a
Setup screen instead of Login. `POST /api/setup/complete` creates the first
admin and logs them in. The auto-generated password in `docker logs` is gone;
an explicit `CODEX_ADMIN_USER`/`CODEX_ADMIN_PASSWORD` env pair still works as an
override for headless/CI deployments.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import signal
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Form, Request, status
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
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

SESSION_COOKIE = "codex_session"
SESSION_TTL = timedelta(days=14)

app = FastAPI(title="CodexServer", version="0.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain[:72])


def verify_password(plain: str, hashed: Optional[str]) -> bool:
    if not hashed:
        return False
    try:
        return pwd_ctx.verify(plain[:72], hashed)
    except ValueError:
        return False


# =========================================================== SESSIONS ===

_sessions: dict[str, dict] = {}
_sessions_lock = threading.Lock()


def _new_session(user: User) -> str:
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "expires": datetime.utcnow() + SESSION_TTL,
        }
    return token


def _read_session(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None
        if s["expires"] < datetime.utcnow():
            _sessions.pop(token, None)
            return None
        return s


def _drop_session(token: Optional[str]) -> None:
    if not token:
        return
    with _sessions_lock:
        _sessions.pop(token, None)


def _set_session_cookie(resp: JSONResponse, token: str) -> JSONResponse:
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="strict",
        path="/",
        secure=os.environ.get("CODEX_COOKIE_SECURE", "0") == "1",
    )
    return resp


def _ui_401() -> HTTPException:
    """401 for the browser UI - NO WWW-Authenticate header, so no native dialog."""
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not signed in")


def require_ui_auth(request: Request) -> dict:
    """Dependency for /api/* routes. Cookie session only."""
    s = _read_session(request.cookies.get(SESSION_COOKIE))
    if not s:
        raise _ui_401()
    if s["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return s


def require_sync_auth(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency for /sync/* routes. HTTP Basic only (KOReader client).

    WWW-Authenticate is intentionally present here - KOReader handles the
    challenge properly and it is the documented KOReader sync protocol.
    """
    import base64 as _b64

    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Basic auth required",
            headers={"WWW-Authenticate": 'Basic realm="codexserver-koreader"'},
        )
    try:
        raw = _b64.b64decode(header.split(None, 1)[1]).decode("utf-8")
        username, _, password = raw.partition(":")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Basic header",
            headers={"WWW-Authenticate": 'Basic realm="codexserver-koreader"'},
        )

    user = db.query(User).filter(User.username == username).first()
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid KOReader credentials",
            headers={"WWW-Authenticate": 'Basic realm="codexserver-koreader"'},
        )
    return user


def _admin_exists(db: Session) -> bool:
    return db.query(User).filter(User.role == "admin").count() > 0


# ======================================================= RCLONE MOUNT MGR ===

_mounts: dict[int, dict] = {}
_mounts_lock = threading.Lock()


def _slugify(s: str) -> str:
    import re
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", s).strip("_")
    return (s or "remote")[:60]


_OAUTH_BACKENDS = {"gdrive", "onedrive", "dropbox", "box", "pcloud"}


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
        return (
            f"[{cfg.remote_name}]\ntype = webdav\nurl = {creds.get('url','')}\nvendor = nextcloud\n"
            f"user = {creds.get('user','')}\npass = {creds.get('pass','')}\n"
        )
    if cfg.backend == "s3":
        return (
            f"[{cfg.remote_name}]\ntype = s3\nprovider = {creds.get('provider','Other')}\n"
            f"access_key_id = {creds.get('access_key_id','')}\n"
            f"secret_access_key = {creds.get('secret_access_key','')}\n"
            f"region = {creds.get('region','')}\nendpoint = {creds.get('endpoint','')}\n"
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
        "rclone", "mount", remote_spec, str(mountpoint),
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
            subprocess.run(["fusermount", "-u", str(mountpoint)], capture_output=True, check=False)
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

    with SessionLocal() as db:
        needs_setup = not _admin_exists(db)
        env_user = os.environ.get("CODEX_ADMIN_USER", "").strip()
        env_pass = os.environ.get("CODEX_ADMIN_PASSWORD", "").strip()
        if needs_setup and env_user and env_pass:
            db.add(User(username=env_user, role="admin", password_hash=hash_password(env_pass)))
            db.commit()
            needs_setup = False
            log.info("admin user %r created from CODEX_ADMIN_USER env override", env_user)

    if needs_setup:
        log.info("=" * 64)
        log.info("  No admin user yet - open the web UI to run first-run setup.")
        log.info("=" * 64)
    else:
        log.info("CodexServer: admin account present, login required.")

    def _worker():
        with SessionLocal() as db:
            remount_all(db)
    threading.Thread(target=_worker, daemon=True, name="remount-all").start()
    log.info("CodexServer up. BOOKS_ROOT=%s CLOUD_MOUNT_ROOT=%s", BOOKS_ROOT, CLOUD_MOUNT_ROOT)


# =============================================================== health ===

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok", "service": "codexserver", "version": "0.4.0",
        "books_root": BOOKS_ROOT, "cloud_mount_root": str(CLOUD_MOUNT_ROOT),
        "active_mounts": [sid for sid, m in _mounts.items() if m["proc"].poll() is None],
    }


# ================================================================ setup ===

class SetupIn(BaseModel):
    username: str
    password: str


@app.get("/api/setup/status")
def setup_status(db: Session = Depends(get_db)) -> dict:
    return {"needs_setup": not _admin_exists(db)}


@app.post("/api/setup/complete")
def setup_complete(payload: SetupIn, db: Session = Depends(get_db)) -> JSONResponse:
    if _admin_exists(db):
        raise HTTPException(409, "Setup already completed")
    username = payload.username.strip()
    if len(username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    existing = db.query(User).filter(User.username == username).first()
    if existing is not None:
        # Adopt a leftover KOReader row with the same name: promote to admin,
        # set the password. Their existing Progress rows are preserved.
        existing.role = "admin"
        existing.password_hash = hash_password(payload.password)
        existing.last_login_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        user = existing
        log.info("setup: adopted KOReader user %r as admin", username)
    else:
        user = User(username=username, role="admin",
                    password_hash=hash_password(payload.password),
                    last_login_at=datetime.utcnow())
        db.add(user)
        db.commit()
        db.refresh(user)
        log.info("setup: created new admin user %r", username)

    token = _new_session(user)
    resp = JSONResponse({"username": user.username, "role": user.role, "created": True}, status_code=201)
    return _set_session_cookie(resp, token)


# ================================================================= auth ===

class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def auth_login(payload: LoginIn, db: Session = Depends(get_db)) -> JSONResponse:
    user = db.query(User).filter(User.username == payload.username.strip()).first()
    if user is None or user.role != "admin" or not verify_password(payload.password, user.password_hash):
        raise _ui_401()
    user.last_login_at = datetime.utcnow()
    db.commit()
    token = _new_session(user)
    resp = JSONResponse({"username": user.username, "role": user.role})
    return _set_session_cookie(resp, token)


@app.post("/api/auth/logout")
def auth_logout(request: Request) -> JSONResponse:
    _drop_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/auth/me")
def auth_me(request: Request) -> dict:
    s = _read_session(request.cookies.get(SESSION_COOKIE))
    if not s:
        raise _ui_401()
    return {"username": s["username"], "role": s["role"]}


# ========================================================== KOReader users

class KUserIn(BaseModel):
    username: str
    password: Optional[str] = None


@app.get("/api/koreader/users", dependencies=[Depends(require_ui_auth)])
def list_koreader_users(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(User).filter(User.role == "koreader").order_by(User.username).all()
    return [
        {"id": u.id, "username": u.username, "has_password": bool(u.password_hash),
         "created_at": u.created_at.isoformat()} for u in rows
    ]


@app.post("/api/koreader/users", dependencies=[Depends(require_ui_auth)])
def create_koreader_user(payload: KUserIn, db: Session = Depends(get_db)) -> dict:
    username = payload.username.strip()
    if not username:
        raise HTTPException(400, "username required")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already taken")
    generated = None
    password = payload.password
    if not password:
        generated = secrets.token_urlsafe(12)
        password = generated
    u = User(username=username, role="koreader", password_hash=hash_password(password))
    db.add(u)
    db.commit()
    db.refresh(u)
    out = {"id": u.id, "username": u.username}
    if generated:
        out["generated_password"] = generated  # shown once in the UI
    return out


@app.delete("/api/koreader/users/{uid}", dependencies=[Depends(require_ui_auth)])
def delete_koreader_user(uid: int, db: Session = Depends(get_db)) -> dict:
    u = db.get(User, uid)
    if not u or u.role != "koreader":
        raise HTTPException(404, "koreader user not found")
    db.delete(u)
    db.commit()
    return {"deleted": uid}


# ================================================================ books ===

@app.get("/api/books", dependencies=[Depends(require_ui_auth)])
def list_books(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(Book).order_by(Book.added_at.desc()).all()
    return [
        {"id": b.id, "title": b.title, "author": b.author,
         "storage_path": b.storage_path, "storage_backend": b.storage_backend,
         "file_size": b.file_size, "added_at": b.added_at.isoformat()}
        for b in rows
    ]


@app.post("/upload", dependencies=[Depends(require_ui_auth)])
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
        db.query(MetadataConfig).filter(MetadataConfig.is_active.is_(True))
        .order_by(MetadataConfig.priority.asc()).all()
    )
    title, author = epub_washer.enrich(blob, active)
    if not title:
        title = Path(file.filename).stem
    if not author:
        author = "Unknown Author"

    chosen_root, chosen_label = BOOKS_ROOT, backend
    if backend != "local":
        with _mounts_lock:
            for sid, m in _mounts.items():
                cfg = db.get(StorageConfig, sid)
                if cfg and cfg.backend == backend and m["proc"].poll() is None:
                    chosen_root, chosen_label = str(m["mountpoint"]), cfg.label
                    break

    dest = epub_washer.safe_storage_path(chosen_root, author, title, file.filename)
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(blob)

    book = Book(title=title, author=author, storage_path=dest,
                storage_backend=chosen_label, file_size=len(blob))
    db.add(book)
    db.commit()
    db.refresh(book)
    return JSONResponse(
        {"id": book.id, "title": title, "author": author,
         "saved_to": dest, "providers_used": [c.provider_name for c in active]},
        status_code=201,
    )


# ============================================================== storage ===

class StorageIn(BaseModel):
    label: str
    backend: str
    remote_name: Optional[str] = None
    remote_path: Optional[str] = None
    credentials_json: Optional[str] = None
    is_active: bool = True


SUPPORTED_BACKENDS = {"local", "gdrive", "onedrive", "dropbox", "webdav", "s3"}


def _auth_status_dict(s: StorageConfig) -> dict:
    if not s.auth_status:
        return {"state": "idle"}
    try:
        return json.loads(s.auth_status)
    except ValueError:
        return {"state": "error", "error": "corrupt auth_status JSON"}


def _set_auth_status(s: StorageConfig, **fields) -> dict:
    current = _auth_status_dict(s)
    current.update(fields)
    s.auth_status = json.dumps(current)
    return current


@app.get("/api/storage", dependencies=[Depends(require_ui_auth)])
def list_storage(db: Session = Depends(get_db)) -> list[dict]:
    out = []
    for s in db.query(StorageConfig).all():
        mounted = s.id in _mounts and _mounts[s.id]["proc"].poll() is None
        out.append({
            "id": s.id, "label": s.label, "backend": s.backend,
            "remote_name": s.remote_name, "remote_path": s.remote_path,
            "is_active": s.is_active, "created_at": s.created_at.isoformat(),
            "mounted": mounted, "auth": _auth_status_dict(s),
        })
    return out


@app.post("/api/storage", dependencies=[Depends(require_ui_auth)])
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
        except Exception as e:  # noqa: BLE001
            log.exception("mount failed for storage id=%s", s.id)
            return {"id": s.id, "label": s.label, "backend": s.backend, "mount_error": str(e)}
    return {"id": s.id, "label": s.label, "backend": s.backend, "stub": False}


@app.delete("/api/storage/{sid}", dependencies=[Depends(require_ui_auth)])
def delete_storage(sid: int, db: Session = Depends(get_db)) -> dict:
    if sid in _mounts:
        unmount_storage(sid)
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    db.delete(s)
    db.commit()
    return {"deleted": sid}


@app.post("/api/storage/{sid}/mount", dependencies=[Depends(require_ui_auth)])
def api_mount(sid: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    _ensure_rclone_config(db)
    return mount_storage(s)


@app.post("/api/storage/{sid}/unmount", dependencies=[Depends(require_ui_auth)])
def api_unmount(sid: int) -> dict:
    return unmount_storage(sid)


# ========================================================== OAuth flow ===

class AuthCompleteIn(BaseModel):
    token_blob: str
    mode: str = "auto"


_OAUTH_INSTRUCTIONS = {
    "gdrive": (
        "1. On a machine with rclone installed and a browser, run:\n"
        "     rclone authorize \"drive\"\n"
        "2. A browser window opens (or you copy the URL). Sign in to the Google account.\n"
        "3. rclone prints a single line of JSON that starts with\n"
        '   {"access_token":... or {"token":"...  - copy that ENTIRE line.\n'
        "4. Paste it into the field below and click 'Complete connection'.\n"
        "\nThe container has no browser; step 1 cannot run here."
    ),
    "onedrive": (
        "1. On a machine with rclone + browser, run:\n"
        "     rclone authorize \"onedrive\"\n"
        "2. Sign in to your Microsoft account, grant the requested scopes.\n"
        "3. rclone prints a JSON token line - copy the entire line.\n"
        "4. Paste it below and click 'Complete connection'."
    ),
    "dropbox": (
        "1. On a machine with rclone + browser, run:\n"
        "     rclone authorize \"dropbox\"\n"
        "2. Sign in to Dropbox, allow rclone access.\n"
        "3. rclone prints a JSON token line - copy the entire line.\n"
        "4. Paste it below and click 'Complete connection'."
    ),
    "box": (
        "1. On a machine with rclone + browser, run:\n"
        "     rclone authorize \"box\"\n"
        "2. Sign in to Box, allow rclone access.\n"
        "3. rclone prints a JSON token line - copy the entire line.\n"
        "4. Paste it below and click 'Complete connection'."
    ),
}


@app.post("/api/storage/{sid}/auth_start", dependencies=[Depends(require_ui_auth)])
def api_auth_start(sid: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    if s.backend == "local":
        raise HTTPException(400, "local backend needs no auth")
    if s.backend not in _OAUTH_INSTRUCTIONS:
        raise HTTPException(400, f"backend {s.backend!r} uses non-OAuth credentials; "
                                 "fill the credentials_json field directly.")
    instructions = _OAUTH_INSTRUCTIONS[s.backend]
    _set_auth_status(s, state="pending", backend=s.backend, instructions=instructions, error=None)
    db.commit()
    return {
        "storage_id": sid, "backend": s.backend, "remote_name": s.remote_name,
        "state": "pending", "instructions": instructions,
        "note": ("rclone v1.60 has no true Device-Code-Flow. We surface rclone's own "
                 "`rclone authorize` instructions and accept the pasted token blob. "
                 "No client secret is shipped or required."),
    }


@app.get("/api/storage/{sid}/auth_status", dependencies=[Depends(require_ui_auth)])
def api_auth_status(sid: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    return {"storage_id": sid, **_auth_status_dict(s)}


@app.post("/api/storage/{sid}/auth_complete", dependencies=[Depends(require_ui_auth)])
def api_auth_complete(sid: int, payload: AuthCompleteIn, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    blob = payload.token_blob.strip()
    if not blob:
        raise HTTPException(400, "token_blob is empty")
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

    creds = parsed if payload.mode == "raw" else {"token": json.dumps(parsed)}
    s.credentials_json = json.dumps(creds)
    _set_auth_status(s, state="complete", error=None)
    db.commit()
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


@app.get("/api/metadata", dependencies=[Depends(require_ui_auth)])
def list_metadata(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(MetadataConfig).order_by(MetadataConfig.priority.asc()).all()
    return [
        {"id": m.id, "provider_name": m.provider_name, "is_active": m.is_active,
         "priority": m.priority, "api_key_or_url": m.api_key_or_url}
        for m in rows
    ]


@app.post("/api/metadata", dependencies=[Depends(require_ui_auth)])
def create_metadata(payload: MetadataIn, db: Session = Depends(get_db)) -> dict:
    if payload.provider_name not in epub_washer.PROVIDERS:
        raise HTTPException(400, f"unknown provider, supported: {sorted(epub_washer.PROVIDERS)}")
    m = MetadataConfig(**payload.model_dump())
    db.add(m)
    db.commit()
    db.refresh(m)
    return {"id": m.id, "provider_name": m.provider_name, "priority": m.priority}


@app.put("/api/metadata/{mid}", dependencies=[Depends(require_ui_auth)])
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


@app.delete("/api/metadata/{mid}", dependencies=[Depends(require_ui_auth)])
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
    password: Optional[str] = None
    document: str
    progress: str
    percentage: Optional[float] = None
    device: Optional[str] = None


@app.post("/sync/syncs")
def koreader_push(body: SyncBody, user: User = Depends(require_sync_auth),
                  db: Session = Depends(get_db)) -> dict:
    book = db.query(Book).filter(Book.storage_path.like(f"%{body.document}%")).first()
    if book is None:
        book = Book(title=f"[unmatched:{body.document[:12]}]", author="Unknown Author",
                    storage_path=body.document, storage_backend="sync")
        db.add(book)
        db.commit()
        db.refresh(book)
    p = db.query(Progress).filter(Progress.user_id == user.id, Progress.book_id == book.id).first()
    if p is None:
        db.add(Progress(user_id=user.id, book_id=book.id, progress_percent=body.progress, device=body.device))
    else:
        p.progress_percent = body.progress
        p.device = body.device
    db.commit()
    return {"status": "ok"}


@app.get("/sync/progress/{username}/{document}")
def koreader_pull(username: str, document: str, user: User = Depends(require_sync_auth),
                  db: Session = Depends(get_db)) -> dict:
    if username != user.username:
        raise HTTPException(403, "username mismatch")
    book = db.query(Book).filter(Book.storage_path == document).first()
    if book is None:
        raise HTTPException(404, "unknown document")
    p = db.query(Progress).filter(Progress.user_id == user.id, Progress.book_id == book.id).first()
    if p is None:
        raise HTTPException(404, "no progress recorded")
    return {"username": username, "document": document, "progress": p.progress_percent,
            "device": p.device, "timestamp": int(p.updated_at.timestamp())}


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

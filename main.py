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
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

import epub_washer
from database import get_db, init_db, SessionLocal
from models import Book, KosyncProgress, MetadataConfig, Progress, StorageConfig, User

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

    # Compute KOReader's partialMD5 over the saved file. This is the value
    # KOReader clients will send as `document` when they sync progress for
    # this book, so we persist it on the book row to JOIN against the
    # kosync_progress table the Web UI reads.
    try:
        from koreader_hash import partial_md5 as _partial_md5
        kh = _partial_md5(dest)
    except Exception:
        kh = None

    book = Book(title=title, author=author, storage_path=dest,
                storage_backend=chosen_label, file_size=len(blob),
                koreader_hash=kh)
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


# ============================================================ kosync v1 sync
#
# Implements the kosync v1 protocol described in
# https://github.com/pid1/kosync-conformance/blob/main/SPEC.md
# (CC0, observational spec of koreader/koreader-sync-server). Verified with
# the official conformance verifier verify.mjs.
#
# Auth: x-auth-user + x-auth-key (lowercase MD5 hex of the plaintext password
# the user typed into KOReader). No Basic Auth, no Bearer, no cookies. The
# server never sees the plaintext password.
#
# Storage: kosync_progress rows per (user, document). Last-write-wins, no
# conflict resolution server-side (K-PUT-5). The opaque document id is what
# KOReader sends - normally a 32-char lowercase hex partialMD5.

import re as _re_kosync
import json as _json_kosync
from starlette.responses import JSONResponse as _JSONResponse_kosync
from fastapi import Request as _Request_kosync
_DOCUMENT_RE = _re_kosync.compile(r"^[A-Za-z0-9_]+$")
_USERNAME_RE = _re_kosync.compile(r"^[^:]+$")


class _KosyncHTTPError(Exception):
    """Internal: raise this from a kosync endpoint; the global handler
    registered below converts it into a flat {code, message} JSONResponse
    with the right status code and a SPEC.md-conformant body."""

    def __init__(self, status: int, code: int, message: str):
        self.status = status
        self.code = code
        self.message = message


@app.exception_handler(_KosyncHTTPError)
async def _kosync_error_handler(request: Request, exc: _KosyncHTTPError):
    return _JSONResponse_kosync(
        status_code=exc.status,
        content={"code": exc.code, "message": exc.message},
        headers={"Content-Type": "application/json"},
    )


def _kosync_error(status: int, code: int, message: str) -> _KosyncHTTPError:
    """Emit a SPEC.md-conformant error: flat {code, message} JSONResponse.
    Returns an exception to raise, not a response to return."""
    return _KosyncHTTPError(status, code, message)


def _accept_v1_strict(request) -> None:
    """Gate the v1 Accept header per SPEC.md [K-ACC-1]/[K-ACC-2].

    Per [K-ACC-3], the spec says a server MAY relax the header check and
    serve requests that omit it (or send */*, application/json, etc).
    Because real KOReader builds routinely send no Accept header, we are
    permissive: any header that mentions "json", is a JSON media type,
    or is the wildard */* is accepted. Only explicit non-JSON types raise.

    Use --strict-accept with the verifier to exercise the strict path.
    """
    accept = (request.headers.get("accept") or "").lower().strip()
    if not accept:
        return
    if "application/vnd.koreader.v1+json" in accept:
        return
    if accept == "*/*":
        return
    if "json" in accept:
        return
    raise _kosync_error(412, 101, "Invalid Accept header format.")


async def _kosync_read_json(request: _Request_kosync) -> dict:
    """Parse the request body without Content-Type inspection.

    SPEC.md [K-CT-2] requires the server to accept JSON bodies regardless of
    Content-Type. FastAPI's BaseModel dependency inspects Content-Type and
    returns 422 if it's not application/json, which breaks the protocol.
    """
    raw = await request.body()
    if not raw:
        return {}
    try:
        obj = _json_kosync.loads(raw)
    except Exception:
        raise _kosync_error(400, 103, "Bad JSON")
    if not isinstance(obj, dict):
        raise _kosync_error(400, 104, "JSON body must be an object")
    return obj


def _kosync_auth_or_401(request: Request, db: Session):
    """Read x-auth-user + x-auth-key and look up the user.

    Per SPEC.md [K-AUTH-3]: key is compared byte-exact, hex case matters.
    Per [K-AUTH-6]: bad credentials -> 401, code 2001, no WWW-Authenticate
    header (this is JSON API, not Basic).

    Returns the user on success, raises a 401 JSONResponse on failure so
    FastAPI doesn't wrap our body in {"detail": ...}.
    """
    username = request.headers.get("x-auth-user", "")
    key = request.headers.get("x-auth-key", "")
    if not username or ":" in username:
        raise _kosync_error(401, 2001, "Unauthorized")
    if not key:
        raise _kosync_error(401, 2001, "Unauthorized")
    u = db.query(User).filter(User.username == username).first()
    if u is None or not u.kosync_key or u.kosync_key != key:
        raise _kosync_error(401, 2001, "Unauthorized")
    return u


class _KosyncAuthDep:
    """FastAPI dependency wrapper: pulls request + db and runs the auth check."""

    def __init__(self, request: Request, db: Session = Depends(get_db)):
        self.user = _kosync_auth_or_401(request, db)


# ============================================================ OPDS CATALOG =
#
# Minimal OPDS 1.2 Acquisition Feed for KOReader's built-in OPDS catalog
# plugin. Same HTTP-Basic-Auth scheme as /sync/* (the KOReader user).
# Storage is read-only: books come from books.storage_path, which works for
# both local /books/ and FUSE-mounted /mnt/cloud/<backend>_<name>/.
#
# Spec: https://specs.opds.io/opds-1.2 (Atom + OPDS namespaces).
#
import html as _html_mod
from email.utils import format_datetime as _rfc3339
from datetime import timezone as _tz
import uuid as _uuid
import xml.etree.ElementTree as _ET  # still used by _epub_cover() to parse OPF


def _esc(s: object) -> str:
    """Escape a string for XML element text/attribute use."""
    return _html_mod.escape(str(s) if s is not None else "", quote=True)


def _opds_iso(dt) -> str:
    if dt is None:
        dt = __import__("datetime").datetime.utcnow()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_tz.utc)
    return _rfc3339(dt.astimezone(_tz.utc))


def _opds_entry_uuid(book_id: int) -> str:
    """Stable URN-UUID for a book. Same book id -> same UUID across runs,
    so KOReader doesn't see duplicate entries when we restart the server.
    """
    return "urn:uuid:" + str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"codexserver:book:{book_id}"))


# OPDS acquisition MIME types per the OPDS spec + IANA registrations.
# KOReader (DocumentRegistry / koplugins) keys on the type attribute: a
# PDF with type=application/epub+zip is treated as not supported.
# Add new formats here as the catalog ingests them.
_OPDS_MIME_BY_EXT = {
    "epub":  "application/epub+zip",
    "pdf":   "application/pdf",
    "mobi":  "application/x-mobipocket-ebook",
    "azw":   "application/vnd.amazon.ebook",
    "azw3":  "application/vnd.amazon.ebook",
    "fb2":   "application/x-fictionbook+xml",
    "djvu":  "image/vnd.djvu",
    "djv":   "image/vnd.djvu",
    "cbz":   "application/vnd.comicbook+zip",
    "cbr":   "application/vnd.comicbook-rar",
    "html":  "text/html",
    "htm":   "text/html",
    "txt":   "text/plain",
    "rtf":   "application/rtf",
    "odt":   "application/vnd.oasis.opendocument.text",
}


def _opds_mime_for_book(book: "Book") -> str:
    """MIME type for a book, derived from its storage_path extension.
    Falls back to application/octet-stream so KOReader still shows the
    entry (with a generic icon) instead of dropping it silently.
    """
    path = getattr(book, "storage_path", "") or ""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _OPDS_MIME_BY_EXT.get(ext, "application/octet-stream")


# OPDS 1.2 acquisition-feed XML is hand-written rather than built via
# ElementTree. Reasons:
#   * KOReader's OPDS parser is strict: every <entry> needs xmlns="atom",
#     xmlns:dc, xmlns:opds ON the entry (not just the feed root), the
#     acquisition link MUST be rel="http://opds-spec.org/acquisition" with
#     type="application/epub+zip", and <id> must be a real urn:uuid:.
#   * ElementTree emits duplicate xmlns attrs when you mix register_namespace()
#     and root.set('xmlns:...'), and reflows attributes into an order that
#     trips up some strict parsers. A string template is simpler and matches
#     the OPDS spec example feed almost line-for-line.
#
# Format spec: https://specs.opds.io/opds-1.2
OPDS_XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>\n'
OPDS_FEED_OPEN = (
    '<feed xmlns="http://www.w3.org/2005/Atom"'
    ' xmlns:dc="http://purl.org/dc/terms/"'
    ' xmlns:opds="http://opds-spec.org/2010/catalog">\n'
)
OPDS_FEED_CLOSE = '</feed>\n'


def _opds_root_feed() -> bytes:
    body = (
        OPDS_FEED_OPEN
        + '<id>urn:codexserver:opds:root</id>\n'
        + '<title>CodexServer Catalog</title>\n'
        + f'<updated>{_opds_iso(None)}</updated>\n'
        + '<link rel="self"'
        + ' href="/opds"'
        + ' type="application/atom+xml;profile=opds-catalog"/>\n'
        # KOReader's OPDS plugin only follows `subsection` (not
        # `catalog`) as a navigation entry — see
        # plugins/opds.koplugin/opdsbrowser.lua::catalog_rel. Emit two
        # <link> elements so both KOReader and spec-strict clients work.
        + '<link rel="subsection"'
        + ' href="/opds/books"'
        + ' type="application/atom+xml;profile=opds-catalog"'
        + ' title="All books"/>\n'
        + '<link rel="http://opds-spec.org/subsection"'
        + ' href="/opds/books"'
        + ' type="application/atom+xml;profile=opds-catalog"'
        + ' title="All books"/>\n'
        + OPDS_FEED_CLOSE
    )
    return (OPDS_XML_DECL + body).encode("utf-8")


def _opds_books_feed(books: list) -> bytes:
    parts = [
        OPDS_XML_DECL,
        OPDS_FEED_OPEN,
        '<id>urn:codexserver:opds:books</id>\n',
        '<title>CodexServer Books</title>\n',
        f'<updated>{_opds_iso(None)}</updated>\n',
        '<link rel="self"'
        ' href="/opds/books"'
        ' type="application/atom+xml;profile=opds-catalog"/>\n',
    ]
    for b in books:
        title = _esc(b.title or "Untitled")
        author = _esc(b.author or "Unknown Author")
        # The acquisition link is the part KOReader actually downloads.
        # rel MUST be exactly the OPDS spec rel (no /open-access suffix for
        # anonymous download) and type MUST include +zip, otherwise KOReader
        # ignores the entry entirely.
        parts.append('<entry>\n')
        parts.append(f'  <id>{_opds_entry_uuid(b.id)}</id>\n')
        parts.append(f'  <title>{title}</title>\n')
        parts.append(f'  <updated>{_opds_iso(b.added_at)}</updated>\n')
        parts.append(f'  <author><name>{author}</name></author>\n')
        if b.file_size:
            parts.append(f'  <dc:extent>{int(b.file_size)}</dc:extent>\n')
        # Acquisition link: the file download. The type attribute MUST
        # match the actual file extension — KOReader's DocumentRegistry
        # rejects unsupported MIME types with "file type not supported".
        mime = _opds_mime_for_book(b)
        parts.append(
            '  <link rel="http://opds-spec.org/acquisition"'
            f' href="/opds/download/{b.id}"'
            f' type="{mime}"'
            f' title="{title}"/>\n'
        )
        # Thumbnail: optional, KOReader falls back gracefully on 404.
        parts.append(
            '  <link rel="http://opds-spec.org/image/thumbnail"'
            f' href="/opds/cover/{b.id}"'
            ' type="image/jpeg"/>\n'
        )
        parts.append('</entry>\n')
    parts.append(OPDS_FEED_CLOSE)
    return "".join(parts).encode("utf-8")


def _require_opds_auth(request: Request, db: Session = Depends(get_db)) -> User:
    """HTTP Basic for /opds/*. Same UX as the KOReader sync dialog, so the
    user types one pair of credentials that works for both.

    Active users of any role can browse. (Read-only access; downloads are
    mediated by FileResponse which checks the path on every request.)
    """
    import base64 as _b64

    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Basic auth required",
            headers={"WWW-Authenticate": 'Basic realm="codexserver-opds"'},
        )
    try:
        raw = _b64.b64decode(header.split(None, 1)[1]).decode("utf-8")
        username, _, password = raw.partition(":")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Basic header",
            headers={"WWW-Authenticate": 'Basic realm="codexserver-opds"'},
        )

    user = db.query(User).filter(User.username == username).first()
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OPDS credentials",
            headers={"WWW-Authenticate": 'Basic realm="codexserver-opds"'},
        )
    return user


def _epub_cover(path: str) -> tuple[bytes, str] | None:
    """Extract the cover image bytes from an EPUB.

    Strategy:
      1. Look for `cover.jpg`/`cover.jpeg`/`cover.png` in the EPUB root.
      2. Else read META-INF/container.xml -> OPF -> first image with
         `properties="cover-image"` or `meta name="cover"`.
    Returns (bytes, mime) or None.
    """
    import zipfile
    import posixpath as _p

    try:
        zf = zipfile.ZipFile(path, "r")
    except Exception:
        return None

    try:
        names = zf.namelist()

        # (1) Heuristic root covers.
        for cand in ("cover.jpg", "cover.jpeg", "cover.png"):
            if cand in names:
                with zf.open(cand) as fh:
                    return fh.read(), "image/jpeg" if cand.endswith((".jpg", ".jpeg")) else "image/png"

        # (2) container.xml -> OPF
        try:
            container = _ET.fromstring(zf.read("META-INF/container.xml"))
        except Exception:
            return None

        ns_c = {"c": "urn:oasis:names:tc:opendocument:xmlns:container"}
        rootfile = container.find(".//c:rootfile", ns_c)
        if rootfile is None:
            return None
        opf_path = rootfile.get("full-path")
        if not opf_path:
            return None
        try:
            opf = _ET.fromstring(zf.read(opf_path))
        except Exception:
            return None

        ns_opf = {"opf": "http://www.idpf.org/2007/opf"}
        opf_dir = _p.dirname(opf_path)

        # Find <item> with properties="cover-image".
        cover_id = None
        for item in opf.findall(".//opf:manifest/opf:item", ns_opf):
            props = item.get("properties", "") or ""
            if "cover-image" in props.split():
                cover_id = item.get("id")
                break

        # Else <meta name="cover" content="item-id">.
        if cover_id is None:
            for meta in opf.findall(".//opf:metadata/opf:meta", ns_opf):
                if (meta.get("name") or "").lower() == "cover":
                    cover_id = meta.get("content")
                    if cover_id:
                        break

        if cover_id is None:
            return None

        # Map id -> href via manifest.
        for item in opf.findall(".//opf:manifest/opf:item", ns_opf):
            if item.get("id") == cover_id:
                href = item.get("href")
                if not href:
                    return None
                media_type = (item.get("media-type") or "image/jpeg").lower()
                member = _p.normpath(_p.join(opf_dir, href))
                with zf.open(member) as fh:
                    return fh.read(), media_type

        return None
    finally:
        zf.close()


# ----------------------------------------------------------------- /opds
@app.get("/opds", response_class=Response)
@app.head("/opds", response_class=Response)
def opds_root(user: User = Depends(_require_opds_auth), db: Session = Depends(get_db)) -> Response:
    """OPDS 1.2 catalog root: returns ALL books directly as an acquisition
    feed.

    Why combine root + acquisition in one feed? Because the OPDS spec
    allows it, and several common clients (including older KOReader
    builds) only follow links whose `type` matches the catalog type
    *and* which appear inside entries — they ignore navigation links
    on the root. Calibre's OPDS server does the same thing.

    /opds/books is kept as an alias for clients that prefer to navigate
    via subsection links first.
    """
    rows = db.query(Book).order_by(Book.added_at.desc()).all()
    # Last-Modified is needed for KOReader's CatalogCache (see
    # plugins/opds.koplugin/opdsbrowser.lua::parseFeed). Without it,
    # the plugin won't cache and will refetch each time. We use the
    # latest book added_at as the feed's mtime, which is monotonic
    # under the order_by above.
    last_mod = max((b.added_at for b in rows if b.added_at is not None), default=None)
    headers = {"Cache-Control": "public, max-age=60"}
    if last_mod is not None:
        headers["Last-Modified"] = _rfc3339(last_mod.astimezone(_tz.utc))
    return Response(
        content=_opds_books_feed(rows),
        media_type="application/atom+xml;profile=opds-catalog",
        headers=headers,
    )


# ------------------------------------------------------------ /opds/books
@app.get("/opds/books", response_class=Response)
@app.head("/opds/books", response_class=Response)
def opds_books(user: User = Depends(_require_opds_auth), db: Session = Depends(get_db)) -> Response:
    """OPDS 1.2 acquisition feed: every book in the catalog."""
    rows = db.query(Book).order_by(Book.added_at.desc()).all()
    last_mod = max((b.added_at for b in rows if b.added_at is not None), default=None)
    headers = {"Cache-Control": "public, max-age=60"}
    if last_mod is not None:
        headers["Last-Modified"] = _rfc3339(last_mod.astimezone(_tz.utc))
    return Response(
        content=_opds_books_feed(rows),
        media_type="application/atom+xml;profile=opds-catalog",
        headers=headers,
    )


# ------------------------------------------------------ /opds/download/{id}
@app.get("/opds/download/{book_id}")
@app.head("/opds/download/{book_id}")
def opds_download(book_id: int, user: User = Depends(_require_opds_auth),
                  db: Session = Depends(get_db)):
    """Stream a book file to the OPDS client.

    KOReader's OPDS plugin (opds.koplugin/opdsbrowser.lua) does a HEAD
    on the acquisition href first to discover the local filename (it
    looks at Content-Disposition; falls back to the URL basename if no
    disposition is set). With a URL like `/opds/download/1`, the
    basename is "1" — no extension — so the file lands on the reader
    as "1" and DocumentRegistry:hasProvider rejects it with
    "file 1 is not supported".

    Three things fix this:
      1. A `@app.head` route on the same path so the HEAD probe succeeds.
      2. A Content-Disposition with a properly-extended filename so
         getServerFileName() extracts it cleanly.
      3. The MIME type of the actual file (not hardcoded application/
         epub+zip) so non-EPUB books also work.
    """
    book = db.get(Book, book_id)
    if book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    src = Path(book.storage_path)
    if not src.is_file():
        raise HTTPException(status_code=410, detail="Book file is gone from its backend")
    mime = _opds_mime_for_book(book)
    # Use the book's own extension (epub / pdf / mobi / ...); fall back
    # to deriving one from the MIME so KOReader's hasProvider() finds
    # a registered provider based on the local filename suffix.
    src_suffix = src.suffix.lstrip(".").lower() or mime.split("/", 1)[-1].split("+", 1)[0]
    safe_title = "".join(c if c.isalnum() or c in " _.-" else "_" for c in book.title).strip() or "book"
    fname = f"{safe_title}.{src_suffix}"
    return FileResponse(
        path=str(src),
        media_type=mime,
        filename=fname,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# -------------------------------------------------------- /opds/cover/{id}
@app.get("/opds/cover/{book_id}")
def opds_cover(book_id: int, user: User = Depends(_require_opds_auth),
               db: Session = Depends(get_db)) -> Response:
    book = db.get(Book, book_id)
    if book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    src = Path(book.storage_path)
    if not src.is_file():
        raise HTTPException(status_code=410, detail="Book file is gone")
    cover = _epub_cover(str(src))
    if cover is None:
        # 404 keeps the OPDS feed honest; KOReader falls back to a placeholder.
        raise HTTPException(status_code=404, detail="No cover image in EPUB")
    data, mime = cover
    return Response(content=data, media_type=mime)


# ------------------------------------------------------------ /healthcheck
@app.get("/healthcheck")
def kosync_healthcheck(request: Request) -> _JSONResponse_kosync:
    """[K-HC-1] Liveness probe, unauthenticated, vendor Accept required."""
    _accept_v1_strict(request)
    return _JSONResponse_kosync(
        status_code=200,
        content={"state": "OK"},
        headers={"Content-Type": "application/json"},
    )


# ------------------------------------------------------------ /users/create
@app.post("/users/create")
async def kosync_create_user(
    request: Request, db: Session = Depends(get_db)
) -> _JSONResponse_kosync:
    """[K-REG-1..5] Self-registration. The 'password' field carries the
    client-derived key (MD5 hex of the plaintext the user typed)."""
    _accept_v1_strict(request)
    body = await _kosync_read_json(request)
    username = (str(body.get("username") or "")).strip()
    key = str(body.get("password") or "")
    if not username or ":" in username or not key:
        raise _kosync_error(403, 2003, "Invalid request")
    existing = db.query(User).filter(User.username == username).first()
    if existing is not None:
        # [K-REG-3]: existing username returns 402 / code 2002. We do NOT
        # silently adopt an existing koreader-only account - that's a
        # security boundary KOReader clients will trip over (they treat
        # 201 as the only success signal and may skip /users/auth).
        raise _kosync_error(402, 2002, "Username is already registered.")
    u = User(username=username, role="koreader", kosync_key=key)
    db.add(u)
    db.commit()
    return _JSONResponse_kosync(
        status_code=201,
        content={"username": username},
        headers={"Content-Type": "application/json"},
    )


# ------------------------------------------------------------ /users/auth
@app.get("/users/auth")
def kosync_auth_check(request: Request, db: Session = Depends(get_db)) -> _JSONResponse_kosync:
    """[K-AUTH-7] Credential check, no body."""
    _accept_v1_strict(request)
    _kosync_auth_or_401(request, db)
    return _JSONResponse_kosync(
        status_code=200,
        content={"authorized": "OK"},
        headers={"Content-Type": "application/json"},
    )


# ------------------------------------------------------------ /syncs/progress
@app.put("/syncs/progress")
async def kosync_put_progress(
    request: Request, db: Session = Depends(get_db)
) -> _JSONResponse_kosync:
    """[K-PUT-1..5] Push a reading position. Last-write-wins."""
    _accept_v1_strict(request)
    user = _kosync_auth_or_401(request, db)
    body = await _kosync_read_json(request)
    doc = str(body.get("document") or "")
    if not doc or ":" in doc or not _DOCUMENT_RE.match(doc):
        raise _kosync_error(403, 2004, "Field 'document' not provided.")
    pct_raw = body.get("percentage")
    progress = body.get("progress")
    device = body.get("device")
    device_id = body.get("device_id")
    # [K-FLD-5]: percentage 0 is legal; only None / non-numeric are errors.
    try:
        pct = float(pct_raw) if pct_raw is not None else None
    except (TypeError, ValueError):
        pct = None
    if pct is None or progress is None or not device:
        raise _kosync_error(403, 2003, "Invalid request")
    if not isinstance(progress, str):
        progress = str(progress)
    if not isinstance(device, str) or not device:
        raise _kosync_error(403, 2003, "Invalid request")
    import time as _t
    ts = int(_t.time())
    row = (
        db.query(KosyncProgress)
        .filter(KosyncProgress.user_id == user.id, KosyncProgress.document == doc)
        .first()
    )
    if row is None:
        row = KosyncProgress(
            user_id=user.id,
            document=doc,
            progress=progress,
            percentage=str(pct),
            device=device,
            device_id=device_id,
            timestamp=ts,
        )
        db.add(row)
    else:
        row.progress = progress
        row.percentage = str(pct)
        row.device = device
        row.device_id = device_id
        row.timestamp = ts
    db.commit()
    return _JSONResponse_kosync(
        status_code=200,
        content={"document": doc, "timestamp": ts},
        headers={"Content-Type": "application/json"},
    )


# ------------------------------------------------------------ /syncs/progress/{document}
@app.get("/syncs/progress/{document}")
def kosync_get_progress(
    document: str,
    request: Request,
    db: Session = Depends(get_db),
) -> _JSONResponse_kosync:
    """[K-GET-1..3] Pull the stored position for one document.

    Unknown document returns 200 with {} - the most frequently
    reimplemented-wrong behaviour in the protocol. Clients test for the
    absence of `percentage`, not for a status code.
    """
    _accept_v1_strict(request)
    user = _kosync_auth_or_401(request, db)
    if not _DOCUMENT_RE.match(document):
        raise _kosync_error(403, 2004, "Field 'document' not provided.")
    row = (
        db.query(KosyncProgress)
        .filter(KosyncProgress.user_id == user.id, KosyncProgress.document == document)
        .first()
    )
    if row is None:
        return _JSONResponse_kosync(
            status_code=200,
            content={},
            headers={"Content-Type": "application/json"},
        )
    out: dict = {}
    if row.device_id:
        out["device_id"] = row.device_id
    out["progress"] = row.progress
    out["document"] = row.document
    out["percentage"] = float(row.percentage) if row.percentage else 0.0
    out["timestamp"] = row.timestamp
    out["device"] = row.device or ""
    return _JSONResponse_kosync(
        status_code=200,
        content=out,
        headers={"Content-Type": "application/json"},
    )


# ------------------------------------------------------------ /users/me (DELETE)
@app.delete("/users/me")
def kosync_delete_me(request: Request, db: Session = Depends(get_db)) -> _JSONResponse_kosync:
    """[K-DEL-1..3] Delete account and all its reading progress."""
    _accept_v1_strict(request)
    user = _kosync_auth_or_401(request, db)
    db.query(KosyncProgress).filter(KosyncProgress.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    return _JSONResponse_kosync(
        status_code=200,
        content={"deleted": True},
        headers={"Content-Type": "application/json"},
    )


# ------------------------------------------------------------ /users/password (PUT)
@app.put("/users/password")
async def kosync_change_password(
    request: Request, db: Session = Depends(get_db)
) -> _JSONResponse_kosync:
    """[K-PWD-*] Replace the sync credential; reading progress is preserved."""
    _accept_v1_strict(request)
    user = _kosync_auth_or_401(request, db)
    body = await _kosync_read_json(request)
    new_key = str(body.get("password") or "")
    if not new_key:
        raise _kosync_error(403, 2003, "Invalid request")
    user.kosync_key = new_key
    db.commit()
    return _JSONResponse_kosync(
        status_code=200,
        content={"updated": True},
        headers={"Content-Type": "application/json"},
    )


# ------------------------------------------------------------ Web UI bridge
@app.get("/api/koreader/progress")
def api_koreader_progress(
    _admin: dict = Depends(require_ui_auth),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Joined view of kosync_progress + books for the Web UI.

    Returns one row per (user, document) the kosync server has stored, with
    title/author populated if the document matches a book we have hashed.
    Documents without a known book appear as `unmatched:abcd1234...` so the
    user can see sync is happening even before uploads arrive.
    """
    rows = (
        db.query(KosyncProgress, User, Book)
        .outerjoin(User, KosyncProgress.user_id == User.id)
        .outerjoin(Book, Book.koreader_hash == KosyncProgress.document)
        .order_by(KosyncProgress.updated_at.desc())
        .all()
    )
    out = []
    for prog, owner, book in rows:
        out.append({
            "id": prog.id,
            "username": owner.username if owner else None,
            "document": prog.document,
            "percentage": float(prog.percentage) if prog.percentage else 0.0,
            "progress": prog.progress,
            "device": prog.device,
            "device_id": prog.device_id,
            "timestamp": prog.timestamp,
            "updated_at": prog.updated_at.isoformat() if prog.updated_at else None,
            "book_id": book.id if book else None,
            "title": book.title if book else None,
            "author": book.author if book else None,
        })
    return out


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

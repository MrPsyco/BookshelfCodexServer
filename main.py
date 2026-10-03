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
import base64
import posixpath
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Form, Request, status
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_, func, desc, asc

import epub_washer
from database import get_db, init_db, SessionLocal
from models import Book, ClientProgress, KosyncProgress, MetadataConfig, Progress, StorageConfig, User, WebSession

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("codexserver")

BOOKS_ROOT = os.environ.get("BOOKS_ROOT", "/books")
STATIC_DIR = Path(__file__).parent / "static"
CLOUD_MOUNT_ROOT = Path(os.environ.get("CLOUD_MOUNT_ROOT", "/mnt/cloud"))
RCLONE_CONFIG = Path("/root/.config/rclone/rclone.conf")
RCLONE_LOG_DIR = Path("/var/log/codex-rclone")
RCLONE_LOG_DIR.mkdir(parents=True, exist_ok=True)

# Extracted EPUB covers, keyed by book id. Serving a cover used to re-open the
# EPUB zip over FUSE/network per request (hundreds of downloads for a filled
# library). Extract once, then serve the cached file. MIME is guessed from the
# cached extension.
COVER_CACHE_DIR = Path(os.environ.get("COVER_CACHE_DIR", "/app/cover_cache"))
COVER_CACHE_DIR.mkdir(parents=True, exist_ok=True)

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
#
# Web UI sessions are persisted in the `web_sessions` table so they survive
# container restarts. The cookie itself is a 64-char URL-safe token; the row
# holds user/role snapshot and an expires_at timestamp. Expired rows are
# pruned lazily on read and on insert.

_sessions_lock = threading.Lock()


def _new_session(user: User) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + SESSION_TTL
    with _sessions_lock:
        db = SessionLocal()
        try:
            db.add(WebSession(
                token=token,
                user_id=user.id,
                username=user.username,
                role=user.role,
                expires_at=expires_at,
            ))
            db.commit()
        finally:
            db.close()
    return token


def _read_session(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    with _sessions_lock:
        db = SessionLocal()
        try:
            row = db.query(WebSession).filter(WebSession.token == token).first()
            if not row:
                return None
            if row.expires_at < datetime.utcnow():
                db.delete(row)
                db.commit()
                return None
            return {"user_id": row.user_id, "username": row.username, "role": row.role}
        finally:
            db.close()


def _drop_session(token: Optional[str]) -> None:
    if not token:
        return
    with _sessions_lock:
        db = SessionLocal()
        try:
            row = db.query(WebSession).filter(WebSession.token == token).first()
            if row:
                db.delete(row)
                db.commit()
        finally:
            db.close()


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


def _force_unmount(mountpoint) -> None:
    """Lazily detach any stale/dead FUSE mount before (re)mounting.

    Errno 107 ("Transport endpoint is not connected") means a previous
    rclone mount died but left a stale kernel mount. Detach it silently.
    Both fusermount and umount can fail here (not yet mounted, missing
    binary, etc.) -- those errors are intentionally ignored.
    """
    for cmd in (
        ["fusermount", "-uz", str(mountpoint)],
        ["umount", "-l", str(mountpoint)],
    ):
        try:
            subprocess.run(cmd, capture_output=True, check=False)
        except Exception:  # noqa: BLE001
            pass

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
    if os.path.ismount(str(mountpoint)):
        # Something is attached here. But after a container restart the daemon
        # is gone while the kernel mount lingers STALE ("Transport endpoint is
        # not connected"). A healthy mount lists its directory; a stale one
        # raises OSError. Reuse only a live mount, otherwise detach and remount.
        try:
            os.listdir(str(mountpoint))
            # Live mount: reuse it instead of stacking a second one on top
            # (rclone --daemon forks, so the launcher Popen can't be tracked).
            return {"status": "already-mounted", "mountpoint": str(mountpoint)}
        except OSError:
            log.info("stale mount at %s, detaching before remount", mountpoint)
    _force_unmount(mountpoint)
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
        _mounts[cfg.id] = {"proc": proc, "mountpoint": mountpoint, "log": log_path, "backend": cfg.backend, "label": cfg.label}
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
            subprocess.run(["fusermount", "-uz", str(mountpoint)], capture_output=True, check=False)
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


# ======================================================= library scan (async) ===

_SCAN_STATE = {"running": False, "added": 0, "started_at": None, "finished_at": None, "error": None}
_scan_lock = threading.Lock()

# Background metadata enrichment: how often to poll for unresolved books after
# a full pass. Once resolved (metadata_enriched=True), a book is never re-read.
_ENRICH_STATE = {"running": False}
_enrich_lock = threading.Lock()
_ENRICH_POLL_SECONDS = 300.0
_ENRICH_BATCH_SIZE = 200
_ENRICH_WORKERS = 8
_ENRICH_BATCH_TIMEOUT = 120.0


def _scan_roots() -> list:
    """Return (path, backend, label) for every scan target: the local books
    root plus each live cloud mountpoint.

    A mountpoint counts as live when the FUSE fs is actually attached
    (os.path.ismount) -- NOT when the launcher process is alive, because
    "rclone mount --daemon" forks into the background and its parent
    Popen process exits immediately (leaving poll() non-None forever).
    """
    roots = [(BOOKS_ROOT, "local", "local")]
    with _mounts_lock:
        for m in _mounts.values():
            mp = m.get("mountpoint")
            if mp is not None and os.path.ismount(str(mp)):
                roots.append((str(mp), m.get("backend", "cloud"), m.get("label", "cloud")))
    return roots


def _wait_for_mount_readiness(timeout: float = 120.0) -> None:
    """Block until every live cloud mount is attached AND listable.

    rclone mount needs real time after launch to refresh OAuth tokens and do
    its first listing; a cold start can take 30-60s on Google Drive before
    the mountpoint answers. Scanning before that reads an empty/unattached
    directory and indexes nothing (empty library after a successful mount).
    Returns no later than timeout seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with _mounts_lock:
            mps = [m.get("mountpoint") for m in _mounts.values() if m.get("mountpoint")]
        if not mps:
            return
        ready = True
        for mp in mps:
            try:
                if not os.path.ismount(str(mp)):
                    ready = False
                    break
                os.listdir(str(mp))  # raises OSError until the fs answers
            except OSError:
                ready = False
                break
        if ready:
            return
        time.sleep(0.5)


def _scan_author_title(p: Path) -> tuple:
    """Fallback metadata: full filename stem as title, author unknown.

    We deliberately do NOT parse "Author - Title.epub" out of the filename —
    naming conventions vary too much (Calibre, plain, '[tag] Author - ...',
    'Title - Author', bare titles) and mis-parsing produces garbage. The scan
    must complete in seconds and index thousands of files, so real metadata
    is filled in later by the background enrichment task (see
    `_enrich_metadata_worker`), which reads the EPUB's own OPF.
    """
    return p.stem.strip(), "Unknown Author"


def _scan_library() -> int:
    """Walk every scan root and index any e-book file not yet in the DB.

    The KOReader partialMD5 hash is NOT computed here. For a cloud backend
    that means up to 12 content reads per file over FUSE/network -- hashing a
    ~30k-book Google Drive in one pass takes hours and leaves the library
    empty for the whole time. Instead books are indexed by metadata only and
    the hash is resolved lazily on first kosync match (see
    `_lazy_koreader_hash`). Books are committed incrementally so they appear
    in the UI while a long scan is still running.
    """
    added = 0
    _wait_for_mount_readiness()
    with SessionLocal() as db:
        existing = {b.storage_path for b in db.query(Book).all()}
        batch = []
        for root, backend, label in _scan_roots():
            rp = Path(root)
            if not rp.exists():
                continue
            # os.walk with an onerror handler instead of Path.rglob():
            # rglob raises straight through a transient FUSE/network error on a
            # single directory (e.g. "Errno 5 I/O error" when Google Drive
            # briefly stops answering), which killed an otherwise-healthy scan
            # of 20k+ books. os.walk lets us skip the bad directory and keep
            # indexing everything else.
            def _on_walk_error(err: OSError) -> None:
                log.warning("scan: skipping unreadable dir (%s): %s", err.filename, err)

            for dirpath, _dirnames, filenames in os.walk(root, onerror=_on_walk_error):
                for fn in filenames:
                    p = Path(dirpath) / fn
                    ext = Path(fn).suffix.lstrip(".").lower()
                    if ext not in _EBOOK_EXTENSIONS:
                        continue
                    sp = str(p)
                    if sp in existing:
                        continue
                    title, author = _scan_author_title(p)
                    try:
                        size = p.stat().st_size
                    except OSError:
                        size = None
                    batch.append(Book(
                        title=title, author=author, storage_path=sp,
                        storage_backend=label, file_size=size, koreader_hash=None,
                    ))
                    existing.add(sp)
                    if len(batch) >= 50:
                        db.add_all(batch)
                        db.commit()
                        added += len(batch)
                        batch = []
        if batch:
            db.add_all(batch)
            db.commit()
            added += len(batch)
    return added


_MD5_RE = re.compile(r"^[0-9a-f]{32}$")


def _lazy_koreader_hash(db: Session, book: Book) -> Optional[str]:
    """Compute + cache a book's KOReader partialMD5 on first need.

    The scan intentionally leaves koreader_hash NULL (hashing every cloud
    file up front is far too slow). Resolve it the first time a kosync
    document needs hash-matching, then persist so later matches are free.
    """
    if book.koreader_hash:
        return book.koreader_hash
    try:
        from koreader_hash import partial_md5 as _partial_md5
        kh = _partial_md5(book.storage_path)
    except Exception:
        return None
    book.koreader_hash = kh
    db.commit()
    return kh


def start_library_scan() -> None:
    """Kick off a background library scan if none is already running."""
    with _scan_lock:
        if _SCAN_STATE["running"]:
            return
        _SCAN_STATE.update(running=True, added=0, error=None,
                           started_at=datetime.now(timezone.utc), finished_at=None)

    def _run() -> None:
        try:
            added = _scan_library()
            with _scan_lock:
                _SCAN_STATE.update(running=False, added=added,
                                   finished_at=datetime.now(timezone.utc))
            log.info("library scan finished: %d new book(s)", added)
        except Exception as e:  # noqa: BLE001
            log.exception("library scan failed")
            with _scan_lock:
                _SCAN_STATE.update(running=False, error=str(e),
                                   finished_at=datetime.now(timezone.utc))

    threading.Thread(target=_run, daemon=True, name="library-scan").start()


# ---- Background metadata enrichment ----------------------------------


def _needs_enrichment(db: Session, limit: int) -> list[Book]:
    """Books whose metadata is still the scan placeholder (or was mis-parsed
    by older code) — i.e. everything not yet marked metadata_enriched.
    Capped to `limit` so a huge backlog is processed in bounded batches rather
    than materializing tens of thousands of ORM objects at once."""
    return (
        db.query(Book)
        .filter(Book.metadata_enriched.is_(False))
        .order_by(Book.id.asc())
        .limit(limit)
        .all()
    )


def _enrich_metadata_worker() -> None:
    """Fill real title/author from each book's own OPF, continuously.

    Loops forever: each pass processes a bounded batch of rows where
    metadata_enriched is False, then sleeps. Reading a cloud EPUB goes over
    FUSE/network, so the OPF extraction is parallelized across a small thread
    pool and results are committed once per batch (not once per book — the old
    per-book commit meant one fsync per row, ~700/h instead of thousands/h).
    Idempotent: only metadata_enriched=False rows are touched. A book that
    yields ("", "") as .epub is left unmarked so a later pass retries
    (transient mount/zip failure); non-EPUB formats are marked done."""
    with _enrich_lock:
        if _ENRICH_STATE["running"]:
            return
        _ENRICH_STATE["running"] = True
    try:
        # Cloud files live behind FUSE mounts that take ~30-40s to become
        # listable on a cold start. Reading an EPUB before that throws
        # FileNotFoundError; waiting here means we don't burn a whole pass
        # marking every cloud book "enriched" with no metadata actually read.
        _wait_for_mount_readiness()
        while True:
            with SessionLocal() as db:
                pending = _needs_enrichment(db, _ENRICH_BATCH_SIZE)
                if not pending:
                    time.sleep(_ENRICH_POLL_SECONDS)
                    continue

                log.info("metadata enrichment: %d book(s) in this batch", len(pending))

                def _extract(book: Book) -> tuple[str, str]:
                    try:
                        t, a = epub_washer.enrich_from_path(book.storage_path)
                    except Exception as e:  # noqa: BLE001
                        log.warning("enrich %s failed: %s", book.id, e)
                        t, a = "", ""
                    return t, a

                results: dict[int, tuple[str, str]] = {}
                ex = ThreadPoolExecutor(max_workers=_ENRICH_WORKERS)
                try:
                    futs = {ex.submit(_extract, b): b for b in pending}
                    # Complete what we can within a bounded window. A single
                    # scripted FUSE/network read that never returns must not
                    # wedge the whole enrichment loop forever (the old code
                    # iterated as_completed() with no timeout, so one hung
                    # Google Drive read silently parked the worker for good and
                    # the wrong-author sidebar never progressed).
                    try:
                        for fut in as_completed(futs, timeout=_ENRICH_BATCH_TIMEOUT):
                            book = futs[fut]
                            try:
                                title, author = fut.result()
                            except Exception as e:  # noqa: BLE001
                                log.warning("enrich %s failed: %s", book.id, e)
                                title, author = "", ""
                            results[book.id] = (title, author)
                    except TimeoutError:
                        # Some reads are still hung past the window. Abandon
                        # them; they stay metadata_enriched=False and retry.
                        pass
                finally:
                    # MUST NOT block on hung reads: shutdown(wait=False) returns
                    # immediately and abandons any still-running futures, so a
                    # stuck FUSE read can't stall the next batch. (The `with`
                    # form calls shutdown(wait=True) and would hang the same way
                    # the timeout was meant to prevent.)
                    ex.shutdown(wait=False, cancel_futures=True)

                for book in pending:
                    title, author = results.get(book.id, ("", ""))
                    is_epub = book.storage_path.lower().endswith(".epub")
                    got_data = bool(title or author)
                    if got_data or not is_epub:
                        # We have authoritative OPF data for this book — write
                        # BOTH fields unconditionally so a mis-parsed legacy
                        # author (from the old filename splitter) is corrected,
                        # not left standing. Missing author falls back to
                        # "Unknown Author", never the stale value.
                        book.title = title if title else book.title
                        if author and author != "Unknown Author":
                            book.author = author
                        elif title and not author:
                            book.author = "Unknown Author"
                        book.metadata_enriched = True
                db.commit()
                log.info("metadata enrichment: batch complete")

                # Keep chewing through the backlog without a sleep when the
                # batch came back full (more pending rows definitely remain).
                # Only idle when the batch was short — i.e. we've reached the
                # end and can wait for the next scan to add fresh books. The
                # old code slept _ENRICH_POLL_SECONDS after EVERY batch, which
                # capped throughput at ~BATCH_SIZE per 5 min and left a large
                # backlog (and thus a wrong author sidebar) for hours.
                if len(pending) < _ENRICH_BATCH_SIZE:
                    time.sleep(_ENRICH_POLL_SECONDS)
    except Exception as e:  # noqa: BLE001
        log.exception("metadata enrichment crashed: %s", e)
    finally:
        with _enrich_lock:
            _ENRICH_STATE["running"] = False


def start_metadata_enrichment() -> None:
    threading.Thread(
        target=_enrich_metadata_worker, daemon=True, name="metadata-enrich"
    ).start()


@app.get("/api/scan/status", dependencies=[Depends(require_ui_auth)])
def api_scan_status(db: Session = Depends(get_db)) -> dict:
    with _scan_lock:
        scan = {
            "running": _SCAN_STATE["running"],
            "added": _SCAN_STATE["added"],
            "started_at": _SCAN_STATE["started_at"].isoformat() if _SCAN_STATE["started_at"] else None,
            "finished_at": _SCAN_STATE["finished_at"].isoformat() if _SCAN_STATE["finished_at"] else None,
            "error": _SCAN_STATE["error"],
        }
    # Enrichment progress: X = processed (metadata_enriched=True), Y = total,
    # pending = still-outstanding rows. Fed to the UI "Scanning… (X/Y)" badge.
    total = db.query(func.count(Book.id)).scalar() or 0
    enriched = (
        db.query(func.count(Book.id))
        .filter(Book.metadata_enriched.is_(True))
        .scalar() or 0
    )
    with _enrich_lock:
        enrich_running = _ENRICH_STATE["running"]
    return {
        **scan,
        "enrich_running": enrich_running,
        "enriched": enriched,
        "pending": max(0, total - enriched),
        "total": total,
    }


@app.on_event("startup")
def _startup() -> None:
    init_db()
    Path(BOOKS_ROOT).mkdir(parents=True, exist_ok=True)
    CLOUD_MOUNT_ROOT.mkdir(parents=True, exist_ok=True)
    WEBDAV_ROOT.mkdir(parents=True, exist_ok=True)
    _backfill_client_progress()

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
        start_library_scan()
        start_metadata_enrichment()
    threading.Thread(target=_worker, daemon=True, name="remount-all").start()
    log.info("CodexServer up. BOOKS_ROOT=%s CLOUD_MOUNT_ROOT=%s", BOOKS_ROOT, CLOUD_MOUNT_ROOT)


# =============================================================== health ===

@app.get("/health")
def health() -> dict:
    # `rclone mount --daemon` forks into the background and its launcher Popen
    # exits immediately, so `proc.poll()` is never None. Count a mount as active
    # when the kernel actually reports the FUSE fs as attached (same rule
    # _scan_roots uses) -- otherwise the badge shows "0 mounts" while active.
    return {
        "status": "ok", "service": "codexserver", "version": "0.4.0",
        "books_root": BOOKS_ROOT, "cloud_mount_root": str(CLOUD_MOUNT_ROOT),
        "active_mounts": [
            sid for sid, m in _mounts.items()
            if os.path.ismount(str(m.get("mountpoint", "")))
        ],
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


# ================================================================ books ===

@app.get("/api/books", dependencies=[Depends(require_ui_auth)])
def list_books(
    q: Optional[str] = None,
    author: Optional[str] = None,
    sort: str = "author",
    order: str = "asc",
    limit: int = 60,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> dict:
    """Searchable, sortable, paginated book list.

    ``sort`` one of: author | title | added | progress. ``order`` asc|desc.
    ``q`` filters title+author (case-insensitive substring); ``author`` is an
    exact author filter (drives the sidebar). Returns
    {items, total, limit, offset} so the UI can page without N+1 requests.

    Progress comes from ``client_progress``, matched by the already-indexed
    ``book_id`` column (not a per-document O(N) scan) — the old path called
    ``_dav_book_for_key`` for every sync row, re-scanning all books each time.
    """
    q = (q or "").strip()
    author = (author or "").strip()
    query = db.query(Book)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Book.title.ilike(like), Book.author.ilike(like)))
    if author:
        query = query.filter(Book.author == author)
    total = query.count()

    # Progress: one latest row per book, keyed by book_id (indexed).
    rows = (
        db.query(ClientProgress)
        .filter(ClientProgress.book_id.isnot(None), ClientProgress.percentage.isnot(None))
        .order_by(ClientProgress.updated_at.desc())
        .all()
    )
    latest_by_book: dict[int, dict] = {}
    for cp in rows:
        if cp.book_id in latest_by_book:
            continue
        latest_by_book[cp.book_id] = {"pct": float(cp.percentage), "client": cp.client}

    # Sorting. Progress is derived in Python; the rest map to SQL columns.
    if sort == "progress":
        books = query.all()
        books.sort(
            key=lambda b: (latest_by_book.get(b.id, {}).get("pct", -1.0) or -1.0),
            reverse=(order == "desc"),
        )
        books = books[offset:offset + limit]
    else:
        col = {"title": Book.title, "added": Book.added_at, "author": Book.author}.get(sort, Book.author)
        order_expr = desc(col) if order == "desc" else asc(col)
        # Secondary sort: keep deterministic within equal primary values.
        books = query.order_by(order_expr, asc(Book.id)).offset(offset).limit(limit).all()

    out = []
    for b in books:
        ext = (b.storage_path.rsplit(".", 1)[-1] if "." in b.storage_path else "").lower()
        mime = _OPDS_MIME_BY_EXT.get(ext, "application/octet-stream")
        entry = latest_by_book.get(b.id)
        pct_raw = entry["pct"] if entry else None
        is_finished = pct_raw is not None and pct_raw >= 1.0
        out.append({
            "id": b.id,
            "title": b.title,
            "author": b.author,
            "storage_path": b.storage_path,
            "storage_backend": b.storage_backend,
            "file_size": b.file_size,
            "added_at": b.added_at.isoformat(),
            "format": mime,
            "format_ext": ext or None,
            "koreader_hash": b.koreader_hash,
            "progress": pct_raw,
            "progress_pct": int(round(pct_raw * 100)) if pct_raw is not None else None,
            "is_finished": is_finished,
            "progress_client": entry["client"] if entry else None,
        })
    return {"items": out, "total": total, "limit": limit, "offset": offset}


@app.get("/api/books/continue", dependencies=[Depends(require_ui_auth)])
def continue_reading(limit: int = 20, db: Session = Depends(get_db)) -> dict:
    """Books with active progress, most-recently-synced first (Netflix row).

    Only unfinished books (0 < progress < 100%) qualify. Matches the same
    client_progress rows the Library uses, but ordered by recency.
    """
    rows = (
        db.query(ClientProgress)
        .filter(ClientProgress.book_id.isnot(None), ClientProgress.percentage.isnot(None))
        .order_by(ClientProgress.updated_at.desc())
        .all()
    )
    seen: set[int] = set()
    latest: dict[int, dict] = {}
    for cp in rows:
        if cp.book_id in seen:
            continue
        seen.add(cp.book_id)
        pct = float(cp.percentage)
        if pct >= 1.0:
            continue
        latest[cp.book_id] = {"pct": pct, "client": cp.client}
        if len(latest) >= limit:
            break
    out = []
    for bid, entry in latest.items():
        b = db.get(Book, bid)
        if b is None:
            continue
        out.append({
            "id": b.id,
            "title": b.title,
            "author": b.author,
            "progress": entry["pct"],
            "progress_pct": int(round(entry["pct"] * 100)),
            "progress_client": entry["client"],
        })
    return {"items": out}


@app.get("/api/books/authors", dependencies=[Depends(require_ui_auth)])
def list_authors(db: Session = Depends(get_db)) -> dict:
    """Distinct authors with book counts, for the Calibre-style filter sidebar."""
    rows = (
        db.query(Book.author, func.count(Book.id))
        .group_by(Book.author)
        .order_by(func.lower(Book.author).asc())
        .all()
    )
    authors = [
        {"author": a or "Unknown Author", "count": c}
        for a, c in rows
    ]
    return {"items": authors, "total": len(authors)}


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
                koreader_hash=kh, metadata_enriched=True)
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
        # `rclone mount --daemon` forks and its launcher Popen exits immediately,
        # so `proc.poll()` is never None. A mount is "connected" only when the
        # kernel actually reports the FUSE fs attached (same rule _scan_roots and
        # /health use). Otherwise settings shows "unmounted" while the cloud fs
        # is served and indexed.
        m = _mounts.get(s.id)
        mp = m["mountpoint"] if m else None
        connected = bool(mp and os.path.ismount(str(mp)))
        out.append({
            "id": s.id, "label": s.label, "backend": s.backend,
            "remote_name": s.remote_name, "remote_path": s.remote_path,
            "is_active": s.is_active, "created_at": s.created_at.isoformat(),
            "mounted": connected, "auth": _auth_status_dict(s),
        })
    return out


@app.post("/api/storage", dependencies=[Depends(require_ui_auth)])
def create_storage(payload: StorageIn, db: Session = Depends(get_db)) -> dict:
    if payload.backend not in SUPPORTED_BACKENDS:
        raise HTTPException(400, f"backend must be one of {sorted(SUPPORTED_BACKENDS)}")
    if payload.backend != "local" and not payload.remote_name:
        payload.remote_name = _slugify(f"{payload.backend}_{payload.label}")
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
    # Rebuild the rclone config now, otherwise the deleted remote's section
    # lingers in rclone.conf (duplicate [remote] blocks, stale tokens) until
    # the next container restart.
    _ensure_rclone_config(db)
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


# ============================================================ browse/select ===


class BrowseIn(BaseModel):
    path: str = ""


class SelectIn(BaseModel):
    path: str = ""


def _list_remote_dirs(s: StorageConfig, path: str) -> list:
    remote_path = (path or "").strip("/")
    remote_spec = f"{s.remote_name}:" + (f"/{remote_path}" if remote_path else "")
    out = subprocess.run(
        ["rclone", "lsjson", remote_spec, "--config", str(RCLONE_CONFIG),
         "--dirs-only", "--max-depth", "1"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError((out.stderr or "rclone lsjson failed").strip())
    try:
        entries = json.loads(out.stdout)
    except ValueError:
        return []
    return [e.get("Name", "") for e in entries if e.get("IsDir")]


@app.post("/api/storage/{sid}/browse", dependencies=[Depends(require_ui_auth)])
def api_browse(sid: int, payload: BrowseIn, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    path = (payload.path or "").strip("/")
    if s.backend == "local":
        root = Path(BOOKS_ROOT) / path if path else Path(BOOKS_ROOT)
        try:
            dirs = sorted(p.name for p in root.iterdir() if p.is_dir())
        except FileNotFoundError:
            dirs = []
        parent = "/".join(path.split("/")[:-1]) if path else None
        return {"backend": "local", "path": path, "parent": parent, "dirs": dirs}
    _ensure_rclone_config(db)
    try:
        dirs = _list_remote_dirs(s, path)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"browse failed: {e}")
    parent = "/".join(path.split("/")[:-1]) if path else None
    return {"backend": s.backend, "path": path, "parent": parent, "dirs": dirs}


@app.post("/api/storage/{sid}/select", dependencies=[Depends(require_ui_auth)])
def api_select(sid: int, payload: SelectIn, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    if s.backend == "local":
        return {"storage_id": sid, "remote_path": None}
    s.remote_path = ("/" + (payload.path or "").strip("/")) if payload.path else None
    db.commit()
    if sid in _mounts:
        unmount_storage(sid)
    _ensure_rclone_config(db)
    try:
        m = mount_storage(s)
        start_library_scan()
        return {"storage_id": sid, "remote_path": s.remote_path, "mount": m}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"remount failed: {e}")


class CredentialsIn(BaseModel):
    credentials: dict


@app.post("/api/storage/{sid}/credentials", dependencies=[Depends(require_ui_auth)])
def api_set_credentials(sid: int, payload: CredentialsIn, db: Session = Depends(get_db)) -> dict:
    """Set non-OAuth credentials (webdav url/user/pass, s3 keys) directly."""
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    if s.backend in _OAUTH_BACKENDS:
        raise HTTPException(400, f"backend {s.backend!r} uses OAuth, not direct credentials")
    s.credentials_json = json.dumps(payload.credentials)
    db.commit()
    _ensure_rclone_config(db)
    try:
        m = mount_storage(s)
        return {"storage_id": sid, "mount": m}
    except Exception as e:  # noqa: BLE001
        log.exception("mount after credentials failed for storage id=%s", s.id)
        raise HTTPException(500, f"credentials saved but mount failed: {e}")


# =============================================== Google OAuth (click-to-login) ===

_GOOGLE_OAUTH_CLIENT_ID = "202264815644.apps.googleusercontent.com"
_GOOGLE_OAUTH_CLIENT_SECRET = "X4Z3ca8xfWDb1Voo-F9a7ZxJ"
_GOOGLE_OAUTH_REDIRECT_URI = "http://127.0.0.1:53682/"
_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_SCOPE = "https://www.googleapis.com/auth/drive"


def _gdrive_login_url() -> str:
    params = {
        "client_id": _GOOGLE_OAUTH_CLIENT_ID,
        "redirect_uri": _GOOGLE_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": _GOOGLE_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
    }
    return _GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)


@app.get("/api/storage/oauth-login-url", dependencies=[Depends(require_ui_auth)])
def api_oauth_login_url(backend: str = "gdrive") -> dict:
    if backend == "gdrive":
        return {"url": _gdrive_login_url()}
    raise HTTPException(400, f"no click-to-login URL for backend {backend!r}")


class AuthCodeIn(BaseModel):
    code: str


def _google_code_to_rclone_token(code: str) -> dict:
    body = urllib.parse.urlencode({
        "client_id": _GOOGLE_OAUTH_CLIENT_ID,
        "client_secret": _GOOGLE_OAUTH_CLIENT_SECRET,
        "redirect_uri": _GOOGLE_OAUTH_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
    }).encode()
    req = urllib.request.Request(
        _GOOGLE_TOKEN_URL, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            tok = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"Google token exchange failed: {e.read().decode()}")
    if "access_token" not in tok or "refresh_token" not in tok:
        raise HTTPException(502, "Google returned no token (missing access/refresh token)")
    # rclone expects an 'expiry' RFC3339 field, not Google's 'expires_in' seconds
    expires_in = int(tok.get("expires_in", 3599))
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()
    return {
        "access_token": tok["access_token"],
        "token_type": tok.get("token_type", "Bearer"),
        "refresh_token": tok["refresh_token"],
        "expiry": expiry,
    }


@app.post("/api/storage/{sid}/auth_code", dependencies=[Depends(require_ui_auth)])
def api_auth_code(sid: int, payload: AuthCodeIn, db: Session = Depends(get_db)) -> dict:
    """Exchange the short Google auth code for a token, server-side."""
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    code = payload.code.strip()
    if not code:
        raise HTTPException(400, "code is empty")
    try:
        rclone_token = _google_code_to_rclone_token(code)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"token exchange failed: {e}")
    s.credentials_json = json.dumps({"token": json.dumps(rclone_token)})
    _set_auth_status(s, state="complete", error=None)
    db.commit()
    _ensure_rclone_config(db)
    try:
        m = mount_storage(s)
        return {"storage_id": sid, "auth": "complete", "mount": m}
    except Exception as e:  # noqa: BLE001
        log.exception("mount after auth_code failed for storage id=%s", s.id)
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


def _record_client_progress(
    db: Session,
    user: User,
    client: str,
    document: str,
    percentage: Optional[float],
    *,
    page: Optional[int] = None,
    position: Optional[str] = None,
    book: Optional[Book] = None,
    timestamp: Optional[int] = None,
) -> None:
    """Upsert the client-neutral progress row for (user, client, document).

    Every protocol funnels through here, so the Web UI can read one table
    regardless of which client produced the update. Protocol-specific tables
    (e.g. `kosync_progress`) stay authoritative for their own wire format.
    """
    if book is None and document:
        book = _dav_book_for_key(db, document)
    if timestamp is None:
        timestamp = int(time.time())
    row = (
        db.query(ClientProgress)
        .filter(
            ClientProgress.user_id == user.id,
            ClientProgress.client == client,
            ClientProgress.document == document,
        )
        .first()
    )
    if row is None:
        row = ClientProgress(user_id=user.id, client=client, document=document)
        db.add(row)
    row.book_id = book.id if book else None
    row.percentage = percentage
    row.page = page
    row.position = position
    row.timestamp = timestamp
    db.commit()


def _backfill_client_progress() -> None:
    """Mirror existing kosync_progress rows into client_progress once.

    Runs on every startup but only touches documents that have no
    client_progress row yet, so it is cheap after the first run.
    """
    with SessionLocal() as db:
        existing = {
            (r.user_id, r.document)
            for r in db.query(ClientProgress.user_id, ClientProgress.document)
            .filter(ClientProgress.client == "kosync").all()
        }
        added = 0
        books = db.query(Book).all()
        for row in db.query(KosyncProgress).all():
            if (row.user_id, row.document) in existing:
                continue
            try:
                pct = float(row.percentage)
            except (TypeError, ValueError):
                pct = None
            try:
                ts = int(row.timestamp or 0)
            except (TypeError, ValueError):
                ts = 0
            book_id = None
            for b in books:
                if (b.koreader_hash or "").lower() == (row.document or "").lower():
                    book_id = b.id
                    break
            db.add(ClientProgress(
                user_id=row.user_id,
                book_id=book_id,
                client="kosync",
                document=row.document,
                percentage=pct,
                position=row.progress,
                timestamp=ts,
            ))
            added += 1
        if added:
            db.commit()
            log.info("client_progress: backfilled %d kosync row(s)", added)

        # Repair step: fix cross-client matching on existing moon_webdav rows
        # whose `document` still carries an e-book extension (e.g.
        # "anna-geschichten.epub") and/or whose `book_id` is NULL because the
        # old key never matched `books.storage_path`. Re-normalises the key and
        # re-resolves the book so both clients reference the same book entity.
        repaired = 0
        for cp in db.query(ClientProgress).filter(ClientProgress.client == "moon_webdav").all():
            norm = _normalize_book_key(cp.document)
            book = _dav_book_for_key(db, norm)
            changed = False
            if norm != cp.document:
                cp.document = norm
                changed = True
            if book is not None and cp.book_id != book.id:
                cp.book_id = book.id
                changed = True
            if changed:
                repaired += 1
        if repaired:
            db.commit()
            log.info("client_progress: repaired %d moon_webdav row(s)", repaired)


# ============================================================ WEBDAV SYNC ===
# Lightweight WebDAV endpoint for clients that sync reading positions as tiny
# files rather than JSON (Moon+ Reader: `<ts>*<chapter>@<section>#<offset>:<pct>%`
# in `<book>.po` under `.Moon+/Cache/`).  Writes are persisted on disk *and*
# materialised into the client-neutral `client_progress` table so the Web UI
# shows them next to KOReader/kosync progress.
#
# The OPDS block below is intentionally untouched by this module.
#
# Auth: HTTP Basic, same `users` table as OPDS/kosync.

WEBDAV_ROOT = Path(os.environ.get("WEBDAV_ROOT", "/app/webdav"))
_MOON_PO_RE = re.compile(
    r"^([0-9]+)\*([0-9]+)@([0-9]+)#([0-9]+):([0-9]+(?:\.[0-9]+)?)%$"
)


def _dav_auth(request: Request, db: Session) -> User:
    header = request.headers.get("authorization", "")
    challenge = {"WWW-Authenticate": 'Basic realm="codexserver-dav"'}
    if not header.lower().startswith("basic "):
        raise HTTPException(status_code=401, detail="Basic auth required", headers=challenge)
    try:
        raw = base64.b64decode(header.split(None, 1)[1]).decode("utf-8")
        username, _, password = raw.partition(":")
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed Basic header", headers=challenge)
    user = db.query(User).filter(User.username == username).first()
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid WebDAV credentials", headers=challenge)
    return user


def _dav_relpath(request: Request) -> str:
    decoded = urllib.parse.unquote(request.path_params.get("path", "") or "").replace("\\", "/")
    parts = [p for p in decoded.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise HTTPException(status_code=400, detail="Invalid WebDAV path")
    return "/".join(parts)


def _dav_user_root(user: User) -> Path:
    root = WEBDAV_ROOT / str(user.id)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _dav_file(user: User, rel: str) -> Path:
    root = _dav_user_root(user).resolve()
    candidate = (root / rel).resolve() if rel else root
    if candidate != root and root not in candidate.parents:
        raise HTTPException(status_code=400, detail="Invalid WebDAV path")
    return candidate


def _dav_prop(target: Path, href: str) -> str:
    is_dir = target.is_dir()
    size = "" if is_dir else str(target.stat().st_size)
    modified = datetime.utcfromtimestamp(target.stat().st_mtime).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    resource = "<d:collection/>" if is_dir else ""
    return (
        f"<d:response><d:href>{href}</d:href>"
        f"<d:propstat><d:prop><d:resourcetype>{resource}</d:resourcetype>"
        f"<d:getcontentlength>{size}</d:getcontentlength>"
        f"<d:getlastmodified>{modified}</d:getlastmodified></d:prop>"
        f"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


def _dav_href(rel: str, is_dir: bool) -> str:
    href = "/dav/" + urllib.parse.quote(rel, safe="/.~+-_<>") if rel else "/dav/"
    if is_dir and not href.endswith("/"):
        href += "/"
    return href


def _dav_propfind(user: User, rel: str, depth: str) -> Response:
    target = _dav_file(user, rel)
    if not target.exists():
        raise HTTPException(status_code=404, detail="WebDAV resource not found")
    responses = [_dav_prop(target, _dav_href(rel, target.is_dir()))]
    if target.is_dir() and depth != "0":
        for child in sorted(target.iterdir(), key=lambda p: p.name.lower()):
            child_rel = "/".join(x for x in (rel, child.name) if x)
            responses.append(_dav_prop(child, _dav_href(child_rel, child.is_dir())))
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<d:multistatus xmlns:d="DAV:">' + "".join(responses) + "</d:multistatus>"
    )
    return Response(content=body, status_code=207, media_type="application/xml; charset=utf-8")


_EBOOK_EXTENSIONS = {
    "epub", "pdf", "mobi", "azw", "azw3", "fb2", "djvu", "djv",
    "cbz", "cbr", "txt", "html", "htm", "rtf", "odt", "doc", "docx",
}


def _normalize_book_key(key: str) -> str:
    """Strip both the progress-file extension (`.po`) AND any e-book
    extension (`.epub`, `.pdf`, …) so a Moon+ `.po` filename resolves to the
    same book entity as its `storage_path` stem and KOReader's hash.

    Moon+ stores `<book>.po` under `.Moon+/Cache/` where `<book>` keeps the
    original file extension, e.g. `Anna-Geschichten.epub.po`. Naively taking
    `Path(...).stem` left `.epub` in the key, which then failed to match the
    DB stem and left `book_id` NULL — the data-silo root cause.
    """
    key = key.strip().lower()
    # Take only the basename so directory prefixes in `storage_path`
    # (`/books/Funke, Cornelia/Anna-Geschichten.epub`) collapse to the bare
    # filename and match the WebDAV relpath / Moon+ key.
    if "/" in key or "\\" in key:
        key = key.replace("\\", "/").rsplit("/", 1)[-1]
    # Drop a trailing `.po` (Moon+/KOReader progress file suffix).
    if "." in key:
        base, ext = key.rsplit(".", 1)
        if ext == "po":
            key = base
    # Drop a trailing e-book extension if present.
    if "." in key:
        base, ext = key.rsplit(".", 1)
        if ext in _EBOOK_EXTENSIONS:
            key = base
    return key

def _dav_book_for_key(db: Session, key: str) -> Optional[Book]:
    key = _normalize_book_key(key)
    for book in db.query(Book).all():
        stem = _normalize_book_key(book.storage_path)
        title = re.sub(r"[^a-z0-9]+", "", (book.title or "").lower())
        if key in {stem, (book.koreader_hash or "").lower(), title}:
            return book
    # No stem/title/hash match. KOReader addresses books by partialMD5, so if
    # the key looks like one, resolve any missing hashes lazily and retry.
    if _MD5_RE.match(key):
        for book in db.query(Book).all():
            kh = _lazy_koreader_hash(db, book)
            if kh and kh.lower() == key:
                return book
    return None


def _global_best_for_book(db: Session, user: User, book: Book) -> Optional[tuple[float, int]]:
    """Highest (percentage, timestamp) across ALL clients for one book + user.

    Cross-client sync: kosync (KOReader) and moon_webdav (Moon+ Reader) each
    write their own `client_progress` row for the same book_id. This returns
    whichever client is furthest, so a pull from either protocol can surface
    the other client's position instead of staying siloed.
    """
    rows = (
        db.query(ClientProgress)
        .filter(
            ClientProgress.user_id == user.id,
            ClientProgress.book_id == book.id,
            ClientProgress.percentage.isnot(None),
        )
        .all()
    )
    if not rows:
        return None
    best = max(rows, key=lambda r: (r.percentage or 0.0, r.timestamp or 0))
    return (float(best.percentage), int(best.timestamp or 0))


def _global_best_progress(db: Session, user: User, document: str) -> Optional[tuple[float, int, str]]:
    """Look up the global best position for one document across ALL clients.

    Takes the raw `document` string from the KOSync GET request (typically a
    partial-MD5 hash) and resolves it via two strategies:
      1. Exact match on `ClientProgress.document` (direct kosync path).
      2. Map `document` → `Book` via `_dav_book_for_key`, then query by
         `book_id` to gather every client's progress for that book.

    Returns `(percentage, timestamp, position)` of the highest value across
    all clients, or None when nothing exists for this document/user pair.
    """
    candidates: list[ClientProgress] = []

    # Strategy 1: direct document lookup
    direct = (
        db.query(ClientProgress)
        .filter(
            ClientProgress.user_id == user.id,
            ClientProgress.document == document,
            ClientProgress.percentage.isnot(None),
        )
        .all()
    )
    candidates.extend(direct)

    # Strategy 2: resolve document → book → all client_progress rows for that book
    book = _dav_book_for_key(db, document)
    if book is not None:
        book_rows = (
            db.query(ClientProgress)
            .filter(
                ClientProgress.user_id == user.id,
                ClientProgress.book_id == book.id,
                ClientProgress.percentage.isnot(None),
            )
            .all()
        )
        candidates.extend(book_rows)

    if not candidates:
        return None
    best = max(candidates, key=lambda r: (r.percentage or 0.0, r.timestamp or 0))
    return (float(best.percentage), int(best.timestamp or 0), best.position or "")


def _patch_po_progress(rel: str, body: bytes, best: tuple[float, int]) -> bytes:
    """Patch a Moon+ `.po` body to a higher percentage from another client.

    Keeps the existing chapter/section/offset, replaces timestamp (ms) and
    percentage so Moon+ Reader resumes at the cross-client position rather
    than its own, older local value. Returns `body` unchanged when the local
    `.po` already reports an equal-or-further position.
    """
    text = body.decode("utf-8", errors="replace").strip()
    match = _MOON_PO_RE.fullmatch(text)
    cur_pct = (float(match.group(5)) / 100.0) if match else 0.0
    best_pct, best_ts = best
    if best_pct <= cur_pct:
        return body
    chapter = match.group(2) if match else "0"
    section = match.group(3) if match else "0"
    offset = match.group(4) if match else "0"
    pct_disp = f"{best_pct * 100:g}"
    new = f"{best_ts * 1000}*{chapter}@{section}#{offset}:{pct_disp}%"
    return new.encode("utf-8")


def _dav_record_moon_progress(user: User, rel: str, body: bytes, db: Session) -> None:
    """Parse a Moon+ `.po` body and upsert one `client_progress` row."""
    raw = body.decode("utf-8", errors="replace").strip()
    match = _MOON_PO_RE.fullmatch(raw)
    if not match:
        log.info("WebDAV: unparsed .po payload for %s (stored verbatim)", rel)
        return
    timestamp_ms, _chapter, _section, _offset, percent = match.groups()
    pct = float(percent) / 100.0
    key = _normalize_book_key(rel)
    _record_client_progress(
        db, user, "moon_webdav", key, pct,
        position=raw, timestamp=int(int(timestamp_ms) / 1000),
    )
    log.info("WebDAV progress: user=%s book=%s percent=%.4f", user.username, key, pct)


@app.api_route("/dav", methods=["OPTIONS", "PROPFIND", "GET", "PUT", "MKCOL"])
@app.api_route("/dav/{path:path}", methods=["OPTIONS", "PROPFIND", "GET", "PUT", "MKCOL"])
async def webdav(request: Request, path: str = "", db: Session = Depends(get_db)) -> Response:
    user = _dav_auth(request, db)
    rel = _dav_relpath(request)
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={"Allow": "OPTIONS, PROPFIND, GET, PUT, MKCOL", "DAV": "1"},
        )
    if request.method == "PROPFIND":
        return _dav_propfind(user, rel, request.headers.get("depth", "1"))
    target = _dav_file(user, rel)
    if request.method == "MKCOL":
        target.mkdir(parents=True, exist_ok=True)
        return Response(status_code=201)
    if request.method == "GET":
        if not target.is_file():
            raise HTTPException(status_code=404, detail="WebDAV file not found")
        data = target.read_bytes()
        # Cross-client sync: if this is a Moon+ `.po` and another client
        # (e.g. KOReader via kosync) is further ahead, serve a patched `.po`
        # reflecting the global best position instead of the stale on-disk one.
        if target.suffix.lower() == ".po":
            book = _dav_book_for_key(db, Path(rel).stem)
            if book is not None:
                best = _global_best_for_book(db, user, book)
                if best is not None:
                    data = _patch_po_progress(rel, data, best)
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"Content-Length": str(len(data))},
        )
    if not rel or rel.endswith("/"):
        raise HTTPException(status_code=405, detail="PUT requires a file path")
    existed = target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(await request.body())
    if target.suffix.lower() == ".po":
        _dav_record_moon_progress(user, rel, target.read_bytes(), db)
    return Response(status_code=204 if existed else 201)


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
from email.utils import format_datetime as _http_date
from datetime import timezone as _tz
import uuid as _uuid


def _rfc3339(dt) -> str:
    """RFC 3339 / ISO 8601 UTC timestamp for Atom <updated>.

    Atom (RFC 4287) requires RFC 3339 date-time, e.g. '2026-09-29T16:52:50Z'.
    email.utils.format_datetime() emits RFC 2822 ('Sat, 26 Sep 2026 16:52:50
    +0000'), which is the *HTTP-date* format used for Last-Modified. Mixing
    the two made strict Atom parsers (Moon+ Reader) abort on the feed, so the
    two formats are kept apart: _rfc3339() here, _http_date() for headers.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_tz.utc)
    return dt.astimezone(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

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


def _opds_root_feed(base_url: str = "") -> bytes:
    body = (
        OPDS_FEED_OPEN
        + '<id>urn:codexserver:opds:root</id>\n'
        + '<title>CodexServer Catalog</title>\n'
        + f'<updated>{_opds_iso(None)}</updated>\n'
        + '<link rel="self"'
        + f' href="{base_url}/opds"'
        + ' type="application/atom+xml; charset=utf-8; profile=opds-catalog"/>\n'
        # KOReader's OPDS plugin only follows `subsection` (not
        # `catalog`) as a navigation entry — see
        # plugins/opds.koplugin/opdsbrowser.lua::catalog_rel. Emit two
        # <link> elements so both KOReader and spec-strict clients work.
        + '<link rel="subsection"'
        + f' href="{base_url}/opds/books"'
        + ' type="application/atom+xml;profile=opds-catalog"'
        + ' title="All books"/>\n'
        + '<link rel="http://opds-spec.org/subsection"'
        + f' href="{base_url}/opds/books"'
        + ' type="application/atom+xml;profile=opds-catalog"'
        + ' title="All books"/>\n'
        + OPDS_FEED_CLOSE
    )
    return (OPDS_XML_DECL + body).encode("utf-8")


def _opds_books_feed(books: list, base_url: str = "") -> bytes:
    parts = [
        OPDS_XML_DECL,
        OPDS_FEED_OPEN,
        '<id>urn:codexserver:opds:books</id>\n',
        '<title>CodexServer Books</title>\n',
        f'<updated>{_opds_iso(None)}</updated>\n',
        '<link rel="self"'
        f' href="{base_url}/opds/books"'
        ' type="application/atom+xml; charset=utf-8; profile=opds-catalog"/>\n',
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
            f' href="{base_url}/opds/download/{b.id}"'
            f' type="{mime}"'
            f' title="{title}"/>\n'
        )
        # Thumbnail: optional, KOReader falls back gracefully on 404.
        parts.append(
            '  <link rel="http://opds-spec.org/image/thumbnail"'
            f' href="{base_url}/opds/cover/{b.id}"'
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


def _cached_cover(book: Book) -> tuple[bytes, str] | None:
    """Return (bytes, mime) for a book's cover, using an on-disk cache.

    Cache key is the book id; the file is written with an extension matching
    its MIME so the cache dir is human-inspectable and any future thumbnailer
    can distinguish jpeg/png. A cache miss extracts from the EPUB once and
    stores it; a hit avoids the FUSE/network re-read entirely.
    """
    src = Path(book.storage_path)
    if not src.is_file():
        return None
    # Hit: any existing cache entry for this book.
    for ext, mime in ((".jpg", "image/jpeg"), (".jpeg", "image/jpeg"), (".png", "image/png")):
        cf = COVER_CACHE_DIR / f"{book.id}{ext}"
        if cf.is_file():
            return cf.read_bytes(), mime
    # Miss: extract and cache under the matching extension.
    cover = _epub_cover(str(src))
    if cover is None:
        return None
    data, mime = cover
    ext = ".png" if mime == "image/png" else ".jpg"
    cf = COVER_CACHE_DIR / f"{book.id}{ext}"
    try:
        cf.write_bytes(data)
    except Exception:  # noqa: BLE001 — cache write must never break serving
        log.warning("cover cache write failed for book %s", book.id, exc_info=True)
    return data, mime


# OPDS content type per OPDS 1.2 / RFC 5023. Some clients (notably Moon+
# Reader) are picky: they want the charset spelled out AND the profile
# parameter to match what their parser pattern-matches.
OPDS_CONTENT_TYPE = "application/atom+xml; charset=utf-8; profile=opds-catalog"

# ---------------------------------------------------------- /opds root
@app.get("/opds", response_class=Response)
@app.head("/opds", response_class=Response)
def opds_root(request: Request, user: User = Depends(_require_opds_auth), db: Session = Depends(get_db)) -> Response:
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
        headers["Last-Modified"] = _http_date(last_mod.astimezone(_tz.utc))
    return Response(
        content=_opds_books_feed(rows, base_url=str(request.base_url).rstrip("/")),
        media_type=OPDS_CONTENT_TYPE,
        headers=headers,
    )


# ------------------------------------------------------------ /opds/books
@app.get("/opds/books", response_class=Response)
@app.head("/opds/books", response_class=Response)
def opds_books(request: Request, user: User = Depends(_require_opds_auth), db: Session = Depends(get_db)) -> Response:
    """OPDS 1.2 acquisition feed: every book in the catalog."""
    rows = db.query(Book).order_by(Book.added_at.desc()).all()
    last_mod = max((b.added_at for b in rows if b.added_at is not None), default=None)
    headers = {"Cache-Control": "public, max-age=60"}
    if last_mod is not None:
        headers["Last-Modified"] = _http_date(last_mod.astimezone(_tz.utc))
    return Response(
        content=_opds_books_feed(rows, base_url=str(request.base_url).rstrip("/")),
        media_type=OPDS_CONTENT_TYPE,
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
def opds_cover(book_id: int, db: Session = Depends(get_db)) -> Response:
    """Serve an EPUB's cover image.

    Intentionally UNauthenticated: OPDS clients (Moon+ Reader in particular)
    do not reliably resend the Basic-Auth header on subsequent cover/image
    fetches, only on the feed request itself. Cover thumbnails carry no
    sensitive data, so they are public to keep image loads working; the feed
    and downloads remain Basic-auth-protected.
    """
    book = db.get(Book, book_id)
    if book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    cover = _cached_cover(book)
    if cover is None:
        # 404 keeps the OPDS feed honest; KOReader falls back to a placeholder.
        raise HTTPException(status_code=404, detail="No cover image in EPUB")
    data, mime = cover
    return Response(content=data, media_type=mime)


# -------------------------------------------------------- /api/cover/{id} (Web UI)
@app.get("/api/cover/{book_id}", dependencies=[Depends(require_ui_auth)])
def ui_cover(book_id: int, db: Session = Depends(get_db)) -> Response:
    """Cookie-authenticated cover endpoint for the Web UI.

    /opds/cover/{id} is HTTP-Basic-only (OPDS clients), but the browser UI uses
    a `codex_session` cookie — an <img> tag can't send a Basic header. This route
    mirrors `opds_cover` with cookie auth so the Library can render real covers.
    """
    book = db.get(Book, book_id)
    if book is None:
        raise HTTPException(status_code=404, detail="Book not found")
    cover = _cached_cover(book)
    if cover is None:
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
    _record_client_progress(db, user, "kosync", doc, pct, position=progress)
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
    # Cross-client sync: look up the global best position for this document
    # across ALL clients (kosync + moon_webdav) so KOReader pulls a further
    # Moon+ position instead of staying siloed. Falls back to the kosync row
    # when no cross-client entry exists (or the kosync row is the best).
    global_best = _global_best_progress(db, user, document)
    if global_best is None and row is None:
        return _JSONResponse_kosync(
            status_code=200,
            content={},
            headers={"Content-Type": "application/json"},
        )
    if global_best is not None:
        best_pct, best_ts, best_position = global_best
        # Never leak a Moon+ `.po` payload back into KOReader's `progress`
        # field — that field is KOReader's own position encoding. When the
        # global best comes from WebDAV/Moon+, only the percentage + timestamp
        # are translated; KOReader resumes at that percentage, not at a foreign
        # offset string it cannot parse.
        if best_position and _MOON_PO_RE.fullmatch(best_position.strip()):
            best_position = ""
    else:
        best_pct = float(row.percentage) if row.percentage else 0.0
        best_ts = row.timestamp
        best_position = row.progress
    out: dict = {}
    if row and row.device_id:
        out["device_id"] = row.device_id
    out["progress"] = best_position or ""
    out["document"] = document
    out["percentage"] = best_pct
    out["timestamp"] = best_ts
    out["device"] = (row.device if row else "") or ""
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
            "client": "kosync",
        })
    return out


@app.get("/api/progress")
def api_progress(
    _admin: dict = Depends(require_ui_auth),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Client-neutral progress feed for the Web UI.

    ONE entry per book (or unmatched document): the entry carries the
    reader that synced MOST RECENTLY (highest `updated_at`), together with
    that reader's percentage/timestamp. This is a true "last activity"
    history — the furthest-reading aggregate lives separately in the
    Library view, which is the meaningful place for progress bars.
    """
    rows = (
        db.query(ClientProgress, User, Book)
        .outerjoin(User, ClientProgress.user_id == User.id)
        .outerjoin(Book, ClientProgress.book_id == Book.id)
        .order_by(ClientProgress.updated_at.desc())
        .all()
    )
    grouped: dict[str, dict] = {}
    for prog, owner, book in rows:
        key = f"book:{book.id}" if book else f"doc:{prog.document}"
        if key in grouped:
            continue  # rows are ordered newest-first; first hit is the latest sync
        grouped[key] = {
            "username": owner.username if owner else None,
            "client": prog.client,
            "document": prog.document,
            "percentage": prog.percentage,
            "position": prog.position,
            "timestamp": prog.timestamp,
            "updated_at": prog.updated_at.isoformat() if prog.updated_at else None,
            "book_id": book.id if book else None,
            "title": book.title if book else None,
            "author": book.author if book else None,
        }
    return list(grouped.values())


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

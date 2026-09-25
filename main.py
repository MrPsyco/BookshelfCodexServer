"""CodexServer - FastAPI entrypoint.

Endpoints:
  GET  /health
  POST /upload                     multipart EPUB upload -> metadata pipeline -> storage
  GET  /api/books
  GET/POST/PUT/DELETE /api/storage  (StorageConfig CRUD)
  GET/PUT/POST/DELETE /api/metadata (MetadataConfig CRUD)
  POST /sync/syncs                 KOReader progress push
  GET  /sync/progress/<username>/<doc>  KOReader progress pull
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Form, Request
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

import epub_washer
from database import get_db, init_db
from models import Book, MetadataConfig, Progress, StorageConfig, User

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("codexserver")

BOOKS_ROOT = os.environ.get("BOOKS_ROOT", "/books")
STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="CodexServer", version="0.2.0")

# Permissive CORS so a Cloudflare tunnel / remote reverse proxy works later.
# Tighten this once a real auth layer exists.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    Path(BOOKS_ROOT).mkdir(parents=True, exist_ok=True)
    log.info("CodexServer up. BOOKS_ROOT=%s", BOOKS_ROOT)


# ---------------------------------------------------------------- health -----

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "codexserver", "books_root": BOOKS_ROOT}


# ---------------------------------------------------------------- books ------

@app.get("/api/books")
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


@app.post("/upload")
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

    dest = epub_washer.safe_storage_path(BOOKS_ROOT, author, title, file.filename)
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(blob)

    book = Book(
        title=title, author=author, storage_path=dest,
        storage_backend=backend, file_size=len(blob),
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


# ------------------------------------------------------------- storage -------

class StorageIn(BaseModel):
    label: str
    backend: str
    remote_name: Optional[str] = None
    remote_path: Optional[str] = None
    credentials_json: Optional[str] = None
    is_active: bool = True


SUPPORTED_BACKENDS = {"local", "gdrive", "onedrive", "dropbox", "webdav", "s3"}


@app.get("/api/storage")
def list_storage(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": s.id, "label": s.label, "backend": s.backend,
            "remote_name": s.remote_name, "remote_path": s.remote_path,
            "is_active": s.is_active, "created_at": s.created_at.isoformat(),
        }
        for s in db.query(StorageConfig).all()
    ]


@app.post("/api/storage")
def create_storage(payload: StorageIn, db: Session = Depends(get_db)) -> dict:
    if payload.backend not in SUPPORTED_BACKENDS:
        raise HTTPException(400, f"backend must be one of {sorted(SUPPORTED_BACKENDS)}")
    if payload.backend != "local":
        # TODO(phase2): run `rclone config create <remote> <backend> ...` and mount FUSE.
        # Credential storage below is intentionally a stub - do NOT claim it works yet.
        log.warning("backend=%s is a UI stub; rclone remote is not provisioned", payload.backend)
    s = StorageConfig(**payload.model_dump())
    db.add(s)
    db.commit()
    db.refresh(s)
    return {"id": s.id, "label": s.label, "backend": s.backend, "stub": payload.backend != "local"}


@app.delete("/api/storage/{sid}")
def delete_storage(sid: int, db: Session = Depends(get_db)) -> dict:
    s = db.get(StorageConfig, sid)
    if not s:
        raise HTTPException(404, "storage config not found")
    db.delete(s)
    db.commit()
    return {"deleted": sid}


# ------------------------------------------------------------ metadata -------

class MetadataIn(BaseModel):
    provider_name: str
    is_active: bool = True
    priority: int = 100
    api_key_or_url: Optional[str] = None


@app.get("/api/metadata")
def list_metadata(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(MetadataConfig).order_by(MetadataConfig.priority.asc()).all()
    return [
        {
            "id": m.id, "provider_name": m.provider_name, "is_active": m.is_active,
            "priority": m.priority, "api_key_or_url": m.api_key_or_url,
        }
        for m in rows
    ]


@app.post("/api/metadata")
def create_metadata(payload: MetadataIn, db: Session = Depends(get_db)) -> dict:
    if payload.provider_name not in epub_washer.PROVIDERS:
        raise HTTPException(400, f"unknown provider, supported: {sorted(epub_washer.PROVIDERS)}")
    m = MetadataConfig(**payload.model_dump())
    db.add(m)
    db.commit()
    db.refresh(m)
    return {"id": m.id, "provider_name": m.provider_name, "priority": m.priority}


@app.put("/api/metadata/{mid}")
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


@app.delete("/api/metadata/{mid}")
def delete_metadata(mid: int, db: Session = Depends(get_db)) -> dict:
    m = db.get(MetadataConfig, mid)
    if not m:
        raise HTTPException(404, "metadata config not found")
    db.delete(m)
    db.commit()
    return {"deleted": mid}


# ------------------------------------------------------- KOReader sync -------

class SyncBody(BaseModel):
    """KOReader's POST /sync/syncs payload (subset we act on)."""

    username: str
    password: str
    document: str          # md5 of the document file
    progress: str          # "X.XX" 0..100
    percentage: Optional[float] = None
    device: Optional[str] = None


@app.post("/sync/syncs")
def koreader_push(body: SyncBody, db: Session = Depends(get_db)) -> dict:
    user = db.query(User).filter(User.username == body.username).first()
    if user is None:
        user = User(username=body.username)
        db.add(user)
        db.commit()
        db.refresh(user)

    # Emulation notes: KOReader identifies documents by md5. We store it in
    # storage_path's basename lookup on a best-effort basis; unknown docs still
    # get a Progress row keyed by a synthetic Book row so sync doesn't error.
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


@app.get("/sync/progress/{username}/{document}")
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


# ---------------------------------------------------------------- root -------

@app.get("/", response_class=HTMLResponse)
def root() -> FileResponse:
    """Serve the SPA entrypoint explicitly. This guarantees '/' returns the
    dashboard regardless of how StaticFiles is mounted."""
    index = STATIC_DIR / "index.html"
    if not index.exists():
        return HTMLResponse("<h1>CodexServer</h1><p>UI not built (index.html missing).</p>", status_code=500)
    return FileResponse(index, media_type="text/html")


@app.get("/favicon.ico")
def favicon() -> JSONResponse:
    # No favicon file shipped — return 204 to silence browser 404 noise.
    return JSONResponse({}, status_code=204)


# Serve /static/* from the static/ directory so the dashboard's
# <link rel="stylesheet" href="/static/dist/tailwind.css"> resolves.
# Note: this MUST come after all API routes so FastAPI matches API paths first.
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    log.warning("static/ directory missing at %s - CSS/JS assets will 404", STATIC_DIR)

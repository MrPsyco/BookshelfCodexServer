"""SQLAlchemy ORM models for CodexServer."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(120), unique=True, nullable=False, index=True)
    # RBAC: 'admin' can hit /api/* & /ui/; 'koreader' only hits /sync/*
    role = Column(String(20), nullable=False, default="koreader")
    # bcrypt hash; NULL for legacy KOReader rows that have no password
    password_hash = Column(String(255), nullable=True)
    # KOReader sync credential: client-side MD5(lowercase hex) of the
    # password the user typed into KOReader's sync settings. Compared
    # byte-exact against the x-auth-key header (kosync v1 protocol).
    # NULL until the user registers via POST /users/create.
    kosync_key = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    progress = relationship("Progress", back_populates="user", cascade="all, delete-orphan")


class Book(Base):
    __tablename__ = "books"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False, index=True)
    author = Column(String(500), nullable=True, index=True)
    storage_path = Column(String(1000), nullable=False)
    storage_backend = Column(String(50), nullable=False, default="local")  # local | gdrive | onedrive | ...
    file_size = Column(Integer, nullable=True)
    added_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    # KOReader document hash (32-char lowercase hex, MD5 over 12 sampled
    # 1024-byte blocks at the partialMD5 offsets). NULL until a real file is
    # attached and hashed. Used to JOIN kosync_progress rows to books.
    koreader_hash = Column(String(32), nullable=True, index=True)


class Progress(Base):
    """KOReader sync emulation: per-user, per-book reading progress."""

    __tablename__ = "progress"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"), nullable=False)
    # KOReader's `progress` field is a string percentage "X.XX" up to 100.00
    progress_percent = Column(String(10), nullable=False, default="0.00")
    device = Column(String(120), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="progress")


class KosyncProgress(Base):
    """Real kosync v1 progress store: per-user, per-opaque-document.

    The `document` field is an opaque string supplied by the KOReader client.
    KOReader always sends a 32-character lowercase hex partialMD5, which
    matches our [A-Za-z0-9_]+ route pattern and the books.koreader_hash column
    we populate when uploading files. When a row is written, we also try to
    JOIN books on koreader_hash and expose the link in /api/koreader/progress
    so the Web UI can show the book title alongside the device percentage.
    """

    __tablename__ = "kosync_progress"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    document = Column(String(64), nullable=False, index=True)  # KOReader's 32-hex digest
    progress = Column(String(2048), nullable=False, default="")  # XPointer string
    percentage = Column(String(20), nullable=False, default="0")  # stored as text to preserve float repr
    device = Column(String(120), nullable=True)
    device_id = Column(String(120), nullable=True)
    timestamp = Column(Integer, nullable=False, default=0)  # server-set epoch seconds
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User")


class StorageConfig(Base):
    """Rclone remote configurations. Type = local | gdrive | onedrive | dropbox | webdav | s3."""

    __tablename__ = "storage_configs"

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(120), nullable=False)              # user-facing name
    backend = Column(String(50), nullable=False)             # local | gdrive | onedrive | dropbox | webdav | s3
    remote_name = Column(String(120), nullable=True)         # rclone remote name
    remote_path = Column(String(500), nullable=True)         # subdir inside the remote
    credentials_json = Column(Text, nullable=True)           # oauth JSON / token blob snapshot
    is_active = Column(Boolean, default=True, nullable=False)
    # JSON snapshot of the latest OAuth/auth flow state.
    # Shape: {"state":"idle|pending|complete|error", "backend": "...", "instructions": "...", "error": "..."}
    auth_status = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class WebSession(Base):
    """Persistent Web UI session. Survives container restarts so the admin
    does not have to log in again on every codexserver deploy."""
    __tablename__ = "web_sessions"

    token = Column(String(80), primary_key=True)            # cookie value (random URL-safe)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    username = Column(String(120), nullable=False)          # snapshot for logging/auditing
    role = Column(String(20), nullable=False)               # snapshot (typically "admin")
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class MetadataConfig(Base):
    """Metadata provider chain. Ordered by ascending priority (1 = tried first)."""

    __tablename__ = "metadata_configs"

    id = Column(Integer, primary_key=True, index=True)
    provider_name = Column(String(60), nullable=False, index=True)  # internal_opf | google_books | ollama | openai
    is_active = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    api_key_or_url = Column(String(1000), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

"""SQLAlchemy ORM models for CodexServer."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(120), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

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


class MetadataConfig(Base):
    """Metadata provider chain. Ordered by ascending priority (1 = tried first)."""

    __tablename__ = "metadata_configs"

    id = Column(Integer, primary_key=True, index=True)
    provider_name = Column(String(60), nullable=False, index=True)  # internal_opf | google_books | ollama | openai
    is_active = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    api_key_or_url = Column(String(1000), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

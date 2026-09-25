"""SQLAlchemy engine + session setup for CodexServer."""
from pathlib import Path
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, declarative_base

DB_PATH = Path(__file__).parent / "library.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a SQLAlchemy session, ensures close."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_columns() -> None:
    """Idempotent migration: add columns introduced after v0.1 without dropping tables.

    `library.db` is a live database; never use drop_all/create_all to apply schema
    changes. Instead, inspect the table and ALTER TABLE ADD COLUMN if missing.
    """
    insp = inspect(engine)
    if insp.has_table("storage_configs"):
        cols = {c["name"] for c in insp.get_columns("storage_configs")}
        if "auth_status" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE storage_configs ADD COLUMN auth_status TEXT"))
    if insp.has_table("users"):
        cols = {c["name"] for c in insp.get_columns("users")}
        with engine.begin() as conn:
            if "role" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'koreader'"))
            if "password_hash" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
            if "last_login_at" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_login_at DATETIME"))


def init_db() -> None:
    """Create all tables, run idempotent migrations, seed defaults if empty."""
    from models import MetadataConfig  # local import: avoids circular at import time

    Base.metadata.create_all(bind=engine)
    _ensure_columns()

    with SessionLocal() as db:
        if db.query(MetadataConfig).count() == 0:
            db.add_all(
                [
                    MetadataConfig(
                        provider_name="internal_opf", is_active=True, priority=1,
                        api_key_or_url="",
                    ),
                    MetadataConfig(
                        provider_name="google_books", is_active=True, priority=2,
                        api_key_or_url="",
                    ),
                    MetadataConfig(
                        provider_name="ollama",
                        is_active=False,
                        priority=3,
                        api_key_or_url="http://192.168.1.146:11434/api/generate",
                    ),
                ]
            )
            db.commit()

"""SQLAlchemy engine + session setup for CodexServer."""
from pathlib import Path
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, declarative_base

DB_PATH = Path(__file__).parent / "library.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False, "timeout": 30},
    # The enrichment worker runs 8 parallel OPF readers while the scanner and
    # request handlers each hold their own session. SQLite is a single-writer
    # DB, so a small default pool (size 5 + overflow 10) exhausts under that
    # concurrency ("QueuePool limit of size 5 overflow 10 reached"). A roomier
    # pool + a real busy timeout + pre_ping keeps worker threads from wedging
    # the ASGI app mid-request.
    pool_size=10,
    max_overflow=30,
    pool_timeout=30,
    pool_pre_ping=True,
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
            if "kosync_key" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN kosync_key VARCHAR(64)"))
    if insp.has_table("books"):
        cols = {c["name"] for c in insp.get_columns("books")}
        with engine.begin() as conn:
            if "koreader_hash" not in cols:
                conn.execute(text("ALTER TABLE books ADD COLUMN koreader_hash VARCHAR(32)"))
            if "metadata_enriched" not in cols:
                conn.execute(text("ALTER TABLE books ADD COLUMN metadata_enriched BOOLEAN NOT NULL DEFAULT 0"))
            if "metadata_source" not in cols:
                conn.execute(text("ALTER TABLE books ADD COLUMN metadata_source VARCHAR(60)"))
        # index is best-effort; duplicate index will raise, we ignore.
        with engine.begin() as conn:
            for ddl in (
                "CREATE INDEX IF NOT EXISTS ix_books_koreader_hash ON books(koreader_hash)",
                "CREATE INDEX IF NOT EXISTS ix_books_added_at ON books(added_at)",
                "CREATE INDEX IF NOT EXISTS ix_books_storage_path ON books(storage_path)",
            ):
                try:
                    conn.execute(text(ddl))
                except Exception:
                    pass
    if insp.has_table("client_progress"):
        with engine.begin() as conn:
            for ddl in (
                "CREATE INDEX IF NOT EXISTS ix_client_progress_book_id ON client_progress(book_id)",
                "CREATE INDEX IF NOT EXISTS ix_client_progress_updated_at ON client_progress(updated_at)",
            ):
                try:
                    conn.execute(text(ddl))
                except Exception:
                    pass


def init_db() -> None:
    """Create all tables, run idempotent migrations, seed defaults if empty."""
    from models import MetadataConfig, AppSetting, DEFAULT_SETTINGS  # local import: avoids circular at import time

    # WAL lets readers and the single writer proceed concurrently instead of
    # blocking every read on a transaction under journal_mode=DELETE. It is a
    # persistent DB setting: applied once, survives restarts. Necessary now that
    # the enrichment worker, scanner, and request handlers all hit SQLite at
    # once.
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA busy_timeout=30000"))

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

        # Seed default app_settings rows for any key not already present.
        existing_keys = {s.key for s in db.query(AppSetting).all()}
        for key, value in DEFAULT_SETTINGS.items():
            if key not in existing_keys:
                db.add(AppSetting(key=key, value=value))
        db.commit()

"""SQLAlchemy engine + session setup for CodexServer."""
from pathlib import Path
from sqlalchemy import create_engine
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


def init_db() -> None:
    """Create all tables and seed default metadata providers if empty."""
    from models import MetadataConfig  # local import: avoids circular at import time

    Base.metadata.create_all(bind=engine)

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

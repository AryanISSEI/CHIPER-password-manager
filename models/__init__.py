"""Database engine, session, and declarative base for standalone SQLAlchemy."""

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from config import Config

engine = create_engine(Config.DATABASE_URI, echo=False)
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


def _migrate_vault_entries():
    """Adds new columns to existing vault_entries table if missing.

    This is a safe, idempotent migration that uses ALTER TABLE to add
    columns that were introduced after the initial schema. Each column
    addition is wrapped in a try/except to handle the case where the
    column already exists.
    """
    inspector = inspect(engine)
    if 'vault_entries' not in inspector.get_table_names():
        return  # Table doesn't exist yet; create_all will handle it

    existing_cols = {col['name'] for col in inspector.get_columns('vault_entries')}

    migrations = [
        ("category", "VARCHAR(50) DEFAULT 'login'"),
        ("is_favorite", "BOOLEAN DEFAULT 0"),
        ("last_used_at", "DATETIME"),
    ]

    with engine.connect() as conn:
        for col_name, col_def in migrations:
            if col_name not in existing_cols:
                try:
                    conn.execute(text(
                        f"ALTER TABLE vault_entries ADD COLUMN {col_name} {col_def}"
                    ))
                    conn.commit()
                except Exception:
                    pass  # Column already exists or other benign error


def init_db():
    """Create all tables if they don't exist, then run migrations."""
    from models.user import User      # noqa: F401
    from models.vault import VaultEntry  # noqa: F401
    try:
        Base.metadata.create_all(engine)
        _migrate_vault_entries()
    except Exception as e:
        print(f"Database initialization warning: {e}")
        # Try create_all one more time in case migration interfered
        try:
            Base.metadata.create_all(engine)
        except Exception:
            pass

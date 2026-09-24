"""conftest.py — Test fixtures for standalone SQLAlchemy and crypto testing."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base


@pytest.fixture
def db_session():
    """Provides an isolated in-memory SQLite database session for testing."""
    engine = create_engine('sqlite:///:memory:', echo=False)
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    yield session

    session.close()
    Base.metadata.drop_all(engine)

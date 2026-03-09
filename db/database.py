import asyncio

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

DATABASE_URL = "sqlite+aiosqlite:///afo.db"

engine = create_async_engine(DATABASE_URL, echo=False, future=True)


async def _migrate_schema(conn):
    """Add missing columns to existing tables."""
    # Check and add expires_at to deploymentlog if missing
    result = await conn.execute(text("PRAGMA table_info(deploymentlog)"))
    columns = [row[1] for row in result.fetchall()]
    if columns and "expires_at" not in columns:
        await conn.execute(
            text("ALTER TABLE deploymentlog ADD COLUMN expires_at TIMESTAMP")
        )


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        await _migrate_schema(conn)


def init_db_sync():
    """Synchronous wrapper for database initialization (for CLI)."""
    asyncio.run(init_db())
    print("✓ Database initialized successfully")


async def get_session() -> AsyncSession:
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session

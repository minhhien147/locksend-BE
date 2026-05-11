"""FastAPI dependency: yields an async DB session per request."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from .session import AsyncSessionLocal


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

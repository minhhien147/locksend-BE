"""Tạo PostgreSQL test database nếu chưa tồn tại."""
import asyncio
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine


async def main():
    engine = create_async_engine(
        "postgresql+asyncpg://postgres:postgres@localhost:5432/postgres",
        isolation_level="AUTOCOMMIT",
    )
    async with engine.connect() as conn:
        result = await conn.execute(
            sa.text(
                "SELECT 1 FROM pg_database "
                "WHERE datname = 'secure_file_sharing_test'"
            )
        )
        exists = result.scalar()
        if not exists:
            await conn.execute(sa.text("CREATE DATABASE secure_file_sharing_test"))
            print("OK: Database 'secure_file_sharing_test' created")
        else:
            print("OK: Database 'secure_file_sharing_test' already exists")
    await engine.dispose()


asyncio.run(main())

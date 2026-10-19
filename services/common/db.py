"""Accès PostgreSQL partagé (psycopg 3 asynchrone, requêtes SQL explicites).

Aucun ORM : les requêtes sont écrites en SQL lisible, ce qui facilite l'audit
et la justification des privilèges accordés à chaque rôle (voir `docs/DESIGN.md`
section 1.1).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger("common.db")

_pool: AsyncConnectionPool | None = None


async def init_pool(
    dsn: str,
    *,
    min_size: int = 1,
    max_size: int = 8,
    timeout: float = 10.0,
) -> AsyncConnectionPool:
    """Ouvre le pool de connexions. Appelée une fois au démarrage du service."""
    global _pool
    if _pool is not None:
        return _pool

    pool = AsyncConnectionPool(
        conninfo=dsn,
        min_size=min_size,
        max_size=max_size,
        open=False,
        timeout=timeout,
        kwargs={"row_factory": dict_row, "autocommit": False},
    )
    await pool.open(wait=True, timeout=30.0)
    _pool = pool
    logger.info("pool de connexions ouvert")
    return pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def get_pool() -> AsyncConnectionPool:
    if _pool is None:
        raise RuntimeError("le pool de connexions n'est pas initialise")
    return _pool


@asynccontextmanager
async def connection() -> AsyncIterator[Any]:
    async with get_pool().connection() as conn:
        yield conn


@asynccontextmanager
async def transaction() -> AsyncIterator[Any]:
    """Transaction explicite : validation en sortie, annulation sur exception."""
    async with get_pool().connection() as conn:
        async with conn.transaction():
            yield conn


async def fetch_all(
    sql: str, params: Sequence[Any] | dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    async with connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            return await cur.fetchall()


async def fetch_one(
    sql: str, params: Sequence[Any] | dict[str, Any] | None = None
) -> dict[str, Any] | None:
    async with connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            return await cur.fetchone()


async def fetch_value(
    sql: str, params: Sequence[Any] | dict[str, Any] | None = None
) -> Any:
    row = await fetch_one(sql, params)
    if row is None:
        return None
    return next(iter(row.values()))


async def execute(
    sql: str, params: Sequence[Any] | dict[str, Any] | None = None
) -> int:
    """Exécute une instruction et renvoie le nombre de lignes affectées."""
    async with transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            return cur.rowcount


async def ping() -> bool:
    try:
        value = await fetch_value("SELECT 1 AS ok")
        return value == 1
    except Exception:  # pragma: no cover - dépend de la disponibilité
        return False

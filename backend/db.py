"""
ARNIE Database Layer
PostgreSQL connection pool, auth, and audit trail.
"""

import os
import json
import uuid
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("arnie.db")

_pool = None

try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False
    log.warning("asyncpg not installed — database features disabled")

try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    os.environ.get("ARNIE_DATABASE_URL", "")
)
JWT_SECRET = os.environ.get("ARNIE_JWT_SECRET", "arnie-dev-secret-change-me")


async def get_pool():
    global _pool
    if _pool is None and HAS_ASYNCPG and DATABASE_URL:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    if _pool is None:
        raise RuntimeError("Database not available")
    return _pool


async def close_pool():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    if not HAS_JWT:
        return None
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def _make_jwt(payload: Dict[str, Any]) -> str:
    if not HAS_JWT:
        return ""
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=24)
    payload["iat"] = datetime.now(timezone.utc)
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")


async def create_account(email: str, password: str,
                         name: str = "", organization: str = "") -> Dict[str, Any]:
    pool = await get_pool()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    account_id = uuid.uuid4()
    await pool.execute(
        """INSERT INTO accounts (id, email, password_hash, name, organization, created_at)
           VALUES ($1, $2, $3, $4, $5, NOW())""",
        account_id, email, pw_hash, name, organization,
    )
    return {"id": str(account_id), "email": email, "name": name}


async def authenticate(email: str, password: str) -> Optional[Dict[str, Any]]:
    pool = await get_pool()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    row = await pool.fetchrow(
        "SELECT id, email, name, organization FROM accounts WHERE email = $1 AND password_hash = $2",
        email, pw_hash,
    )
    if not row:
        return None
    token = _make_jwt({"sub": str(row["id"]), "email": row["email"]})
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "name": row["name"],
        "organization": row["organization"],
        "token": token,
    }


async def get_account(account_id: str) -> Optional[Dict[str, Any]]:
    pool = await get_pool()
    row = await pool.fetchrow(
        "SELECT id, email, name, organization FROM accounts WHERE id = $1",
        uuid.UUID(account_id),
    )
    if not row:
        return None
    return {k: str(v) if isinstance(v, uuid.UUID) else v for k, v in dict(row).items()}


async def update_account(account_id: str, **kwargs) -> Dict[str, Any]:
    pool = await get_pool()
    sets = []
    vals = []
    i = 2
    for k, v in kwargs.items():
        if v is not None:
            sets.append(f"{k} = ${i}")
            vals.append(json.dumps(v) if isinstance(v, dict) else v)
            i += 1
    if sets:
        query = f"UPDATE accounts SET {', '.join(sets)} WHERE id = $1"
        await pool.execute(query, uuid.UUID(account_id), *vals)
    return await get_account(account_id) or {}


async def get_audit_log(account_id: str) -> List[Dict[str, Any]]:
    pool = await get_pool()
    rows = await pool.fetch(
        "SELECT * FROM audit_log WHERE account_id = $1 ORDER BY created_at DESC LIMIT 100",
        uuid.UUID(account_id),
    )
    return [dict(r) for r in rows]

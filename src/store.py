"""Credential storage using SQLite."""

import sqlite3
import os
from pathlib import Path

DB_PATH = Path.home() / ".local" / "share" / "linux-hello" / "credentials.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id          BLOB PRIMARY KEY,
            rp_id       TEXT NOT NULL,
            user_id     BLOB NOT NULL,
            user_name   TEXT,
            pub_key     BLOB NOT NULL,
            priv_key    BLOB NOT NULL,
            sign_count  INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    return conn


def save(cred_id: bytes, rp_id: str, user_id: bytes, user_name: str,
         pub_key: bytes, priv_key: bytes) -> None:
    """Save a new credential."""
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO credentials VALUES (?,?,?,?,?,?,0)",
            (cred_id, rp_id, user_id, user_name, pub_key, priv_key)
        )


def get(cred_id: bytes) -> dict | None:
    """Fetch a credential by ID."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT rp_id, user_id, user_name, pub_key, priv_key, sign_count "
            "FROM credentials WHERE id=?", (cred_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "rp_id": row[0], "user_id": row[1], "user_name": row[2],
        "pub_key": row[3], "priv_key": row[4], "sign_count": row[5],
    }


def get_by_rp(rp_id: str) -> list[dict]:
    """Fetch all credentials for a relying party."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, user_id, user_name, pub_key, priv_key, sign_count "
            "FROM credentials WHERE rp_id=?", (rp_id,)
        ).fetchall()
    return [
        {"id": r[0], "user_id": r[1], "user_name": r[2],
         "pub_key": r[3], "priv_key": r[4], "sign_count": r[5]}
        for r in rows
    ]


def increment_sign_count(cred_id: bytes) -> int:
    """Increment and return the new sign count."""
    with _connect() as conn:
        conn.execute(
            "UPDATE credentials SET sign_count = sign_count + 1 WHERE id=?", (cred_id,)
        )
        row = conn.execute(
            "SELECT sign_count FROM credentials WHERE id=?", (cred_id,)
        ).fetchone()
    return row[0] if row else 0

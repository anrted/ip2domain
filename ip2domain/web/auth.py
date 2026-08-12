"""User, password and browser-session storage for the Web UI."""

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional


PBKDF2_ITERATIONS = 600_000
SESSION_TTL_DAYS = 7


def normalize_username(username: str) -> str:
    return username.strip().lower()


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS, salt.hex(), digest.hex()
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, expected_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(actual.hex(), expected_hex)
    except (TypeError, ValueError):
        return False


class AuthManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user'
                        CHECK(role IN ('admin', 'user')),
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id "
                "ON user_sessions(user_id)"
            )
            conn.commit()

    @staticmethod
    def _public_user(row) -> Optional[dict]:
        if row is None:
            return None
        data = dict(row)
        data.pop("password_hash", None)
        data["is_active"] = bool(data["is_active"])
        return data

    def count_users(self) -> int:
        with self._get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"])

    def create_user(self, username: str, password: str, role: str = "user") -> dict:
        username = normalize_username(username)
        if not (3 <= len(username) <= 64):
            raise ValueError("Username must contain between 3 and 64 characters")
        if not all(ch.isalnum() or ch in "._-" for ch in username):
            raise ValueError("Username may contain only letters, numbers, '.', '_' and '-'")
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters")
        if role not in ("admin", "user"):
            raise ValueError("Role must be 'admin' or 'user'")
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, hash_password(password), role),
                )
                conn.commit()
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ValueError("A user with this username already exists") from exc
        return self.get_user(user_id)

    def ensure_admin(self, username: str, password: str) -> bool:
        if self.count_users() != 0:
            return False
        self.create_user(username, password, role="admin")
        return True

    def get_user(self, user_id: int) -> Optional[dict]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._public_user(row)

    def list_users(self) -> list:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT id, username, role, is_active, created_at, updated_at, last_login_at "
                "FROM users ORDER BY id"
            ).fetchall()
        return [self._public_user(row) for row in rows]

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (normalize_username(username),),
            ).fetchone()
        if row is None or not row["is_active"]:
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?",
                (row["id"],),
            )
            conn.commit()
        return self.get_user(row["id"])

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)
        with self._get_connection() as conn:
            conn.execute("DELETE FROM user_sessions WHERE expires_at <= CURRENT_TIMESTAMP")
            conn.execute(
                "INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, expires_at.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
        return token

    def get_session_user(self, token: Optional[str]) -> Optional[dict]:
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT u.* FROM user_sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ?
                  AND s.expires_at > CURRENT_TIMESTAMP
                  AND u.is_active = 1
            """, (token_hash,)).fetchone()
        return self._public_user(row)

    def delete_session(self, token: Optional[str]) -> None:
        if not token:
            return
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._get_connection() as conn:
            conn.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))
            conn.commit()

    def set_active(self, user_id: int, is_active: bool) -> Optional[dict]:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if is_active else 0, user_id),
            )
            if not is_active:
                conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
            conn.commit()
        return self.get_user(user_id)

    def set_password(self, user_id: int, password: str) -> Optional[dict]:
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters")
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (hash_password(password), user_id),
            )
            conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
            conn.commit()
        return self.get_user(user_id)

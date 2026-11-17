"""交付域持久化：批次、授权、包与下载凭据。

并发约定：
- 所有写操作使用 ``BEGIN IMMEDIATE``，撤销与下载在同一把写锁上串行化。
- 撤销会同时作废该授权下的全部下载凭据，并把包标记为 REVOKED。
- 下载在返回前会再次读取授权状态，因此在制包/出包期间到达的撤销仍然生效。
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from . import core

SCHEMA = """
CREATE TABLE IF NOT EXISTS delivery_batches (
    batch_id TEXT PRIMARY KEY,
    source_name TEXT NOT NULL,
    digest TEXT NOT NULL,
    raw TEXT NOT NULL,
    parsed TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS delivery_grants (
    grant_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL,
    service TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS delivery_packages (
    package_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL,
    service TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    status TEXT NOT NULL,
    cursor INTEGER NOT NULL DEFAULT 0,
    progress TEXT NOT NULL DEFAULT '[]',
    scope TEXT NOT NULL DEFAULT '{}',
    artifact TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(batch_id, service, grant_id)
);
CREATE TABLE IF NOT EXISTS delivery_tokens (
    token_hash TEXT PRIMARY KEY,
    package_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    invalidated_at TEXT,
    download_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS delivery_downloads (
    token_hash TEXT NOT NULL,
    package_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    downloaded_at TEXT NOT NULL
);
"""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DeliveryStore:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @contextmanager
    def write(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @contextmanager
    def read(self):
        db = self.connect()
        try:
            yield db
        finally:
            db.close()

    # ---- 批次 -------------------------------------------------------------
    def import_batch(self, source_name: str, raw: str) -> dict:
        parsed = core.parse_batch(raw)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        batch_id = "batch-" + digest[:12]
        with self.write() as db:
            existing = db.execute("SELECT batch_id FROM delivery_batches WHERE batch_id=?",
                                  (batch_id,)).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO delivery_batches VALUES (?, ?, ?, ?, ?, ?)",
                    (batch_id, source_name, digest, raw,
                     json.dumps(parsed, ensure_ascii=False, sort_keys=True),
                     core.iso(core.utc_now())),
                )
        return self.batch(batch_id)

    def batch(self, batch_id: str) -> dict:
        with self.read() as db:
            row = db.execute("SELECT * FROM delivery_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            return None
        parsed = json.loads(row["parsed"])
        return {
            "batch_id": row["batch_id"],
            "source_name": row["source_name"],
            "digest": row["digest"],
            "created_at": row["created_at"],
            "input_rows": parsed["input_rows"],
            "valid_rows": parsed["valid_rows"],
            "quarantine_rows": parsed["quarantine_rows"],
            "services": core.services(parsed["rows"]),
            "quarantine": parsed["quarantine"],
        }

    def batch_raw(self, batch_id: str) -> tuple[str, dict] | None:
        with self.read() as db:
            row = db.execute("SELECT raw FROM delivery_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            return None
        return row["raw"], self.batch(batch_id)

    def batch_rows(self, batch_id: str) -> list[dict] | None:
        with self.read() as db:
            row = db.execute("SELECT parsed FROM delivery_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row["parsed"])["rows"]

    def known_services(self, batch_id: str) -> list[str] | None:
        rows = self.batch_rows(batch_id)
        return None if rows is None else core.services(rows)

    def all_batches(self) -> list[dict]:
        with self.read() as db:
            ids = [row["batch_id"] for row in db.execute(
                "SELECT batch_id FROM delivery_batches ORDER BY created_at, batch_id")]
        return [self.batch(batch_id) for batch_id in ids]

    # ---- 授权 -------------------------------------------------------------
    def create_grant(self, batch_id: str, service: str, expires_at: str) -> dict:
        grant_id = "grant-" + secrets.token_hex(8)
        with self.write() as db:
            db.execute(
                "INSERT INTO delivery_grants VALUES (?, ?, ?, 'active', ?, ?, NULL)",
                (grant_id, batch_id, service, core.iso(core.utc_now()), expires_at),
            )
        return self.grant(grant_id)

    def grant(self, grant_id: str, db: sqlite3.Connection | None = None) -> dict | None:
        if db is not None:
            row = db.execute("SELECT * FROM delivery_grants WHERE grant_id=?", (grant_id,)).fetchone()
        else:
            with self.read() as conn:
                row = conn.execute("SELECT * FROM delivery_grants WHERE grant_id=?",
                                   (grant_id,)).fetchone()
        return None if row is None else self._grant_row(row)

    @staticmethod
    def _grant_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        now = core.utc_now()
        expires = core.parse_dt(item["expires_at"])
        if item["status"] == "revoked":
            state = "revoked"
        elif expires is not None and expires <= now:
            state = "expired"
        else:
            state = "active"
        item["state"] = state
        item["active"] = state == "active"
        item["scope"] = {"batch_id": item["batch_id"], "service": item["service"]}
        return item

    def grants(self, batch_id: str | None = None, service: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM delivery_grants", []
        clauses = []
        if batch_id:
            clauses.append("batch_id=?")
            params.append(batch_id)
        if service:
            clauses.append("service=?")
            params.append(service)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at, grant_id"
        with self.read() as db:
            rows = db.execute(sql, params).fetchall()
        return [self._grant_row(row) for row in rows]

    def revoke_grant(self, grant_id: str) -> dict | None:
        now = core.iso(core.utc_now())
        with self.write() as db:
            row = db.execute("SELECT * FROM delivery_grants WHERE grant_id=?", (grant_id,)).fetchone()
            if row is None:
                return None
            if row["status"] != "revoked":
                db.execute("UPDATE delivery_grants SET status='revoked', revoked_at=? WHERE grant_id=?",
                           (now, grant_id))
                db.execute("UPDATE delivery_packages SET status='revoked', updated_at=? WHERE grant_id=?",
                           (now, grant_id))
                db.execute("UPDATE delivery_tokens SET invalidated_at=? WHERE grant_id=? AND invalidated_at IS NULL",
                           (now, grant_id))
            row = db.execute("SELECT * FROM delivery_grants WHERE grant_id=?", (grant_id,)).fetchone()
        return self._grant_row(row)

    # ---- 包 ---------------------------------------------------------------
    def package(self, package_id: str) -> dict | None:
        with self.read() as db:
            row = db.execute("SELECT * FROM delivery_packages WHERE package_id=?",
                             (package_id,)).fetchone()
        return None if row is None else self._package_row(row)

    def package_for(self, batch_id: str, service: str, grant_id: str) -> dict | None:
        with self.read() as db:
            row = db.execute(
                "SELECT * FROM delivery_packages WHERE batch_id=? AND service=? AND grant_id=?",
                (batch_id, service, grant_id)).fetchone()
        return None if row is None else self._package_row(row)

    @staticmethod
    def _package_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["progress"] = json.loads(item["progress"] or "[]")
        item["scope"] = json.loads(item["scope"] or "{}")
        if item["status"] == "revoked":
            item["state"] = "revoked"
        elif item["status"] == "ready":
            item["state"] = "claimable"
        else:
            item["state"] = "pending"
        return item

    def packages(self, batch_id: str | None = None, service: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM delivery_packages", []
        clauses = []
        if batch_id:
            clauses.append("batch_id=?")
            params.append(batch_id)
        if service:
            clauses.append("service=?")
            params.append(service)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at, package_id"
        with self.read() as db:
            rows = db.execute(sql, params).fetchall()
        return [self._package_row(row) for row in rows]

    def claim_or_create_package(self, batch_id: str, service: str, grant_id: str) -> tuple[dict, bool]:
        """幂等入口：同一 (batch, service, grant) 永远复用同一个包。

        返回 (package, created)。制包过程在锁外分块进行，进度逐块提交，故中断后可续。
        """
        package_id = "pkg-" + hashlib.sha256(
            f"{batch_id}\x1f{service}\x1f{grant_id}".encode("utf-8")).hexdigest()[:12]
        now = core.iso(core.utc_now())
        with self.write() as db:
            row = db.execute(
                "SELECT * FROM delivery_packages WHERE batch_id=? AND service=? AND grant_id=?",
                (batch_id, service, grant_id)).fetchone()
            if row is not None:
                return self._package_row(row), False
            db.execute(
                "INSERT INTO delivery_packages (package_id, batch_id, service, grant_id, status,"
                " cursor, progress, scope, artifact, attempt, error, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 'pending', 0, '[]', '{}', NULL, 0, NULL, ?, ?)",
                (package_id, batch_id, service, grant_id, now, now),
            )
            row = db.execute("SELECT * FROM delivery_packages WHERE package_id=?",
                             (package_id,)).fetchone()
        return self._package_row(row), True

    def save_progress(self, package_id: str, cursor: int, progress: list[dict],
                      attempt: int, error: str | None = None) -> None:
        with self.write() as db:
            db.execute(
                "UPDATE delivery_packages SET cursor=?, progress=?, attempt=?, error=?, updated_at=?"
                " WHERE package_id=? AND status='pending'",
                (cursor, json.dumps(progress, ensure_ascii=False, sort_keys=True),
                 attempt, error, core.iso(core.utc_now()), package_id),
            )

    def finish_package(self, package_id: str, progress: list[dict], artifact: str,
                       scope: dict, attempt: int) -> dict | None:
        now = core.iso(core.utc_now())
        with self.write() as db:
            db.execute(
                "UPDATE delivery_packages SET status='ready', cursor=?, progress=?, artifact=?,"
                " scope=?, attempt=?, error=NULL, updated_at=? WHERE package_id=? AND status='pending'",
                (len(progress), json.dumps(progress, ensure_ascii=False, sort_keys=True),
                 artifact, json.dumps(scope, ensure_ascii=False, sort_keys=True), attempt, now,
                 package_id),
            )
            row = db.execute("SELECT * FROM delivery_packages WHERE package_id=?",
                             (package_id,)).fetchone()
        return None if row is None else self._package_row(row)

    # ---- 下载凭据 ---------------------------------------------------------
    def issue_token(self, package_id: str, grant_id: str, ttl_seconds: int,
                    grant_expires_at: str) -> tuple[str, dict]:
        token = secrets.token_urlsafe(24)
        now = core.utc_now()
        grant_expires = core.parse_dt(grant_expires_at)
        expires = now.replace(microsecond=0) + timedelta(seconds=ttl_seconds)
        if grant_expires is not None and grant_expires < expires:
            expires = grant_expires
        record = {
            "token_hash": token_hash(token),
            "package_id": package_id,
            "grant_id": grant_id,
            "issued_at": core.iso(now),
            "expires_at": core.iso(expires),
        }
        with self.write() as db:
            db.execute(
                "INSERT INTO delivery_tokens (token_hash, package_id, grant_id, issued_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (record["token_hash"], package_id, grant_id, record["issued_at"], record["expires_at"]),
            )
        return token, record

    def authorize_download(self, token: str) -> dict:
        """下载前的最终裁决，与撤销共用同一把写锁。

        撤销先提交：此处读到 revoked/invalidated 并拒绝。
        下载先提交：随后撤销会作废凭据，但本次下载已成立。
        """
        from app.errors import DomainError

        with self.write() as db:
            record = db.execute("SELECT * FROM delivery_tokens WHERE token_hash=?",
                                (token_hash(token),)).fetchone()
            if record is None:
                raise DomainError("TOKEN_INVALID", "下载凭据无效", 403)
            if record["invalidated_at"] is not None:
                raise DomainError("TOKEN_REVOKED", "下载凭据已随授权撤销失效", 403)
            expires = core.parse_dt(record["expires_at"])
            if expires is not None and expires <= core.utc_now():
                raise DomainError("TOKEN_EXPIRED", "下载凭据已过期", 403)
            package = db.execute("SELECT * FROM delivery_packages WHERE package_id=?",
                                 (record["package_id"],)).fetchone()
            if package is None:
                raise DomainError("PACKAGE_NOT_FOUND", "包不存在", 404)
            grant = db.execute("SELECT * FROM delivery_grants WHERE grant_id=?",
                               (record["grant_id"],)).fetchone()
            if grant is None:
                raise DomainError("GRANT_NOT_FOUND", "授权不存在", 404)
            state = self._grant_row(grant)["state"]
            if state == "revoked":
                raise DomainError("GRANT_REVOKED", "授权已撤销", 403)
            if state == "expired":
                raise DomainError("GRANT_EXPIRED", "授权已过期", 403)
            if package["status"] == "revoked":
                raise DomainError("PACKAGE_REVOKED", "包已随授权撤销", 403)
            if package["status"] != "ready":
                raise DomainError("PACKAGE_NOT_READY", "包尚未生成完成", 409)
            now = core.iso(core.utc_now())
            db.execute("INSERT INTO delivery_downloads VALUES (?, ?, ?, ?)",
                       (token_hash(token), package["package_id"], grant["grant_id"], now))
            db.execute("UPDATE delivery_tokens SET download_count=download_count+1"
                       " WHERE token_hash=?", (token_hash(token),))
            return {
                "package": self._package_row(package),
                "grant": self._grant_row(grant),
            }

    def still_valid(self, token: str, package_id: str, grant_id: str) -> bool:
        """出包前的收尾复核；撤销若已提交则拒绝返回字节。"""
        with self.read() as db:
            record = db.execute("SELECT invalidated_at FROM delivery_tokens WHERE token_hash=?",
                                (token_hash(token),)).fetchone()
            grant = db.execute("SELECT * FROM delivery_grants WHERE grant_id=?",
                               (grant_id,)).fetchone()
            package = db.execute("SELECT status FROM delivery_packages WHERE package_id=?",
                                 (package_id,)).fetchone()
        if record is None or record["invalidated_at"] is not None:
            return False
        if grant is None or self._grant_row(grant)["state"] != "active":
            return False
        return package is not None and package["status"] == "ready"

    def delivery_scope(self, grant_id: str) -> dict | None:
        grant = self.grant(grant_id)
        if grant is None:
            return None
        packages = [pkg for pkg in self.packages() if pkg["grant_id"] == grant_id]
        return {
            "grant_id": grant_id,
            "grant_state": grant["state"],
            "batch_id": grant["batch_id"],
            "service": grant["service"],
            "expires_at": grant["expires_at"],
            "revoked_at": grant["revoked_at"],
            "packages": [
                {
                    "package_id": pkg["package_id"],
                    "state": pkg["state"],
                    "scope": pkg["scope"],
                }
                for pkg in packages
            ],
        }

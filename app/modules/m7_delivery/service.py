"""按服务授权的批次交付。

- 原件仅审计权限可读；受限副本只含授权服务。
- 撤销优先：下载在写事务内做最后一次授权核验，撤销并发时下载被拒。
- 制包分块提交进度，中断后续跑；同一 (batch, service, grant) 只建一个包。
"""
from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path

from app.errors import DomainError

from . import core
from .store import DeliveryStore

CHUNK_SIZE = 25
_SAMPLE_DIR = Path(__file__).resolve().parents[3] / "sample_data"

_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}


def _package_lock(package_id: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(package_id, threading.Lock())


class DeliveryService:
    def __init__(self, store: DeliveryStore, settings=None):
        self.store = store
        self.settings = settings
        if self.settings is None:
            from app.config import Settings
            self.settings = Settings.from_env()

    # ---- 批次导入（实际日志）---------------------------------------------
    def import_batch(self, source_name: str | None, content: str | None) -> dict:
        if content is None:
            content = self._read_sample(source_name)
        if not content.strip():
            raise DomainError("EMPTY_BATCH", "批次内容为空")
        batch = self.store.import_batch(source_name or "inline", content)
        return self._batch_view(batch)

    @staticmethod
    def _read_sample(source_name: str | None) -> str:
        if not source_name:
            raise DomainError("EMPTY_BATCH", "缺少批次内容")
        name = Path(str(source_name)).name
        candidate = (_SAMPLE_DIR / name).resolve()
        if candidate.parent != _SAMPLE_DIR.resolve() or not candidate.is_file():
            raise DomainError("SAMPLE_NOT_FOUND", "样例日志不存在")
        return candidate.read_text(encoding="utf-8")

    @staticmethod
    def _batch_view(batch: dict) -> dict:
        return {
            "batch_id": batch["batch_id"],
            "source_name": batch["source_name"],
            "digest": batch["digest"],
            "created_at": batch["created_at"],
            "input_rows": batch["input_rows"],
            "valid_rows": batch["valid_rows"],
            "quarantine_rows": batch["quarantine_rows"],
            "services": batch["services"],
            "quarantine": batch["quarantine"],
        }

    def batch(self, batch_id: str) -> dict:
        batch = self.store.batch(batch_id)
        if batch is None:
            raise DomainError("BATCH_NOT_FOUND", "批次不存在", 404)
        return self._batch_view(batch)

    def batches(self) -> dict:
        return {"batches": [self._batch_view(item) for item in self.store.all_batches()]}

    def original(self, batch_id: str) -> tuple[str, dict]:
        """独立审计权限读取原件；保留原始字节，供逐行核对。"""
        value = self.store.batch_raw(batch_id)
        if value is None:
            raise DomainError("BATCH_NOT_FOUND", "批次不存在", 404)
        raw, batch = value
        manifest = {
            "batch_id": batch_id,
            "digest": batch["digest"],
            "input_rows": batch["input_rows"],
            "valid_rows": batch["valid_rows"],
            "quarantine_rows": batch["quarantine_rows"],
            "services": batch["services"],
        }
        return raw, manifest

    # ---- 授权 ------------------------------------------------------------
    def create_grant(self, batch_id: str, service: str | None,
                     expires_at: str | None, ttl_seconds: int | None) -> dict:
        known = self.store.known_services(batch_id)
        if known is None:
            raise DomainError("BATCH_NOT_FOUND", "批次不存在", 404)
        if not service:
            raise DomainError("SERVICE_REQUIRED", "必须指定服务")
        if service not in known:
            raise DomainError("SERVICE_NOT_IN_BATCH", "批次中不包含该服务")
        if expires_at:
            try:
                expires = core.parse_dt(expires_at)
            except ValueError as exc:
                raise DomainError("INVALID_EXPIRY", "授权到期时间无法解析") from exc
        else:
            seconds = 3600 if ttl_seconds is None else int(ttl_seconds)
            expires = core.utc_now() + timedelta(seconds=seconds)
        grant = self.store.create_grant(batch_id, service, core.iso(expires))
        return self._grant_view(grant)

    def _grant_view(self, grant: dict) -> dict:
        return {
            "grant_id": grant["grant_id"],
            "batch_id": grant["batch_id"],
            "service": grant["service"],
            "state": grant["state"],
            "created_at": grant["created_at"],
            "expires_at": grant["expires_at"],
            "revoked_at": grant["revoked_at"],
            "scope": grant["scope"],
        }

    def grant(self, grant_id: str) -> dict:
        grant = self.store.grant(grant_id)
        if grant is None:
            raise DomainError("GRANT_NOT_FOUND", "授权不存在", 404)
        return self._grant_view(grant)

    def grants(self, batch_id: str | None, service: str | None) -> dict:
        return {"grants": [self._grant_view(item)
                           for item in self.store.grants(batch_id, service)]}

    def revoke(self, grant_id: str) -> dict:
        grant = self.store.revoke_grant(grant_id)
        if grant is None:
            raise DomainError("GRANT_NOT_FOUND", "授权不存在", 404)
        view = self._grant_view(grant)
        view["invalidated_tokens"] = True
        return view

    # ---- 制包 ------------------------------------------------------------
    def build_package(self, grant_id: str, interrupt_at: int | None = None,
                      chunk_size: int = CHUNK_SIZE) -> dict:
        grant = self.store.grant(grant_id)
        if grant is None:
            raise DomainError("GRANT_NOT_FOUND", "授权不存在", 404)
        self._require_active(grant)
        rows = self.store.batch_rows(grant["batch_id"])
        if rows is None:
            raise DomainError("BATCH_NOT_FOUND", "批次不存在", 404)
        buckets = core.bucket_rows(rows, grant["service"])
        return self._materialize(grant, buckets, interrupt_at, chunk_size)

    def _materialize(self, grant: dict, buckets: list[dict], interrupt_at: int | None,
                     chunk_size: int) -> dict:
        package, _ = self.store.claim_or_create_package(
            grant["batch_id"], grant["service"], grant["grant_id"])
        if package["state"] == "revoked":
            raise DomainError("PACKAGE_REVOKED", "授权已撤销，包不可再生成", 403)
        with _package_lock(package["package_id"]):
            package = self.store.package(package["package_id"])
            if package["state"] == "revoked":
                raise DomainError("PACKAGE_REVOKED", "授权已撤销，包不可再生成", 403)
            if package["status"] == "ready":
                return self._package_view(package)

            progress = list(package["progress"])
            cursor = int(package["cursor"])
            attempt = int(package["attempt"]) + 1
            chunk = max(1, int(chunk_size))
            while cursor < len(buckets):
                grant_now = self.store.grant(grant["grant_id"])
                if grant_now is None or grant_now["state"] != "active":
                    raise DomainError("GRANT_REVOKED" if grant_now and grant_now["state"] == "revoked"
                                      else "GRANT_EXPIRED",
                                      "授权已失效，停止制包", 403)
                end = min(cursor + chunk, len(buckets))
                progress.extend(buckets[cursor:end])
                cursor = end
                self.store.save_progress(package["package_id"], cursor, progress, attempt)
                if interrupt_at is not None and cursor >= int(interrupt_at):
                    raise DomainError("PACKAGE_INTERRUPTED", "制包中断，可重试续跑", 503)

            artifact = core.csv_text(progress)
            scope = self._scope_for(grant, progress)
            finished = self.store.finish_package(package["package_id"], progress, artifact,
                                                scope, attempt)
            if finished is None:
                raise DomainError("PACKAGE_NOT_FOUND", "包不存在", 404)
            if finished["state"] == "revoked":
                # 撤销在最后一刻先提交：包按撤销落地，不向制包方返回可领取状态。
                raise DomainError("PACKAGE_REVOKED", "授权已撤销，包不可生成", 403)
            return self._package_view(finished)

    def _scope_for(self, grant: dict, progress: list[dict]) -> dict:
        batch = self.store.batch(grant["batch_id"]) or {}
        batch_rows = self.store.batch_rows(grant["batch_id"]) or []
        included = core.totals(progress)
        # 授权服务的全部有效行都应恰好出现一次，且不含其他服务。
        expected = sum(1 for row in batch_rows if row["service"] == grant["service"])
        all_restricted = all(item["service"] == grant["service"] for item in progress)
        return {
            "delivery": "restricted",
            "batch_id": grant["batch_id"],
            "service": grant["service"],
            "batch_input_rows": batch.get("input_rows", 0),
            "batch_valid_rows": batch.get("valid_rows", 0),
            "batch_quarantine_rows": batch.get("quarantine_rows", 0),
            "batch_service_count": len(batch.get("services", [])),
            **included,
            "service_expected_rows": expected,
            "counts_match": (
                all_restricted
                and included["included_rows"] == included["source_line_count"] == expected
                and included["included_rows"] <= batch.get("valid_rows", 0)
            ),
            "rules": {"timezone": "UTC", "interval": "[start,end)", "dedupe": "unchanged"},
        }

    def _package_view(self, package: dict, grant_state: str | None = None) -> dict:
        state = package["state"]
        if state == "claimable" and grant_state in ("revoked", "expired"):
            # 授权已失效但包尚未被撤销写入时，仍按不可领取回读。
            state = grant_state
        return {
            "package_id": package["package_id"],
            "batch_id": package["batch_id"],
            "service": package["service"],
            "grant_id": package["grant_id"],
            "state": state,
            "status": package["status"],
            "grant_state": grant_state,
            "attempt": package["attempt"],
            "cursor": package["cursor"],
            "total_buckets": len(package["progress"]),
            "scope": package["scope"],
            "error": package["error"],
            "created_at": package["created_at"],
            "updated_at": package["updated_at"],
        }

    def package(self, package_id: str) -> dict:
        package = self.store.package(package_id)
        if package is None:
            raise DomainError("PACKAGE_NOT_FOUND", "包不存在", 404)
        return self._package_view(package)

    def packages(self, batch_id: str | None, service: str | None) -> dict:
        return {"packages": [self._package_view(item)
                             for item in self.store.packages(batch_id, service)]}

    # ---- 领取与下载 -------------------------------------------------------
    def claim(self, package_id: str, ttl_seconds: int | None = None) -> dict:
        package = self.store.package(package_id)
        if package is None:
            raise DomainError("PACKAGE_NOT_FOUND", "包不存在", 404)
        if package["state"] == "revoked":
            raise DomainError("PACKAGE_REVOKED", "授权已撤销，包不可领取", 403)
        if package["state"] == "pending":
            raise DomainError("PACKAGE_NOT_READY", "包尚未生成完成", 409)
        grant = self.store.grant(package["grant_id"])
        if grant is None:
            raise DomainError("GRANT_NOT_FOUND", "授权不存在", 404)
        self._require_active(grant)
        ttl = self.settings.token_ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        token, record = self.store.issue_token(package["package_id"], grant["grant_id"],
                                              ttl, grant["expires_at"])
        return {
            "package_id": package_id,
            "grant_id": grant["grant_id"],
            "service": package["service"],
            "token": token,
            "expires_at": record["expires_at"],
            "download_url": f"/api/delivery/downloads/{token}",
            "scope": package["scope"],
        }

    def download(self, token: str) -> dict:
        # 最终授权核验与下载记账在同一写事务内完成，撤销与下载并发时以撤销为准：
        # 撤销先提交 -> 此处读到 revoked 并拒绝；下载先提交 -> 撤销随后作废旧凭据。
        verdict = self.store.authorize_download(token)
        package, grant = verdict["package"], verdict["grant"]
        if not self.store.still_valid(token, package["package_id"], grant["grant_id"]):
            raise DomainError("TOKEN_REVOKED", "下载凭据已随授权撤销失效", 403)
        return {
            "package_id": package["package_id"],
            "grant_id": grant["grant_id"],
            "service": grant["service"],
            "csv": package["artifact"],
            "scope": package["scope"],
        }

    # ---- 回读 ------------------------------------------------------------
    def readback(self, batch_id: str | None = None, grant_id: str | None = None) -> dict:
        if grant_id is not None:
            scope = self.store.delivery_scope(grant_id)
            if scope is None:
                raise DomainError("GRANT_NOT_FOUND", "授权不存在", 404)
            return {"grant": scope}
        grants = [self._grant_view(item) for item in self.store.grants(batch_id)]
        states = {item["grant_id"]: item["state"] for item in grants}
        packages = [self._package_view(item, states.get(item["grant_id"]))
                    for item in self.store.packages(batch_id)]
        return {
            "pending": [item for item in packages if item["state"] == "pending"],
            "claimable": [item for item in packages if item["state"] == "claimable"],
            "revoked": [item for item in packages if item["state"] == "revoked"],
            "expired": [item for item in packages if item["state"] == "expired"],
            "grants": grants,
            "scope": [self.store.delivery_scope(item["grant_id"]) for item in grants],
        }

    # ---- 辅助 ------------------------------------------------------------
    @staticmethod
    def _require_active(grant: dict) -> None:
        if grant["state"] == "revoked":
            raise DomainError("GRANT_REVOKED", "授权已撤销", 403)
        if grant["state"] == "expired":
            raise DomainError("GRANT_EXPIRED", "授权已过期", 403)

    @staticmethod
    def verify_restricted_copy(csv_text: str, service: str, scope: dict) -> bool:
        """受限副本自检：只含授权服务，且计数/摘要与交付范围一致。"""
        import csv as _csv
        import io as _io
        rows = list(_csv.DictReader(_io.StringIO(csv_text)))
        if any(row["service"] != service for row in rows):
            return False
        if core.artifact_digest([{key: _coerce(key, row[key]) for key in core.CSV_FIELDS}
                                 for row in rows]) != scope.get("artifact_digest"):
            return False
        included = sum(int(row["count"]) for row in rows)
        lines = sum(int(row["source_lines"]) for row in rows)
        return included == lines == scope.get("included_rows")

    def reconcile(self, grant_id: str) -> dict:
        """按授权服务的原行独立重算，与已交付包的范围逐桶比对。"""
        grant = self.store.grant(grant_id)
        if grant is None:
            raise DomainError("GRANT_NOT_FOUND", "授权不存在", 404)
        rows = self.store.batch_rows(grant["batch_id"])
        if rows is None:
            raise DomainError("BATCH_NOT_FOUND", "批次不存在", 404)
        expected = core.bucket_rows(rows, grant["service"])
        package = self.store.package_for(grant["batch_id"], grant["service"], grant_id)
        delivered = package["progress"] if package and package["status"] == "ready" else None
        return {
            "grant_id": grant_id,
            "batch_id": grant["batch_id"],
            "service": grant["service"],
            "grant_state": grant["state"],
            "expected": core.totals(expected),
            "delivered": None if delivered is None else core.totals(delivered),
            "matches": delivered is not None and core.artifact_digest(delivered) == core.artifact_digest(expected),
            "rules": {"timezone": "UTC", "interval": "[start,end)", "dedupe": "unchanged"},
        }


def _coerce(key: str, value: str):
    return int(value) if key in {"count", "errors", "source_lines"} else value

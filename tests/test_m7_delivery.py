import csv
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

ADMIN = {"x-admin-key": "dev-admin"}
AUDIT = {"x-audit-key": "dev-audit"}

CLEAN = (
    '{"request_id":"r1","timestamp":"2026-11-15T01:05:00Z","service":"pay","status":200}\\n'
    '{"request_id":"r2","timestamp":"2026-11-15T02:05:00Z","service":"pay","status":500}\\n'
    '{"request_id":"s1","timestamp":"2026-11-15T03:05:00Z","service":"search","status":200}\\n'
    '{"request_id":"s2","timestamp":"2026-11-15T03:59:59Z","service":"search","status":200}\\n'
)
DIRTY = (
    '{"request_id":"9007199254740993","timestamp":"2026-11-15T01:05:00Z","service":"pay","status":200}\\n'
    '{"request_id":"r2","timestamp":"2026-11-15T09:10:00+08:00","service":"pay","status":500}\\n'
    '{"request_id":"r3"'
)


def _batch(client, content=CLEAN, name="inline"):
    response = client.post("/api/delivery/batches",
                           json={"source_name": name, "content": content}, headers=ADMIN)
    assert response.status_code == 200, response.text
    return response.json()


def _grant(client, batch_id, service, **extra):
    response = client.post("/api/delivery/grants",
                           json={"batch_id": batch_id, "service": service, **extra},
                           headers=ADMIN)
    assert response.status_code == 200, response.text
    return response.json()


def _package(client, grant_id, **extra):
    response = client.post(f"/api/delivery/grants/{grant_id}/packages",
                           json=extra, headers=ADMIN)
    assert response.status_code == 200, response.text
    return response.json()


def _claim(client, package_id, **extra):
    response = client.post(f"/api/delivery/packages/{package_id}/claim",
                           json=extra, headers=ADMIN)
    assert response.status_code == 200, response.text
    return response.json()


# ---- 实际日志接入与原件 -------------------------------------------------
def test_import_actual_batch_counts_and_lines(client):
    batch = _batch(client, DIRTY)
    assert batch["input_rows"] == 3
    assert batch["valid_rows"] == 2
    assert batch["quarantine_rows"] == 1
    assert batch["quarantine"][0]["reason"] == "TRUNCATED"
    assert batch["quarantine"][0]["source_line"] == 3
    assert batch["services"] == ["pay"]
    assert batch["input_rows"] == batch["valid_rows"] + batch["quarantine_rows"]


def test_literal_backslash_newlines_keep_line_numbers(client):
    batch = _batch(client, CLEAN)
    assert batch["input_rows"] == 4
    assert batch["services"] == ["pay", "search"]


def test_import_sample_file(client):
    response = client.post("/api/delivery/batches",
                           json={"source_name": "events_dirty.jsonl"}, headers=ADMIN)
    assert response.status_code == 200
    assert response.json()["valid_rows"] == 2


def test_import_rejects_path_traversal(client):
    response = client.post("/api/delivery/batches",
                           json={"source_name": "../Dockerfile"}, headers=ADMIN)
    assert response.status_code == 422
    assert response.json()["error"] == "SAMPLE_NOT_FOUND"


def test_original_requires_independent_audit_key(client):
    batch = _batch(client, DIRTY)
    assert client.get(f"/api/audit/batches/{batch['batch_id']}/original").status_code == 403
    assert client.get(f"/api/audit/batches/{batch['batch_id']}/original",
                      headers=ADMIN).status_code == 403
    response = client.get(f"/api/audit/batches/{batch['batch_id']}/original", headers=AUDIT)
    assert response.status_code == 200
    assert response.text == DIRTY
    assert int(response.headers["X-Batch-Input-Rows"]) == 3


def test_original_missing(client):
    assert client.get("/api/audit/batches/batch-nope/original", headers=AUDIT).status_code == 404


# ---- 授权与受限副本 -----------------------------------------------------
def test_restricted_copy_only_authorized_service(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "search")
    package = _package(client, grant["grant_id"])
    rows = list(csv.DictReader(io.StringIO(package_artifact(client, package, grant))))
    assert {row["service"] for row in rows} == {"search"}
    assert sum(int(row["count"]) for row in rows) == 2
    assert sum(int(row["source_lines"]) for row in rows) == 2
    assert package["scope"]["counts_match"] is True
    assert package["scope"]["included_rows"] == package["scope"]["service_expected_rows"] == 2
    assert package["scope"]["batch_input_rows"] == 4
    assert package["scope"]["batch_service_count"] == 2


def package_artifact(client, package, grant):
    claim = _claim(client, package["package_id"])
    response = client.get(f"/api/delivery/downloads/{claim['token']}")
    assert response.status_code == 200, response.text
    return response.text


def test_download_headers_support_audit_reconciliation(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "search")
    package = _package(client, grant["grant_id"])
    token = _claim(client, package["package_id"])["token"]
    response = client.get(f"/api/delivery/downloads/{token}")
    assert response.headers["X-Service"] == "search"
    assert int(response.headers["X-Included-Rows"]) == 2
    assert response.headers["X-Counts-Match"] == "true"
    assert len(response.headers["X-Artifact-Digest"]) == 64
    assert response.headers["X-Artifact-Digest"] == package["scope"]["artifact_digest"]
    # 同一凭据也能通过请求头下载，凭据不出现在 URL 中
    again = client.get("/api/delivery/download", headers={"x-delivery-token": token})
    assert again.status_code == 200
    assert again.text == response.text


def test_line_digest_lets_audit_reconcile_with_original(client):
    batch = _batch(client, DIRTY)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    rows = list(csv.DictReader(io.StringIO(package_artifact(client, package, grant))))
    original = client.get(
        f"/api/audit/batches/{batch['batch_id']}/original", headers=AUDIT).text
    imported = client.get(f"/api/delivery/batches/{batch['batch_id']}", headers=ADMIN).json()
    assert imported["input_rows"] == len(original.split("\\n")) == 3
    assert rows[0]["source_lines"] == "2"
    assert rows[0]["count"] == rows[0]["source_lines"]
    assert len(rows[0]["line_digest"]) == 16


def test_restricted_copy_wider_than_authorization_is_detectable(client):
    from app.modules.m7_delivery.service import DeliveryService
    scope = {"included_rows": 1, "artifact_digest": "0" * 64}
    assert DeliveryService.verify_restricted_copy(
        "hour,service,count,errors,source_lines,line_digest\n"
        "2026-11-15T01:00:00Z,search,1,0,1,abc\n", "search", scope) is False


def test_pay_restricted_copy_hour_buckets(client):
    batch = _batch(client, DIRTY)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    text = package_artifact(client, package, grant)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 1
    assert rows[0]["hour"] == "2026-11-15T01:00:00Z"
    assert rows[0]["count"] == "2" and rows[0]["errors"] == "1"


def test_grant_unknown_service_rejected(client):
    batch = _batch(client)
    response = client.post("/api/delivery/grants",
                           json={"batch_id": batch["batch_id"], "service": "nope"},
                           headers=ADMIN)
    assert response.status_code == 422
    assert response.json()["error"] == "SERVICE_NOT_IN_BATCH"


def test_grant_requires_admin(client):
    batch = _batch(client)
    response = client.post("/api/delivery/grants",
                           json={"batch_id": batch["batch_id"], "service": "pay"})
    assert response.status_code == 403
    response = client.post("/api/delivery/grants",
                           json={"batch_id": batch["batch_id"], "service": "pay"},
                           headers=AUDIT)
    assert response.status_code == 403


def test_existing_export_is_controlled(client):
    assert client.get("/api/export/buckets.csv").status_code == 403
    assert client.get("/api/export/buckets.csv", headers=ADMIN).status_code == 403
    response = client.get("/api/export/buckets.csv", headers=AUDIT)
    assert response.status_code == 200
    assert response.text.startswith("hour,service,count,errors")


# ---- 撤销、过期与并发 ---------------------------------------------------
def test_revoke_invalidates_old_token(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    token = _claim(client, package["package_id"])["token"]
    assert client.get(f"/api/delivery/downloads/{token}").status_code == 200

    revoked = client.post(f"/api/delivery/grants/{grant['grant_id']}/revoke", headers=ADMIN)
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoked"

    response = client.get(f"/api/delivery/downloads/{token}")
    assert response.status_code == 403
    assert response.json()["error"] == "TOKEN_REVOKED"
    assert client.post(f"/api/delivery/packages/{package['package_id']}/claim",
                       headers=ADMIN).status_code == 403
    assert client.post(f"/api/delivery/grants/{grant['grant_id']}/packages",
                       json={}, headers=ADMIN).status_code == 403


def test_revoke_is_idempotent_and_marks_package(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    first = client.post(f"/api/delivery/grants/{grant['grant_id']}/revoke", headers=ADMIN)
    second = client.post(f"/api/delivery/grants/{grant['grant_id']}/revoke", headers=ADMIN)
    assert first.status_code == second.status_code == 200
    assert first.json()["revoked_at"] == second.json()["revoked_at"]
    readback = client.get("/api/delivery/readback", headers=ADMIN).json()
    assert [item["package_id"] for item in readback["revoked"]] == [package["package_id"]]


def test_expired_grant_rejected(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay", expires_at="2020-01-01T00:00:00Z")
    assert grant["state"] == "expired"
    assert client.post(f"/api/delivery/grants/{grant['grant_id']}/packages",
                       json={}, headers=ADMIN).status_code == 403


def test_expired_token_rejected(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    token = _claim(client, package["package_id"], ttl_seconds=-5)["token"]
    response = client.get(f"/api/delivery/downloads/{token}")
    assert response.status_code == 403
    assert response.json()["error"] == "TOKEN_EXPIRED"


def test_token_cannot_exceed_grant_expiry(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay", expires_at="2030-01-01T00:00:00Z")
    package = _package(client, grant["grant_id"])
    claim = _claim(client, package["package_id"], ttl_seconds=10**9)
    assert claim["expires_at"] <= "2030-01-01T00:00:00Z"


def test_concurrent_revoke_wins_over_download(client):
    """并发时先完成撤销的一侧为准：撤销返回后，旧凭据一律下载失败。"""
    batch = _batch(client, DIRTY)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    token = _claim(client, package["package_id"])["token"]
    barrier = threading.Barrier(2)

    def revoke():
        barrier.wait()
        return client.post(f"/api/delivery/grants/{grant['grant_id']}/revoke", headers=ADMIN).status_code

    def download():
        barrier.wait()
        return client.get(f"/api/delivery/downloads/{token}").status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        revoke_future = pool.submit(revoke)
        download_future = pool.submit(download)
    assert revoke_future.result() == 200
    assert download_future.result() in (200, 403)
    # 无论下载是否抢在撤销之前，撤销生效后凭据必须失效。
    assert client.get(f"/api/delivery/downloads/{token}").status_code == 403


def test_download_after_revoke_never_succeeds(client):
    batch = _batch(client)
    for _ in range(5):
        grant = _grant(client, batch["batch_id"], "pay")
        package = _package(client, grant["grant_id"])
        token = _claim(client, package["package_id"])["token"]
        client.post(f"/api/delivery/grants/{grant['grant_id']}/revoke", headers=ADMIN)
        assert client.get(f"/api/delivery/downloads/{token}").status_code == 403


# ---- 中断恢复与幂等 -----------------------------------------------------
def test_interrupt_then_resume(client):
    content = "".join(
        json.dumps({"request_id": f"r{i}", "service": "pay",
                    "timestamp": f"2026-11-15T{i:02d}:05:00Z", "status": 200}) + "\\n"
        for i in range(10))
    batch = _batch(client, content)
    grant = _grant(client, batch["batch_id"], "pay")
    response = client.post(f"/api/delivery/grants/{grant['grant_id']}/packages",
                           json={"chunk_size": 3, "interrupt_at": 3}, headers=ADMIN)
    assert response.status_code == 503
    assert response.json()["error"] == "PACKAGE_INTERRUPTED"

    readback = client.get("/api/delivery/readback", headers=ADMIN).json()
    assert len(readback["pending"]) == 1
    package_id = readback["pending"][0]["package_id"]
    assert readback["pending"][0]["cursor"] == 3
    # 未完成前不可领取
    assert client.post(f"/api/delivery/packages/{package_id}/claim",
                       headers=ADMIN).status_code == 409

    resumed = _package(client, grant["grant_id"], chunk_size=3)
    assert resumed["package_id"] == package_id
    assert resumed["state"] == "claimable"
    assert resumed["cursor"] == resumed["total_buckets"] == 10
    assert resumed["attempt"] == 2

    text = package_artifact(client, resumed, grant)
    assert sum(int(row["count"]) for row in csv.DictReader(io.StringIO(text))) == 10


def test_retry_does_not_duplicate_package(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay")
    first = _package(client, grant["grant_id"])
    second = _package(client, grant["grant_id"])
    assert first["package_id"] == second["package_id"]
    assert len(client.get("/api/delivery/packages", headers=ADMIN).json()["packages"]) == 1


def test_concurrent_build_creates_one_package(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay")

    def build():
        return client.post(f"/api/delivery/grants/{grant['grant_id']}/packages",
                           json={}, headers=ADMIN).json()["package_id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(lambda _: build(), range(4)))
    assert len(set(ids)) == 1


def test_build_unknown_grant(client):
    assert client.post("/api/delivery/grants/grant-nope/packages", json={},
                       headers=ADMIN).status_code == 404


# ---- 回读 --------------------------------------------------------------
def test_readback_states_and_scope(client):
    batch = _batch(client)
    pay = _grant(client, batch["batch_id"], "pay")
    search = _grant(client, batch["batch_id"], "search")
    claimable = _package(client, pay["grant_id"])
    revoked_grant = _grant(client, batch["batch_id"], "pay")
    revoked_package = _package(client, revoked_grant["grant_id"])
    client.post(f"/api/delivery/grants/{revoked_grant['grant_id']}/revoke", headers=ADMIN)

    readback = client.get("/api/delivery/readback", headers=ADMIN).json()
    assert [p["package_id"] for p in readback["claimable"]] == [claimable["package_id"]]
    assert [p["package_id"] for p in readback["revoked"]] == [revoked_package["package_id"]]
    assert readback["pending"] == []
    assert {scope["service"] for scope in readback["scope"]} == {"pay", "search"}

    scope = client.get(f"/api/delivery/readback?grant_id={search['grant_id']}",
                       headers=ADMIN).json()["grant"]
    assert scope["grant_state"] == "active"
    assert scope["packages"] == []


def test_readback_requires_admin(client):
    assert client.get("/api/delivery/readback").status_code == 403


def test_delivery_page_renders(client):
    response = client.get("/delivery")
    assert response.status_code == 200
    assert "panel" in response.text
    assert "待生成" in response.text


# ---- 规则边界：不扩展时区更正、不扩展到去重 ------------------------------
def test_no_per_service_timezone_correction(client):
    # 带 +08:00 的时间按 UTC 归一后入桶，不套用 zones.csv 的服务时区。
    content = ('{"request_id":"a","timestamp":"2026-11-15T09:10:00+08:00",'
               '"service":"pay","status":200}')
    batch = _batch(client, content)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    rows = list(csv.DictReader(io.StringIO(package_artifact(client, package, grant))))
    assert rows[0]["hour"] == "2026-11-15T01:00:00Z"


def test_duplicate_request_ids_are_not_deduped(client):
    content = ('{"request_id":"r1","timestamp":"2026-11-15T01:05:00Z","service":"pay","status":200}\\n'
               '{"request_id":"r1","timestamp":"2026-11-15T01:05:00Z","service":"pay","status":200}')
    batch = _batch(client, content)
    assert batch["valid_rows"] == 2
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    rows = list(csv.DictReader(io.StringIO(package_artifact(client, package, grant))))
    assert rows[0]["count"] == "2"


# ---- 独立审计重算 -------------------------------------------------------
def test_reconcile_matches_delivered_scope(client):
    batch = _batch(client, DIRTY)
    grant = _grant(client, batch["batch_id"], "pay")
    package = _package(client, grant["grant_id"])
    response = client.get(f"/api/delivery/grants/{grant['grant_id']}/reconcile", headers=AUDIT)
    assert response.status_code == 200
    data = response.json()
    assert data["matches"] is True
    assert data["expected"]["included_rows"] == data["delivered"]["included_rows"] == 2
    assert data["expected"]["artifact_digest"] == package["scope"]["artifact_digest"]


def test_reconcile_before_build_reports_not_delivered(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "search")
    data = client.get(f"/api/delivery/grants/{grant['grant_id']}/reconcile",
                      headers=AUDIT).json()
    assert data["delivered"] is None
    assert data["matches"] is False
    assert data["expected"]["included_rows"] == 2


def test_reconcile_requires_audit(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay")
    _package(client, grant["grant_id"])
    assert client.get(f"/api/delivery/grants/{grant['grant_id']}/reconcile",
                      headers=ADMIN).status_code == 403
    assert client.get(f"/api/delivery/grants/{grant['grant_id']}/reconcile").status_code == 403


def test_readback_shows_expired_grant_packages(client):
    batch = _batch(client)
    grant = _grant(client, batch["batch_id"], "pay", ttl_seconds=3600)
    package = _package(client, grant["grant_id"])
    # 直接改库模拟时间流逝，避免等待
    from app.modules.m7_delivery import service as svc
    import sqlite3
    db = sqlite3.connect(client.app.state.delivery.store.path)
    db.execute("UPDATE delivery_grants SET expires_at=? WHERE grant_id=?",
               ("2000-01-01T00:00:00Z", grant["grant_id"]))
    db.commit(); db.close()
    readback = client.get("/api/delivery/readback", headers=ADMIN).json()
    assert [item["package_id"] for item in readback["expired"]] == [package["package_id"]]
    assert readback["claimable"] == []
    assert client.post(f"/api/delivery/packages/{package['package_id']}/claim",
                       headers=ADMIN).status_code == 403

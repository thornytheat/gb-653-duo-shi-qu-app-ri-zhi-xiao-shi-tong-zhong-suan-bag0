"""M7 按服务授权交付的 HTTP 入口。

权限边界：
- 管理密钥：导入批次、签发/撤销授权、制包（管理视角）。
- 独立审计密钥：读取原件与全量导出；不能替代受限交付。
- 下载凭据：仅能领取/下载受限副本，撤销即失效。
"""
from fastapi import APIRouter, Body, Request
from fastapi.responses import PlainTextResponse, Response

from app import auth
from app.errors import DomainError

from .service import DeliveryService

router = APIRouter(tags=["M7-按服务交付"])


def _service(request: Request) -> DeliveryService:
    service = getattr(request.app.state, "delivery", None)
    if service is None:
        raise DomainError("NOT_CONFIGURED", "交付服务未初始化", 500)
    return service


@router.get("/delivery")
def page(request: Request):
    service = _service(request)
    view = service.readback()
    batches = service.batches()["batches"]
    view = {
        **view,
        "input_count": sum(item["input_rows"] for item in batches),
        "valid_count": sum(item["valid_rows"] for item in batches),
        "quarantine_count": sum(item["quarantine_rows"] for item in batches),
        "batch_count": len(batches),
    }
    return request.app.state.templates.TemplateResponse(
        request, "m7_delivery.html", {"title": "按服务交付", "data": view})


# ---- 批次与原件 ----------------------------------------------------------
@router.post("/api/delivery/batches")
def import_batch(request: Request, payload: dict = Body(default={})):
    auth.require_admin(request)
    return _service(request).import_batch(payload.get("source_name"),
                                          payload.get("content"))


@router.get("/api/delivery/batches")
def list_batches(request: Request):
    auth.require_admin(request)
    return _service(request).batches()


@router.get("/api/delivery/batches/{batch_id}")
def get_batch(request: Request, batch_id: str):
    auth.require_admin(request)
    return _service(request).batch(batch_id)


@router.get("/api/audit/batches/{batch_id}/original", response_class=PlainTextResponse)
def read_original(request: Request, batch_id: str):
    """原件只能凭独立审计权限读取，用于逐行核对受限副本。"""
    auth.require_audit(request)
    raw, manifest = _service(request).original(batch_id)
    return PlainTextResponse(raw, headers={
        "X-Batch-Digest": manifest["digest"],
        "X-Batch-Input-Rows": str(manifest["input_rows"]),
        "X-Batch-Quarantine-Rows": str(manifest["quarantine_rows"]),
        "X-Batch-Services": ",".join(manifest["services"]),
    })


# ---- 授权 ---------------------------------------------------------------
@router.post("/api/delivery/grants")
def create_grant(request: Request, payload: dict = Body(default={})):
    auth.require_admin(request)
    return _service(request).create_grant(
        payload.get("batch_id"), payload.get("service"),
        payload.get("expires_at"), payload.get("ttl_seconds"))


@router.get("/api/delivery/grants")
def list_grants(request: Request, batch_id: str | None = None,
                service: str | None = None):
    auth.require_admin(request)
    return _service(request).grants(batch_id, service)


@router.get("/api/delivery/grants/{grant_id}")
def get_grant(request: Request, grant_id: str):
    auth.require_admin(request)
    return _service(request).grant(grant_id)


@router.post("/api/delivery/grants/{grant_id}/revoke")
def revoke_grant(request: Request, grant_id: str):
    auth.require_admin(request)
    return _service(request).revoke(grant_id)


# ---- 制包 ---------------------------------------------------------------
@router.post("/api/delivery/grants/{grant_id}/packages")
def build_package(request: Request, grant_id: str, payload: dict = Body(default={})):
    auth.require_admin(request)
    return _service(request).build_package(
        grant_id,
        interrupt_at=payload.get("interrupt_at"),
        chunk_size=payload.get("chunk_size", 25))


@router.get("/api/delivery/packages")
def list_packages(request: Request, batch_id: str | None = None,
                  service: str | None = None):
    auth.require_admin(request)
    return _service(request).packages(batch_id, service)


@router.get("/api/delivery/packages/{package_id}")
def get_package(request: Request, package_id: str):
    auth.require_admin(request)
    return _service(request).package(package_id)


@router.post("/api/delivery/packages/{package_id}/claim")
def claim_package(request: Request, package_id: str, payload: dict = Body(default={})):
    auth.require_admin(request)
    return _service(request).claim(package_id, payload.get("ttl_seconds"))


@router.get("/api/delivery/downloads/{token}")
def download(request: Request, token: str):
    """受限副本仅含授权服务；凭据随授权撤销或到期而失效。"""
    result = _service(request).download(token)
    return _download_response(result)


@router.get("/api/delivery/download")
def download_with_header(request: Request):
    """同一凭据也可从请求头提交，避免出现在访问日志的 URL 中。"""
    result = _service(request).download(auth.delivery_token(request))
    return _download_response(result)


def _download_response(result: dict) -> Response:
    scope = result["scope"]
    return Response(result["csv"], media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename={result['package_id']}.csv",
        "X-Package-Id": result["package_id"],
        "X-Grant-Id": result["grant_id"],
        "X-Service": result["service"],
        "X-Included-Rows": str(scope.get("included_rows", "")),
        "X-Artifact-Digest": scope.get("artifact_digest", ""),
        "X-Counts-Match": str(scope.get("counts_match", "")).lower(),
    })


# ---- 回读 ---------------------------------------------------------------
@router.get("/api/delivery/readback")
def readback(request: Request, batch_id: str | None = None,
             grant_id: str | None = None):
    auth.require_admin(request)
    return _service(request).readback(batch_id, grant_id)


@router.get("/api/delivery/grants/{grant_id}/reconcile")
def reconcile(request: Request, grant_id: str):
    """按原件重算授权服务范围，与已交付包逐桶核对。"""
    auth.require_audit(request)
    return _service(request).reconcile(grant_id)

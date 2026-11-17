"""访问控制：管理、审计与受限下载凭据使用彼此独立的密钥/令牌。"""
from __future__ import annotations

import hmac

from fastapi import Request

from .errors import DomainError


def _header(request: Request, name: str) -> str | None:
    return request.headers.get(name) or request.headers.get(name.lower())


def _bearer(request: Request) -> str | None:
    value = _header(request, "authorization") or ""
    scheme, _, token = value.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


def _same(left: str | None, right: str) -> bool:
    return bool(left) and hmac.compare_digest(left, right)


def require_admin(request: Request) -> None:
    settings = request.app.state.settings
    supplied = _header(request, "x-admin-key") or _bearer(request)
    if not _same(supplied, settings.admin_key):
        raise DomainError("FORBIDDEN", "需要管理权限", 403)


def require_audit(request: Request) -> None:
    """原件与全量导出只接受独立审计密钥，管理密钥不能替代。"""
    settings = request.app.state.settings
    supplied = _header(request, "x-audit-key") or _bearer(request)
    if not _same(supplied, settings.audit_key):
        raise DomainError("AUDIT_FORBIDDEN", "需要独立审计权限", 403)


def delivery_token(request: Request) -> str:
    supplied = _header(request, "x-delivery-token") or _bearer(request)
    if not supplied:
        raise DomainError("FORBIDDEN", "需要下载凭据", 403)
    return supplied

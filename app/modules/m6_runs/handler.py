from fastapi import APIRouter, Request
from fastapi.responses import Response
from app import auth
from .service import execute
router = APIRouter(tags=["M6-批次对账"])

@router.get("/runs")
def page(request: Request):
    data = execute({"store": request.app.state.store})
    return request.app.state.templates.TemplateResponse(request, "m6_runs.html", {"title": "批次对账", "data": data})

@router.get("/api/runs")
def runs(request: Request):
    execute({"store": request.app.state.store})
    return {"runs": request.app.state.store.all()}

@router.get("/api/export/buckets.csv")
def export(request: Request):
    # 全量导出含未授权服务，因此与原件同属全量口径，只接受独立审计权限。
    auth.require_audit(request)
    data = execute({"store": request.app.state.store})
    return Response(data["csv"], media_type="text/csv", headers={"Content-Disposition": "attachment; filename=evidence.csv"})

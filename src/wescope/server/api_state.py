"""첫 화면 판단(프로젝트 유무·마지막 프로젝트·진행 중인 스캔)과 화면이 붙이는 분류 이름."""
from fastapi import APIRouter, Request

from wescope.store import history
from wescope.taxonomy import catalog

router = APIRouter(prefix="/api")


@router.get("/state")
def state(request: Request):
    repos = history.list_repos()
    jobs = request.app.state.jobs
    current = jobs.current
    return {
        "repos": len(repos),
        "last_repo": history.last_scanned_repo() or (repos[-1]["id"] if repos else None),
        "running": jobs.snapshot(current)[1] if current else None,
    }


@router.get("/catalog")
def names():
    """결과 JSON은 코드값만 가진다. 화면은 이 이름을 붙인다 (DASHBOARD.md §8-1)."""
    return {"ws": [{"code": a["code"], "name_ko": a["name_ko"]} for a in catalog.ws_areas()],
            "owasp": [{"code": o["code"], "name": o["name"]} for o in catalog.owasp_top10()]}

"""첫 화면 판단: 프로젝트가 있는지, 마지막으로 본 프로젝트, 진행 중인 스캔."""
from fastapi import APIRouter, Request

from wescope.store import history

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

"""첫 화면 판단(프로젝트 유무·마지막 프로젝트·진행 중인 스캔), 화면이 붙이는 분류 이름, 전역 설정."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from wescope.store import config, history
from wescope.taxonomy import catalog

router = APIRouter(prefix="/api")


class SettingsIn(BaseModel):
    theme: str | None = None
    ai_level: str | None = None
    ai_on_hook: bool | None = None


@router.get("/state")
def state(request: Request):
    repos = history.list_repos()
    jobs = request.app.state.jobs
    current = jobs.current
    return {
        "repos": len(repos),
        "last_repo": history.last_scanned_repo() or (repos[-1]["id"] if repos else None),
        "running": jobs.snapshot(current)[1] if current else None,
        "latest_scan": history.latest_scan_id(),   # 바뀌면 화면이 목록·결과를 다시 읽는다 (커밋 자동 검사 등)
    }


@router.get("/catalog")
def names():
    """결과 JSON은 코드값만 가진다. 화면은 이 이름을 붙인다 (DASHBOARD.md §8-1). rules는 설정 창의 꺼 둔 규칙 이름."""
    return {"ws": [{"code": a["code"], "name_ko": a["name_ko"]} for a in catalog.ws_areas()],
            "owasp": [{"code": o["code"], "name": o["name"]} for o in catalog.owasp_top10()],
            "rules": [{"id": r["id"], "tech_name_ko": r["tech_name_ko"]} for r in catalog.rules().values()]}


@router.get("/settings")
def get_settings():
    return config.load()


@router.post("/settings")
def update_settings(body: SettingsIn):
    """보낸 항목만 바뀐다."""
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        if not config.is_allowed(value, config.CHOICES[key]):
            raise HTTPException(400, f"{key}는 {', '.join(map(str, config.CHOICES[key]))} 중 하나예요")
    return config.save(changes)

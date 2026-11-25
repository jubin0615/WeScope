"""프로젝트 연결·해제·설정. 연결하면 바로 첫 검사를 작업 큐에 넣는다."""
import re
import shutil

import pathspec
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from wescope.collector.snapshot import Target
from wescope.paths import home
from wescope.store import history, results
from wescope.taxonomy import catalog

router = APIRouter(prefix="/api")
# GitHub 주소만 받는다 (file://·ssh·다른 호스트로 git clone을 시키지 못하게)
GITHUB_URL = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?:\.git)?/?")


class RepoIn(BaseModel):
    path: str | None = None
    github: str | None = None
    branch: str | None = Field(None, max_length=200)
    name: str | None = Field(None, max_length=100)


class SettingsIn(BaseModel):
    disabled_rules: list[str] | None = None
    excludes: list[str] | None = Field(None, max_length=200)


def view(repo: dict) -> dict:
    last = history.scans(repo["id"], limit=1)
    return {**repo, "last_scan": last[0] if last else None}


def get_or_404(repo_id: str) -> dict:
    repo = history.get_repo(repo_id)
    if repo is None:
        raise HTTPException(404, "연결되지 않은 프로젝트예요")
    return repo


@router.get("/repos")
def list_repos():
    return [view(repo) for repo in history.list_repos()]


@router.post("/repos", status_code=201)
def add_repo(body: RepoIn, request: Request):
    if bool(body.path) == bool(body.github):
        raise HTTPException(400, "프로젝트 폴더 경로나 GitHub 주소 중 하나만 입력하세요")
    if body.github:
        url = body.github.strip()
        if not GITHUB_URL.fullmatch(url):
            raise HTTPException(400, "https://github.com/소유자/저장소 형식의 주소를 입력하세요")
        target = Target("github", url.rstrip("/"), body.branch)
    else:
        target = Target("folder", body.path.strip())
    try:
        repo = history.add_repo(target, body.name)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
    job = request.app.state.jobs.submit(repo["id"])
    return {"repo": view(repo), "scan_id": job.scan_id}


@router.delete("/repos/{repo_id}", status_code=204)
def remove_repo(repo_id: str, request: Request):
    get_or_404(repo_id)
    if request.app.state.jobs.busy(repo_id):
        raise HTTPException(409, "검사가 끝난 뒤에 연결을 해제할 수 있어요")
    history.remove_repo(repo_id)
    results.purge(repo_id)
    shutil.rmtree(home() / "repos" / repo_id, ignore_errors=True)   # GitHub 주소용 We-Scope 전용 clone
    return Response(status_code=204)


@router.get("/repos/{repo_id}/settings")
def get_settings(repo_id: str):
    repo = get_or_404(repo_id)
    return {"disabled_rules": repo["disabled_rules"], "excludes": repo["excludes"]}


@router.post("/repos/{repo_id}/settings")
def update_settings(repo_id: str, body: SettingsIn):
    get_or_404(repo_id)
    unknown = sorted(set(body.disabled_rules or []) - set(catalog.rules()))
    if unknown:
        raise HTTPException(400, f"알 수 없는 규칙: {', '.join(unknown)}")
    if body.excludes is not None:
        body.excludes = [p.strip() for p in body.excludes if p.strip()]
        if any(len(p) > 200 for p in body.excludes):
            raise HTTPException(400, "제외 패턴이 너무 길어요")
        for pattern in body.excludes:   # 틀린 패턴이 저장되면 그 프로젝트의 모든 검사가 실패하므로 저장 전에 해석해 본다
            try:
                pathspec.PathSpec.from_lines("gitwildmatch", [pattern])
            except ValueError:
                raise HTTPException(400, f"제외 패턴을 해석할 수 없어요: {pattern}") from None
    history.update_settings(repo_id, disabled_rules=body.disabled_rules, excludes=body.excludes)
    return get_settings(repo_id)

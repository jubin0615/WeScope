"""스캔 시작·진행(SSE)·결과·내려받기."""
import asyncio
import json
from pathlib import PurePath

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from wescope.report.markdown import render
from wescope.server.api_repos import get_or_404
from wescope.store import history, results

router = APIRouter(prefix="/api")
FINISHED = ("done", "failed")


class ScanIn(BaseModel):
    repo_id: str


@router.post("/scans", status_code=202)
def start_scan(body: ScanIn, request: Request):
    """[다시 스캔]. 폴더는 지금 파일, GitHub는 원격 최신 커밋을 검사한다."""
    get_or_404(body.repo_id)
    return {"scan_id": request.app.state.jobs.submit(body.repo_id).scan_id}


@router.post("/hook-trigger", status_code=202)
def hook_trigger(body: ScanIn, request: Request):
    """post-commit hook(wescope.hook)이 부른다. 열린 대시보드는 /api/state의 running·latest_scan으로 조용히 알아챈다."""
    get_or_404(body.repo_id)
    return {"scan_id": request.app.state.jobs.submit(body.repo_id, "hook").scan_id}


def load_result(scan_id: str, request: Request):
    repo_id = history.repo_of_scan(scan_id)
    if repo_id is None:
        job = request.app.state.jobs.get(scan_id)
        if job and job.status not in FINISHED:
            raise HTTPException(409, "아직 검사 중이에요")
        raise HTTPException(404, "검사 결과가 없어요")
    result = results.load(repo_id, scan_id)
    if result is None:
        raise HTTPException(404, "검사 결과 파일이 없어요")
    return result


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, request: Request):
    return Response(load_result(scan_id, request).to_json(), media_type="application/json")


@router.get("/scans/{scan_id}/events")
async def scan_events(scan_id: str, request: Request):
    """진행 단계 이벤트(SSE). event: progress → done 또는 failed 한 번으로 끝난다."""
    jobs = request.app.state.jobs
    job = jobs.get(scan_id)
    if job is None:
        if history.repo_of_scan(scan_id) is None:     # 서버를 다시 켜기 전에 끝난 검사는 바로 done
            raise HTTPException(404, "검사를 찾을 수 없어요")
        return StreamingResponse(iter([_event("done", {"scan_id": scan_id, "status": "done"})]),
                                 media_type="text/event-stream")
    return StreamingResponse(job_events(jobs, job, request.is_disconnected), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


async def job_events(jobs, job, is_disconnected):
    """작업이 바뀔 때마다 그 순간의 사본을 보낸다. 끝낼지는 '방금 보낸 사본'으로 정한다.
    (보낸 뒤 작업을 다시 읽으면, 기다리는 사이 끝난 작업의 done을 보내지 않고 닫아 버린다)"""
    seen = -1
    while True:
        version, snapshot = jobs.snapshot(job)
        if version != seen:
            seen = version
            finished = snapshot["status"] in FINISHED
            yield _event(snapshot["status"] if finished else "progress", snapshot)
            if finished:
                return
        if await is_disconnected():
            return
        await asyncio.sleep(0.2)


@router.get("/scans/{scan_id}/export")
def export(scan_id: str, request: Request, format: str = "md"):
    result = load_result(scan_id, request)
    name = PurePath(result.source["location"].rstrip("/\\")).name or "project"
    if format == "md":
        body, media = render(result), "text/markdown; charset=utf-8"
    elif format == "json":
        body, media = result.to_json(), "application/json"
    else:
        raise HTTPException(400, "format은 md 또는 json이에요")
    filename = f"wescope-{_ascii(name)}-{scan_id}.{format}"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _event(kind: str, data: dict) -> str:
    return f"event: {kind}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _ascii(name: str) -> str:
    return "".join(c if c.isascii() and (c.isalnum() or c in "-_.") else "_" for c in name)

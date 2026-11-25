"""로컬 대시보드 서버. 127.0.0.1에만 바인딩하고, 실행마다 발급한 접속 티켓이 있어야 쓸 수 있다.

- 첫 접속 `/?ticket=…` → HttpOnly 쿠키로 바꾸고 주소창에서 티켓을 지운다 (303 → `/`)
- 모든 요청: Host가 127.0.0.1/localhost:포트인지(DNS 리바인딩 방지), Origin이 있으면 같은 주소인지 확인
- `/healthz`만 티켓 없이 열려 있다 (실행기가 서버가 살아 있는지 확인하는 용도, 코드·결과 없음)
"""
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from wescope.server import api_repos, api_scans, api_state
from wescope.server.jobs import Jobs
from wescope.server.state import COOKIE
WEB_DIR = Path(__file__).parent.parent / "web"


def create_app(ticket: str, port: int, jobs: Jobs | None = None) -> FastAPI:
    jobs = jobs or Jobs()

    @asynccontextmanager
    async def lifespan(app):
        jobs.start()
        yield
        await run_in_threadpool(jobs.stop)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.jobs = jobs
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{host}" for host in hosts}

    def deny(request: Request, status: int, message: str):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": message}, status)
        return PlainTextResponse(message, status)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host") not in hosts:
            return deny(request, 400, "허용되지 않은 주소예요")
        if request.headers.get("origin") not in (None, *origins):
            return deny(request, 403, "다른 사이트에서 온 요청은 받지 않아요")
        if request.url.path == "/healthz":
            return await call_next(request)
        given = request.query_params.get("ticket")
        if request.url.path == "/" and given is not None:
            if not _same(given, ticket):
                return deny(request, 401, "접속 티켓이 맞지 않아요. 터미널에서 wescope를 다시 실행하세요.")
            response = RedirectResponse("/", 303)
            response.set_cookie(COOKIE, ticket, httponly=True, samesite="strict", path="/")
            return response
        if not _same(request.cookies.get(COOKIE, ""), ticket):
            return deny(request, 401, "터미널에 표시된 주소로 다시 열어 주세요.")
        return await call_next(request)

    @app.get("/healthz")
    def healthz():
        return {"app": "wescope", "pid": os.getpid()}

    @app.get("/")
    def index():
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")   # CSS·JS·폰트. 위 guard(티켓 쿠키)를 똑같이 거친다

    for module in (api_state, api_repos, api_scans):
        app.include_router(module.router)
    return app


def _same(given: str, expected: str) -> bool:
    return secrets.compare_digest(given.encode(), expected.encode())

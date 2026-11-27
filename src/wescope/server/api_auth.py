"""ChatGPT 연결 (Sign in with ChatGPT).

[ChatGPT 연결] → POST /api/auth/login → 대시보드가 새 탭으로 승인 주소를 연다 → OpenAI 승인 → /auth/callback
(이 PC를 처음 연결하면 등록 승인 뒤 로그인 승인이 한 번 더) → "연결했어요" 페이지. 대시보드는 GET /api/auth를 다시 읽는다.

/auth/callback은 OpenAI에서 넘어오는 요청이라 SameSite=Strict 티켓 쿠키가 실리지 않는다. 그래서 app.py의 쿠키 검사에서
빼고, 대신 이번 로그인에서만 쓰는 state(32바이트 난수)·PKCE·nonce로 확인한다. Host 검사는 그대로 받는다.
"""
import html

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from wescope.llm import auth
from wescope.llm.client import LLMError

router = APIRouter()
CALLBACK = "/auth/callback"


@router.get("/api/auth")
def get_auth(request: Request):
    """{"state": login|plan|ready, "message"}. 마지막 연결 시도가 실패했으면 그 이유를 message로."""
    status = auth.status()
    error = request.app.state.auth_error
    return {**status, "message": error} if error and status["state"] != "ready" else status


@router.post("/api/auth/login")
def login(request: Request):
    """→ {"url": OpenAI 승인 주소}. 대시보드가 새 탭으로 연다. 다시 누르면 이전 시도는 무효가 된다."""
    url, request.app.state.auth_pending = auth.start(request.app.state.auth_redirect)
    request.app.state.auth_error = None
    return {"url": url}


@router.post("/api/auth/logout", status_code=204)
def logout():
    auth.logout()


@router.get(CALLBACK)
def callback(request: Request):
    state = request.app.state
    pending, state.auth_pending = state.auth_pending, None        # 한 번만 쓴다
    query = {name: request.query_params.getlist(name) for name in request.query_params}
    try:
        following = auth.finish(pending, query)
    except LLMError as error:
        state.auth_error = str(error)
        return _page("ChatGPT에 연결하지 못했어요", str(error), 400)
    except Exception:   # 예외 메시지에 code·토큰·주소가 들어 있을 수 있어 내용은 보이지 않는다
        state.auth_error = "ChatGPT 연결을 마치지 못했어요. 다시 시도하세요"
        return _page("ChatGPT에 연결하지 못했어요", state.auth_error, 400)
    if following:                                                 # 등록을 마쳤다: 이어서 로그인 승인
        url, state.auth_pending = following
        return RedirectResponse(url, 303)
    return _page("ChatGPT에 연결했어요", "대시보드로 돌아가세요. 대시보드가 다른 탭에 열려 있으면 이 탭은 닫아도 돼요.")


def _page(title: str, message: str, status: int = 200) -> HTMLResponse:
    """새 탭이 막히면 대시보드 탭 자체가 로그인으로 넘어온다. 그래서 돌아갈 링크를 둔다
    (이 서버 안의 링크라 SameSite=Strict 쿠키가 실린다)."""
    body = (f'<!doctype html><html lang="ko"><meta charset="utf-8"><title>We-Scope</title>'
            f'<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">'
            f'<h1>{html.escape(title)}</h1><p>{html.escape(message)}</p><p><a href="/">대시보드로 돌아가기</a></p>'
            f"</body></html>")
    return HTMLResponse(body, status, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

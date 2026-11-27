"""Sign in with ChatGPT (v0.2 vibescan register·login·session 이식).

공식 공개 OAuth가 아니라 v0.2가 쓰던 방식이라 바뀌거나 막힐 수 있다 (IMPLEMENTATION_PLAN 위험 11).
1. 등록 (PC마다 처음 한 번): client_id 없이 승인 화면을 열면 콜백으로 이 PC용 client_id가 온다.
2. 로그인: PKCE(S256)·state·nonce로 승인 → 콜백의 code를 토큰으로 바꾼다. 등록이 필요하면 1→2를 한 번에 잇는다.
3. 토큰은 ~/.wescope/auth.json. Windows는 DPAPI로 암호화(현재 Windows 사용자만 풀 수 있다), 그 밖은 권한 600.
4. access token은 만료 60초 전에 갱신한다. 서버와 서버 없이 도는 hook이 동시에 갱신하지 않게 auth.lock으로 막는다
   (refresh token은 한 번 쓰면 바뀌어, 둘이 동시에 쓰면 한쪽이 invalid_grant로 로그인이 풀린다).

비밀값(토큰·code·verifier)은 어떤 출력·예외 메시지에도 넣지 않는다.
"""
import base64
import ctypes
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlencode

from wescope.llm.client import LLMError
from wescope.paths import home
from wescope.store.lock import held

ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
PLAN_SCOPE = "chatgpt.tokens.use.direct"
SCOPE = "openid profile email offline_access resource.invoke " + PLAN_SCOPE
APP_NAME = "We-Scope"          # 등록 승인 화면에 보이는 이름
DYNAMIC = "dynamic_agent_client"
PENDING_SECONDS = 300


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트를 따라가지 않는다 (Authorization 헤더가 다른 호스트로 넘어가지 않게)."""

    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http(method: str, url: str, *, headers=None, data: bytes | None = None, timeout=20):
    """→ 열린 응답(성공) 또는 HTTPError(실패). 테스트는 이 함수를 바꿔 끼운다."""
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        return _opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        return error
    except (urllib.error.URLError, OSError) as error:
        raise LLMError(f"ChatGPT에 연결하지 못했어요 ({type(error).__name__})") from None


# ── 저장 ──────────────────────────────────────────────────────────────

class _Blob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buffer = ctypes.create_string_buffer(data, len(data))
    source, out = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), _Blob()
    call = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not call(ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(out)):   # 0x1: UI 띄우지 않음
        raise OSError("DPAPI")
    try:
        return ctypes.string_at(out.data, out.size)
    finally:
        kernel32.LocalFree(out.data)


def _path():
    return home() / "auth.json"


def load() -> dict:
    """{"host": 설치 id, "client": 등록된 client_id|None, "session": 토큰 기록|None}. 읽지 못하면 빈 기록."""
    try:
        raw = _path().read_bytes()
        return json.loads(_dpapi(raw, False) if os.name == "nt" else raw)
    except (OSError, ValueError):
        return {}


def _save(record: dict) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(record).encode()
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(_dpapi(raw, True) if os.name == "nt" else raw)
    os.replace(temp, path)


# ── 로그인 흐름 (서버의 /api/auth/login → 브라우저 → /auth/callback) ───────────

def start(redirect: str) -> tuple[str, dict]:
    """→ (브라우저로 열 승인 주소, 서버가 콜백까지 들고 있을 pending). 등록 전이면 등록부터."""
    with held("auth.lock", 30):
        record = load()
        if not record.get("host"):
            record = {"host": uuid.uuid4().urn, "client": None, "session": None}
            _save(record)
    pending = {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
               "verifier": secrets.token_urlsafe(64), "redirect": redirect, "at": time.monotonic(),
               "client": record.get("client")}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(pending["verifier"].encode()).digest()).decode().rstrip("=")
    params = {"client_id": pending["client"] or DYNAMIC, "ext_agent_host_id": record["host"], "redirect_uri": redirect,
              "response_type": "code", "scope": SCOPE, "resource": RESOURCE, "state": pending["state"],
              "nonce": pending["nonce"], "code_challenge": challenge, "code_challenge_method": "S256"}
    if not pending["client"]:
        params["agent_name_hint"] = APP_NAME
    elif (record.get("session") or {}).get("id_token"):
        params["id_token_hint"] = record["session"]["id_token"]
    return ISSUER + "/api/accounts/authorize?" + urlencode(params), pending


def finish(pending: dict | None, query: dict[str, list[str]]) -> tuple[str, dict] | None:
    """콜백 처리. → 등록을 마쳤으면 이어서 로그인할 (승인 주소, 새 pending), 로그인을 마쳤으면 None. 실패하면 LLMError.
    query: 같은 이름이 여러 번 온 것까지 보려고 이름 → 값 목록."""
    if not pending or query.get("state") != [pending["state"]] or time.monotonic() - pending["at"] > PENDING_SECONDS:
        raise LLMError("로그인 요청이 만료됐거나 올바르지 않아요. 대시보드에서 다시 연결하세요", "login")
    if "error" in query:
        raise LLMError("ChatGPT에서 승인하지 않았어요", "login")
    if not pending["client"]:                      # 등록 콜백: 이 PC용 client_id
        ids = query.get("client_id", [])
        if len(ids) != 1 or not ids[0] or ids[0] == DYNAMIC:
            raise LLMError("등록 응답에서 client ID를 확인하지 못했어요", "login")
        with held("auth.lock", 30):
            record = load()
            record["client"] = ids[0]
            _save(record)
        return start(pending["redirect"])
    codes = query.get("code", [])
    if len(codes) != 1 or not codes[0] or query.get("client_id") not in (None, [pending["client"]]):
        raise LLMError("로그인 응답이 올바르지 않아요", "login")
    tokens = _token_request(pending["client"], grant_type="authorization_code", code=codes[0],
                            code_verifier=pending["verifier"], redirect_uri=pending["redirect"])
    subject = _subject(tokens.get("id_token"), pending["client"], pending["nonce"])
    with held("auth.lock", 30):
        record = load()
        old = record.get("session") or {}
        if old.get("sub") and old["sub"] != subject:
            # 다른 계정으로 로그인: 이전 계정 토큰은 버리고 새 계정으로 바꾼다
            old = {}
        record["session"] = _session(tokens, old, subject)
        _save(record)
    return None


def _token_request(client: str, **form) -> dict:
    body = urlencode({"client_id": client, "resource": RESOURCE, **form}).encode()
    with http("POST", ISSUER + "/api/accounts/oauth/token", data=body,
              headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}) as response:
        status = response.status
        try:
            data = json.loads(response.read() or b"{}")
        except ValueError:
            data = {}
    if status != 200:
        if status in (400, 401) and data.get("error") == "invalid_grant":
            raise LLMError("ChatGPT 승인이 만료됐어요. 다시 연결하세요", "login")
        raise LLMError(f"ChatGPT 토큰을 받지 못했어요 (HTTP {status})", "error")
    return data


def _subject(id_token, client: str, nonce: str | None = None) -> str:
    """id_token의 계정 id(sub). 토큰 엔드포인트에서 HTTPS로 직접 받은 토큰이라 서명 대신 TLS를 믿고
    (OIDC Core 3.1.3.7 6번) 발급자·대상·만료·nonce만 확인한다."""
    try:
        body = id_token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (AttributeError, IndexError, ValueError):
        raise LLMError("계정 정보를 확인하지 못했어요. 다시 연결하세요", "login") from None
    audience = claims.get("aud")
    if (claims.get("iss") != ISSUER or client not in (audience if isinstance(audience, list) else [audience])
            or not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < time.time() - 60
            or not claims.get("sub") or (nonce is not None and claims.get("nonce") != nonce)):
        raise LLMError("계정 정보가 맞지 않아요. 다시 연결하세요", "login")
    return claims["sub"]


def _session(tokens: dict, previous: dict, subject: str) -> dict:
    scope = tokens.get("scope", previous.get("scope", ""))
    if PLAN_SCOPE in scope.split() and not tokens.get("access_token"):
        raise LLMError("구독 사용에 필요한 토큰이 없어요", "plan")
    return {"sub": subject, "scope": scope, "access_token": tokens.get("access_token"),
            "expires_at": time.time() + int(tokens.get("expires_in", 0)),
            "id_token": tokens.get("id_token", previous.get("id_token")),
            "refresh_token": tokens.get("refresh_token", previous.get("refresh_token"))}


# ── 상태·토큰 ─────────────────────────────────────────────────────────

def status() -> dict:
    """{"state": login|plan|ready, "message"}. 네트워크·갱신 없이 저장된 기록만 본다 (대시보드가 자주 부른다)."""
    record = load()
    session = record.get("session") or {}
    if not record.get("client") or not session:
        return {"state": "login", "message": "ChatGPT에 연결하지 않았어요"}
    if PLAN_SCOPE not in session.get("scope", "").split():
        return {"state": "plan", "message": "ChatGPT 구독 사용 승인이 없어요. Plus 이상 구독을 확인하고 다시 연결하세요"}
    if session["expires_at"] <= time.time() + 60 and not session.get("refresh_token"):
        return {"state": "login", "message": "ChatGPT 연결이 만료됐어요. 다시 연결하세요"}
    return {"state": "ready", "message": "ChatGPT 연결됨"}


def access_token() -> str:
    """쓸 수 있는 access token. 만료가 가까우면 갱신한다. 실패하면 LLMError(login|plan|error)."""
    with held("auth.lock", 30):
        record = load()
        session, client = record.get("session") or {}, record.get("client")
        if not client or not session or PLAN_SCOPE not in session.get("scope", "").split():
            raise LLMError("ChatGPT에 연결하지 않았어요", "login" if not session else "plan")
        if session["expires_at"] > time.time() + 60:
            return session["access_token"]
        if not session.get("refresh_token"):
            raise LLMError("ChatGPT 연결이 만료됐어요. 다시 연결하세요", "login")
        try:
            tokens = _token_request(client, grant_type="refresh_token", refresh_token=session["refresh_token"])
        except LLMError as error:
            if error.kind == "login":          # invalid_grant: 다시 써도 소용없는 토큰은 지운다
                record["session"] = None
                _save(record)
            raise
        if tokens.get("id_token") and _subject(tokens["id_token"], client) != session["sub"]:
            raise LLMError("갱신된 계정 정보가 맞지 않아요. 다시 연결하세요", "login")
        record["session"] = _session(tokens, session, session["sub"])
        _save(record)
        if PLAN_SCOPE not in record["session"]["scope"].split():
            raise LLMError("ChatGPT 구독 사용 승인이 없어요", "plan")
        return record["session"]["access_token"]


def expire() -> None:
    """ChatGPT가 access token을 거절(401)했을 때: 다음 access_token()이 refresh token으로 새로 받게 한다."""
    with held("auth.lock", 30):
        record = load()
        if record.get("session"):
            record["session"]["expires_at"] = 0
            _save(record)


def logout() -> None:
    """이 PC에 저장한 토큰만 지운다 (등록·ChatGPT 설정의 앱 연결은 그대로)."""
    with held("auth.lock", 30):
        record = load()
        if record.get("session"):
            record["session"] = None
            _save(record)

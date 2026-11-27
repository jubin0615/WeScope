"""Sign in with ChatGPT·실제 클라이언트 (llm/auth.py·llm/chatgpt.py): OpenAI를 흉내 낸 가짜로 등록→로그인→갱신→요청까지."""
import base64
import hashlib
import io
import json
import os
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from wescope.llm import auth, chatgpt
from wescope.llm.client import LLMError, connected
from wescope.paths import home
from wescope.server.app import create_app

TICKET, PORT = "t" * 43, 8765
BASE = f"http://127.0.0.1:{PORT}"


class Response(io.BytesIO):
    def __init__(self, status, body: bytes | dict | list[dict]):
        if isinstance(body, list):          # SSE 이벤트들
            body = b"".join(b"data: " + json.dumps(e).encode() + b"\n\n" for e in body)
        elif isinstance(body, dict):
            body = json.dumps(body).encode()
        super().__init__(body)
        self.status = status


def jwt(**claims) -> str:
    encode = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{encode({'alg': 'RS256'})}.{encode(claims)}.sig"


class FakeOpenAI:
    """auth.http 자리에 끼운다. 승인 화면은 테스트가 직접 콜백 주소를 부르는 것으로 대신한다."""

    def __init__(self):
        self.calls, self.authorize, self.issued = [], None, 0
        self.refresh = "ok"            # ok / invalid_grant
        self.responses = lambda body: Response(200, [
            {"type": "response.output_text.delta", "delta": '{"answer": '},
            {"type": "response.output_text.delta", "delta": "1}"}, {"type": "response.completed"}])

    def __call__(self, method, url, *, headers=None, data=None, timeout=20):
        self.calls.append((method, url, headers or {}, data))
        if url == auth.ISSUER + "/api/accounts/oauth/token":
            return self.token({k: v[0] for k, v in parse_qs(data.decode()).items()})
        assert headers["Authorization"] == f"Bearer access-{self.issued}"
        if url == auth.RESOURCE + "/models":
            return Response(200, {"models": [{"slug": "hidden", "visibility": "hide"}, {"slug": "gpt-test", "visibility": "list"}]})
        if url == auth.RESOURCE + "/responses":
            return self.responses(json.loads(data))
        raise AssertionError(url)

    def token(self, form):
        if form["grant_type"] == "authorization_code":
            query = parse_qs(urlsplit(self.authorize).query)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=")
            assert form["code"] == "good-code" and challenge == query["code_challenge"][0]
            assert form["redirect_uri"] == query["redirect_uri"][0]
            nonce = query["nonce"][0]
        elif self.refresh == "invalid_grant":
            return Response(400, {"error": "invalid_grant"})
        else:
            nonce = None
        self.issued += 1
        return Response(200, {"access_token": f"access-{self.issued}", "refresh_token": f"refresh-{self.issued}",
                              "expires_in": 3600, "scope": auth.SCOPE,
                              "id_token": jwt(iss=auth.ISSUER, aud=form["client_id"], sub="user-1", nonce=nonce,
                                              exp=time.time() + 3600)})


@pytest.fixture
def openai(monkeypatch):
    fake = FakeOpenAI()
    monkeypatch.setattr(auth, "http", fake)
    return fake


@pytest.fixture
def server():
    """(대시보드 탭: 티켓 쿠키 있음, OpenAI가 돌려보내는 요청: 쿠키 없음). 같은 서버를 본다."""
    app = create_app(TICKET, PORT)
    with TestClient(app, base_url=BASE) as tab:
        tab.get(f"/?ticket={TICKET}")
        yield tab, TestClient(app, base_url=BASE)


def query(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def log_in(server, openai):
    tab, redirect = server
    openai.authorize = tab.post("/api/auth/login").json()["url"]
    first = query(openai.authorize)
    back = redirect.get("/auth/callback", params={"state": first["state"], "client_id": "client-1"}, follow_redirects=False)
    assert back.status_code == 303                       # 처음이면 등록 → 이어서 로그인 승인
    openai.authorize = back.headers["location"]
    second = query(openai.authorize)
    done = redirect.get("/auth/callback", params={"state": second["state"], "code": "good-code"})
    return first, second, done


def test_register_then_login_then_ask(server, openai):
    tab, _ = server
    assert tab.get("/api/auth").json()["state"] == "login" and connected() is None
    first, second, done = log_in(server, openai)

    assert first["client_id"] == auth.DYNAMIC and first["agent_name_hint"] == "We-Scope"
    assert first["redirect_uri"] == f"{BASE}/auth/callback" and first["code_challenge_method"] == "S256"
    assert second["client_id"] == "client-1" and "agent_name_hint" not in second and second["state"] != first["state"]
    assert done.status_code == 200 and "연결했어요" in done.text
    assert '<a href="/">' in done.text           # 새 탭이 막혀 대시보드 탭에서 로그인했어도 돌아갈 수 있게
    assert tab.get("/api/auth").json() == {"state": "ready", "message": "ChatGPT 연결됨"}
    if os.name == "nt":                                  # 토큰은 DPAPI로 암호화해 둔다
        assert b"access-1" not in (home() / "auth.json").read_bytes()

    client = connected()
    assert client.ask("지시", {"x": 1}) == {"answer": 1} and client.model == "gpt-test"
    method, url, headers, data = openai.calls[-1]
    body = json.loads(data)
    assert url.endswith("/responses") and body["store"] is False and body["stream"] is True
    assert body["model"] == "gpt-test" and json.loads(body["input"][0]["content"]) == {"x": 1}

    assert tab.post("/api/auth/logout").status_code == 204
    assert tab.get("/api/auth").json()["state"] == "login" and connected() is None


@pytest.mark.parametrize("bad", [{"state": "guess"}, {"error": "access_denied"}])
def test_callback_rejects_wrong_or_refused_answers(server, openai, bad):
    tab, redirect = server
    url = tab.post("/api/auth/login").json()["url"]
    params = {"state": query(url)["state"], "client_id": "client-1", **bad}
    resp = redirect.get("/auth/callback", params=params)
    assert resp.status_code == 400
    assert tab.get("/api/auth").json()["state"] == "login" and "<" not in resp.text.split("<p>")[1].split("</p>")[0]
    # 한 번 쓴 state로는 다시 들어올 수 없다
    assert redirect.get("/auth/callback", params={"state": query(url)["state"], "client_id": "c"}).status_code == 400


def test_wrong_nonce_is_rejected(server, openai, monkeypatch):
    tab, redirect = server
    real = openai.token
    monkeypatch.setattr(openai, "token", lambda form: (
        Response(200, {**json.loads(real(form).getvalue()), "id_token": jwt(iss=auth.ISSUER, aud=form["client_id"],
                                                                            sub="u", nonce="other", exp=time.time() + 60)})))
    _, _, done = log_in(server, openai)
    assert done.status_code == 400 and tab.get("/api/auth").json()["state"] == "login"


def test_expired_token_is_refreshed_and_dead_refresh_logs_out(server, openai):
    log_in(server, openai)
    record = auth.load()
    record["session"]["expires_at"] = time.time() - 1
    auth._save(record)
    assert auth.access_token() == "access-2" and auth.load()["session"]["refresh_token"] == "refresh-2"

    record = auth.load()
    record["session"]["expires_at"] = time.time() - 1
    auth._save(record)
    openai.refresh = "invalid_grant"
    with pytest.raises(LLMError) as error:
        auth.access_token()
    assert error.value.kind == "login" and auth.status()["state"] == "login"


@pytest.mark.parametrize("status, kind", [(401, "login"), (403, "plan"), (429, "limit"), (500, "error")])
def test_http_errors_map_to_kinds(server, openai, status, kind):
    log_in(server, openai)
    openai.responses = lambda body: Response(status, {})
    with pytest.raises(LLMError) as error:
        connected().ask("지시", {})
    assert error.value.kind == kind


class Stalls(io.BytesIO):
    """스트림 도중 네트워크가 멈춘다 (소켓 시간 초과)."""
    status = 200

    def __iter__(self):
        yield b'data: {"type": "response.output_text.delta", "delta": "{"}\n'
        raise TimeoutError("timed out")


@pytest.mark.parametrize("broken", [lambda body: Stalls(), lambda body: Response(200, b"data: {not json\n")])
def test_broken_response_stops_ai_but_keeps_the_scan(server, openai, monkeypatch, tmp_path, broken):
    """읽는 도중의 네트워크·형식 오류도 LLMError로: AI 단계만 멈추고 정적 결과는 남는다."""
    from conftest import materialize
    from wescope.collector.snapshot import Target
    from wescope.scan import run_scan
    monkeypatch.setattr("wescope.analyzers.semgrep.find_semgrep", lambda: None)
    log_in(server, openai)
    openai.responses = broken
    root, _ = materialize("vuln_flask", tmp_path)
    result = run_scan(Target("folder", str(root)), ai=connected())
    assert result.findings and result.ai["error"]["kind"] == "error" and result.ai["fixes"]["failed"] == 0


def test_stream_must_complete_and_be_a_json_object():
    done = {"type": "response.completed"}
    delta = lambda text: {"type": "response.output_text.delta", "delta": text}
    lines = lambda events: Response(200, events).getvalue().splitlines(keepends=True)
    assert chatgpt.collect(lines([delta("a"), delta("b"), done])) == "ab"
    with pytest.raises(LLMError):
        chatgpt.collect(lines([delta("a")]))                       # 완료 전에 끊김
    with pytest.raises(LLMError):
        chatgpt.collect(lines([delta("a"), {"type": "response.failed"}]))
    assert chatgpt.parse('```json\n{"a": 1}\n```') == {"a": 1}
    with pytest.raises(LLMError):
        chatgpt.parse("[1]")

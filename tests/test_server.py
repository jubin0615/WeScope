import asyncio
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from conftest import git, materialize
from wescope.paths import home
from wescope.models.scan_result import ScanResult
from wescope.server.api_scans import job_events
from wescope.server.app import COOKIE, create_app
from wescope.server.jobs import Jobs

TICKET = "t" * 43
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"


@pytest.fixture
def client(monkeypatch):
    """로그인(티켓→쿠키)까지 마친 클라이언트. 서버 동작만 보므로 Semgrep은 끈다."""
    monkeypatch.setattr("wescope.analyzers.semgrep.find_semgrep", lambda: None)
    with TestClient(create_app(TICKET, PORT), base_url=BASE) as c:
        assert c.get(f"/?ticket={TICKET}", follow_redirects=False).status_code == 303
        yield c


def wait(client, scan_id) -> list[tuple[str, dict]]:
    """SSE를 끝까지 읽어 (event, data) 목록을 돌려준다."""
    events, kind = [], None
    with client.stream("GET", f"/api/scans/{scan_id}/events") as resp:
        assert resp.status_code == 200
        for line in resp.iter_lines():
            if line.startswith("event: "):
                kind = line[7:]
            elif line.startswith("data: "):
                events.append((kind, json.loads(line[6:])))
    return events


def test_ticket_becomes_cookie_and_is_required():
    with TestClient(create_app(TICKET, PORT), base_url=BASE) as c:
        assert c.get("/api/state").status_code == 401
        assert c.get("/").status_code == 401
        assert c.get("/static/app.css").status_code == 401                    # 정적 파일도 티켓 필요
        assert c.get("/?ticket=wrong").status_code == 401
        resp = c.get(f"/?ticket={TICKET}", follow_redirects=False)
        assert resp.status_code == 303 and resp.headers["location"] == "/"     # 주소창에서 티켓을 지운다
        assert "httponly" in resp.headers["set-cookie"].lower() and "samesite=strict" in resp.headers["set-cookie"].lower()
        assert c.get("/api/state").json() == {"repos": 0, "last_repo": None, "running": None, "latest_scan": None}
        assert c.get("/healthz").json()["app"] == "wescope"
        names = c.get("/api/catalog").json()
        assert [w["code"] for w in names["ws"]] == [f"WS-{i:02}" for i in range(1, 11)] and names["ws"][4]["name_ko"] == "입력값 주입"
        assert [o["code"] for o in names["owasp"]][:2] == ["A01:2025", "A02:2025"] and names["owasp"][4]["name"] == "Injection"
        assert c.get("/static/app.css").headers["content-type"].startswith("text/css")
        assert c.get("/static/fonts/PretendardVariable.woff2").status_code == 200
        assert c.get("/static/%2e%2e/server/app.py").status_code == 404           # web/ 밖은 못 읽음


def test_rejects_other_hosts_and_origins(client):
    assert client.get("/api/state", headers={"host": "evil.example"}).status_code == 400   # DNS 리바인딩
    assert client.get("/api/state", headers={"origin": "https://evil.example"}).status_code == 403
    assert client.get("/api/state", headers={"origin": BASE}).status_code == 200
    with TestClient(create_app(TICKET, PORT), base_url="http://evil.example") as other:
        assert other.get("/healthz").status_code == 400


def test_folder_flow_from_add_to_export(client, tmp_path):
    root, planted = materialize("vuln_flask", tmp_path)
    added = client.post("/api/repos", json={"path": str(root)})
    assert added.status_code == 201
    repo_id, scan_id = added.json()["repo"]["id"], added.json()["scan_id"]

    # 이벤트는 0.2초마다 '현재 상태'를 보내므로 빠른 스캔에서는 중간 단계가 생략될 수 있다. 끝은 항상 done 한 번.
    events = wait(client, scan_id)
    kind, last = events[-1]
    assert kind == "done" and last["stage"] == "save" and last["summary"]["risk_score"] > 0
    assert [k for k, _ in events].count("done") == 1

    result = ScanResult.from_json(client.get(f"/api/scans/{scan_id}").text)
    assert result.scan_id == scan_id and result.repo == repo_id and result.findings
    state = client.get("/api/state").json()
    assert state["repos"] == 1 and state["last_repo"] == repo_id
    assert client.get("/api/repos").json()[0]["last_scan"]["id"] == scan_id

    report = client.get(f"/api/scans/{scan_id}/export?format=md")
    assert report.headers["content-disposition"] == f'attachment; filename="wescope-vuln_flask-{scan_id}.md"'
    assert report.text.startswith("# 보안 진단 보고서 — vuln_flask")
    assert not [p for p in planted if p in report.text or p in client.get(f"/api/scans/{scan_id}").text]
    assert client.get(f"/api/scans/{scan_id}/export?format=json").json()["scan_id"] == scan_id
    assert client.get(f"/api/scans/{scan_id}/export?format=pdf").status_code == 400

    again = client.post("/api/scans", json={"repo_id": repo_id}).json()["scan_id"]   # [다시 스캔]
    wait(client, again)
    assert client.get(f"/api/scans/{again}").json()["baseline_scan"] == scan_id


def test_settings_exclude_files_on_next_scan(client, tmp_path):
    root, _ = materialize("vuln_flask", tmp_path)
    added = client.post("/api/repos", json={"path": str(root)}).json()
    repo_id = added["repo"]["id"]
    wait(client, added["scan_id"])
    assert client.post(f"/api/repos/{repo_id}/settings", json={"disabled_rules": ["no-such-rule"]}).status_code == 400
    for broken in ("foo\\", "!"):   # 해석할 수 없는 패턴은 저장 전에 거절 (저장되면 이후 검사가 모두 실패)
        assert client.post(f"/api/repos/{repo_id}/settings", json={"excludes": [broken]}).status_code == 400
    saved = client.post(f"/api/repos/{repo_id}/settings", json={"excludes": ["templates/", " "]}).json()
    assert saved == {"disabled_rules": [], "excludes": ["templates/"]}
    scan_id = client.post("/api/scans", json={"repo_id": repo_id}).json()["scan_id"]
    wait(client, scan_id)
    files = {f["location"]["file"] for f in client.get(f"/api/scans/{scan_id}").json()["findings"] if f["change"] != "fixed"}
    assert "templates/comments.html" not in files and "app.py" in files


def test_bad_inputs(client, tmp_path):
    assert client.post("/api/repos", json={}).status_code == 400
    assert client.post("/api/repos", json={"path": str(tmp_path), "github": "https://github.com/a/b"}).status_code == 400
    for url in ("file:///etc", "https://gitlab.com/a/b", "https://github.com/a/b;rm -rf", "--upload-pack=x"):
        assert client.post("/api/repos", json={"github": url}).status_code == 400, url
    assert client.post("/api/repos", json={"path": str(tmp_path / "missing")}).status_code == 400
    assert client.post("/api/scans", json={"repo_id": "nope"}).status_code == 404
    assert client.get("/api/scans/0123456789ab").status_code == 404
    assert client.get("/api/scans/0123456789ab/events").status_code == 404
    assert client.delete("/api/repos/nope").status_code == 404


def test_delete_repo_removes_results(client, tmp_path):
    root, _ = materialize("clean_app", tmp_path)
    added = client.post("/api/repos", json={"path": str(root)}).json()
    wait(client, added["scan_id"])
    assert client.delete(f"/api/repos/{added['repo']['id']}").status_code == 204
    assert client.get("/api/repos").json() == []
    assert client.get(f"/api/scans/{added['scan_id']}").status_code == 404


def test_sse_sends_done_when_scan_finishes_during_yield():
    """PR #2 리뷰: 진행 이벤트를 보내고 기다리는 사이 스캔이 끝나면 done 없이 스트림이 닫히던 문제."""
    jobs = Jobs(run=None)
    job = jobs.submit("repo")
    jobs._update(job, status="running", stage="analyze")

    async def connected():
        return False

    async def drive():
        stream = job_events(jobs, job, connected)
        first = await stream.__anext__()
        jobs._update(job, status="done", stage="save", summary={"risk_score": 0})   # 제너레이터가 yield에서 멈춘 사이
        return first, [event async for event in stream]

    first, rest = asyncio.run(drive())
    assert first.startswith("event: progress")
    assert len(rest) == 1 and rest[0].startswith("event: done") and '"stage": "save"' in rest[0]


def test_queue_merges_waiting_requests_and_survives_failures():
    gate, calls = threading.Event(), []

    def run(repo_id, *, trigger, scan_id, progress):
        calls.append(repo_id)
        gate.wait(5)
        if repo_id == "bad":
            raise RuntimeError("검사 실패")
        return type("R", (), {"summary": {"ok": True}})()

    jobs = Jobs(run)
    jobs.start()
    first = jobs.submit("a")
    while jobs.current is None:          # a가 실행되기 시작할 때까지
        pass
    second, third = jobs.submit("a"), jobs.submit("a", trigger="hook")
    assert second is third and second is not first     # 기다리는 요청은 하나로 합친다
    bad = jobs.submit("bad")
    assert jobs.busy("a") and jobs.busy("bad")
    gate.set()
    deadline = time.monotonic() + 5
    while bad.status not in ("done", "failed") and time.monotonic() < deadline:
        time.sleep(0.01)
    jobs.stop()
    assert (first.status, second.status, bad.status) == ("done", "done", "failed")
    assert bad.error == "검사 실패" and calls == ["a", "a", "bad"]


def test_hook_history_and_ignores(client, tmp_path):
    root, _ = materialize("vuln_flask", tmp_path)
    git(root, "init", "-q")
    added = client.post("/api/repos", json={"path": str(root)}).json()
    repo_id = added["repo"]["id"]
    assert added["repo"]["hook"] is True                         # 로컬 Git 폴더는 연결하면 자동 검사 켬 (PRD P6)
    hook_file = root / ".git" / "hooks" / "post-commit"
    assert repo_id in hook_file.read_text(encoding="utf-8")
    first = wait(client, added["scan_id"])[-1][1]["scan_id"]

    assert client.post(f"/api/repos/{repo_id}/hook", json={"enabled": False}).json() == {"hook": False}
    assert client.get("/api/repos").json()[0]["hook"] is False and not hook_file.exists()
    assert client.post(f"/api/repos/{repo_id}/hook", json={"enabled": True}).json() == {"hook": True}

    finding = next(f for f in client.get(f"/api/scans/{first}").json()["findings"] if f["severity"] == "HIGH")
    fp = finding["fingerprint"]
    assert client.post(f"/api/repos/{repo_id}/ignores", json={"fingerprint": "zz"}).status_code == 400
    assert client.post(f"/api/repos/{repo_id}/ignores", json={"fingerprint": "0" * 16}).status_code == 404
    marked = client.post(f"/api/repos/{repo_id}/ignores", json={"fingerprint": fp, "reason": " 테스트 코드 "})
    assert marked.status_code == 201
    assert [(i["fingerprint"], i["reason"]) for i in marked.json()] == [(fp, "테스트 코드")] and marked.json()[0]["created_at"]
    assert client.get(f"/api/repos/{repo_id}/ignores").json() == marked.json()

    hooked = client.post("/api/hook-trigger", json={"repo_id": repo_id}).json()["scan_id"]   # hook이 부르는 경로
    wait(client, hooked)
    result = client.get(f"/api/scans/{hooked}").json()
    assert result["trigger"] == "hook" and result["summary"]["dismissed"] >= 1
    assert next(f for f in result["findings"] if f["fingerprint"] == fp)["status"] == "dismissed"   # 다음 검사에 반영
    assert client.get("/api/state").json()["latest_scan"] == hooked
    assert [s["id"] for s in client.get(f"/api/repos/{repo_id}/history").json()] == [hooked, first]
    assert client.get(f"/api/repos/{repo_id}/history?limit=1").json()[0]["trigger"] == "hook"

    assert client.delete(f"/api/repos/{repo_id}/ignores/{fp}").status_code == 204
    assert client.delete(f"/api/repos/{repo_id}/ignores/{fp}").status_code == 404
    again = client.post("/api/scans", json={"repo_id": repo_id}).json()["scan_id"]
    wait(client, again)
    assert next(f for f in client.get(f"/api/scans/{again}").json()["findings"] if f["fingerprint"] == fp)["status"] == "open"

    assert client.delete(f"/api/repos/{repo_id}").status_code == 204
    assert not hook_file.exists()                                # 연결 해제하면 우리 hook 줄도 지운다


def test_hook_needs_local_git_folder_and_global_settings(client, tmp_path):
    root, _ = materialize("clean_app", tmp_path)
    added = client.post("/api/repos", json={"path": str(root)}).json()
    assert added["repo"]["hook"] is None
    assert client.post(f"/api/repos/{added['repo']['id']}/hook", json={"enabled": True}).status_code == 400
    assert client.post("/api/hook-trigger", json={"repo_id": "nope"}).status_code == 404
    for path in ("/api/repos/nope/history", "/api/repos/nope/ignores"):
        assert client.get(path).status_code == 404

    defaults = {"theme": "system", "ai_level": "deep", "ai_on_hook": False}
    assert client.get("/api/settings").json() == defaults
    assert client.post("/api/settings", json={"theme": "blue"}).status_code == 400
    assert client.post("/api/settings", json={"ai_level": "max"}).status_code == 400
    assert client.post("/api/settings", json={"theme": "dark"}).json() == {**defaults, "theme": "dark"}
    assert client.post("/api/settings", json={"ai_on_hook": True}).json() == {**defaults, "theme": "dark",
                                                                               "ai_on_hook": True}   # 보낸 항목만 바뀐다
    assert 'theme = "dark"' in (home() / "config.toml").read_text(encoding="utf-8")


def test_fix_api_attaches_fix_to_latest_scan(client, tmp_path, monkeypatch):
    from test_llm.fake_chatgpt import FakeChatGPT, answer, replace_lines
    root, _ = materialize("vuln_flask", tmp_path)
    added = client.post("/api/repos", json={"path": str(root)}).json()
    first = added["scan_id"]
    wait(client, first)
    url = f"/api/scans/{first}/groups/config-weak-secret/fix"
    assert client.post(url).status_code == 409                          # ChatGPT 연결 전

    weak = 'app.config["SECRET_KEY"] = "dev"'
    fake = FakeChatGPT(lambda p: answer(replace_lines(p, "app.py", {weak: 'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]'}))
                       if p["rule"]["rule_id"] == "config-weak-secret" else answer("x"))
    monkeypatch.setattr("wescope.llm.client.connected", lambda: fake)
    assert client.post(f"/api/scans/{first}/groups/no-such-rule/fix").status_code == 404
    started = client.post(url)
    assert started.status_code == 202 and started.json() == {"scan_id": first}
    kind, job = wait(client, first)[-1]
    assert kind == "done" and job["rule_id"] == "config-weak-secret"
    fixed = next(f for f in client.get(f"/api/scans/{first}").json()["findings"] if f["rule_id"] == "config-weak-secret")
    assert fixed["fix"]["verification"] == "verified"

    again = client.post("/api/scans", json={"repo_id": added["repo"]["id"]}).json()["scan_id"]   # AI 연결 후 검사
    wait(client, again)
    assert client.get(f"/api/scans/{again}").json()["ai"]["fixes"]["verified"] == 1   # HIGH 묶음 자동 생성
    assert client.post(url).status_code == 409                          # 예전 검사에는 만들지 않는다

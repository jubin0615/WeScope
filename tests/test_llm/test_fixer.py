"""수정안 생성·검증 (AI.md §3): 가짜 ChatGPT로 끝까지. Semgrep은 꺼서 빠르게 (재검사는 Python 탐지기로 충분)."""
import hashlib
import json
from pathlib import Path

import pytest

from conftest import materialize
from fake_chatgpt import FakeChatGPT, answer, replace_lines
from wescope.collector.snapshot import Target
from wescope.llm.client import LLMError
from wescope.scan import run_scan

WEAK = 'app.config["SECRET_KEY"] = "dev"'
FIXED_WEAK = 'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]'


@pytest.fixture(autouse=True)
def no_semgrep(monkeypatch):
    monkeypatch.setattr("wescope.analyzers.semgrep.find_semgrep", lambda: None)


@pytest.fixture
def app(tmp_path):
    return materialize("vuln_flask", tmp_path)


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode() + path.read_bytes())
    return digest.hexdigest()


def by_rule(rules: dict):
    """rule_id → respond(payload). 다른 묶음에는 diff가 아닌 응답(→ failed)을 준다."""
    def respond(payload):
        make = rules.get(payload["rule"]["rule_id"])
        return make(payload) if make else answer("고칠 수 없어요")
    return respond


def fixes(result):
    return {f.rule_id: f.fix for f in result.findings if f.fix}


def weak_secret_fix(payload):
    return answer(replace_lines(payload, "app.py", {WEAK: FIXED_WEAK}),
                  follow_ups=["배포 환경에 SECRET_KEY를 등록하세요"])


def test_verified_fix_is_attached_and_original_untouched(app):
    root, _ = app
    before = tree_hash(root)
    fake = FakeChatGPT(by_rule({"config-weak-secret": weak_secret_fix}))
    result = run_scan(Target("folder", str(root)), ai=fake)

    fix = fixes(result)["config-weak-secret"]
    assert fix["verification"] == "verified" and fix["attempts"] == 1
    assert fix["checks"] == {"apply": True, "syntax": True, "rescan": True, "reasons": []}
    assert list(fix)[-5:] == ["verification", "checks", "attempts", "cache_key", "instruction_suspect"]
    assert fix["follow_ups"] == ["배포 환경에 SECRET_KEY를 등록하세요"]
    first = next(f for f in result.findings if f.rule_id == "config-weak-secret")
    assert first.fix is fix                                  # 묶음의 대표(첫) 발견에 붙는다
    ai = result.ai
    assert ai["fixes"]["verified"] == 1 and ai["fixes"]["failed"] == 4
    assert ai["budget_exceeded"] and ai["remaining_groups"] > 0          # HIGH 묶음이 5개보다 많다
    assert ai["requests"] == len(fake.requests) == 1 + 4 * 2             # 실패한 묶음은 한 번씩 다시 요청
    assert tree_hash(root) == before                                     # 사용자 코드는 고치지 않는다


def test_secrets_never_leave_and_placeholders_round_trip(app):
    root, planted = app

    def env_fix(payload):
        diff = replace_lines(payload, "app.py", {
            "OPENAI_API_KEY =": 'OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]',
            "DATABASE_URL =": 'DATABASE_URL = os.environ["DATABASE_URL"]'})
        return answer(diff)

    fake = FakeChatGPT(by_rule({"secret-hardcoded": env_fix}))
    result = run_scan(Target("folder", str(root)), ai=fake)

    sent = json.dumps(fake.requests, ensure_ascii=False)
    assert planted and not [s for s in planted if s in sent]             # 보낸 요청 어디에도 원문 없음
    assert "«WS_SECRET_1»" in sent
    fix = fixes(result)["secret-hardcoded"]
    assert fix["verification"] == "verified"                             # 자리표시를 복원해 적용·재검사했다
    assert "«WS_SECRET_" in fix["diff"] and not [s for s in planted if s in result.to_json()]


def test_failed_attempt_is_retried_with_reasons(app):
    root, _ = app

    def respond(payload):
        if payload["rule"]["rule_id"] != "config-weak-secret":
            return answer("x")
        if payload["previous_attempt"] is None:     # 첫 시도: 적용은 되지만 문법이 깨진다
            return answer(replace_lines(payload, "app.py", {WEAK: 'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"'}))
        return weak_secret_fix(payload)

    fake = FakeChatGPT(respond)
    fix = fixes(run_scan(Target("folder", str(root)), ai=fake))["config-weak-secret"]
    assert fix["verification"] == "verified" and fix["attempts"] == 2
    retry = [r for r in fake.requests if r["rule"]["rule_id"] == "config-weak-secret"][1]
    assert any("문법 오류" in reason for reason in retry["previous_attempt"]["failures"])


def test_fix_that_leaves_the_problem_is_partial_and_bad_diffs_fail(app):
    root, _ = app
    rules = {
        # 적용·문법은 되지만 약한 키가 그대로 → 재검사에서 남음
        "config-weak-secret": lambda p: answer(replace_lines(p, "app.py", {WEAK: WEAK + "  # TODO"})),
        # 묶음에 없는 파일을 고침 → 적용 전에 거절
        "config-cors-credentials": lambda p: answer("--- a/models.py\n+++ b/models.py\n@@ -1,1 +1,1 @@\n-x\n+y\n"),
    }
    result = run_scan(Target("folder", str(root)), ai=FakeChatGPT(by_rule(rules)))
    weak, cors = fixes(result)["config-weak-secret"], fixes(result)["config-cors-credentials"]
    assert weak["verification"] == "partial" and weak["attempts"] == 2
    assert weak["checks"]["apply"] and weak["checks"]["syntax"] and weak["checks"]["rescan"] is False
    assert any(r.startswith("문제가 남아 있어요: app.py:") for r in weak["checks"]["reasons"])
    assert cors["verification"] == "failed" and "고칠 대상이 아닌 파일" in cors["checks"]["reasons"][0]


def test_same_code_is_answered_from_cache(app):
    root, _ = app
    first = FakeChatGPT(by_rule({"config-weak-secret": weak_secret_fix}))
    one = run_scan(Target("folder", str(root)), ai=first)
    again = FakeChatGPT(lambda p: pytest.fail("같은 코드인데 다시 요청했어요"))
    two = run_scan(Target("folder", str(root)), ai=again)
    assert two.ai["requests"] == 0 and two.ai["cache_hits"] == one.ai["requests"]
    assert fixes(two)["config-weak-secret"]["diff"] == fixes(one)["config-weak-secret"]["diff"]


def test_usage_limit_stops_ai_but_keeps_static_results(app):
    root, _ = app
    static = run_scan(Target("folder", str(root)))
    fake = FakeChatGPT(lambda p: LLMError("ChatGPT 사용량 한도에 도달했어요", "limit"))
    result = run_scan(Target("folder", str(root)), ai=fake)
    assert len(fake.requests) == 1 and result.ai["error"]["kind"] == "limit"
    assert not fixes(result)
    assert [f.fingerprint for f in result.findings] == [f.fingerprint for f in static.findings]

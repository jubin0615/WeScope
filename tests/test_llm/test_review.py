"""보완 탐지 (AI.md §5, llm/review.py): 가짜 ChatGPT로. 벤치 앱 vuln_logic은 정적 분석으로는 찾기 어려운
IDOR(서비스 계층)·대량 할당·가격 변조·파일 간 SQL을 심어 두었다 (`# ai-expect:` 주석)."""
import json

import pytest

from conftest import materialize
from fake_chatgpt import FakeChatGPT, answer, sent_lines
from wescope.collector.context import collect
from wescope.collector.snapshot import Target
from wescope.llm import review
from wescope.scan import run_scan


@pytest.fixture(autouse=True)
def no_semgrep(monkeypatch):
    monkeypatch.setattr("wescope.analyzers.semgrep.find_semgrep", lambda: None)


@pytest.fixture
def logic(tmp_path):
    return materialize("vuln_logic", tmp_path)[0]


def at(payload, path, needle, **fields) -> dict:
    """보낸 코드에서 needle이 든 줄을 정확히 인용한 보완 탐지 항목 (모델이 하는 일)."""
    line, code = next((n, c) for n, c in sent_lines(payload, path).items() if needle in c)
    return {"file": path, "line_start": line, "line_end": line, "quoted_code": code.strip(),
            "attack_scenario_ko": "공격자가 값을 바꿔 보내요", "why_ko": f"{needle} 때문에 위험해요",
            "fix_ko": "서버에서 다시 계산하세요", **fields}


def scan(root, found, **kw):
    fake = FakeChatGPT(lambda p: answer("고칠 수 없어요"), review=lambda p: {"findings": found(p)})
    return run_scan(Target("folder", str(root)), ai=fake, **kw), fake


def ai_findings(result):
    return {f.rule_id: f for f in result.findings if f.source == "ai"}


def test_targets_are_the_risky_route_files(logic):
    with collect(Target("folder", str(logic))) as ctx:
        assert review.targets(ctx) == [{"path": "app.py", "areas": ["payment", "authz", "authn", "mass", "flow"],
                                        "with": ["repo.py", "models.py", "services.py"]}]   # 쿼리가 있는 파일 먼저 함께 보낸다


def test_quoted_findings_become_ai_findings(logic):
    def found(p):
        return [at(p, "app.py", 'request.json["unit_price"]', vuln_type="price-tampering", severity="CRITICAL"),
                at(p, "app.py", "load_order(order_id)", vuln_type="idor", severity="CRITICAL"),     # 상한 HIGH
                at(p, "repo.py", "conn.execute", vuln_type="cross-file-injection-sql", severity="HIGH")]
    result, fake = scan(logic, found)
    ai = ai_findings(result)
    assert set(ai) == {"ai-price-tampering", "ai-idor", "ai-cross-file-injection-sql"}
    price = ai["ai-price-tampering"]
    assert (price.severity, price.confidence, price.confidence_source) == ("CRITICAL", "Potential", "ai")
    assert price.category == "WS-07" and price.cwe == "CWE-602" and price.owasp == "A06:2025"
    assert "unit_price" in price.evidence and price.why_ko == 'request.json["unit_price"] 때문에 위험해요'
    assert price.extra["attack_scenario_ko"] and "why_ko" not in price.extra
    assert ai["ai-idor"].severity == "HIGH"                                   # 유형별 상한을 넘지 못한다
    assert ai["ai-cross-file-injection-sql"].location.file == "repo.py"
    assert result.ai["review"] == {"targets": 1, "found": 3, "merged": 0, "discarded": 0, "remaining": 0}
    rows = {r.code: (r.state, r.findings) for r in result.ai_coverage}
    assert rows == {"AI-AUTHZ": ("reviewed", 3), "AI-PAYMENT": ("reviewed", 3), "AI-FLOW": ("reviewed", 3),
                    "AI-LANG": ("not_applicable", 0)}
    assert fake.efforts == {"review": {"high"}, "fix": {"high"}}            # AI.md §7: 수정안·보완 탐지는 높게
    sent = [r for r in fake.requests if r["task"] == "review"][0]
    assert [f["path"] for f in sent["files"]] == ["app.py", "repo.py", "models.py", "services.py"] and "price-tampering" in json.dumps(sent)


@pytest.mark.parametrize("bad", [
    {"vuln_type": "sql-magic"},                                                  # 정해진 유형이 아님
    {"file": "models.py"},                                                       # 보내지 않은 파일
    {"line_start": 1, "line_end": 1},                                            # 그 줄에 없는 코드
    {"quoted_code": "total = request.json['price']"},                            # 지어낸 코드
    {"quoted_code": 7},
])
def test_hallucinated_findings_are_discarded(logic, bad):
    result, _ = scan(logic, lambda p: [{**at(p, "app.py", "unit_price", vuln_type="price-tampering"), **bad}])
    assert not ai_findings(result) and result.ai["review"]["discarded"] == 1


def test_same_place_and_cwe_as_a_static_finding_is_merged(tmp_path):
    root, _ = materialize("vuln_flask", tmp_path)            # authz-idor(CWE-639)가 GET /orders 핸들러에 있다
    result, _ = scan(root, lambda p: [at(p, "app.py", "def get_order", vuln_type="idor")])
    assert not ai_findings(result) and result.ai["review"]["merged"] == 1
    idor = next(f for f in result.findings if f.rule_id == "authz-idor")
    assert idor.extra["ai_also_ko"].startswith("ChatGPT도 같은 문제를 지적했어요")


def test_secrets_never_leave_in_review_requests(tmp_path):
    root, planted = materialize("vuln_flask", tmp_path)
    _, fake = scan(root, lambda p: [])
    sent = json.dumps([r for r in fake.requests if r["task"] == "review"], ensure_ascii=False)
    assert sent and planted and not [s for s in planted if s in sent]


def test_basic_level_does_not_review(logic):
    result, fake = scan(logic, lambda p: pytest.fail("기본 수준에서 보완 탐지를 했어요"), ai_level="basic")
    assert result.ai["review"] is None and result.ai_coverage == []
    assert not [r for r in fake.requests if r["task"] == "review"]


def test_same_issue_quoted_from_another_line_stays_one_finding(logic):
    """코드가 바뀌어 다시 물으면 ChatGPT가 같은 문제를 다른 줄부터 인용할 수 있다 (실제 확인에서 34행 → 35행).
    같은 함수 안의 같은 유형이면 같은 발견(existing)이어야 한다. 새 발견 + 고쳐짐으로 갈라지면 안 된다."""
    first, _ = scan(logic, lambda p: [at(p, "app.py", "unit_price", vuln_type="price-tampering")])
    app = logic / "app.py"
    app.write_text(app.read_text(encoding="utf-8").replace("@app.route(\"/search\")", "# 검색\n@app.route(\"/search\")"),
                   encoding="utf-8")                                             # 다른 함수만 바뀜 → 다시 묻는다
    again, _ = scan(logic, lambda p: [at(p, "app.py", "quantity = int", vuln_type="price-tampering")], previous=first)
    price = [f for f in again.findings if f.rule_id == "ai-price-tampering"]
    assert [f.change for f in price] == ["existing"]


def test_files_sent_along_count_as_reviewed(logic):
    """함께 보낸 파일(repo.py)도 검토한 것이다: 다시 검토했는데 없으면 확인 불가가 아니라 고쳐짐 (실제 확인에서 unknown이 났다)."""
    first, _ = scan(logic, lambda p: [at(p, "repo.py", "conn.execute", vuln_type="cross-file-injection-sql")])
    app = logic / "app.py"
    app.write_text(app.read_text(encoding="utf-8") + "\n", encoding="utf-8")   # 다시 묻게
    again, _ = scan(logic, lambda p: [], previous=first)
    assert ai_findings(again)["ai-cross-file-injection-sql"].change == "fixed"


def test_ai_findings_not_rechecked_are_unknown_not_fixed(logic):
    """직전 AI 발견: 이번에 AI가 그 파일을 검토하지 않았으면 확인 불가(unknown), 검토했는데 없으면 고쳐짐(fixed)."""
    first, _ = scan(logic, lambda p: [at(p, "app.py", "unit_price", vuln_type="price-tampering")])
    without_ai = run_scan(Target("folder", str(logic)), previous=first)          # 커밋 자동 검사처럼 AI 없이
    assert ai_findings(without_ai)["ai-price-tampering"].change == "unknown"
    again, _ = scan(logic, lambda p: pytest.fail("코드가 같은데 다시 물었어요"), previous=first)   # 캐시: 같은 답
    assert ai_findings(again)["ai-price-tampering"].change == "existing"
    app = logic / "app.py"                                                       # 고친 뒤 다시 검토하면 없다
    app.write_text(app.read_text(encoding="utf-8").replace('float(request.json["unit_price"])', "float(product.price)"),
                   encoding="utf-8")
    fixed, _ = scan(logic, lambda p: [], previous=first)
    assert ai_findings(fixed)["ai-price-tampering"].change == "fixed"


def test_fix_for_an_ai_finding_is_never_verified_by_static_rescan(logic):
    """정적 재검사는 AI 발견을 원래 못 찾는다: 주석만 단 수정안도 '문제가 사라졌다'로 보인다. 그래서 partial로 두고
    (AI.md §3-4), 다시 물어도 판정이 같으므로 재요청하지 않는다."""
    from fake_chatgpt import replace_lines
    found = lambda p: [at(p, "app.py", 'request.json["unit_price"]', vuln_type="price-tampering")]
    comment = lambda p: answer(replace_lines(p, "app.py", {'request.json["unit_price"]':
                                                           '    total = float(request.json["unit_price"]) * quantity  # ok'}))
    fake = FakeChatGPT(comment, review=lambda p: {"findings": found(p)})
    fix = ai_findings(run_scan(Target("folder", str(logic)), ai=fake))["ai-price-tampering"].fix
    assert fix["verification"] == "partial" and fix["checks"]["rescan"] is None and fix["attempts"] == 1
    assert "정적 분석으로는 다시 확인할 수 없는" in fix["checks"]["reasons"][0]


def test_previous_ai_finding_outside_the_sent_excerpt_is_unknown(logic, monkeypatch):
    """큰 파일은 발췌만 보낸다. 직전 AI 발견이 보낸 줄 밖이면 모델이 못 본 것이니 고쳐짐이 아니라 확인 불가."""
    path = logic / "services.py"
    filler = "".join(f"\n\ndef helper_{n}(x):\n    return x + {n}\n" for n in range(40))
    path.write_text(path.read_text(encoding="utf-8") + filler + "\n\nSTORE = {}\n\n\ndef cached_item(key):\n    return STORE[key]\n",
                    encoding="utf-8")
    first, _ = scan(logic, lambda p: [at(p, "services.py", "return STORE[key]", vuln_type="idor")])
    monkeypatch.setattr(review, "WHOLE_FILE", 50)                                # 큰 파일처럼: 발췌만 보낸다
    app = logic / "app.py"
    app.write_text(app.read_text(encoding="utf-8") + "\n", encoding="utf-8")      # 다시 묻게
    again, fake = scan(logic, lambda p: [], previous=first)
    sent = [f for r in fake.requests if r["task"] == "review" for f in r["files"] if f["path"] == "services.py"]
    assert sent and sent[0]["excerpt"] and "STORE[key]" not in sent[0]["content"]
    assert ai_findings(again)["ai-idor"].change == "unknown"


@pytest.mark.parametrize("broken", [{}, {"error": "unable to review"}, {"findings": "none"}])
def test_malformed_review_answer_does_not_count_as_reviewed(logic, broken):
    """findings 목록이 없는 응답은 '검토했는데 없음'이 아니다: 직전 AI 발견을 고쳐짐으로 바꾸지 않는다."""
    first, _ = scan(logic, lambda p: [at(p, "app.py", "unit_price", vuln_type="price-tampering")])
    app = logic / "app.py"
    app.write_text(app.read_text(encoding="utf-8") + "\n", encoding="utf-8")      # 다시 묻게
    fake = FakeChatGPT(lambda p: answer("x"), review=lambda p: broken)
    again = run_scan(Target("folder", str(logic)), ai=fake, previous=first)
    assert ai_findings(again)["ai-price-tampering"].change == "unknown"
    assert again.ai["error"]["kind"] == "error" and again.ai["review"]["targets"] == 0


def test_same_method_name_in_different_classes_stays_separate(tmp_path):
    """다른 클래스의 같은 이름 메서드(OrderAPI.get, UserAPI.get)는 다른 함수다: 같은 유형이어도 발견 둘."""
    (tmp_path / "app.py").write_text(
        "from flask import Flask\nfrom flask.views import MethodView\n\napp = Flask(__name__)\n\n\n"
        "class OrderAPI(MethodView):\n    def get(self, id):\n        return Order.query.get(id)\n\n\n"
        "class UserAPI(MethodView):\n    def get(self, id):\n        return User.query.get(id)\n\n\n"
        "@app.route('/ping')\ndef ping():\n    return 'ok'\n", encoding="utf-8")
    found = lambda p: [at(p, "app.py", "Order.query.get(id)", vuln_type="idor"),
                       at(p, "app.py", "User.query.get(id)", vuln_type="idor")]
    result, _ = scan(tmp_path, found)
    assert len([f for f in result.findings if f.rule_id == "ai-idor"]) == 2


def test_malformed_review_answer_is_asked_again_next_time(logic):
    """틀린 응답은 캐시에 남지 않는다: 코드가 그대로여도 다음 검사에서 다시 물어 제대로 검토한다."""
    fake = FakeChatGPT(lambda p: answer("x"), review=lambda p: {"error": "busy"})
    run_scan(Target("folder", str(logic)), ai=fake)
    again, _ = scan(logic, lambda p: [at(p, "app.py", "unit_price", vuln_type="price-tampering")])
    assert "ai-price-tampering" in ai_findings(again)

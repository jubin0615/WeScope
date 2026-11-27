"""rules/semgrep 규칙별 취약·안전 표본. 'ruleid: X' 다음 줄은 잡혀야 하고 'ok: X' 다음 줄은 잡히면 안 된다."""
import re
import shutil
from pathlib import Path

import pytest

from wescope.analyzers.semgrep import SemgrepAnalyzer
from wescope.collector.context import collect
from wescope.collector.snapshot import Target

SAMPLES = Path(__file__).parent / "semgrep_samples"
_MARK = re.compile(r"(?:#|//|\{#)\s*(ruleid|ok):\s*([\w-]+)")


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep 미설치")
def test_semgrep_samples():
    with collect(Target("folder", str(SAMPLES))) as ctx:
        result = SemgrepAnalyzer().run(ctx)
        got = {(h.file, h.line, h.rule_id) for h in result.hits}
        expect, ok = set(), set()
        for path in ctx.files:
            for number, line in enumerate(ctx.text(path).splitlines(), 1):
                if m := _MARK.search(line):
                    (expect if m[1] == "ruleid" else ok).add((path, number + 1, m[2]))
        react = [h for h in result.hits if h.file == "client.jsx" and h.line == 6]
    assert result.status == "ok"
    assert expect - got == set(), "놓친 취약 표본"
    assert got & ok == set(), "안전 표본 오탐"
    assert got - expect == set(), "표시하지 않은 발견"
    assert react and react[0].confidence == "Potential"   # 흐름을 보지 못한 React 패턴은 부재 추정


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep 미설치")
def test_rescan_runs_only_on_changed_files():
    """수정안 재검사(ctx.changed)는 바뀐 파일만 본다. 규칙이 파일 하나 안에서만 보므로 그 파일의 결과는 전체 검사와 같다."""
    with collect(Target("folder", str(SAMPLES))) as ctx:
        full = {(h.file, h.line, h.rule_id) for h in SemgrepAnalyzer().run(ctx).hits}
        ctx.changed = frozenset({"inject_js.js"})
        only = {(h.file, h.line, h.rule_id) for h in SemgrepAnalyzer().run(ctx).hits}
        ctx.changed = frozenset({"tests/test_app.py"})        # 테스트 파일은 전체 검사처럼 빠진다
        skipped = SemgrepAnalyzer().run(ctx)
    assert only and only == {h for h in full if h[0] == "inject_js.js"}
    assert skipped.hits == [] and skipped.status == "ok"
